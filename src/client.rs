use std::collections::HashMap;

use serde::Deserialize;
use url::Url;

use std::sync::Arc;

use crate::callback::{AuthorizationRequest, Callback, PendingAuth};
use crate::clock::{Clock, SystemClock};
use crate::config::{ProviderConfig, REDACTED};
use crate::jwks::Jwks;
use crate::provider::ClientAuth;
use crate::spec::{ProviderId, TokenExtra};
use crate::{pkce, profile, Error, ExternalIdentity, Result};

/// How long a [`PendingAuth`] stays valid.
const PENDING_TTL_SECS: u64 = 15 * 60;
/// Upper bound for any provider response body.
const MAX_RESPONSE_BYTES: usize = 1 << 20;
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Token endpoint response. `Debug` prints no token values.
#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    /// Access token.
    pub access_token: String,
    #[serde(default)]
    /// Token type, usually `Bearer`.
    pub token_type: Option<String>,
    #[serde(default)]
    /// OIDC `id_token`.
    pub id_token: Option<String>,
    #[serde(default)]
    /// Refresh token, if issued.
    pub refresh_token: Option<String>,
    #[serde(default)]
    /// Access token lifetime in seconds.
    pub expires_in: Option<u64>,
    #[serde(flatten)]
    /// Provider-specific extra fields.
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut extra: Vec<&str> = self.extra.keys().map(String::as_str).collect();
        extra.sort_unstable();
        f.debug_struct("TokenResponse")
            .field("access_token", &REDACTED)
            .field("token_type", &self.token_type)
            .field("id_token", &self.id_token.as_ref().map(|_| REDACTED))
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| REDACTED),
            )
            .field("expires_in", &self.expires_in)
            .field("extra", &extra)
            .finish()
    }
}

/// OAuth 2.0 / OIDC client for all configured providers.
#[derive(Clone)]
pub struct OAuthClient {
    http: reqwest::Client,
    clock: Arc<dyn Clock>,
    providers: HashMap<ProviderId, Registration>,
}

/// A registered provider with what is derived from its configuration once.
#[derive(Clone)]
struct Registration {
    config: ProviderConfig,
    /// Authorization URL with every per-registration parameter already
    /// encoded; `authorize` only appends the per-request ones.
    base_url: std::result::Result<Url, String>,
    jwks: Option<Arc<Jwks>>,
}

impl std::fmt::Debug for OAuthClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut providers: Vec<&ProviderId> = self.providers.keys().collect();
        providers.sort();
        f.debug_struct("OAuthClient")
            .field("providers", &providers)
            .finish_non_exhaustive()
    }
}

impl Default for OAuthClient {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthClient {
    /// Client with sane defaults: no redirects, 5 s connect and 15 s request timeouts.
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("rega/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("default HTTP client");
        Self::with_http_client(http)
    }

    /// Client using a custom HTTP client (proxies, custom TLS, timeouts).
    pub fn with_http_client(http: reqwest::Client) -> Self {
        Self {
            http,
            clock: Arc::new(SystemClock),
            providers: HashMap::new(),
        }
    }

    /// Replaces the time source used for the lifetime of a login attempt and
    /// the expiry of `id_token`s checked without signature verification.
    /// Meant for tests; signature verification and the Apple-secret and JWKS
    /// caches keep using the system clock.
    pub fn with_clock(mut self, clock: impl Clock + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Registers (or replaces) a provider.
    pub fn register(mut self, config: ProviderConfig) -> Self {
        let registration = Registration {
            base_url: base_authorize_url(&config),
            jwks: config
                .spec
                .endpoints
                .jwks
                .clone()
                .map(|url| Arc::new(Jwks::new(url))),
            config,
        };
        self.providers
            .insert(registration.config.spec.id.clone(), registration);
        self
    }

    /// Verifies an `id_token` obtained outside the redirect flow — e.g. from the
    /// Google Sign-In or Sign in with Apple SDK in a mobile app — and returns the
    /// identity. The signature is always checked against the provider's JWKS.
    /// `audience` defaults to the configured `client_id`; mobile apps usually
    /// have their own (iOS bundle id / Android client id).
    pub async fn verify_id_token(
        &self,
        provider: impl Into<ProviderId>,
        id_token: &str,
        audience: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<ExternalIdentity> {
        let reg = self.registration(provider.into())?;
        let cfg = &reg.config;
        let jwks = reg.jwks.as_ref().ok_or_else(|| {
            Error::Config(format!(
                "{}: no JWKS endpoint, id_token login is unsupported",
                cfg.spec.id
            ))
        })?;
        let aud = audience.unwrap_or(&cfg.client_id);
        let issuer = cfg.spec.endpoints.issuer.as_deref();
        let claims = jwks
            .verify(&self.http, issuer, id_token, aud, nonce)
            .await?;
        profile::map(&cfg.spec, claims, &Callback::default())
    }

    /// Exchanges a refresh token for a new access token.
    pub async fn refresh(
        &self,
        provider: impl Into<ProviderId>,
        refresh_token: &str,
    ) -> Result<TokenResponse> {
        let cfg = self.config(provider)?;
        let form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];
        let resp = self.client_request(cfg, &cfg.spec.endpoints.token, form)?;
        let body = read_json(resp.send().await?).await?;
        Ok(serde_json::from_value(body)?)
    }

    /// Revokes an access or refresh token (RFC 7009). Apple requires this when
    /// a user deletes their account.
    pub async fn revoke(
        &self,
        provider: impl Into<ProviderId>,
        token: &str,
        hint: Option<&str>,
    ) -> Result<()> {
        let cfg = self.config(provider)?;
        let url = cfg.spec.endpoints.revoke.as_deref().ok_or_else(|| {
            Error::Config(format!("{}: token revocation is unsupported", cfg.spec.id))
        })?;
        let mut form = vec![("token", token)];
        if let Some(hint) = hint {
            form.push(("token_type_hint", hint));
        }
        let resp = self.client_request(cfg, url, form)?.send().await?;
        if resp.status().is_success() {
            return Ok(());
        }
        read_json(resp).await.map(drop)
    }

    /// Registered providers.
    pub fn providers(&self) -> impl Iterator<Item = &ProviderId> + '_ {
        self.providers.keys()
    }

    /// Registration of `provider`.
    pub fn config(&self, provider: impl Into<ProviderId>) -> Result<&ProviderConfig> {
        self.registration(provider.into()).map(|r| &r.config)
    }

    fn registration(&self, provider: ProviderId) -> Result<&Registration> {
        match self.providers.get(&provider) {
            Some(registration) => Ok(registration),
            None => Err(Error::NotConfigured(provider)),
        }
    }

    /// Step 1: build the URL to redirect the user to.
    pub fn authorize(&self, provider: impl Into<ProviderId>) -> Result<AuthorizationRequest> {
        let reg = self.registration(provider.into())?;
        let spec = &reg.config.spec;
        if !spec.redirect_flow {
            return Err(Error::Config(format!(
                "{} has no redirect flow (Telegram: use rega::telegram::verify_login)",
                spec.id
            )));
        }
        let mut url = match &reg.base_url {
            Ok(url) => url.clone(),
            Err(e) => return Err(Error::Config(format!("authorize endpoint: {e}"))),
        };

        let [state, nonce, code_verifier] = pkce::random_tokens::<3>();
        let nonce = spec.nonce.then_some(nonce);
        let code_verifier = spec.pkce.then_some(code_verifier);

        {
            let mut q = url.query_pairs_mut();
            q.append_pair("state", &state);
            if let Some(v) = &code_verifier {
                q.append_pair("code_challenge", &pkce::challenge(v))
                    .append_pair("code_challenge_method", "S256");
            }
            if let Some(n) = &nonce {
                q.append_pair("nonce", n);
            }
        }

        Ok(AuthorizationRequest {
            url,
            pending: PendingAuth {
                provider: spec.id.clone(),
                state,
                nonce,
                code_verifier,
                created_at: self.clock.now(),
            },
        })
    }

    /// Step 2: handle the redirect back — verify state, exchange the code and
    /// load the user's profile.
    pub async fn complete(
        &self,
        callback: &Callback,
        pending: &PendingAuth,
    ) -> Result<ExternalIdentity> {
        callback.reject_duplicates()?;
        if let Some(error) = callback.get("error") {
            return Err(Error::Provider {
                error: error.to_string(),
                description: callback
                    .get("error_description")
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        let state = callback.get("state").unwrap_or_default();
        if pending.state.is_empty() || !pkce::constant_time_eq(state, &pending.state) {
            return Err(Error::StateMismatch);
        }
        let now = self.clock.now();
        if now.saturating_sub(pending.created_at) > PENDING_TTL_SECS {
            return Err(Error::Expired);
        }
        let code = callback
            .get("code")
            .filter(|c| !c.is_empty())
            .ok_or(Error::MissingCode)?;
        let reg = self.registration(pending.provider.clone())?;
        let cfg = &reg.config;
        let token = self.exchange_code(cfg, code, callback, pending).await?;
        let jwks = reg.jwks.as_deref();
        profile::fetch(&self.http, cfg, &token, callback, pending, jwks, now).await
    }

    async fn exchange_code(
        &self,
        cfg: &ProviderConfig,
        code: &str,
        callback: &Callback,
        pending: &PendingAuth,
    ) -> Result<TokenResponse> {
        let mut form: Vec<(&str, &str)> = Vec::with_capacity(8);
        form.extend([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", cfg.redirect_uri.as_str()),
        ]);
        if let Some(v) = &pending.code_verifier {
            form.push(("code_verifier", v));
        }
        match cfg.spec.token_extra {
            TokenExtra::None => {}
            // VK ID binds the code to the device id returned in the callback.
            TokenExtra::DeviceIdAndState => {
                form.push(("device_id", callback.get("device_id").unwrap_or_default()));
                form.push(("state", &pending.state));
            }
        }
        let req = self.client_request(cfg, &cfg.spec.endpoints.token, form)?;
        let body = read_json(req.send().await?).await?;
        Ok(serde_json::from_value(body)?)
    }

    /// A form POST carrying the client's credentials the way the provider
    /// expects them (HTTP Basic or form fields).
    fn client_request<'a>(
        &self,
        cfg: &'a ProviderConfig,
        url: &str,
        form: Vec<(&'a str, &'a str)>,
    ) -> Result<reqwest::RequestBuilder> {
        let secret = cfg.client_secret.resolve(&cfg.client_id)?;
        let mut req = self.http.post(url).header("Accept", "application/json");
        // Re-borrow at a lifetime short enough to also hold the resolved secret.
        let mut form: Vec<(&str, &str)> = form.into_iter().collect();
        form.push(("client_id", &cfg.client_id));
        if let Some(secret) = &secret {
            match cfg.spec.client_auth {
                ClientAuth::Basic => req = req.basic_auth(&cfg.client_id, Some(secret)),
                ClientAuth::Post => form.push(("client_secret", secret)),
            }
        }
        Ok(req.form(&form))
    }
}

/// Authorization URL with the parameters that never change per request.
fn base_authorize_url(cfg: &ProviderConfig) -> std::result::Result<Url, String> {
    let spec = &cfg.spec;
    let mut url = Url::parse(&spec.endpoints.authorize).map_err(|e| e.to_string())?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", &cfg.client_id)
            .append_pair("redirect_uri", &cfg.redirect_uri);
        if !cfg.scopes.is_empty() {
            q.append_pair("scope", &cfg.scopes.join(&spec.scope_separator));
        }
        if spec.form_post {
            q.append_pair("response_mode", "form_post");
        }
        for (k, v) in spec.authorize_params.iter().chain(&cfg.authorize_params) {
            q.append_pair(k, v);
        }
    }
    Ok(url)
}

/// Reads a JSON body and maps OAuth error payloads (including GitHub's
/// `200 OK` + `{"error": ...}`) to [`Error::Provider`].
pub(crate) async fn read_json(mut resp: reqwest::Response) -> Result<serde_json::Value> {
    let status = resp.status();
    if resp
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err(Error::InvalidResponse(format!(
            "HTTP {status}: response too large"
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(Error::InvalidResponse(format!(
                "HTTP {status}: response too large"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    let json: serde_json::Value = serde_json::from_slice(&body).map_err(|_| {
        let head = String::from_utf8_lossy(&body[..body.len().min(200)]);
        Error::InvalidResponse(format!("HTTP {status}: {head}"))
    })?;
    if let Some(error) = json.get("error") {
        let error = match error {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let description = json["error_description"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        return Err(Error::Provider { error, description });
    }
    if !status.is_success() {
        return Err(Error::InvalidResponse(format!("HTTP {status}: {json}")));
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provider;

    fn client() -> OAuthClient {
        Provider::ALL.into_iter().fold(OAuthClient::new(), |c, p| {
            c.register(ProviderConfig::new(
                p,
                "cid",
                "secret",
                "https://app.test/cb",
            ))
        })
    }

    #[test]
    fn authorize_url_for_every_provider() {
        let c = client();
        for p in Provider::ALL
            .into_iter()
            .filter(|p| *p != Provider::Telegram)
        {
            let req = c.authorize(p).unwrap();
            let q: HashMap<_, _> = req.url.query_pairs().into_owned().collect();
            assert_eq!(q["client_id"], "cid", "{p}");
            assert_eq!(q["state"], req.pending.state);
            assert_eq!(q["redirect_uri"], "https://app.test/cb");
            assert_eq!(q.contains_key("code_challenge"), p.supports_pkce(), "{p}");
            assert_eq!(req.pending.code_verifier.is_some(), p.supports_pkce());
        }
    }

    #[test]
    fn apple_uses_form_post_and_nonce() {
        let req = client().authorize(Provider::Apple).unwrap();
        let q: HashMap<_, _> = req.url.query_pairs().into_owned().collect();
        assert_eq!(q["response_mode"], "form_post");
        assert_eq!(q["scope"], "name email");
        assert_eq!(q.get("nonce"), req.pending.nonce.as_ref());
    }

    #[test]
    fn facebook_scopes_are_comma_separated() {
        let req = client().authorize(Provider::Facebook).unwrap();
        assert!(req.url.as_str().contains("scope=email%2Cpublic_profile"));
    }

    #[test]
    fn unconfigured_provider() {
        assert!(matches!(
            OAuthClient::new().authorize(Provider::Google),
            Err(Error::NotConfigured(_))
        ));
    }

    #[tokio::test]
    async fn rejects_state_mismatch_and_provider_error() {
        let c = client();
        let req = c.authorize(Provider::Google).unwrap();
        let err = c
            .complete(&Callback::parse("code=x&state=wrong"), &req.pending)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::StateMismatch));
        let err = c
            .complete(
                &Callback::parse("error=access_denied&error_description=nope"),
                &req.pending,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Provider { ref error, .. } if error == "access_denied"));
    }
}
