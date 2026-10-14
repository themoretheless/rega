use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use url::Url;

use std::sync::Arc;

use crate::apple::{self, AppleKey, AppleSigner};
use crate::jwks::Jwks;
use crate::provider::{ClientAuth, Endpoints};
use crate::{pkce, profile, Error, ExternalIdentity, Provider, Result};

/// How long a [`PendingAuth`] stays valid.
const PENDING_TTL_SECS: u64 = 15 * 60;
/// Upper bound for any provider response body.
const MAX_RESPONSE_BYTES: usize = 1 << 20;
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Client credential used at the token endpoint.
#[derive(Debug, Clone)]
pub enum ClientSecret {
    /// Public client: PKCE only, no secret.
    None,
    /// Fixed client secret.
    Static(String),
    /// Sign in with Apple: the secret is generated from the `.p8` key and
    /// cached until shortly before it expires.
    Apple(AppleSigner),
}

impl ClientSecret {
    pub(crate) fn static_secret(&self) -> Option<&str> {
        match self {
            ClientSecret::Static(s) => Some(s),
            _ => None,
        }
    }

    fn resolve(&self, client_id: &str) -> Result<Option<String>> {
        match self {
            ClientSecret::None => Ok(None),
            ClientSecret::Static(s) => Ok(Some(s.clone())),
            ClientSecret::Apple(signer) => signer.client_secret(client_id).map(Some),
        }
    }
}

/// Application registration at a provider.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// Provider this registration belongs to.
    pub provider: Provider,
    /// OAuth client id.
    pub client_id: String,
    /// Credential for the token endpoint.
    pub client_secret: ClientSecret,
    /// Redirect URI registered at the provider.
    pub redirect_uri: String,
    /// Requested scopes; defaults to [`Provider::default_scopes`].
    pub scopes: Vec<String>,
    /// Provider endpoints; defaults to [`Provider::endpoints`].
    pub endpoints: Endpoints,
    /// Extra query parameters for the authorization URL (`prompt`, `hd`, ...).
    pub authorize_params: Vec<(String, String)>,
    /// Verify `id_token` signatures against the provider's JWKS during the
    /// code flow. Off by default: the token comes straight from the token
    /// endpoint over TLS (OIDC Core §3.1.3.7), and verification costs a
    /// (cached) key-set download. Tokens passed to
    /// [`OAuthClient::verify_id_token`] are always verified.
    pub verify_signatures: bool,
}

impl ProviderConfig {
    /// Registration with default scopes and endpoints. An empty secret makes a public (PKCE-only) client.
    pub fn new(
        provider: Provider,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let secret = client_secret.into();
        Self {
            provider,
            client_id: client_id.into(),
            client_secret: if secret.is_empty() {
                ClientSecret::None
            } else {
                ClientSecret::Static(secret)
            },
            redirect_uri: redirect_uri.into(),
            scopes: provider
                .default_scopes()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            endpoints: provider.endpoints(),
            authorize_params: Vec::new(),
            verify_signatures: false,
        }
    }

    /// Sign in with Apple. `client_id` is the Services ID.
    pub fn apple(
        client_id: impl Into<String>,
        key: AppleKey,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let mut cfg = Self::new(Provider::Apple, client_id, "", redirect_uri);
        cfg.client_secret = ClientSecret::Apple(AppleSigner::new(key));
        cfg
    }

    /// Replaces the requested scopes.
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Overrides the endpoints (self-hosted GitLab, Microsoft tenant, tests).
    pub fn with_endpoints(mut self, endpoints: Endpoints) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// Enables JWKS signature verification of `id_token` in the code flow.
    pub fn with_signature_verification(mut self) -> Self {
        self.verify_signatures = true;
        self
    }

    /// Adds an extra query parameter to the authorization URL.
    pub fn with_authorize_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.authorize_params.push((key.into(), value.into()));
        self
    }
}

/// Data that must survive the redirect round-trip (store it in the session or
/// an encrypted, `HttpOnly` cookie). Never expose it to the browser in clear text:
/// it contains the PKCE verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingAuth {
    /// Provider the login was started with.
    pub provider: Provider,
    /// Anti-CSRF `state` value.
    pub state: String,
    /// OIDC `nonce`, for providers that issue an `id_token`.
    pub nonce: Option<String>,
    /// PKCE verifier, for providers that support PKCE.
    pub code_verifier: Option<String>,
    /// Unix time the attempt was started.
    pub created_at: u64,
}

/// Where to send the user, plus the state to keep until the callback.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// URL to redirect the user to.
    pub url: Url,
    /// State to keep until the callback.
    pub pending: PendingAuth,
}

/// Parameters the provider sent to the redirect URI (query string, or form
/// body for Apple's `form_post`).
#[derive(Debug, Clone, Default)]
pub struct Callback {
    params: HashMap<String, String>,
}

impl Callback {
    /// Value of a callback parameter.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }

    /// Parses a raw query string or `application/x-www-form-urlencoded` body.
    pub fn parse(query: &str) -> Self {
        url::form_urlencoded::parse(query.trim_start_matches('?').as_bytes()).collect()
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for Callback {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        Self {
            params: iter
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }
}

/// Token endpoint response.
#[derive(Debug, Clone, Deserialize)]
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

/// OAuth 2.0 / OIDC client for all configured providers.
#[derive(Debug, Clone)]
pub struct OAuthClient {
    http: reqwest::Client,
    providers: HashMap<Provider, ProviderConfig>,
    jwks: HashMap<Provider, Arc<Jwks>>,
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
            providers: HashMap::new(),
            jwks: HashMap::new(),
        }
    }

    /// Registers (or replaces) a provider.
    pub fn register(mut self, config: ProviderConfig) -> Self {
        match &config.endpoints.jwks {
            Some(url) => {
                self.jwks
                    .insert(config.provider, Arc::new(Jwks::new(url.clone())));
            }
            None => {
                self.jwks.remove(&config.provider);
            }
        }
        self.providers.insert(config.provider, config);
        self
    }

    /// Verifies an `id_token` obtained outside the redirect flow — e.g. from the
    /// Google Sign-In or Sign in with Apple SDK in a mobile app — and returns the
    /// identity. The signature is always checked against the provider's JWKS.
    /// `audience` defaults to the configured `client_id`; mobile apps usually
    /// have their own (iOS bundle id / Android client id).
    pub async fn verify_id_token(
        &self,
        provider: Provider,
        id_token: &str,
        audience: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<ExternalIdentity> {
        let cfg = self.config(provider)?;
        let jwks = self.jwks.get(&provider).ok_or_else(|| {
            Error::Config(format!(
                "{provider}: no JWKS endpoint, id_token login is unsupported"
            ))
        })?;
        let aud = audience.unwrap_or(&cfg.client_id);
        let claims = jwks
            .verify(&self.http, provider, id_token, aud, nonce)
            .await?;
        match provider {
            Provider::Apple => profile::map_apple(claims, None),
            _ => profile::map_profile(provider, claims),
        }
    }

    /// Revokes an access or refresh token (RFC 7009). Apple requires this when
    /// a user deletes their account.
    pub async fn revoke(&self, provider: Provider, token: &str, hint: Option<&str>) -> Result<()> {
        let cfg = self.config(provider)?;
        let url =
            cfg.endpoints.revoke.as_deref().ok_or_else(|| {
                Error::Config(format!("{provider}: token revocation is unsupported"))
            })?;
        let secret = cfg.client_secret.resolve(&cfg.client_id)?;
        let mut form: Vec<(&str, &str)> = vec![("token", token), ("client_id", &cfg.client_id)];
        if let Some(hint) = hint {
            form.push(("token_type_hint", hint));
        }
        let mut req = self.http.post(url);
        if let Some(secret) = &secret {
            match provider.client_auth() {
                ClientAuth::Basic => req = req.basic_auth(&cfg.client_id, Some(secret)),
                ClientAuth::Post => form.push(("client_secret", secret)),
            }
        }
        let resp = req.form(&form).send().await?;
        if resp.status().is_success() {
            return Ok(());
        }
        read_json(resp).await.map(drop)
    }

    /// Registered providers.
    pub fn providers(&self) -> impl Iterator<Item = Provider> + '_ {
        self.providers.keys().copied()
    }

    /// Registration of `provider`.
    pub fn config(&self, provider: Provider) -> Result<&ProviderConfig> {
        self.providers
            .get(&provider)
            .ok_or(Error::NotConfigured(provider))
    }

    /// Step 1: build the URL to redirect the user to.
    pub fn authorize(&self, provider: Provider) -> Result<AuthorizationRequest> {
        let cfg = self.config(provider)?;
        let mut url = Url::parse(&cfg.endpoints.authorize)
            .map_err(|e| Error::Config(format!("authorize endpoint: {e}")))?;

        let [state, nonce, code_verifier] = pkce::random_tokens::<3>();
        let nonce = provider.uses_nonce().then_some(nonce);
        let code_verifier = provider.supports_pkce().then_some(code_verifier);

        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &cfg.client_id)
                .append_pair("redirect_uri", &cfg.redirect_uri)
                .append_pair("state", &state);
            if !cfg.scopes.is_empty() {
                q.append_pair("scope", &cfg.scopes.join(provider.scope_separator()));
            }
            if let Some(v) = &code_verifier {
                q.append_pair("code_challenge", &pkce::challenge(v))
                    .append_pair("code_challenge_method", "S256");
            }
            if let Some(n) = &nonce {
                q.append_pair("nonce", n);
            }
            if provider == Provider::Apple && !cfg.scopes.is_empty() {
                // Apple requires form_post whenever name/email scopes are requested.
                q.append_pair("response_mode", "form_post");
            }
            for (k, v) in &cfg.authorize_params {
                q.append_pair(k, v);
            }
        }

        Ok(AuthorizationRequest {
            url,
            pending: PendingAuth {
                provider,
                state,
                nonce,
                code_verifier,
                created_at: apple::now(),
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
        if apple::now().saturating_sub(pending.created_at) > PENDING_TTL_SECS {
            return Err(Error::Expired);
        }
        let code = callback
            .get("code")
            .filter(|c| !c.is_empty())
            .ok_or(Error::MissingCode)?;
        let cfg = self.config(pending.provider)?;
        let token = self.exchange_code(cfg, code, callback, pending).await?;
        let jwks = self.jwks.get(&pending.provider).map(Arc::as_ref);
        profile::fetch(&self.http, cfg, &token, callback, pending, jwks).await
    }

    async fn exchange_code(
        &self,
        cfg: &ProviderConfig,
        code: &str,
        callback: &Callback,
        pending: &PendingAuth,
    ) -> Result<TokenResponse> {
        let secret = cfg.client_secret.resolve(&cfg.client_id)?;
        let mut form: Vec<(&str, &str)> = Vec::with_capacity(8);
        form.extend([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", cfg.redirect_uri.as_str()),
            ("client_id", cfg.client_id.as_str()),
        ]);
        if let Some(v) = &pending.code_verifier {
            form.push(("code_verifier", v));
        }
        if cfg.provider == Provider::Vk {
            // VK ID binds the code to the device id returned in the callback.
            form.push(("device_id", callback.get("device_id").unwrap_or_default()));
            form.push(("state", &pending.state));
        }

        let mut req = self
            .http
            .post(&cfg.endpoints.token)
            .header("Accept", "application/json");
        if let Some(secret) = &secret {
            match cfg.provider.client_auth() {
                ClientAuth::Basic => req = req.basic_auth(&cfg.client_id, Some(secret)),
                ClientAuth::Post => form.push(("client_secret", secret)),
            }
        }

        let body = read_json(req.form(&form).send().await?).await?;
        Ok(serde_json::from_value(body)?)
    }
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
        for p in Provider::ALL {
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
