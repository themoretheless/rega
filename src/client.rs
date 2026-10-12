use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::apple::{self, AppleKey, AppleSigner};
use crate::provider::{ClientAuth, Endpoints};
use crate::{pkce, profile, Error, ExternalIdentity, Provider, Result};

/// How long a [`PendingAuth`] stays valid.
const PENDING_TTL_SECS: u64 = 15 * 60;

/// Client credential used at the token endpoint.
#[derive(Debug, Clone)]
pub enum ClientSecret {
    /// Public client: PKCE only, no secret.
    None,
    Static(String),
    /// Sign in with Apple: the secret is generated from the `.p8` key and
    /// cached until shortly before it expires.
    Apple(AppleSigner),
}

impl ClientSecret {
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
    pub provider: Provider,
    pub client_id: String,
    pub client_secret: ClientSecret,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub endpoints: Endpoints,
    /// Extra query parameters for the authorization URL (`prompt`, `hd`, ...).
    pub authorize_params: Vec<(String, String)>,
}

impl ProviderConfig {
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

    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_endpoints(mut self, endpoints: Endpoints) -> Self {
        self.endpoints = endpoints;
        self
    }

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
    pub provider: Provider,
    pub state: String,
    pub nonce: Option<String>,
    pub code_verifier: Option<String>,
    pub created_at: u64,
}

/// Where to send the user, plus the state to keep until the callback.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub url: Url,
    pub pending: PendingAuth,
}

/// Parameters the provider sent to the redirect URI (query string, or form
/// body for Apple's `form_post`).
#[derive(Debug, Clone, Default)]
pub struct Callback {
    params: HashMap<String, String>,
}

impl Callback {
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
    pub access_token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// OAuth 2.0 / OIDC client for all configured providers.
#[derive(Debug, Clone)]
pub struct OAuthClient {
    http: reqwest::Client,
    providers: HashMap<Provider, ProviderConfig>,
}

impl Default for OAuthClient {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("rega/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("default HTTP client");
        Self::with_http_client(http)
    }

    pub fn with_http_client(http: reqwest::Client) -> Self {
        Self {
            http,
            providers: HashMap::new(),
        }
    }

    pub fn register(mut self, config: ProviderConfig) -> Self {
        self.providers.insert(config.provider, config);
        self
    }

    pub fn providers(&self) -> impl Iterator<Item = Provider> + '_ {
        self.providers.keys().copied()
    }

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

        let state = pkce::random_token();
        let nonce = provider.uses_nonce().then(pkce::random_token);
        let code_verifier = provider.supports_pkce().then(pkce::random_token);

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
        if !pkce::constant_time_eq(state, &pending.state) {
            return Err(Error::StateMismatch);
        }
        if apple::now().saturating_sub(pending.created_at) > PENDING_TTL_SECS {
            return Err(Error::StateMismatch);
        }
        let code = callback
            .get("code")
            .filter(|c| !c.is_empty())
            .ok_or(Error::MissingCode)?;
        let cfg = self.config(pending.provider)?;
        let token = self.exchange_code(cfg, code, callback, pending).await?;
        profile::fetch(&self.http, cfg, &token, callback, pending).await
    }

    async fn exchange_code(
        &self,
        cfg: &ProviderConfig,
        code: &str,
        callback: &Callback,
        pending: &PendingAuth,
    ) -> Result<TokenResponse> {
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "authorization_code".into()),
            ("code", code.into()),
            ("redirect_uri", cfg.redirect_uri.clone()),
            ("client_id", cfg.client_id.clone()),
        ];
        if let Some(v) = &pending.code_verifier {
            form.push(("code_verifier", v.clone()));
        }
        if cfg.provider == Provider::Vk {
            // VK ID binds the code to the device id returned in the callback.
            form.push((
                "device_id",
                callback.get("device_id").unwrap_or_default().into(),
            ));
            form.push(("state", pending.state.clone()));
        }

        let mut req = self
            .http
            .post(&cfg.endpoints.token)
            .header("Accept", "application/json");
        if let Some(secret) = cfg.client_secret.resolve(&cfg.client_id)? {
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
pub(crate) async fn read_json(resp: reqwest::Response) -> Result<serde_json::Value> {
    let status = resp.status();
    let text = resp.text().await?;
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
        Error::InvalidResponse(format!(
            "HTTP {status}: {}",
            text.chars().take(200).collect::<String>()
        ))
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
