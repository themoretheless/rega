//! Application registration at a provider.

use crate::apple::{AppleKey, AppleSigner};
use crate::provider::Endpoints;
use crate::{Provider, Result};

/// Client credential used at the token endpoint. `Debug` never prints the secret.
#[derive(Clone)]
pub enum ClientSecret {
    /// Public client: PKCE only, no secret.
    None,
    /// Fixed client secret.
    Static(String),
    /// Sign in with Apple: the secret is generated from the `.p8` key and
    /// cached until shortly before it expires.
    Apple(AppleSigner),
}

/// Placeholder printed instead of secret values in `Debug` output.
pub(crate) const REDACTED: &str = "[redacted]";

impl std::fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientSecret::None => f.write_str("None"),
            ClientSecret::Static(_) => write!(f, "Static({REDACTED})"),
            ClientSecret::Apple(signer) => f.debug_tuple("Apple").field(signer.key()).finish(),
        }
    }
}

impl ClientSecret {
    pub(crate) fn static_secret(&self) -> Option<&str> {
        match self {
            ClientSecret::Static(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn resolve(&self, client_id: &str) -> Result<Option<String>> {
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
