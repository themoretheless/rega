use crate::Provider;

/// Result alias using [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
/// Errors of the OAuth flow.
pub enum Error {
    #[error("provider {0} is not configured")]
    /// The provider was not registered with [`OAuthClient::register`](crate::OAuthClient::register).
    NotConfigured(Provider),
    #[error("invalid configuration: {0}")]
    /// Invalid client configuration.
    Config(String),
    #[error("provider returned error `{error}`: {description}")]
    /// Error reported by the provider (`error` / `error_description`).
    Provider {
        /// OAuth error code, e.g. `access_denied`.
        error: String,
        /// Human-readable description, may be empty.
        description: String,
    },
    #[error("state parameter does not match the pending authorization")]
    /// The callback `state` does not match: possible CSRF or a mixed-up session.
    StateMismatch,
    #[error("authorization attempt expired; start the login again")]
    /// The login attempt is older than 15 minutes.
    Expired,
    #[error("callback does not contain an authorization code")]
    /// The callback has no `code`.
    MissingCode,
    #[error("invalid response from provider: {0}")]
    /// Unexpected response from the provider.
    InvalidResponse(String),
    #[error("id_token validation failed: {0}")]
    /// The `id_token` failed validation.
    IdToken(String),
    #[error(transparent)]
    /// Network or HTTP error.
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    /// JSON (de)serialization error.
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    /// JWT encoding/decoding error.
    Jwt(#[from] jsonwebtoken::errors::Error),
}
