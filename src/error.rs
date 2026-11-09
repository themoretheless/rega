use crate::ProviderId;

/// Result alias using [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
/// Errors of the OAuth flow.
pub enum Error {
    #[error("provider {0} is not configured")]
    /// The provider was not registered with [`OAuthClient::register`](crate::OAuthClient::register).
    NotConfigured(ProviderId),
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
    #[error("network error: {0}")]
    /// The request to the provider failed (connection, TLS, timeout). The
    /// underlying error is available through [`std::error::Error::source`].
    Network(#[source] Box<dyn std::error::Error + Send + Sync>),
}

// The HTTP, JSON and JWT libraries are implementation details: their error
// types are converted here and never appear in the public enum.

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        // Drop the URL: token endpoints may carry credentials in the query.
        Error::Network(Box::new(e.without_url()))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::InvalidResponse(e.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Error::IdToken(e.to_string())
    }
}
