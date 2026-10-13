use crate::Provider;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("provider {0} is not configured")]
    NotConfigured(Provider),
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("provider returned error `{error}`: {description}")]
    Provider { error: String, description: String },
    #[error("state parameter does not match the pending authorization")]
    StateMismatch,
    #[error("callback does not contain an authorization code")]
    MissingCode,
    #[error("invalid response from provider: {0}")]
    InvalidResponse(String),
    #[error("id_token validation failed: {0}")]
    IdToken(String),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
}
