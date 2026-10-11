use serde::{Deserialize, Serialize};

use crate::Provider;

/// Normalized user profile returned by any provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExternalIdentity {
    pub provider: Provider,
    /// Stable, provider-unique user id. Use it (not the email) as the login key.
    pub subject: String,
    pub email: Option<String>,
    /// `true` only when the provider guarantees the user owns `email`.
    pub email_verified: bool,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    /// Raw profile payload as returned by the provider.
    pub raw: serde_json::Value,
}
