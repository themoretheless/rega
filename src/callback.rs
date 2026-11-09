//! Login state kept across the redirect, and the provider's callback.

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::REDACTED;
use crate::{Error, Provider, Result};

/// Data that must survive the redirect round-trip (store it in the session or
/// an encrypted, `HttpOnly` cookie). Never expose it to the browser in clear text:
/// it contains the PKCE verifier. `Debug` prints none of the secret values.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl std::fmt::Debug for PendingAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingAuth")
            .field("provider", &self.provider)
            .field("state", &REDACTED)
            .field("nonce", &self.nonce.as_ref().map(|_| REDACTED))
            .field(
                "code_verifier",
                &self.code_verifier.as_ref().map(|_| REDACTED),
            )
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Where to send the user, plus the state to keep until the callback.
/// `Debug` omits the URL query, which carries the `state`.
#[derive(Clone)]
pub struct AuthorizationRequest {
    /// URL to redirect the user to.
    pub url: Url,
    /// State to keep until the callback.
    pub pending: PendingAuth,
}

impl std::fmt::Debug for AuthorizationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut url = self.url.clone();
        url.set_query(None);
        f.debug_struct("AuthorizationRequest")
            .field("url", &url.as_str())
            .field("pending", &self.pending)
            .finish()
    }
}

/// Parameters the provider sent to the redirect URI (query string, or form
/// body for Apple's `form_post`). `Debug` prints parameter names only: the
/// values include the authorization code.
#[derive(Clone, Default)]
pub struct Callback {
    params: HashMap<String, String>,
    /// Names that appeared more than once. A repeated parameter is how
    /// parameter-pollution attacks make two parsers disagree, so such
    /// callbacks are rejected rather than resolved first- or last-wins.
    duplicates: Vec<String>,
}

impl std::fmt::Debug for Callback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names: Vec<&str> = self.params.keys().map(String::as_str).collect();
        names.sort_unstable();
        f.debug_struct("Callback").field("params", &names).finish()
    }
}

impl Callback {
    /// Value of a callback parameter.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }

    /// Name of a parameter that was sent more than once, if any.
    pub fn duplicate(&self) -> Option<&str> {
        self.duplicates.first().map(String::as_str)
    }

    pub(crate) fn reject_duplicates(&self) -> Result<()> {
        match self.duplicate() {
            Some(name) => Err(Error::InvalidResponse(format!(
                "callback parameter `{name}` is repeated"
            ))),
            None => Ok(()),
        }
    }

    /// All parameters, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.params.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Parses a raw query string or `application/x-www-form-urlencoded` body.
    pub fn parse(query: &str) -> Self {
        url::form_urlencoded::parse(query.trim_start_matches('?').as_bytes()).collect()
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for Callback {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let mut callback = Self::default();
        for (k, v) in iter {
            match callback.params.entry(k.into()) {
                Entry::Occupied(seen) => callback.duplicates.push(seen.key().clone()),
                Entry::Vacant(slot) => {
                    slot.insert(v.into());
                }
            }
        }
        callback
    }
}
