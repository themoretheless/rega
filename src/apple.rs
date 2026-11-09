use std::sync::{Arc, Mutex};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

use crate::clock::now;
use crate::Result;

const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// Sign in with Apple private key (`AuthKey_XXXXXX.p8`). Apple does not use a
/// static client secret: it is a short-lived ES256 JWT signed with this key.
#[derive(Clone)]
pub struct AppleKey {
    /// Apple Developer Team ID.
    pub team_id: String,
    /// Key ID of the Sign in with Apple key.
    pub key_id: String,
    /// PEM contents of the `.p8` file.
    pub private_key_pem: String,
}

impl std::fmt::Debug for AppleKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleKey")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct ClientSecretClaims<'a> {
    iss: &'a str,
    iat: u64,
    exp: u64,
    aud: &'a str,
    sub: &'a str,
}

/// Lifetime of a generated client secret (Apple allows up to 6 months).
const SECRET_TTL_SECS: u64 = 60 * 60;
/// Regenerate the cached secret when less than this remains.
const SECRET_REFRESH_SECS: u64 = 5 * 60;

impl AppleKey {
    /// Builds a fresh `client_secret` JWT for `client_id` (the Services ID).
    pub fn client_secret(&self, client_id: &str) -> Result<String> {
        let key = EncodingKey::from_ec_pem(self.private_key_pem.as_bytes())?;
        self.sign(&key, client_id, now()).map(|(s, _)| s)
    }

    fn sign(&self, key: &EncodingKey, client_id: &str, iat: u64) -> Result<(String, u64)> {
        let exp = iat + SECRET_TTL_SECS;
        let claims = ClientSecretClaims {
            iss: &self.team_id,
            iat,
            exp,
            aud: APPLE_ISSUER,
            sub: client_id,
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        Ok((jsonwebtoken::encode(&header, &claims, key)?, exp))
    }
}

/// [`AppleKey`] with the parsed key and the last secret cached, so the PEM is
/// parsed once and the ES256 signature is computed about once an hour instead
/// of on every sign-in. Clones share the cache.
#[derive(Debug, Clone)]
pub struct AppleSigner {
    key: AppleKey,
    cache: Arc<Mutex<SignerCache>>,
}

#[derive(Default)]
struct SignerCache {
    encoding_key: Option<EncodingKey>,
    secret: Option<(String, u64)>,
}

impl std::fmt::Debug for SignerCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SignerCache")
    }
}

impl AppleSigner {
    /// Wraps a key; nothing is parsed until the first secret is requested.
    pub fn new(key: AppleKey) -> Self {
        Self {
            key,
            cache: Arc::default(),
        }
    }

    /// The wrapped key.
    pub fn key(&self) -> &AppleKey {
        &self.key
    }

    /// Returns a valid `client_secret`, reusing the cached one when possible.
    pub fn client_secret(&self, client_id: &str) -> Result<String> {
        let now = now();
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((secret, exp)) = &cache.secret {
            if *exp > now + SECRET_REFRESH_SECS {
                return Ok(secret.clone());
            }
        }
        if cache.encoding_key.is_none() {
            cache.encoding_key = Some(EncodingKey::from_ec_pem(
                self.key.private_key_pem.as_bytes(),
            )?);
        }
        let fresh = self.key.sign(
            cache.encoding_key.as_ref().expect("set above"),
            client_id,
            now,
        )?;
        let secret = fresh.0.clone();
        cache.secret = Some(fresh);
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_caches_secret() {
        let signer = AppleSigner::new(AppleKey {
            team_id: "T".into(),
            key_id: "K".into(),
            private_key_pem: include_str!("../tests/apple_test_key.p8").into(),
        });
        let a = signer.client_secret("cid").unwrap();
        assert_eq!(a, signer.clone().client_secret("cid").unwrap());
        assert!(signer.key().client_secret("cid").is_ok());
    }
}
