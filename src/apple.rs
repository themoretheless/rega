use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

use crate::{Error, Result};

const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// Sign in with Apple private key (`AuthKey_XXXXXX.p8`). Apple does not use a
/// static client secret: it is a short-lived ES256 JWT signed with this key.
#[derive(Clone)]
pub struct AppleKey {
    pub team_id: String,
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
    pub fn new(key: AppleKey) -> Self {
        Self {
            key,
            cache: Arc::default(),
        }
    }

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

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reads and validates the claims of an `id_token` received directly from the
/// token endpoint over TLS with client authentication. Per OpenID Connect Core
/// §3.1.3.7 the TLS server validation may be used instead of a signature check
/// in this case; issuer, audience, expiry and nonce are still verified.
pub(crate) fn id_token_claims(
    id_token: &str,
    issuer: Option<&str>,
    client_id: &str,
    nonce: Option<&str>,
) -> Result<serde_json::Value> {
    let payload = id_token
        .split('.')
        .nth(1)
        .ok_or_else(|| Error::IdToken("malformed token".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|e| Error::IdToken(e.to_string()))?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes)?;

    if let Some(issuer) = issuer {
        if claims["iss"].as_str() != Some(issuer) {
            return Err(Error::IdToken("unexpected issuer".into()));
        }
    }
    let aud_ok = match &claims["aud"] {
        serde_json::Value::String(a) => a == client_id,
        serde_json::Value::Array(a) => a.iter().any(|v| v.as_str() == Some(client_id)),
        _ => false,
    };
    if !aud_ok {
        return Err(Error::IdToken("unexpected audience".into()));
    }
    match claims["exp"].as_u64() {
        Some(exp) if exp + 60 >= now() => {}
        _ => return Err(Error::IdToken("token expired".into())),
    }
    if let Some(nonce) = nonce {
        if claims["nonce"].as_str() != Some(nonce) {
            return Err(Error::IdToken("nonce mismatch".into()));
        }
    }
    Ok(claims)
}

pub(crate) const ISSUER: &str = APPLE_ISSUER;

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

    fn token(claims: serde_json::Value) -> String {
        format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()))
    }

    #[test]
    fn validates_claims() {
        let t = token(serde_json::json!({
            "iss": ISSUER, "aud": "app", "exp": now() + 600, "nonce": "n", "sub": "001"
        }));
        assert_eq!(
            id_token_claims(&t, Some(ISSUER), "app", Some("n")).unwrap()["sub"],
            "001"
        );
        assert!(id_token_claims(&t, Some(ISSUER), "other", Some("n")).is_err());
        assert!(id_token_claims(&t, Some(ISSUER), "app", Some("x")).is_err());
        assert!(id_token_claims(&t, Some("evil"), "app", Some("n")).is_err());
    }

    #[test]
    fn rejects_expired() {
        let t = token(serde_json::json!({ "iss": ISSUER, "aud": "app", "exp": 1 }));
        assert!(id_token_claims(&t, Some(ISSUER), "app", None).is_err());
    }
}
