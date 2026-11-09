//! `id_token` claim validation shared by every OpenID Connect provider.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::{Error, Result};

/// Checks the `iss` claim against the expected issuer. `{tenantid}` in the
/// expectation stands for the token's own `tid` claim (Microsoft), and Google's
/// scheme-less spelling is accepted as the spec allows.
pub(crate) fn check_issuer(claims: &serde_json::Value, expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let iss = claims["iss"].as_str().unwrap_or_default();
    let ok = if expected.contains("{tenantid}") {
        let tid = claims["tid"].as_str().unwrap_or_default();
        // A tenant id is a GUID; anything else could smuggle path segments.
        let tid_ok = !tid.is_empty() && tid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        tid_ok && iss == expected.replace("{tenantid}", tid)
    } else {
        iss == expected
            || expected.strip_prefix("https://") == Some(iss) && iss == "accounts.google.com"
    };
    if ok {
        Ok(())
    } else {
        Err(Error::IdToken("unexpected issuer".into()))
    }
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
    now: u64,
) -> Result<serde_json::Value> {
    let payload = id_token
        .split('.')
        .nth(1)
        .ok_or_else(|| Error::IdToken("malformed token".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|e| Error::IdToken(e.to_string()))?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes)?;

    check_issuer(&claims, issuer)?;
    let aud_ok = match &claims["aud"] {
        serde_json::Value::String(a) => a == client_id,
        serde_json::Value::Array(a) => a.iter().any(|v| v.as_str() == Some(client_id)),
        _ => false,
    };
    if !aud_ok {
        return Err(Error::IdToken("unexpected audience".into()));
    }
    match claims["exp"].as_u64() {
        Some(exp) if exp + 60 >= now => {}
        _ => return Err(Error::IdToken("token expired".into())),
    }
    if let Some(nonce) = nonce {
        if claims["nonce"].as_str() != Some(nonce) {
            return Err(Error::IdToken("nonce mismatch".into()));
        }
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::now;

    const ISSUER: &str = "https://appleid.apple.com";

    fn token(claims: serde_json::Value) -> String {
        format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()))
    }

    #[test]
    fn validates_claims() {
        let t = token(serde_json::json!({
            "iss": ISSUER, "aud": "app", "exp": now() + 600, "nonce": "n", "sub": "001"
        }));
        assert_eq!(
            id_token_claims(&t, Some(ISSUER), "app", Some("n"), now()).unwrap()["sub"],
            "001"
        );
        assert!(id_token_claims(&t, Some(ISSUER), "other", Some("n"), now()).is_err());
        assert!(id_token_claims(&t, Some(ISSUER), "app", Some("x"), now()).is_err());
        assert!(id_token_claims(&t, Some("evil"), "app", Some("n"), now()).is_err());
    }

    #[test]
    fn rejects_expired() {
        let t = token(serde_json::json!({ "iss": ISSUER, "aud": "app", "exp": 1 }));
        assert!(id_token_claims(&t, Some(ISSUER), "app", None, now()).is_err());
    }
}
