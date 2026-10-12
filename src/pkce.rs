use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Cryptographically random URL-safe token (32 bytes of entropy).
#[cfg(test)]
pub(crate) fn random_token() -> String {
    let [t] = random_tokens::<1>();
    t
}

/// `N` independent random tokens from a single OS RNG read.
pub(crate) fn random_tokens<const N: usize>() -> [String; N] {
    let mut bytes = [[0u8; 32]; N];
    rand::rngs::OsRng.fill_bytes(bytes.as_flattened_mut());
    bytes.map(|b| URL_SAFE_NO_PAD.encode(b))
}

/// S256 code challenge for a PKCE verifier (RFC 7636).
pub(crate) fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(random_token(), random_token());
        assert_eq!(random_token().len(), 43);
    }
}
