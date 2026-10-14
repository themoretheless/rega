//! Authenticated encryption of [`PendingAuth`] so it can live in a cookie.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;

use crate::{Error, PendingAuth, Result};

const NONCE_LEN: usize = 12;

impl PendingAuth {
    /// Encrypts and authenticates the state with AES-256-GCM. The result is
    /// URL-safe and fits in a cookie value. Use a random 32-byte key per
    /// deployment and set the cookie `HttpOnly; Secure; SameSite=Lax`
    /// (`SameSite=None` for Apple's `form_post`).
    pub fn seal(&self, key: &[u8; 32]) -> Result<String> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let plain = serde_json::to_vec(self)?;
        let sealed = Aes256Gcm::new(key.into())
            .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
            .map_err(|_| Error::Config("encryption failed".into()))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed);
        Ok(URL_SAFE_NO_PAD.encode(out))
    }

    /// Decrypts a value produced by [`PendingAuth::seal`]. Fails on any
    /// tampering or a different key.
    pub fn open(sealed: &str, key: &[u8; 32]) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(sealed)
            .map_err(|_| Error::StateMismatch)?;
        if bytes.len() <= NONCE_LEN {
            return Err(Error::StateMismatch);
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
        let plain = Aes256Gcm::new(key.into())
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| Error::StateMismatch)?;
        Ok(serde_json::from_slice(&plain)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{OAuthClient, PendingAuth, Provider, ProviderConfig};

    #[test]
    fn roundtrip_and_tamper() {
        let client = OAuthClient::new().register(ProviderConfig::new(
            Provider::Google,
            "c",
            "s",
            "https://a/cb",
        ));
        let pending = client.authorize(Provider::Google).unwrap().pending;
        let key = [7u8; 32];
        let sealed = pending.seal(&key).unwrap();
        assert_eq!(PendingAuth::open(&sealed, &key).unwrap(), pending);
        assert!(PendingAuth::open(&sealed, &[8u8; 32]).is_err());
        let mut bad = sealed.into_bytes();
        let last = bad.len() - 2;
        bad[last] = if bad[last] == b'A' { b'B' } else { b'A' };
        assert!(PendingAuth::open(std::str::from_utf8(&bad).unwrap(), &key).is_err());
    }
}
