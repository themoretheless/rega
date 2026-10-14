//! [Telegram Login Widget](https://core.telegram.org/widgets/login) verification.
//!
//! The widget redirects (or calls back in JS) with `id`, `first_name`,
//! `last_name`, `username`, `photo_url`, `auth_date` and `hash`. The hash is an
//! HMAC-SHA256 of the other fields keyed with SHA-256 of the bot token.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{apple, pkce, profile, Callback, Error, ExternalIdentity, Provider, Result};

/// Verifies widget data and returns the identity. Data older than
/// `max_age_secs` is rejected to limit replay of leaked login links.
pub fn verify_login(
    data: &Callback,
    bot_token: &str,
    max_age_secs: u64,
) -> Result<ExternalIdentity> {
    let hash = data.get("hash").ok_or_else(|| invalid("missing hash"))?;

    let mut fields: Vec<(&str, &str)> = data.iter().filter(|(k, _)| *k != "hash").collect();
    fields.sort_unstable_by(|a, b| a.0.cmp(b.0));
    let check_string = fields
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n");

    let secret = Sha256::digest(bot_token.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("HMAC accepts any key");
    mac.update(check_string.as_bytes());
    let expected: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if !pkce::constant_time_eq(&expected, &hash.to_ascii_lowercase()) {
        return Err(invalid("hash mismatch"));
    }

    let auth_date: u64 = data
        .get("auth_date")
        .and_then(|d| d.parse().ok())
        .ok_or_else(|| invalid("missing auth_date"))?;
    if apple::now().saturating_sub(auth_date) > max_age_secs {
        return Err(Error::Expired);
    }

    let raw: serde_json::Map<String, serde_json::Value> = fields
        .into_iter()
        .map(|(k, v)| (k.to_owned(), serde_json::Value::String(v.to_owned())))
        .collect();
    profile::map_profile(Provider::Telegram, serde_json::Value::Object(raw))
}

fn invalid(reason: &str) -> Error {
    Error::Provider {
        error: "invalid_telegram_login".into(),
        description: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(bot_token: &str, fields: &[(&str, String)]) -> Callback {
        let mut sorted = fields.to_vec();
        sorted.sort();
        let check = sorted
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&Sha256::digest(bot_token.as_bytes())).unwrap();
        mac.update(check.as_bytes());
        let hash: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        fields.iter().cloned().chain([("hash", hash)]).collect()
    }

    #[test]
    fn accepts_valid_and_rejects_tampered() {
        let now = apple::now().to_string();
        let fields = [
            ("id", "123".to_string()),
            ("first_name", "Pavel".to_string()),
            ("username", "durov".to_string()),
            ("auth_date", now),
        ];
        let data = signed("123:ABC", &fields);
        let i = verify_login(&data, "123:ABC", 86400).unwrap();
        assert_eq!(
            (i.provider, i.subject.as_str(), i.name.as_deref()),
            (Provider::Telegram, "123", Some("Pavel"))
        );

        assert!(verify_login(&data, "other-bot", 86400).is_err());
        let tampered: Callback = data
            .iter()
            .map(|(k, v)| (k, if k == "id" { "999" } else { v }))
            .collect();
        assert!(verify_login(&tampered, "123:ABC", 86400).is_err());
    }

    #[test]
    fn rejects_stale_login() {
        let data = signed("t", &[("id", "1".into()), ("auth_date", "1000".into())]);
        assert!(matches!(verify_login(&data, "t", 60), Err(Error::Expired)));
    }
}
