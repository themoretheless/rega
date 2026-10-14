//! Fetching and normalizing user profiles. The `map_*` functions are public so
//! they can be reused with profiles obtained elsewhere (e.g. mobile SDKs).

use serde_json::Value;

use crate::client::{read_json, Callback, PendingAuth, ProviderConfig, TokenResponse};
use crate::jwks::Jwks;
use crate::{apple, Error, ExternalIdentity, Provider, Result};

pub(crate) async fn fetch(
    http: &reqwest::Client,
    cfg: &ProviderConfig,
    token: &TokenResponse,
    callback: &Callback,
    pending: &PendingAuth,
    jwks: Option<&Jwks>,
) -> Result<ExternalIdentity> {
    let provider = cfg.provider;
    if provider == Provider::Apple {
        let id_token = token
            .id_token
            .as_deref()
            .ok_or_else(|| Error::InvalidResponse("Apple did not return an id_token".into()))?;
        let claims = id_token_claims(http, cfg, jwks, id_token, pending.nonce.as_deref()).await?;
        // Apple sends the user's name only once, on the first authorization.
        let user = callback
            .get("user")
            .and_then(|u| serde_json::from_str(u).ok());
        return map_apple(claims, user);
    }

    // OIDC providers: validate the id_token once (binds the response to this
    // login attempt via nonce) and, when it already carries the profile, skip
    // the userinfo round-trip. Microsoft/GitLab issuers depend on the tenant or
    // host, so only audience/expiry/nonce are enforced for them.
    if let (Some(nonce), Some(id_token)) = (pending.nonce.as_deref(), token.id_token.as_deref()) {
        let claims = id_token_claims(http, cfg, jwks, id_token, Some(nonce)).await?;
        // Google always includes the profile; Microsoft and GitLab only when the
        // optional `email` claim is configured, otherwise fall back to userinfo.
        if provider == Provider::Google || claims["email"].is_string() {
            return map_profile(provider, claims);
        }
    }

    let userinfo = cfg
        .endpoints
        .userinfo
        .as_deref()
        .ok_or_else(|| Error::Config(format!("{provider}: userinfo endpoint is not set")))?;
    let access = &token.access_token;

    let req = match provider {
        // Mail.ru expects the token as a query parameter.
        Provider::MailRu => http
            .get(userinfo)
            .query(&[("access_token", access.as_str())]),
        Provider::Yandex => http
            .get(userinfo)
            .header("Authorization", format!("OAuth {access}")),
        Provider::Vk => http.post(userinfo).form(&[
            ("client_id", cfg.client_id.as_str()),
            ("access_token", access.as_str()),
        ]),
        Provider::Facebook => {
            let mut req = http.get(userinfo).bearer_auth(access);
            if let Some(secret) = cfg.client_secret.static_secret() {
                req = req.query(&[("appsecret_proof", appsecret_proof(secret, access))]);
            }
            req
        }
        _ => http.get(userinfo).bearer_auth(access),
    };
    let profile = async { read_json(req.header("Accept", "application/json").send().await?).await };

    match (provider, cfg.endpoints.emails.as_deref()) {
        (Provider::GitHub | Provider::Bitbucket, Some(emails_url)) => {
            // Both calls only need the token: run them concurrently.
            let emails =
                async { read_json(http.get(emails_url).bearer_auth(access).send().await?).await };
            let (profile, emails) = futures_util::future::join(profile, emails).await;
            let mut identity = map_profile(provider, profile?)?;
            if provider == Provider::GitHub {
                apply_github_emails(&mut identity, &emails?);
            } else {
                apply_bitbucket_emails(&mut identity, &emails?);
            }
            Ok(identity)
        }
        _ => map_profile(provider, profile.await?),
    }
}

/// Validates `id_token` claims; additionally verifies the signature against the
/// provider's JWKS when [`ProviderConfig::verify_signatures`] is enabled.
async fn id_token_claims(
    http: &reqwest::Client,
    cfg: &ProviderConfig,
    jwks: Option<&Jwks>,
    id_token: &str,
    nonce: Option<&str>,
) -> Result<Value> {
    match jwks.filter(|_| cfg.verify_signatures) {
        Some(jwks) => {
            jwks.verify(http, cfg.provider, id_token, &cfg.client_id, nonce)
                .await
        }
        // Microsoft/GitLab issuers depend on the tenant or host, so only
        // audience/expiry/nonce are enforced for them.
        None => apple::id_token_claims(id_token, cfg.provider.issuers(), &cfg.client_id, nonce),
    }
}

/// Maps a provider's userinfo payload to an [`ExternalIdentity`].
pub fn map_profile(provider: Provider, p: Value) -> Result<ExternalIdentity> {
    let s = |v: &Value| v.as_str().filter(|s| !s.is_empty()).map(str::to_owned);
    let id = |v: &Value| match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };

    let (subject, email, email_verified, name, avatar) = match provider {
        Provider::Google | Provider::LinkedIn | Provider::GitLab => (
            id(&p["sub"]),
            s(&p["email"]),
            truthy(&p["email_verified"]),
            s(&p["name"]),
            s(&p["picture"]),
        ),
        // Microsoft does not guarantee ownership of the `email` claim.
        Provider::Microsoft => (id(&p["sub"]), s(&p["email"]), false, s(&p["name"]), None),
        // Facebook only returns confirmed emails.
        Provider::Facebook => {
            let email = s(&p["email"]);
            let verified = email.is_some();
            (
                id(&p["id"]),
                email,
                verified,
                s(&p["name"]),
                s(&p["picture"]["data"]["url"]),
            )
        }
        Provider::GitHub => (
            id(&p["id"]),
            s(&p["email"]),
            false,
            s(&p["name"]).or_else(|| s(&p["login"])),
            s(&p["avatar_url"]),
        ),
        Provider::X => {
            let d = &p["data"];
            let email = s(&d["confirmed_email"]);
            let verified = email.is_some();
            (
                id(&d["id"]),
                email,
                verified,
                s(&d["name"]),
                s(&d["profile_image_url"]),
            )
        }
        Provider::Discord => {
            let avatar = match (s(&p["id"]), s(&p["avatar"])) {
                (Some(uid), Some(hash)) => {
                    // Hashes of animated avatars start with `a_`.
                    let ext = if hash.starts_with("a_") { "gif" } else { "png" };
                    Some(format!(
                        "https://cdn.discordapp.com/avatars/{uid}/{hash}.{ext}"
                    ))
                }
                _ => None,
            };
            (
                id(&p["id"]),
                s(&p["email"]),
                truthy(&p["verified"]),
                s(&p["global_name"]).or_else(|| s(&p["username"])),
                avatar,
            )
        }
        // Yandex accounts only expose confirmed addresses.
        Provider::Yandex => {
            let email = s(&p["default_email"]);
            let verified = email.is_some();
            let avatar = (p["is_avatar_empty"] != Value::Bool(true))
                .then(|| s(&p["default_avatar_id"]))
                .flatten()
                .map(|a| format!("https://avatars.yandex.net/get-yapic/{a}/islands-200"));
            (
                id(&p["id"]),
                email,
                verified,
                s(&p["real_name"]).or_else(|| s(&p["display_name"])),
                avatar,
            )
        }
        Provider::Vk => {
            let u = &p["user"];
            let name = join_name(s(&u["first_name"]), s(&u["last_name"]));
            (
                id(&u["user_id"]),
                s(&u["email"]),
                false,
                name,
                s(&u["avatar"]),
            )
        }
        Provider::Amazon => (
            id(&p["user_id"]),
            s(&p["email"]),
            false,
            s(&p["name"]),
            None,
        ),
        Provider::Twitch => (
            id(&p["sub"]),
            s(&p["email"]),
            truthy(&p["email_verified"]),
            s(&p["preferred_username"]),
            s(&p["picture"]),
        ),
        Provider::Slack => (
            id(&p["sub"]),
            s(&p["email"]),
            truthy(&p["email_verified"]),
            s(&p["name"]),
            s(&p["picture"]),
        ),
        Provider::Spotify => (
            id(&p["id"]),
            s(&p["email"]),
            false,
            s(&p["display_name"]),
            s(&p["images"][0]["url"]),
        ),
        Provider::Reddit => (id(&p["id"]), None, false, s(&p["name"]), s(&p["icon_img"])),
        Provider::Bitbucket => (
            id(&p["uuid"]),
            None,
            false,
            s(&p["display_name"]).or_else(|| s(&p["nickname"])),
            s(&p["links"]["avatar"]["href"]),
        ),
        Provider::MailRu => (
            id(&p["id"]),
            s(&p["email"]),
            false,
            s(&p["name"]),
            s(&p["image"]),
        ),
        Provider::Telegram => (
            id(&p["id"]),
            None,
            false,
            join_name(s(&p["first_name"]), s(&p["last_name"])).or_else(|| s(&p["username"])),
            s(&p["photo_url"]),
        ),
        Provider::Apple => return map_apple(p, None),
    };

    let subject = subject
        .ok_or_else(|| Error::InvalidResponse(format!("{provider}: profile has no user id")))?;
    Ok(ExternalIdentity {
        provider,
        subject,
        email_verified: email_verified && email.is_some(),
        email: email.map(|e| normalize_email(&e)),
        name,
        avatar_url: avatar,
        raw: p,
    })
}

/// Maps Apple `id_token` claims plus the optional first-login `user` form field.
pub fn map_apple(claims: Value, user: Option<Value>) -> Result<ExternalIdentity> {
    let subject = claims["sub"]
        .as_str()
        .ok_or_else(|| Error::InvalidResponse("apple: id_token has no sub".into()))?
        .to_owned();
    let email = claims["email"].as_str().map(normalize_email);
    let name = user.as_ref().and_then(|u| {
        join_name(
            u["name"]["firstName"].as_str().map(Into::into),
            u["name"]["lastName"].as_str().map(Into::into),
        )
    });
    let mut raw = claims;
    if let Some(u) = user {
        raw["user"] = u;
    }
    Ok(ExternalIdentity {
        provider: Provider::Apple,
        subject,
        email_verified: email.is_some() && truthy(&raw["email_verified"]),
        email,
        name,
        avatar_url: None,
        raw,
    })
}

/// Sets the primary confirmed email from Bitbucket `/2.0/user/emails`.
pub fn apply_bitbucket_emails(identity: &mut ExternalIdentity, emails: &Value) {
    let list = emails["values"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let pick = list
        .iter()
        .find(|e| truthy(&e["is_primary"]) && truthy(&e["is_confirmed"]))
        .or_else(|| list.iter().find(|e| truthy(&e["is_confirmed"])));
    if let Some(email) = pick.and_then(|e| e["email"].as_str()) {
        identity.email = Some(normalize_email(email));
        identity.email_verified = true;
    }
}

/// Replaces the GitHub email with the primary verified one from `/user/emails`.
pub fn apply_github_emails(identity: &mut ExternalIdentity, emails: &Value) {
    let list = emails.as_array().map(Vec::as_slice).unwrap_or_default();
    let pick = list
        .iter()
        .find(|e| truthy(&e["primary"]) && truthy(&e["verified"]))
        .or_else(|| list.iter().find(|e| truthy(&e["verified"])));
    if let Some(email) = pick.and_then(|e| e["email"].as_str()) {
        identity.email = Some(normalize_email(email));
        identity.email_verified = true;
    }
}

/// Trimmed, lower-cased email used for comparison and storage.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// `appsecret_proof` = hex(HMAC-SHA256(key = app secret, msg = access token)),
/// required by Facebook apps with "Require App Secret" enabled.
fn appsecret_proof(secret: &str, access_token: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(access_token.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Apple and some OIDC providers encode booleans as strings.
fn truthy(v: &Value) -> bool {
    matches!(v, Value::Bool(true)) || v.as_str() == Some("true")
}

fn join_name(first: Option<String>, last: Option<String>) -> Option<String> {
    match (first, last) {
        (Some(f), Some(l)) => Some(format!("{f} {l}")),
        (f, l) => f.or(l),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn google() {
        let i = map_profile(
            Provider::Google,
            json!({"sub":"1","email":"A@Gmail.com","email_verified":true,"name":"A","picture":"p"}),
        )
        .unwrap();
        assert_eq!(
            (i.subject.as_str(), i.email.as_deref(), i.email_verified),
            ("1", Some("a@gmail.com"), true)
        );
    }

    #[test]
    fn microsoft_email_is_never_trusted() {
        let i = map_profile(
            Provider::Microsoft,
            json!({"sub":"m","email":"a@b.c","email_verified":true}),
        )
        .unwrap();
        assert!(!i.email_verified);
    }

    #[test]
    fn numeric_ids() {
        let i = map_profile(Provider::GitHub, json!({"id": 42, "login": "octo"})).unwrap();
        assert_eq!(
            (i.subject.as_str(), i.name.as_deref()),
            ("42", Some("octo"))
        );
        let i = map_profile(
            Provider::Vk,
            json!({"user":{"user_id": 7, "first_name":"Ivan","last_name":"P"}}),
        )
        .unwrap();
        assert_eq!(
            (i.subject.as_str(), i.name.as_deref()),
            ("7", Some("Ivan P"))
        );
    }

    #[test]
    fn github_primary_verified_email() {
        let mut i = map_profile(Provider::GitHub, json!({"id": 1})).unwrap();
        apply_github_emails(
            &mut i,
            &json!([{"email":"x@y.z","primary":false,"verified":true},{"email":"Me@y.z","primary":true,"verified":true}]),
        );
        assert_eq!(
            (i.email.as_deref(), i.email_verified),
            (Some("me@y.z"), true)
        );
    }

    #[test]
    fn discord_yandex_x_facebook() {
        let d = map_profile(
            Provider::Discord,
            json!({"id":"9","username":"u","avatar":"h","email":"e@x","verified":true}),
        )
        .unwrap();
        assert_eq!(
            d.avatar_url.as_deref(),
            Some("https://cdn.discordapp.com/avatars/9/h.png")
        );
        assert!(d.email_verified);
        let y = map_profile(Provider::Yandex, json!({"id":"5","default_email":"y@ya.ru","default_avatar_id":"a","is_avatar_empty":false})).unwrap();
        assert!(y.email_verified && y.avatar_url.is_some());
        let x = map_profile(Provider::X, json!({"data":{"id":"3","name":"X"}})).unwrap();
        assert_eq!((x.subject.as_str(), x.email), ("3", None));
        let f = map_profile(
            Provider::Facebook,
            json!({"id":"8","email":"f@b.c","picture":{"data":{"url":"u"}}}),
        )
        .unwrap();
        assert_eq!(
            (f.email_verified, f.avatar_url.as_deref()),
            (true, Some("u"))
        );
    }

    #[test]
    fn apple_name_from_first_login() {
        let i = map_apple(
            json!({"sub":"001.abc","email":"r@privaterelay.appleid.com","email_verified":"true"}),
            Some(json!({"name":{"firstName":"Tim","lastName":"C"}})),
        )
        .unwrap();
        assert_eq!((i.name.as_deref(), i.email_verified), (Some("Tim C"), true));
    }

    #[test]
    fn missing_subject_is_error() {
        assert!(map_profile(Provider::Amazon, json!({"email":"a@b"})).is_err());
    }
}

#[cfg(test)]
mod fixes_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn discord_animated_avatar_is_gif() {
        let d = map_profile(Provider::Discord, json!({"id":"1","avatar":"a_abc"})).unwrap();
        assert!(d.avatar_url.unwrap().ends_with("/a_abc.gif"));
    }

    #[test]
    fn appsecret_proof_matches_reference() {
        // echo -n token | openssl dgst -sha256 -hmac secret
        assert_eq!(
            appsecret_proof("secret", "token"),
            "e941110e3d2bfe82621f0e3e1434730d7305d106c5f68c87165d0b27a4611a4a"
        );
    }

    #[test]
    fn email_is_trimmed_and_lowercased() {
        let i = map_profile(
            Provider::Google,
            json!({"sub":"1","email":"  A@B.C ","email_verified":true}),
        )
        .unwrap();
        assert_eq!(i.email.as_deref(), Some("a@b.c"));
    }
}
