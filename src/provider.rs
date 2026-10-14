use std::fmt;

use serde::{Deserialize, Serialize};

/// Supported identity providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// Google (OpenID Connect).
    Google,
    /// Sign in with Apple.
    Apple,
    /// Microsoft personal and work/school accounts.
    Microsoft,
    /// Facebook Login.
    Facebook,
    /// GitHub OAuth apps.
    GitHub,
    /// X (Twitter) OAuth 2.0.
    X,
    /// LinkedIn (OpenID Connect).
    LinkedIn,
    /// Discord.
    Discord,
    /// Yandex ID.
    Yandex,
    /// VK ID.
    Vk,
    /// GitLab (gitlab.com or self-hosted).
    GitLab,
    /// Login with Amazon.
    Amazon,
}

/// How the client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    /// `Authorization: Basic base64(client_id:client_secret)`.
    Basic,
    /// `client_id` and `client_secret` in the form body.
    Post,
}

/// Provider endpoints. Defaults come from [`Provider::endpoints`]; override
/// them for self-hosted GitLab, a specific Microsoft tenant, or tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// Authorization endpoint.
    pub authorize: String,
    /// Token endpoint.
    pub token: String,
    /// Profile endpoint. `None` when the profile comes from the `id_token` (Apple).
    pub userinfo: Option<String>,
    /// Secondary endpoint (GitHub: `/user/emails`).
    pub emails: Option<String>,
    /// JSON Web Key Set used to verify `id_token` signatures (OIDC providers).
    pub jwks: Option<String>,
    /// Token revocation endpoint (RFC 7009).
    pub revoke: Option<String>,
}

impl Provider {
    /// Every supported provider.
    pub const ALL: [Provider; 12] = [
        Provider::Google,
        Provider::Apple,
        Provider::Microsoft,
        Provider::Facebook,
        Provider::GitHub,
        Provider::X,
        Provider::LinkedIn,
        Provider::Discord,
        Provider::Yandex,
        Provider::Vk,
        Provider::GitLab,
        Provider::Amazon,
    ];

    /// Stable lower-case identifier, e.g. `"google"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Google => "google",
            Provider::Apple => "apple",
            Provider::Microsoft => "microsoft",
            Provider::Facebook => "facebook",
            Provider::GitHub => "github",
            Provider::X => "x",
            Provider::LinkedIn => "linkedin",
            Provider::Discord => "discord",
            Provider::Yandex => "yandex",
            Provider::Vk => "vk",
            Provider::GitLab => "gitlab",
            Provider::Amazon => "amazon",
        }
    }

    /// Default endpoints of the provider.
    pub fn endpoints(self) -> Endpoints {
        let (authorize, token, userinfo, emails) = match self {
            Provider::Google => (
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
                Some("https://openidconnect.googleapis.com/v1/userinfo"),
                None,
            ),
            Provider::Apple => (
                "https://appleid.apple.com/auth/authorize",
                "https://appleid.apple.com/auth/token",
                None,
                None,
            ),
            Provider::Microsoft => (
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                Some("https://graph.microsoft.com/oidc/userinfo"),
                None,
            ),
            Provider::Facebook => (
                "https://www.facebook.com/v21.0/dialog/oauth",
                "https://graph.facebook.com/v21.0/oauth/access_token",
                Some(
                    "https://graph.facebook.com/v21.0/me?fields=id,name,email,picture.type(large)",
                ),
                None,
            ),
            Provider::GitHub => (
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
                Some("https://api.github.com/user"),
                Some("https://api.github.com/user/emails"),
            ),
            Provider::X => (
                "https://x.com/i/oauth2/authorize",
                "https://api.x.com/2/oauth2/token",
                Some("https://api.x.com/2/users/me?user.fields=profile_image_url,confirmed_email"),
                None,
            ),
            Provider::LinkedIn => (
                "https://www.linkedin.com/oauth/v2/authorization",
                "https://www.linkedin.com/oauth/v2/accessToken",
                Some("https://api.linkedin.com/v2/userinfo"),
                None,
            ),
            Provider::Discord => (
                "https://discord.com/oauth2/authorize",
                "https://discord.com/api/oauth2/token",
                Some("https://discord.com/api/users/@me"),
                None,
            ),
            Provider::Yandex => (
                "https://oauth.yandex.ru/authorize",
                "https://oauth.yandex.ru/token",
                Some("https://login.yandex.ru/info?format=json"),
                None,
            ),
            Provider::Vk => (
                "https://id.vk.com/authorize",
                "https://id.vk.com/oauth2/auth",
                Some("https://id.vk.com/oauth2/user_info"),
                None,
            ),
            Provider::GitLab => (
                "https://gitlab.com/oauth/authorize",
                "https://gitlab.com/oauth/token",
                Some("https://gitlab.com/oauth/userinfo"),
                None,
            ),
            Provider::Amazon => (
                "https://www.amazon.com/ap/oa",
                "https://api.amazon.com/auth/o2/token",
                Some("https://api.amazon.com/user/profile"),
                None,
            ),
        };
        Endpoints {
            authorize: authorize.into(),
            token: token.into(),
            userinfo: userinfo.map(Into::into),
            emails: emails.map(Into::into),
            jwks: self.jwks_uri().map(Into::into),
            revoke: self.revoke_uri().map(Into::into),
        }
    }

    fn jwks_uri(self) -> Option<&'static str> {
        match self {
            Provider::Google => Some("https://www.googleapis.com/oauth2/v3/certs"),
            Provider::Apple => Some("https://appleid.apple.com/auth/keys"),
            Provider::Microsoft => {
                Some("https://login.microsoftonline.com/common/discovery/v2.0/keys")
            }
            Provider::GitLab => Some("https://gitlab.com/oauth/discovery/keys"),
            _ => None,
        }
    }

    fn revoke_uri(self) -> Option<&'static str> {
        match self {
            Provider::Google => Some("https://oauth2.googleapis.com/revoke"),
            Provider::Apple => Some("https://appleid.apple.com/auth/revoke"),
            Provider::X => Some("https://api.x.com/2/oauth2/revoke"),
            Provider::Discord => Some("https://discord.com/api/oauth2/token/revoke"),
            Provider::GitLab => Some("https://gitlab.com/oauth/revoke"),
            _ => None,
        }
    }

    /// Accepted `iss` values of the provider's `id_token`. Empty when the issuer
    /// is tenant/host specific (Microsoft is checked against the `tid` claim).
    pub(crate) fn issuers(self) -> &'static [&'static str] {
        match self {
            Provider::Google => &["https://accounts.google.com", "accounts.google.com"],
            Provider::Apple => &["https://appleid.apple.com"],
            _ => &[],
        }
    }

    /// Scopes requested by default: enough for id, email, name and avatar.
    pub fn default_scopes(self) -> &'static [&'static str] {
        match self {
            Provider::Google | Provider::Microsoft | Provider::LinkedIn | Provider::GitLab => {
                &["openid", "email", "profile"]
            }
            Provider::Apple => &["name", "email"],
            Provider::Facebook => &["email", "public_profile"],
            Provider::GitHub => &["read:user", "user:email"],
            Provider::X => &["users.read", "tweet.read"],
            Provider::Discord => &["identify", "email"],
            Provider::Yandex => &["login:email", "login:info", "login:avatar"],
            Provider::Vk => &["vkid.personal_info", "email"],
            Provider::Amazon => &["profile"],
        }
    }

    pub(crate) fn scope_separator(self) -> &'static str {
        match self {
            Provider::Facebook => ",",
            _ => " ",
        }
    }

    /// How the client authenticates at the token endpoint.
    pub fn client_auth(self) -> ClientAuth {
        match self {
            Provider::X | Provider::Discord => ClientAuth::Basic,
            _ => ClientAuth::Post,
        }
    }

    /// Whether the provider accepts PKCE (S256) for confidential web clients.
    /// X and VK ID require it.
    pub fn supports_pkce(self) -> bool {
        !matches!(
            self,
            Provider::Apple | Provider::LinkedIn | Provider::Discord
        )
    }

    /// Whether the provider issues an OIDC `id_token` bound to a `nonce`.
    pub(crate) fn uses_nonce(self) -> bool {
        matches!(
            self,
            Provider::Google | Provider::Apple | Provider::Microsoft | Provider::GitLab
        )
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Provider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Provider::ALL
            .into_iter()
            .find(|p| p.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| format!("unknown provider `{s}`"))
    }
}
