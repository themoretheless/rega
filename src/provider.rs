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
    /// Twitch (OpenID Connect).
    Twitch,
    /// Slack ("Sign in with Slack", OpenID Connect).
    Slack,
    /// Spotify.
    Spotify,
    /// Reddit.
    Reddit,
    /// Bitbucket Cloud.
    Bitbucket,
    /// Mail.ru (VK Group) OAuth.
    MailRu,
    /// Telegram Login Widget. Not an OAuth provider: verify the widget data
    /// with [`telegram::verify_login`](crate::telegram::verify_login).
    Telegram,
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

impl Endpoints {
    /// Microsoft endpoints restricted to one tenant (`organizations`,
    /// `consumers`, a tenant id or domain).
    pub fn microsoft_tenant(tenant: &str) -> Self {
        let base = format!("https://login.microsoftonline.com/{tenant}");
        Self {
            authorize: format!("{base}/oauth2/v2.0/authorize"),
            token: format!("{base}/oauth2/v2.0/token"),
            jwks: Some(format!("{base}/discovery/v2.0/keys")),
            ..Provider::Microsoft.endpoints()
        }
    }

    /// Endpoints of a self-hosted GitLab instance, e.g. `https://gitlab.example.com`.
    pub fn gitlab(base_url: &str) -> Self {
        let base = base_url.trim_end_matches('/');
        Self {
            authorize: format!("{base}/oauth/authorize"),
            token: format!("{base}/oauth/token"),
            userinfo: Some(format!("{base}/oauth/userinfo")),
            emails: None,
            jwks: Some(format!("{base}/oauth/discovery/keys")),
            revoke: Some(format!("{base}/oauth/revoke")),
        }
    }

    /// Loads endpoints from an OpenID Connect discovery document
    /// (`{issuer}/.well-known/openid-configuration`): Keycloak, Auth0, Okta,
    /// Zitadel, self-hosted GitLab, etc.
    pub async fn discover(http: &reqwest::Client, issuer: &str) -> crate::Result<Self> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let doc = crate::client::read_json(http.get(url).send().await?).await?;
        let field = |name: &str| doc[name].as_str().map(str::to_owned);
        let required = |name: &str| {
            field(name).ok_or_else(|| {
                crate::Error::InvalidResponse(format!("discovery document has no `{name}`"))
            })
        };
        Ok(Self {
            authorize: required("authorization_endpoint")?,
            token: required("token_endpoint")?,
            userinfo: field("userinfo_endpoint"),
            emails: None,
            jwks: field("jwks_uri"),
            revoke: field("revocation_endpoint"),
        })
    }
}

impl Provider {
    /// Every supported provider.
    pub const ALL: [Provider; 19] = [
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
        Provider::Twitch,
        Provider::Slack,
        Provider::Spotify,
        Provider::Reddit,
        Provider::Bitbucket,
        Provider::MailRu,
        Provider::Telegram,
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
            Provider::Twitch => "twitch",
            Provider::Slack => "slack",
            Provider::Spotify => "spotify",
            Provider::Reddit => "reddit",
            Provider::Bitbucket => "bitbucket",
            Provider::MailRu => "mailru",
            Provider::Telegram => "telegram",
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
            Provider::Twitch => (
                "https://id.twitch.tv/oauth2/authorize",
                "https://id.twitch.tv/oauth2/token",
                Some("https://id.twitch.tv/oauth2/userinfo"),
                None,
            ),
            Provider::Slack => (
                "https://slack.com/openid/connect/authorize",
                "https://slack.com/api/openid.connect.token",
                Some("https://slack.com/api/openid.connect.userInfo"),
                None,
            ),
            Provider::Spotify => (
                "https://accounts.spotify.com/authorize",
                "https://accounts.spotify.com/api/token",
                Some("https://api.spotify.com/v1/me"),
                None,
            ),
            Provider::Reddit => (
                "https://www.reddit.com/api/v1/authorize",
                "https://www.reddit.com/api/v1/access_token",
                Some("https://oauth.reddit.com/api/v1/me"),
                None,
            ),
            Provider::Bitbucket => (
                "https://bitbucket.org/site/oauth2/authorize",
                "https://bitbucket.org/site/oauth2/access_token",
                Some("https://api.bitbucket.org/2.0/user"),
                Some("https://api.bitbucket.org/2.0/user/emails"),
            ),
            Provider::MailRu => (
                "https://oauth.mail.ru/login",
                "https://oauth.mail.ru/token",
                Some("https://oauth.mail.ru/userinfo"),
                None,
            ),
            Provider::Telegram => ("https://oauth.telegram.org/auth", "", None, None),
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
            Provider::Twitch => Some("https://id.twitch.tv/oauth2/keys"),
            Provider::Slack => Some("https://slack.com/openid/connect/keys"),
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
            Provider::Twitch => Some("https://id.twitch.tv/oauth2/revoke"),
            Provider::Spotify | Provider::Slack | Provider::Bitbucket | Provider::MailRu => None,
            Provider::Reddit => Some("https://www.reddit.com/api/v1/revoke_token"),
            _ => None,
        }
    }

    /// Accepted `iss` values of the provider's `id_token`. Empty when the issuer
    /// is tenant/host specific (Microsoft is checked against the `tid` claim).
    pub(crate) fn issuers(self) -> &'static [&'static str] {
        match self {
            Provider::Google => &["https://accounts.google.com", "accounts.google.com"],
            Provider::Apple => &["https://appleid.apple.com"],
            Provider::Twitch => &["https://id.twitch.tv/oauth2"],
            Provider::Slack => &["https://slack.com"],
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
            Provider::Twitch => &["openid", "user:read:email"],
            Provider::Slack => &["openid", "email", "profile"],
            Provider::Spotify => &["user-read-email", "user-read-private"],
            Provider::Reddit => &["identity"],
            Provider::Bitbucket => &["account", "email"],
            Provider::MailRu => &["userinfo"],
            Provider::Telegram => &[],
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
            Provider::X
            | Provider::Discord
            | Provider::Spotify
            | Provider::Reddit
            | Provider::Bitbucket => ClientAuth::Basic,
            _ => ClientAuth::Post,
        }
    }

    /// Whether the provider accepts PKCE (S256) for confidential web clients.
    /// X and VK ID require it.
    pub fn supports_pkce(self) -> bool {
        !matches!(
            self,
            Provider::Apple
                | Provider::LinkedIn
                | Provider::Discord
                | Provider::Twitch
                | Provider::Slack
                | Provider::Reddit
                | Provider::Bitbucket
                | Provider::MailRu
                | Provider::Telegram
        )
    }

    /// Whether the provider issues an OIDC `id_token` bound to a `nonce`.
    pub(crate) fn uses_nonce(self) -> bool {
        matches!(
            self,
            Provider::Google
                | Provider::Apple
                | Provider::Microsoft
                | Provider::GitLab
                | Provider::Twitch
                | Provider::Slack
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
