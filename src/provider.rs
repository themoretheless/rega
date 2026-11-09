use std::fmt;

use serde::{Deserialize, Serialize};

use crate::spec::{EmailList, ProfileMapper, ProviderSpec, TokenExtra, UserinfoAuth};

/// Supported identity providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
    /// Expected `iss` claim of the provider's `id_token`. `{tenantid}` is
    /// replaced with the token's `tid` claim (Microsoft multi-tenant apps).
    /// `None` disables the issuer check.
    pub issuer: Option<String>,
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
            issuer: Some(base.to_owned()),
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
            issuer: field("issuer"),
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

    /// The whole description of this provider: endpoints, scopes and every
    /// protocol quirk, in one place.
    const fn builtin(self) -> Builtin {
        match self {
            Provider::Google => Builtin {
                authorize: "https://accounts.google.com/o/oauth2/v2/auth",
                token: "https://oauth2.googleapis.com/token",
                userinfo: Some("https://openidconnect.googleapis.com/v1/userinfo"),
                jwks: Some("https://www.googleapis.com/oauth2/v3/certs"),
                revoke: Some("https://oauth2.googleapis.com/revoke"),
                issuer: Some("https://accounts.google.com"),
                scopes: &["openid", "email", "profile"],
                nonce: true,
                profile_in_id_token: true,
                ..BASE
            },
            Provider::Apple => Builtin {
                authorize: "https://appleid.apple.com/auth/authorize",
                token: "https://appleid.apple.com/auth/token",
                jwks: Some("https://appleid.apple.com/auth/keys"),
                revoke: Some("https://appleid.apple.com/auth/revoke"),
                issuer: Some("https://appleid.apple.com"),
                scopes: &["name", "email"],
                pkce: false,
                nonce: true,
                form_post: true,
                ..BASE
            },
            Provider::Microsoft => Builtin {
                authorize: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                token: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                userinfo: Some("https://graph.microsoft.com/oidc/userinfo"),
                jwks: Some("https://login.microsoftonline.com/common/discovery/v2.0/keys"),
                issuer: Some("https://login.microsoftonline.com/{tenantid}/v2.0"),
                scopes: &["openid", "email", "profile"],
                nonce: true,
                ..BASE
            },
            Provider::Facebook => Builtin {
                authorize: "https://www.facebook.com/v21.0/dialog/oauth",
                token: "https://graph.facebook.com/v21.0/oauth/access_token",
                userinfo: Some(
                    "https://graph.facebook.com/v21.0/me?fields=id,name,email,picture.type(large)",
                ),
                scopes: &["email", "public_profile"],
                scope_separator: ",",
                userinfo_auth: UserinfoAuth::BearerWithAppSecretProof,
                ..BASE
            },
            Provider::GitHub => Builtin {
                authorize: "https://github.com/login/oauth/authorize",
                token: "https://github.com/login/oauth/access_token",
                userinfo: Some("https://api.github.com/user"),
                emails: Some("https://api.github.com/user/emails"),
                scopes: &["read:user", "user:email"],
                email_list: EmailList::GitHub,
                ..BASE
            },
            Provider::X => Builtin {
                authorize: "https://x.com/i/oauth2/authorize",
                token: "https://api.x.com/2/oauth2/token",
                userinfo: Some(
                    "https://api.x.com/2/users/me?user.fields=profile_image_url,confirmed_email",
                ),
                revoke: Some("https://api.x.com/2/oauth2/revoke"),
                scopes: &["users.read", "tweet.read"],
                client_auth: ClientAuth::Basic,
                ..BASE
            },
            Provider::LinkedIn => Builtin {
                authorize: "https://www.linkedin.com/oauth/v2/authorization",
                token: "https://www.linkedin.com/oauth/v2/accessToken",
                userinfo: Some("https://api.linkedin.com/v2/userinfo"),
                scopes: &["openid", "email", "profile"],
                pkce: false,
                ..BASE
            },
            Provider::Discord => Builtin {
                authorize: "https://discord.com/oauth2/authorize",
                token: "https://discord.com/api/oauth2/token",
                userinfo: Some("https://discord.com/api/users/@me"),
                revoke: Some("https://discord.com/api/oauth2/token/revoke"),
                scopes: &["identify", "email"],
                client_auth: ClientAuth::Basic,
                pkce: false,
                ..BASE
            },
            Provider::Yandex => Builtin {
                authorize: "https://oauth.yandex.ru/authorize",
                token: "https://oauth.yandex.ru/token",
                userinfo: Some("https://login.yandex.ru/info?format=json"),
                scopes: &["login:email", "login:info", "login:avatar"],
                userinfo_auth: UserinfoAuth::OAuthHeader,
                ..BASE
            },
            Provider::Vk => Builtin {
                authorize: "https://id.vk.com/authorize",
                token: "https://id.vk.com/oauth2/auth",
                userinfo: Some("https://id.vk.com/oauth2/user_info"),
                scopes: &["vkid.personal_info", "email"],
                userinfo_auth: UserinfoAuth::FormWithClientId,
                token_extra: TokenExtra::DeviceIdAndState,
                ..BASE
            },
            Provider::GitLab => Builtin {
                authorize: "https://gitlab.com/oauth/authorize",
                token: "https://gitlab.com/oauth/token",
                userinfo: Some("https://gitlab.com/oauth/userinfo"),
                jwks: Some("https://gitlab.com/oauth/discovery/keys"),
                revoke: Some("https://gitlab.com/oauth/revoke"),
                issuer: Some("https://gitlab.com"),
                scopes: &["openid", "email", "profile"],
                nonce: true,
                ..BASE
            },
            Provider::Amazon => Builtin {
                authorize: "https://www.amazon.com/ap/oa",
                token: "https://api.amazon.com/auth/o2/token",
                userinfo: Some("https://api.amazon.com/user/profile"),
                scopes: &["profile"],
                ..BASE
            },
            Provider::Twitch => Builtin {
                authorize: "https://id.twitch.tv/oauth2/authorize",
                token: "https://id.twitch.tv/oauth2/token",
                userinfo: Some("https://id.twitch.tv/oauth2/userinfo"),
                jwks: Some("https://id.twitch.tv/oauth2/keys"),
                revoke: Some("https://id.twitch.tv/oauth2/revoke"),
                issuer: Some("https://id.twitch.tv/oauth2"),
                scopes: &["openid", "user:read:email"],
                pkce: false,
                nonce: true,
                authorize_params: &[("claims", TWITCH_CLAIMS)],
                ..BASE
            },
            Provider::Slack => Builtin {
                authorize: "https://slack.com/openid/connect/authorize",
                token: "https://slack.com/api/openid.connect.token",
                userinfo: Some("https://slack.com/api/openid.connect.userInfo"),
                jwks: Some("https://slack.com/openid/connect/keys"),
                issuer: Some("https://slack.com"),
                scopes: &["openid", "email", "profile"],
                pkce: false,
                nonce: true,
                ..BASE
            },
            Provider::Spotify => Builtin {
                authorize: "https://accounts.spotify.com/authorize",
                token: "https://accounts.spotify.com/api/token",
                userinfo: Some("https://api.spotify.com/v1/me"),
                scopes: &["user-read-email", "user-read-private"],
                client_auth: ClientAuth::Basic,
                ..BASE
            },
            Provider::Reddit => Builtin {
                authorize: "https://www.reddit.com/api/v1/authorize",
                token: "https://www.reddit.com/api/v1/access_token",
                userinfo: Some("https://oauth.reddit.com/api/v1/me"),
                revoke: Some("https://www.reddit.com/api/v1/revoke_token"),
                scopes: &["identity"],
                client_auth: ClientAuth::Basic,
                pkce: false,
                ..BASE
            },
            Provider::Bitbucket => Builtin {
                authorize: "https://bitbucket.org/site/oauth2/authorize",
                token: "https://bitbucket.org/site/oauth2/access_token",
                userinfo: Some("https://api.bitbucket.org/2.0/user"),
                emails: Some("https://api.bitbucket.org/2.0/user/emails"),
                scopes: &["account", "email"],
                client_auth: ClientAuth::Basic,
                pkce: false,
                email_list: EmailList::Bitbucket,
                ..BASE
            },
            Provider::MailRu => Builtin {
                authorize: "https://oauth.mail.ru/login",
                token: "https://oauth.mail.ru/token",
                userinfo: Some("https://oauth.mail.ru/userinfo"),
                scopes: &["userinfo"],
                pkce: false,
                userinfo_auth: UserinfoAuth::Query,
                ..BASE
            },
            Provider::Telegram => Builtin {
                authorize: "https://oauth.telegram.org/auth",
                token: "",
                scopes: &[],
                pkce: false,
                redirect_flow: false,
                ..BASE
            },
        }
    }

    /// Owned, editable description of this provider, as used by
    /// [`ProviderConfig`](crate::ProviderConfig).
    pub fn spec(self) -> ProviderSpec {
        let b = self.builtin();
        let owned = |s: Option<&str>| s.map(str::to_owned);
        ProviderSpec {
            endpoints: Endpoints {
                authorize: b.authorize.into(),
                token: b.token.into(),
                userinfo: owned(b.userinfo),
                emails: owned(b.emails),
                jwks: owned(b.jwks),
                revoke: owned(b.revoke),
                issuer: owned(b.issuer),
            },
            default_scopes: b.scopes.iter().map(|s| s.to_string()).collect(),
            scope_separator: b.scope_separator.into(),
            client_auth: b.client_auth,
            pkce: b.pkce,
            nonce: b.nonce,
            form_post: b.form_post,
            authorize_params: b
                .authorize_params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            userinfo_auth: b.userinfo_auth,
            token_extra: b.token_extra,
            profile_in_id_token: b.profile_in_id_token,
            email_list: b.email_list,
            redirect_flow: b.redirect_flow,
            ..ProviderSpec::oauth2(self, Endpoints::default(), ProfileMapper::Builtin(self))
        }
    }

    /// Default endpoints of the provider.
    pub fn endpoints(self) -> Endpoints {
        self.spec().endpoints
    }

    /// Scopes requested by default: enough for id, email, name and avatar.
    pub fn default_scopes(self) -> &'static [&'static str] {
        self.builtin().scopes
    }

    /// How the client authenticates at the token endpoint.
    pub fn client_auth(self) -> ClientAuth {
        self.builtin().client_auth
    }

    /// Whether the provider accepts PKCE (S256) for confidential web clients.
    /// X and VK ID require it.
    pub fn supports_pkce(self) -> bool {
        self.builtin().pkce
    }
}

/// Twitch only returns these userinfo claims when asked for explicitly.
const TWITCH_CLAIMS: &str =
    r#"{"userinfo":{"email":null,"email_verified":null,"picture":null,"preferred_username":null}}"#;

/// Static description of a built-in provider; see [`ProviderSpec`] for the
/// meaning of the fields.
#[derive(Clone, Copy)]
struct Builtin {
    authorize: &'static str,
    token: &'static str,
    userinfo: Option<&'static str>,
    emails: Option<&'static str>,
    jwks: Option<&'static str>,
    revoke: Option<&'static str>,
    issuer: Option<&'static str>,
    scopes: &'static [&'static str],
    scope_separator: &'static str,
    client_auth: ClientAuth,
    pkce: bool,
    nonce: bool,
    form_post: bool,
    authorize_params: &'static [(&'static str, &'static str)],
    userinfo_auth: UserinfoAuth,
    token_extra: TokenExtra,
    profile_in_id_token: bool,
    email_list: EmailList,
    redirect_flow: bool,
}

/// The common case: standard OAuth 2.0 with PKCE and a bearer userinfo call.
const BASE: Builtin = Builtin {
    authorize: "",
    token: "",
    userinfo: None,
    emails: None,
    jwks: None,
    revoke: None,
    issuer: None,
    scopes: &[],
    scope_separator: " ",
    client_auth: ClientAuth::Post,
    pkce: true,
    nonce: false,
    form_post: false,
    authorize_params: &[],
    userinfo_auth: UserinfoAuth::Bearer,
    token_extra: TokenExtra::None,
    profile_in_id_token: false,
    email_list: EmailList::None,
    redirect_flow: true,
};

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
