//! Provider identity and the data that describes how a provider behaves.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::provider::{ClientAuth, Endpoints};
use crate::{ExternalIdentity, Provider, Result};

/// Identifier of a provider: a built-in one ([`Provider`]) or one you
/// registered yourself. It is what gets stored next to a login and what
/// appears in `/auth/{provider}` routes, so keep it short and stable.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderId(Cow<'static, str>);

impl ProviderId {
    /// Creates an id; it is lower-cased so lookups are case-insensitive.
    pub fn new(id: impl Into<String>) -> Self {
        let mut id = id.into();
        id.make_ascii_lowercase();
        Self(Cow::Owned(id))
    }

    /// The id as text, e.g. `"google"` or `"keycloak"`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The built-in provider with this id, if it is one.
    pub fn builtin(&self) -> Option<Provider> {
        self.0.parse().ok()
    }
}

impl From<Provider> for ProviderId {
    fn from(provider: Provider) -> Self {
        Self(Cow::Borrowed(provider.as_str()))
    }
}

impl From<&ProviderId> for ProviderId {
    fn from(id: &ProviderId) -> Self {
        id.clone()
    }
}

impl From<&str> for ProviderId {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

impl From<String> for ProviderId {
    fn from(id: String) -> Self {
        Self::new(id)
    }
}

impl PartialEq<Provider> for ProviderId {
    fn eq(&self, other: &Provider) -> bool {
        self.0 == other.as_str()
    }
}

impl PartialEq<ProviderId> for Provider {
    fn eq(&self, other: &ProviderId) -> bool {
        other == self
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

/// How the access token is presented to the userinfo endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UserinfoAuth {
    /// `Authorization: Bearer <token>` (the standard).
    Bearer,
    /// `Authorization: OAuth <token>` (Yandex).
    OAuthHeader,
    /// `?access_token=<token>` query parameter (Mail.ru).
    Query,
    /// POST form with `client_id` and `access_token` (VK ID).
    FormWithClientId,
    /// Bearer plus `appsecret_proof` signed with the client secret (Facebook).
    BearerWithAppSecretProof,
}

/// Extra fields a provider needs in the code-for-token exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenExtra {
    /// Nothing beyond the standard parameters.
    None,
    /// `device_id` from the callback and the `state` (VK ID).
    DeviceIdAndState,
}

/// Format of the secondary "list my emails" endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmailList {
    /// The provider has no such endpoint.
    None,
    /// GitHub `/user/emails`.
    GitHub,
    /// Bitbucket `/2.0/user/emails`.
    Bitbucket,
}

/// Turns a provider's profile payload into an [`ExternalIdentity`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ProfileMapper {
    /// One of the built-in mappings ([`profile::map_profile`](crate::profile::map_profile)).
    Builtin(Provider),
    /// Standard OpenID Connect claims: `sub`, `email`, `email_verified`,
    /// `name` / `preferred_username`, `picture`.
    Oidc,
    /// Your own mapping. The `provider` field of the result is overwritten
    /// with the id of the spec.
    Custom(fn(serde_json::Value) -> Result<ExternalIdentity>),
}

/// Everything rega needs to know about a provider. Built-in providers come
/// from [`Provider::spec`]; build your own with [`ProviderSpec::oidc`] or
/// [`ProviderSpec::oauth2`] and adjust the public fields as needed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProviderSpec {
    /// Identifier stored with logins and used in routes.
    pub id: ProviderId,
    /// Provider endpoints.
    pub endpoints: Endpoints,
    /// Scopes requested unless the registration overrides them.
    pub default_scopes: Vec<String>,
    /// Separator between scopes in the authorization URL (a space, except
    /// for Facebook's comma).
    pub scope_separator: String,
    /// How the client authenticates at the token endpoint.
    pub client_auth: ClientAuth,
    /// Send a PKCE challenge (S256).
    pub pkce: bool,
    /// Send an OIDC `nonce` and validate the returned `id_token`.
    pub nonce: bool,
    /// The provider posts the callback as a form (`response_mode=form_post`),
    /// which needs a `SameSite=None` state cookie.
    pub form_post: bool,
    /// Query parameters always added to the authorization URL.
    pub authorize_params: Vec<(String, String)>,
    /// How to authenticate at the userinfo endpoint.
    pub userinfo_auth: UserinfoAuth,
    /// Extra token-exchange fields.
    pub token_extra: TokenExtra,
    /// The `id_token` always carries the whole profile (Google), so userinfo
    /// is never called. When `false`, the `id_token` is still used whenever
    /// it has an `email` claim or there is no userinfo endpoint.
    pub profile_in_id_token: bool,
    /// Format of `endpoints.emails`, when set.
    pub email_list: EmailList,
    /// Profile mapping.
    pub mapper: ProfileMapper,
    /// `false` for providers without a redirect flow (Telegram's widget).
    pub redirect_flow: bool,
}

impl ProviderSpec {
    /// An OpenID Connect provider (Keycloak, Auth0, Okta, Zitadel, …): PKCE,
    /// nonce, `openid email profile` scopes and the standard claims. Get
    /// `endpoints` from [`Endpoints::discover`].
    pub fn oidc(id: impl Into<ProviderId>, endpoints: Endpoints) -> Self {
        Self {
            default_scopes: vec!["openid".into(), "email".into(), "profile".into()],
            nonce: true,
            ..Self::oauth2(id, endpoints, ProfileMapper::Oidc)
        }
    }

    /// A plain OAuth 2.0 provider: PKCE, bearer userinfo request, no scopes
    /// by default and the mapping you supply.
    pub fn oauth2(id: impl Into<ProviderId>, endpoints: Endpoints, mapper: ProfileMapper) -> Self {
        Self {
            id: id.into(),
            endpoints,
            default_scopes: Vec::new(),
            scope_separator: " ".into(),
            client_auth: ClientAuth::Post,
            pkce: true,
            nonce: false,
            form_post: false,
            authorize_params: Vec::new(),
            userinfo_auth: UserinfoAuth::Bearer,
            token_extra: TokenExtra::None,
            profile_in_id_token: false,
            email_list: EmailList::None,
            mapper,
            redirect_flow: true,
        }
    }
}
