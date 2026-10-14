//! # rega
//!
//! Registration and login through external identity providers
//! (Google, Apple, Microsoft, Facebook, GitHub, X, LinkedIn, Discord,
//! Yandex, VK ID, GitLab, Amazon).
//!
//! The crate has two layers:
//!
//! * [`OAuthClient`] runs the OAuth 2.0 / OpenID Connect authorization-code
//!   flow (state, PKCE, nonce) and returns a normalized [`ExternalIdentity`].
//! * [`Accounts`] turns an identity into a local user: signs in an existing
//!   user, links the login to an account with the same verified email, or
//!   registers a new account. Persistence is abstracted by [`AccountStore`].

mod account;
mod apple;
mod client;
mod error;
mod identity;
mod jwks;
mod pkce;
pub mod profile;
mod provider;

pub use account::{
    AccountError, AccountStore, Accounts, ExternalLogin, InMemoryStore, LinkPolicy, NewUser,
    SignInOutcome, StoreError, UserId,
};
pub use apple::{AppleKey, AppleSigner};
pub use client::{
    AuthorizationRequest, Callback, ClientSecret, OAuthClient, PendingAuth, ProviderConfig,
    TokenResponse,
};
pub use error::{Error, Result};
pub use identity::ExternalIdentity;
pub use provider::{ClientAuth, Endpoints, Provider};
