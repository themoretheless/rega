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
//!
//! ```no_run
//! use rega::{Accounts, Callback, InMemoryStore, OAuthClient, Provider, ProviderConfig};
//!
//! # async fn demo(callback_query: &str) -> Result<(), Box<dyn std::error::Error>> {
//! let oauth = OAuthClient::new().register(ProviderConfig::new(
//!     Provider::Google,
//!     "client-id",
//!     "client-secret",
//!     "https://app.example/auth/google/callback",
//! ));
//! let accounts = Accounts::new(InMemoryStore::new());
//!
//! // 1. Redirect the user; keep `req.pending` in the session.
//! let req = oauth.authorize(Provider::Google)?;
//! println!("redirect to {}", req.url);
//!
//! // 2. On the callback: verify, exchange the code, load the profile.
//! let identity = oauth.complete(&Callback::parse(callback_query), &req.pending).await?;
//! let user = accounts.sign_in(&identity).await?;
//! println!("signed in as {}", user.user_id());
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs)]

mod account;
mod apple;
mod client;
#[cfg(feature = "cookie")]
mod cookie;
mod error;
mod identity;
mod jwks;
mod pkce;
pub mod profile;
mod provider;
pub mod telegram;

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
