use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{ExternalIdentity, Provider};

pub type UserId = String;

/// A provider login attached to a local user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalLogin {
    pub provider: Provider,
    pub subject: String,
}

impl From<&ExternalIdentity> for ExternalLogin {
    fn from(i: &ExternalIdentity) -> Self {
        Self {
            provider: i.provider,
            subject: i.subject.clone(),
        }
    }
}

/// Profile used to create a user on first sign-in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewUser {
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

impl From<&ExternalIdentity> for NewUser {
    fn from(i: &ExternalIdentity) -> Self {
        Self {
            email: i.email.clone(),
            email_verified: i.email_verified,
            name: i.name.clone(),
            avatar_url: i.avatar_url.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The login is already attached to a user (unique constraint).
    #[error("login is already linked")]
    Conflict,
    #[error("storage error: {0}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Persistence for users and their external logins. Implement it on top of
/// your database; the `(provider, subject)` pair must be unique.
#[async_trait]
pub trait AccountStore: Send + Sync {
    async fn find_by_login(&self, login: &ExternalLogin) -> Result<Option<UserId>, StoreError>;
    /// User whose email is **verified** and equal to `email` (case-insensitive).
    async fn find_by_verified_email(&self, email: &str) -> Result<Option<UserId>, StoreError>;
    async fn create_user(&self, user: NewUser) -> Result<UserId, StoreError>;
    /// Must return [`StoreError::Conflict`] if the login belongs to any user.
    async fn add_login(&self, user: &UserId, login: ExternalLogin) -> Result<(), StoreError>;
    async fn remove_login(&self, user: &UserId, login: &ExternalLogin) -> Result<bool, StoreError>;
    async fn logins(&self, user: &UserId) -> Result<Vec<ExternalLogin>, StoreError>;
}

/// When an unknown login may be attached to an existing account automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkPolicy {
    /// Always register a new user; linking only via [`Accounts::link`].
    Never,
    /// Link when both the provider and the local account have the same
    /// verified email. Safe default: unverified emails never link.
    #[default]
    VerifiedEmail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInOutcome {
    /// Known login — existing user.
    SignedIn(UserId),
    /// New login attached to an existing user via verified email.
    Linked(UserId),
    /// New user created.
    Registered(UserId),
}

impl SignInOutcome {
    pub fn user_id(&self) -> &UserId {
        match self {
            Self::SignedIn(u) | Self::Linked(u) | Self::Registered(u) => u,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("this {0} account is already linked to another user")]
    LinkedToAnotherUser(Provider),
    #[error("cannot remove the only login method")]
    LastLogin,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Registration / sign-in / linking logic on top of an [`AccountStore`].
pub struct Accounts<S> {
    store: S,
    policy: LinkPolicy,
}

impl<S: AccountStore> Accounts<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            policy: LinkPolicy::default(),
        }
    }

    pub fn with_policy(mut self, policy: LinkPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Signs in, links or registers the user behind `identity`.
    pub async fn sign_in(
        &self,
        identity: &ExternalIdentity,
    ) -> Result<SignInOutcome, AccountError> {
        let login = ExternalLogin::from(identity);
        if let Some(user) = self.store.find_by_login(&login).await? {
            return Ok(SignInOutcome::SignedIn(user));
        }

        if self.policy == LinkPolicy::VerifiedEmail && identity.email_verified {
            if let Some(email) = &identity.email {
                if let Some(user) = self.store.find_by_verified_email(email).await? {
                    return match self.store.add_login(&user, login.clone()).await {
                        Ok(()) => Ok(SignInOutcome::Linked(user)),
                        Err(StoreError::Conflict) => self.after_race(&login).await,
                        Err(e) => Err(e.into()),
                    };
                }
            }
        }

        let user = self.store.create_user(NewUser::from(identity)).await?;
        match self.store.add_login(&user, login.clone()).await {
            Ok(()) => Ok(SignInOutcome::Registered(user)),
            Err(StoreError::Conflict) => self.after_race(&login).await,
            Err(e) => Err(e.into()),
        }
    }

    /// Concurrent first sign-in with the same login: the other request won.
    async fn after_race(&self, login: &ExternalLogin) -> Result<SignInOutcome, AccountError> {
        match self.store.find_by_login(login).await? {
            Some(user) => Ok(SignInOutcome::SignedIn(user)),
            None => Err(StoreError::Conflict.into()),
        }
    }

    /// Attaches another provider to a signed-in user ("Connect GitHub" button).
    pub async fn link(
        &self,
        user: &UserId,
        identity: &ExternalIdentity,
    ) -> Result<(), AccountError> {
        let login = ExternalLogin::from(identity);
        match self.store.find_by_login(&login).await? {
            Some(owner) if &owner == user => return Ok(()),
            Some(_) => return Err(AccountError::LinkedToAnotherUser(identity.provider)),
            None => {}
        }
        match self.store.add_login(user, login).await {
            Ok(()) => Ok(()),
            Err(StoreError::Conflict) => Err(AccountError::LinkedToAnotherUser(identity.provider)),
            Err(e) => Err(e.into()),
        }
    }

    /// Detaches a provider. Refuses to remove the last login unless
    /// `has_other_credentials` (e.g. the user has a password or passkey).
    pub async fn unlink(
        &self,
        user: &UserId,
        login: &ExternalLogin,
        has_other_credentials: bool,
    ) -> Result<bool, AccountError> {
        if !has_other_credentials {
            let logins = self.store.logins(user).await?;
            if logins.len() <= 1 && logins.contains(login) {
                return Err(AccountError::LastLogin);
            }
        }
        Ok(self.store.remove_login(user, login).await?)
    }
}

/// In-memory [`AccountStore`] for tests and prototypes.
#[derive(Debug, Default)]
pub struct InMemoryStore {
    inner: RwLock<Inner>,
    next_id: AtomicU64,
}

#[derive(Debug, Default)]
struct Inner {
    users: HashMap<UserId, NewUser>,
    logins: HashMap<ExternalLogin, UserId>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn user(&self, id: &UserId) -> Option<NewUser> {
        self.inner.read().await.users.get(id).cloned()
    }
}

#[async_trait]
impl AccountStore for InMemoryStore {
    async fn find_by_login(&self, login: &ExternalLogin) -> Result<Option<UserId>, StoreError> {
        Ok(self.inner.read().await.logins.get(login).cloned())
    }

    async fn find_by_verified_email(&self, email: &str) -> Result<Option<UserId>, StoreError> {
        let inner = self.inner.read().await;
        Ok(inner
            .users
            .iter()
            .find(|(_, u)| {
                u.email_verified
                    && u.email
                        .as_deref()
                        .is_some_and(|e| e.eq_ignore_ascii_case(email))
            })
            .map(|(id, _)| id.clone()))
    }

    async fn create_user(&self, user: NewUser) -> Result<UserId, StoreError> {
        let id = (self.next_id.fetch_add(1, Ordering::Relaxed) + 1).to_string();
        self.inner.write().await.users.insert(id.clone(), user);
        Ok(id)
    }

    async fn add_login(&self, user: &UserId, login: ExternalLogin) -> Result<(), StoreError> {
        let mut inner = self.inner.write().await;
        if inner.logins.contains_key(&login) {
            return Err(StoreError::Conflict);
        }
        inner.logins.insert(login, user.clone());
        Ok(())
    }

    async fn remove_login(&self, user: &UserId, login: &ExternalLogin) -> Result<bool, StoreError> {
        let mut inner = self.inner.write().await;
        if inner.logins.get(login) == Some(user) {
            inner.logins.remove(login);
            return Ok(true);
        }
        Ok(false)
    }

    async fn logins(&self, user: &UserId) -> Result<Vec<ExternalLogin>, StoreError> {
        let inner = self.inner.read().await;
        Ok(inner
            .logins
            .iter()
            .filter(|(_, u)| *u == user)
            .map(|(l, _)| l.clone())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(
        provider: Provider,
        subject: &str,
        email: Option<&str>,
        verified: bool,
    ) -> ExternalIdentity {
        ExternalIdentity {
            provider,
            subject: subject.into(),
            email: email.map(Into::into),
            email_verified: verified,
            name: None,
            avatar_url: None,
            raw: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn register_then_sign_in() {
        let accounts = Accounts::new(InMemoryStore::new());
        let g = identity(Provider::Google, "g1", Some("a@x.io"), true);
        let first = accounts.sign_in(&g).await.unwrap();
        assert!(matches!(first, SignInOutcome::Registered(_)));
        assert_eq!(
            accounts.sign_in(&g).await.unwrap(),
            SignInOutcome::SignedIn(first.user_id().clone())
        );
    }

    #[tokio::test]
    async fn links_by_verified_email_only() {
        let accounts = Accounts::new(InMemoryStore::new());
        let user = accounts
            .sign_in(&identity(Provider::Google, "g1", Some("a@x.io"), true))
            .await
            .unwrap();

        let apple = identity(Provider::Apple, "a1", Some("a@x.io"), true);
        assert_eq!(
            accounts.sign_in(&apple).await.unwrap(),
            SignInOutcome::Linked(user.user_id().clone())
        );

        // Unverified email must not take over the account.
        let ms = identity(Provider::Microsoft, "m1", Some("a@x.io"), false);
        assert!(matches!(
            accounts.sign_in(&ms).await.unwrap(),
            SignInOutcome::Registered(_)
        ));
    }

    #[tokio::test]
    async fn policy_never_does_not_link() {
        let accounts = Accounts::new(InMemoryStore::new()).with_policy(LinkPolicy::Never);
        accounts
            .sign_in(&identity(Provider::Google, "g1", Some("a@x.io"), true))
            .await
            .unwrap();
        let gh = identity(Provider::GitHub, "1", Some("a@x.io"), true);
        assert!(matches!(
            accounts.sign_in(&gh).await.unwrap(),
            SignInOutcome::Registered(_)
        ));
    }

    #[tokio::test]
    async fn manual_link_and_unlink() {
        let accounts = Accounts::new(InMemoryStore::new());
        let u1 = accounts
            .sign_in(&identity(Provider::Google, "g1", None, false))
            .await
            .unwrap()
            .user_id()
            .clone();
        let u2 = accounts
            .sign_in(&identity(Provider::Vk, "v1", None, false))
            .await
            .unwrap()
            .user_id()
            .clone();

        let gh = identity(Provider::GitHub, "42", None, false);
        accounts.link(&u1, &gh).await.unwrap();
        accounts.link(&u1, &gh).await.unwrap(); // idempotent
        assert!(matches!(
            accounts.link(&u2, &gh).await,
            Err(AccountError::LinkedToAnotherUser(Provider::GitHub))
        ));

        let g = ExternalLogin {
            provider: Provider::Google,
            subject: "g1".into(),
        };
        assert!(accounts.unlink(&u1, &g, false).await.unwrap());
        let last = ExternalLogin::from(&gh);
        assert!(matches!(
            accounts.unlink(&u1, &last, false).await,
            Err(AccountError::LastLogin)
        ));
        assert!(accounts.unlink(&u1, &last, true).await.unwrap());
    }
}
