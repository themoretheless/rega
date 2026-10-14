//! PgAccountStore against a real database. Runs when `DATABASE_URL` is set:
//! `DATABASE_URL=postgres://postgres@localhost/rega_test cargo test --features postgres`
#![cfg(feature = "postgres")]

use rega::{
    AccountError, AccountStore, Accounts, ExternalIdentity, ExternalLogin, PgAccountStore,
    Provider, SignInOutcome,
};

async fn store() -> Option<PgAccountStore> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = sqlx::PgPool::connect(&url).await.expect("connect");
    sqlx::raw_sql("DROP TABLE IF EXISTS rega_logins; DROP TABLE IF EXISTS rega_users;")
        .execute(&pool)
        .await
        .unwrap();
    let store = PgAccountStore::new(pool);
    store.migrate().await.unwrap();
    store.migrate().await.unwrap(); // idempotent
    Some(store)
}

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
        name: Some("N".into()),
        avatar_url: None,
        raw: serde_json::Value::Null,
    }
}

// One test so the scenarios share the schema without racing on DROP TABLE.
#[tokio::test]
async fn postgres_store_end_to_end() {
    let Some(store) = store().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let accounts = Accounts::new(store);

    let g = identity(Provider::Google, "g1", Some("A@x.io"), true);
    let user = accounts.sign_in(&g).await.unwrap();
    assert!(matches!(user, SignInOutcome::Registered(_)));
    let uid = user.user_id().clone();
    assert_eq!(
        accounts.sign_in(&g).await.unwrap(),
        SignInOutcome::SignedIn(uid.clone())
    );

    // Verified email links (case-insensitive), unverified registers anew.
    let apple = identity(Provider::Apple, "a1", Some("a@X.io"), true);
    assert_eq!(
        accounts.sign_in(&apple).await.unwrap(),
        SignInOutcome::Linked(uid.clone())
    );
    let ms = identity(Provider::Microsoft, "m1", Some("a@x.io"), false);
    let other = accounts.sign_in(&ms).await.unwrap();
    assert!(matches!(other, SignInOutcome::Registered(_)));

    // Manual link conflicts and unlink protection.
    let gh = identity(Provider::GitHub, "42", None, false);
    accounts.link(&uid, &gh).await.unwrap();
    assert!(matches!(
        accounts.link(other.user_id(), &gh).await,
        Err(AccountError::LinkedToAnotherUser(Provider::GitHub))
    ));
    assert_eq!(accounts.store().logins(&uid).await.unwrap().len(), 3);
    for login in [ExternalLogin::from(&g), ExternalLogin::from(&apple)] {
        assert!(accounts.unlink(&uid, &login, false).await.unwrap());
    }
    assert!(matches!(
        accounts
            .unlink(&uid, &ExternalLogin::from(&gh), false)
            .await,
        Err(AccountError::LastLogin)
    ));
}
