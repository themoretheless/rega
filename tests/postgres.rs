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
        provider: provider.into(),
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
    let uid = *user.user_id();
    assert_eq!(
        accounts.sign_in(&g).await.unwrap(),
        SignInOutcome::SignedIn(uid)
    );

    // Verified email links (case-insensitive), unverified registers anew.
    let apple = identity(Provider::Apple, "a1", Some("a@X.io"), true);
    assert_eq!(
        accounts.sign_in(&apple).await.unwrap(),
        SignInOutcome::Linked(uid)
    );
    let ms = identity(Provider::Microsoft, "m1", Some("a@x.io"), false);
    let other = accounts.sign_in(&ms).await.unwrap();
    assert!(matches!(other, SignInOutcome::Registered(_)));

    // Manual link conflicts and unlink protection.
    let gh = identity(Provider::GitHub, "42", None, false);
    accounts.link(&uid, &gh).await.unwrap();
    assert!(matches!(
        accounts.link(other.user_id(), &gh).await,
        Err(AccountError::LinkedToAnotherUser(p)) if p == Provider::GitHub
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

    concurrent_first_sign_in_creates_one_user(accounts).await;
}

/// Twenty simultaneous first sign-ins with the same login must end with one
/// user and no orphaned user rows.
async fn concurrent_first_sign_in_creates_one_user(accounts: Accounts<PgAccountStore>) {
    let accounts = std::sync::Arc::new(accounts);
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM rega_users")
        .fetch_one(accounts.store().pool())
        .await
        .unwrap();
    let racer = identity(Provider::Discord, "race", None, false);
    let tasks: Vec<_> = (0..20)
        .map(|_| {
            let (accounts, racer) = (accounts.clone(), racer.clone());
            tokio::spawn(async move { *accounts.sign_in(&racer).await.unwrap().user_id() })
        })
        .collect();
    let mut ids = Vec::new();
    for task in tasks {
        ids.push(task.await.unwrap());
    }
    ids.dedup();
    assert_eq!(ids.len(), 1, "every request must resolve to the same user");

    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM rega_users")
        .fetch_one(accounts.store().pool())
        .await
        .unwrap();
    assert_eq!(after - before, 1, "no orphaned users");
    let orphans: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rega_users u WHERE NOT EXISTS (SELECT 1 FROM rega_logins l WHERE l.user_id = u.id)",
    )
    .fetch_one(accounts.store().pool())
    .await
    .unwrap();
    assert_eq!(orphans, 0);
}
