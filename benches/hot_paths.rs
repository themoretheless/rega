use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rega::{
    AccountStore, Accounts, AppleKey, AppleSigner, ExternalIdentity, InMemoryStore, NewUser,
    OAuthClient, Provider, ProviderConfig,
};

const PEM: &str = include_str!("../tests/apple_test_key.p8");

fn apple_key() -> AppleKey {
    AppleKey {
        team_id: "TEAM".into(),
        key_id: "KEY".into(),
        private_key_pem: PEM.into(),
    }
}

fn apple_secret(c: &mut Criterion) {
    let key = apple_key();
    c.bench_function("apple_secret/uncached (parse PEM + ES256)", |b| {
        b.iter(|| key.client_secret(black_box("com.example.web")).unwrap())
    });
    let signer = AppleSigner::new(apple_key());
    c.bench_function("apple_secret/cached", |b| {
        b.iter(|| signer.client_secret(black_box("com.example.web")).unwrap())
    });
}

fn authorize(c: &mut Criterion) {
    let client = OAuthClient::new().register(ProviderConfig::new(
        Provider::Google,
        "cid",
        "s",
        "https://app.test/cb",
    ));
    c.bench_function("authorize_url/google", |b| {
        b.iter(|| client.authorize(black_box(Provider::Google)).unwrap())
    });
}

fn store(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let store = InMemoryStore::new();
    rt.block_on(async {
        for i in 0..10_000 {
            store
                .create_user(NewUser {
                    email: Some(format!("user{i}@example.com")),
                    email_verified: true,
                    name: None,
                    avatar_url: None,
                })
                .await
                .unwrap();
        }
    });
    let accounts = Accounts::new(store);
    let identity = ExternalIdentity {
        provider: Provider::Google,
        subject: "g".into(),
        email: Some("user9999@example.com".into()),
        email_verified: true,
        name: None,
        avatar_url: None,
        raw: serde_json::Value::Null,
    };
    rt.block_on(accounts.sign_in(&identity)).unwrap();
    c.bench_function("sign_in/existing (10k users)", |b| {
        b.iter(|| rt.block_on(accounts.sign_in(black_box(&identity))).unwrap())
    });
    c.bench_function("find_by_verified_email (10k users)", |b| {
        b.iter(|| {
            rt.block_on(
                accounts
                    .store()
                    .find_by_verified_email(black_box("user5000@example.com")),
            )
            .unwrap()
        })
    });
}

criterion_group!(benches, apple_secret, authorize, store);
criterion_main!(benches);
