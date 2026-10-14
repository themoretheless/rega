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

fn jwks_verify(c: &mut Criterion) {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use wiremock::{matchers::path, Mock, MockServer, ResponseTemplate};

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(async {
        let server = MockServer::start().await;
        Mock::given(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(include_str!("../tests/test_jwks.json"), "application/json"),
            )
            .mount(&server)
            .await;
        server
    });
    let mut endpoints = Provider::Google.endpoints();
    endpoints.jwks = Some(format!("{}/jwks", server.uri()));
    let client = OAuthClient::new().register(
        ProviderConfig::new(Provider::Google, "aud", "s", "https://app.test/cb")
            .with_endpoints(endpoints),
    );
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("test-kid".into());
    let claims = serde_json::json!({
        "iss": "https://accounts.google.com", "aud": "aud", "exp": 4_000_000_000u64, "sub": "1",
    });
    let token = jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(PEM.as_bytes()).unwrap(),
    )
    .unwrap();
    rt.block_on(client.verify_id_token(Provider::Google, &token, None, None))
        .unwrap();
    c.bench_function("verify_id_token (cached JWKS, ES256)", |b| {
        b.iter(|| {
            rt.block_on(client.verify_id_token(Provider::Google, black_box(&token), None, None))
                .unwrap()
        })
    });
}

criterion_group!(benches, apple_secret, authorize, store, jwks_verify);
criterion_main!(benches);
