use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rega::{
    Accounts, AppleKey, Callback, Endpoints, InMemoryStore, OAuthClient, Provider, ProviderConfig,
    SignInOutcome,
};
use serde_json::json;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn endpoints(server: &MockServer, userinfo: Option<&str>, emails: Option<&str>) -> Endpoints {
    Endpoints {
        authorize: format!("{}/authorize", server.uri()),
        token: format!("{}/token", server.uri()),
        userinfo: userinfo.map(|p| format!("{}{p}", server.uri())),
        emails: emails.map(|p| format!("{}{p}", server.uri())),
    }
}

#[tokio::test]
async fn github_registers_and_links_google_by_email() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("code=abc"))
        .and(body_string_contains("client_secret=s3cret"))
        .and(body_string_contains("code_verifier="))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":"gho_1","token_type":"bearer"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("authorization", "Bearer gho_1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": 583231, "login": "octocat"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/emails"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!([{"email":"Octo@Example.com","primary":true,"verified":true}]),
            ),
        )
        .mount(&server)
        .await;

    let client = OAuthClient::new().register(
        ProviderConfig::new(Provider::GitHub, "cid", "s3cret", "https://app.test/cb")
            .with_endpoints(endpoints(&server, Some("/user"), Some("/user/emails"))),
    );
    let req = client.authorize(Provider::GitHub).unwrap();
    let cb = Callback::parse(&format!("code=abc&state={}", req.pending.state));
    let identity = client.complete(&cb, &req.pending).await.unwrap();
    assert_eq!(identity.subject, "583231");
    assert_eq!(identity.email.as_deref(), Some("octo@example.com"));
    assert!(identity.email_verified);

    let accounts = Accounts::new(InMemoryStore::new());
    let user = accounts.sign_in(&identity).await.unwrap();
    assert!(matches!(user, SignInOutcome::Registered(_)));

    let mut google = identity.clone();
    google.provider = Provider::Google;
    google.subject = "1097".into();
    assert_eq!(
        accounts.sign_in(&google).await.unwrap(),
        SignInOutcome::Linked(user.user_id().clone())
    );
}

#[tokio::test]
async fn github_error_in_200_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"error":"bad_verification_code"})),
        )
        .mount(&server)
        .await;
    let client = OAuthClient::new().register(
        ProviderConfig::new(Provider::GitHub, "cid", "s", "https://app.test/cb")
            .with_endpoints(endpoints(&server, Some("/user"), None)),
    );
    let req = client.authorize(Provider::GitHub).unwrap();
    let err = client
        .complete(
            &Callback::parse(&format!("code=x&state={}", req.pending.state)),
            &req.pending,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, rega::Error::Provider { ref error, .. } if error == "bad_verification_code")
    );
}

#[tokio::test]
async fn apple_signs_client_secret_and_reads_id_token() {
    let server = MockServer::start().await;
    let client = OAuthClient::new().register(
        ProviderConfig::apple(
            "com.example.web",
            AppleKey {
                team_id: "TEAM123".into(),
                key_id: "KEY123".into(),
                private_key_pem: include_str!("apple_test_key.p8").into(),
            },
            "https://app.test/apple",
        )
        .with_endpoints(endpoints(&server, None, None)),
    );
    let req = client.authorize(Provider::Apple).unwrap();
    let claims = json!({
        "iss": "https://appleid.apple.com",
        "aud": "com.example.web",
        "exp": 4_000_000_000u64,
        "sub": "001234.abcd",
        "email": "x@privaterelay.appleid.com",
        "email_verified": "true",
        "nonce": req.pending.nonce.clone().unwrap(),
    });
    let id_token = format!(
        "eyJhbGciOiJSUzI1NiJ9.{}.sig",
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("client_secret=eyJ"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":"a","id_token": id_token})),
        )
        .expect(1)
        .mount(&server)
        .await;

    // Apple posts the callback as a form body; `user` is present on first login only.
    let user = r#"{"name":{"firstName":"Anna","lastName":"K"}}"#;
    let body: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("code", "c")
        .append_pair("state", &req.pending.state)
        .append_pair("user", user)
        .finish();
    let identity = client
        .complete(&Callback::parse(&body), &req.pending)
        .await
        .unwrap();
    assert_eq!(identity.subject, "001234.abcd");
    assert_eq!(identity.name.as_deref(), Some("Anna K"));
    assert!(identity.email_verified);

    let requests = server.received_requests().await.unwrap();
    let form = String::from_utf8_lossy(&requests[0].body).to_string();
    let secret = url::form_urlencoded::parse(form.as_bytes())
        .find(|(k, _)| k == "client_secret")
        .unwrap()
        .1
        .to_string();
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(secret.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        (header["alg"].as_str(), header["kid"].as_str()),
        (Some("ES256"), Some("KEY123"))
    );
}

#[tokio::test]
async fn vk_passes_device_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("device_id=dev-1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"access_token":"vk1","user_id":7})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/user_info"))
        .and(body_string_contains("access_token=vk1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"user":{"user_id":"7","first_name":"Ivan","email":"i@vk.com"}}),
            ),
        )
        .mount(&server)
        .await;
    let client = OAuthClient::new().register(
        ProviderConfig::new(Provider::Vk, "51234", "", "https://app.test/vk")
            .with_endpoints(endpoints(&server, Some("/user_info"), None)),
    );
    let req = client.authorize(Provider::Vk).unwrap();
    let cb = Callback::parse(&format!(
        "code=c&device_id=dev-1&state={}",
        req.pending.state
    ));
    let identity = client.complete(&cb, &req.pending).await.unwrap();
    assert_eq!(
        (identity.subject.as_str(), identity.email_verified),
        ("7", false)
    );
}
