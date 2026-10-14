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
        jwks: Some(format!("{}/jwks", server.uri())),
        revoke: Some(format!("{}/revoke", server.uri())),
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

#[tokio::test]
async fn google_profile_comes_from_id_token_without_userinfo_call() {
    let server = MockServer::start().await;
    let client = OAuthClient::new().register(
        ProviderConfig::new(Provider::Google, "gid", "gs", "https://app.test/g")
            .with_endpoints(endpoints(&server, Some("/userinfo"), None)),
    );
    let req = client.authorize(Provider::Google).unwrap();
    let claims = json!({
        "iss": "https://accounts.google.com", "aud": "gid", "exp": 4_000_000_000u64,
        "sub": "1097", "email": "a@gmail.com", "email_verified": true, "name": "A",
        "nonce": req.pending.nonce.clone().unwrap(),
    });
    let id_token = format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()));
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":"ya29","id_token": id_token})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/userinfo"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let cb = Callback::parse(&format!("code=c&state={}", req.pending.state));
    let identity = client.complete(&cb, &req.pending).await.unwrap();
    assert_eq!(
        (identity.subject.as_str(), identity.email_verified),
        ("1097", true)
    );
}

async fn oidc_flow(
    provider: Provider,
    claims_extra: serde_json::Value,
    userinfo_calls: u64,
) -> rega::ExternalIdentity {
    let server = MockServer::start().await;
    let client =
        OAuthClient::new().register(
            ProviderConfig::new(provider, "cid", "s", "https://app.test/cb")
                .with_endpoints(endpoints(&server, Some("/userinfo"), None)),
        );
    let req = client.authorize(provider).unwrap();
    let mut claims = json!({
        "iss": "https://issuer.test", "aud": "cid", "exp": 4_000_000_000u64, "sub": "s1",
        "nonce": req.pending.nonce.clone().unwrap(),
    });
    claims
        .as_object_mut()
        .unwrap()
        .extend(claims_extra.as_object().unwrap().clone());
    let id_token = format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()));
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":"at","id_token": id_token})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/userinfo"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"sub":"s1","email":"u@info.test"})),
        )
        .expect(userinfo_calls)
        .mount(&server)
        .await;
    let cb = Callback::parse(&format!("code=c&state={}", req.pending.state));
    client.complete(&cb, &req.pending).await.unwrap()
}

#[tokio::test]
async fn gitlab_and_microsoft_use_id_token_when_it_has_email() {
    let g = oidc_flow(
        Provider::GitLab,
        json!({"email":"G@lab.test","email_verified":true}),
        0,
    )
    .await;
    assert_eq!(
        (g.email.as_deref(), g.email_verified),
        (Some("g@lab.test"), true)
    );
    let m = oidc_flow(
        Provider::Microsoft,
        json!({"email":"m@ms.test","email_verified":true}),
        0,
    )
    .await;
    assert!(!m.email_verified);
}

#[tokio::test]
async fn falls_back_to_userinfo_without_email_claim() {
    let m = oidc_flow(Provider::Microsoft, json!({}), 1).await;
    assert_eq!(m.email.as_deref(), Some("u@info.test"));
}

mod hardening {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};

    fn signed(claims: &serde_json::Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.into());
        let key = EncodingKey::from_ec_pem(include_bytes!("apple_test_key.p8")).unwrap();
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }

    async fn jwks_server() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(include_str!("test_jwks.json"), "application/json"),
            )
            .expect(1) // cached after the first fetch
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn verify_id_token_checks_signature_issuer_and_audience() {
        let server = jwks_server().await;
        let client = OAuthClient::new().register(
            ProviderConfig::new(Provider::Google, "web-id", "s", "https://app.test/cb")
                .with_endpoints(endpoints(&server, None, None)),
        );
        let claims = json!({
            "iss": "https://accounts.google.com", "aud": "ios-id", "exp": 4_000_000_000u64,
            "sub": "42", "email": "M@Gmail.com", "email_verified": true,
        });
        let ok = client
            .verify_id_token(
                Provider::Google,
                &signed(&claims, "test-kid"),
                Some("ios-id"),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            (ok.subject.as_str(), ok.email.as_deref()),
            ("42", Some("m@gmail.com"))
        );

        // Wrong audience, forged signature and unknown kid must all fail.
        let token = signed(&claims, "test-kid");
        assert!(client
            .verify_id_token(Provider::Google, &token, None, None)
            .await
            .is_err());
        let mut forged = token.clone();
        forged.replace_range(forged.len() - 4.., "AAAA");
        assert!(client
            .verify_id_token(Provider::Google, &forged, Some("ios-id"), None)
            .await
            .is_err());
        let mut evil = claims.clone();
        evil["iss"] = json!("https://evil.test");
        assert!(client
            .verify_id_token(
                Provider::Google,
                &signed(&evil, "test-kid"),
                Some("ios-id"),
                None
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn code_flow_can_verify_signatures() {
        let server = jwks_server().await;
        let client = OAuthClient::new().register(
            ProviderConfig::new(Provider::Google, "gid", "s", "https://app.test/cb")
                .with_endpoints(endpoints(&server, Some("/userinfo"), None))
                .with_signature_verification(),
        );
        let req = client.authorize(Provider::Google).unwrap();
        let claims = json!({
            "iss": "https://accounts.google.com", "aud": "gid", "exp": 4_000_000_000u64,
            "sub": "7", "nonce": req.pending.nonce.clone().unwrap(),
        });
        Mock::given(path("/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    json!({"access_token":"a","id_token": signed(&claims, "test-kid")}),
                ),
            )
            .mount(&server)
            .await;
        let cb = Callback::parse(&format!("code=c&state={}", req.pending.state));
        assert_eq!(
            client.complete(&cb, &req.pending).await.unwrap().subject,
            "7"
        );
    }

    #[tokio::test]
    async fn revoke_posts_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .and(body_string_contains("token=rt-1"))
            .and(body_string_contains("client_secret=s"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let client = OAuthClient::new().register(
            ProviderConfig::new(Provider::Google, "gid", "s", "https://app.test/cb")
                .with_endpoints(endpoints(&server, None, None)),
        );
        client
            .revoke(Provider::Google, "rt-1", Some("refresh_token"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn oversized_response_is_rejected() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(2 << 20)))
            .mount(&server)
            .await;
        let client = OAuthClient::new().register(
            ProviderConfig::new(Provider::GitHub, "c", "s", "https://app.test/cb")
                .with_endpoints(endpoints(&server, Some("/user"), None)),
        );
        let req = client.authorize(Provider::GitHub).unwrap();
        let cb = Callback::parse(&format!("code=c&state={}", req.pending.state));
        let err = client.complete(&cb, &req.pending).await.unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }

    #[tokio::test]
    async fn expired_pending_auth() {
        let client = OAuthClient::new().register(ProviderConfig::new(
            Provider::GitHub,
            "c",
            "s",
            "https://app.test/cb",
        ));
        let mut req = client.authorize(Provider::GitHub).unwrap();
        req.pending.created_at -= 3600;
        let cb = Callback::parse(&format!("code=c&state={}", req.pending.state));
        assert!(matches!(
            client.complete(&cb, &req.pending).await,
            Err(rega::Error::Expired)
        ));
    }
}
