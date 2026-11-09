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
        issuer: None,
    }
}

/// Mock endpoints that keep the provider's real issuer expectation.
fn endpoints_for(provider: Provider, server: &MockServer, userinfo: Option<&str>) -> Endpoints {
    Endpoints {
        issuer: provider.endpoints().issuer,
        ..endpoints(server, userinfo, None)
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
    google.provider = Provider::Google.into();
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
    let client = OAuthClient::new().register(
        ProviderConfig::new(provider, "cid", "s", "https://app.test/cb")
            .with_endpoints(endpoints_for(provider, &server, Some("/userinfo"))),
    );
    let req = client.authorize(provider).unwrap();
    let iss = match provider {
        Provider::Microsoft => {
            "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
        }
        _ => "https://gitlab.com",
    };
    let mut claims = json!({
        "iss": iss, "tid": "11111111-2222-3333-4444-555555555555", "aud": "cid", "exp": 4_000_000_000u64, "sub": "s1",
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
                .with_endpoints(endpoints_for(Provider::Google, &server, None)),
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
                .with_endpoints(endpoints_for(Provider::Google, &server, Some("/userinfo")))
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

mod all_providers {
    use super::*;
    use wiremock::matchers::query_param;

    async fn run(
        provider: Provider,
        profile: serde_json::Value,
        expect_sub: &str,
    ) -> rega::ExternalIdentity {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"AT"})))
            .mount(&server)
            .await;
        let userinfo = Mock::given(path("/me"));
        let userinfo = match provider {
            Provider::Yandex => userinfo.and(header("authorization", "OAuth AT")),
            Provider::MailRu => userinfo.and(query_param("access_token", "AT")),
            Provider::Facebook => userinfo.and(query_param(
                "appsecret_proof",
                // HMAC-SHA256(key = "s", msg = "AT")
                "b13552a043dc28fa6891bd0b38e0bb473b5a507c053b8117740e34cd032dfd3a",
            )),
            _ => userinfo.and(header("authorization", "Bearer AT")),
        };
        userinfo
            .respond_with(ResponseTemplate::new(200).set_body_json(profile))
            .expect(1)
            .mount(&server)
            .await;
        let client = OAuthClient::new().register(
            ProviderConfig::new(provider, "cid", "s", "https://app.test/cb")
                .with_endpoints(endpoints(&server, Some("/me"), None)),
        );
        let req = client.authorize(provider).unwrap();
        let cb = Callback::parse(&format!("code=c&state={}", req.pending.state));
        let identity = client.complete(&cb, &req.pending).await.unwrap();
        assert_eq!(identity.subject, expect_sub, "{provider}");
        assert_eq!(identity.provider, provider);
        identity
    }

    #[tokio::test]
    async fn facebook() {
        let i = run(
            Provider::Facebook,
            json!({"id":"10","name":"F","email":"f@fb.test"}),
            "10",
        )
        .await;
        // No verification flag from Facebook: never trusted for auto-linking.
        assert_eq!(
            (i.email.as_deref(), i.email_verified),
            (Some("f@fb.test"), false)
        );
    }

    #[tokio::test]
    async fn x() {
        run(Provider::X, json!({"data":{"id":"11","name":"X"}}), "11").await;
    }

    #[tokio::test]
    async fn linkedin() {
        let i = run(
            Provider::LinkedIn,
            json!({"sub":"li","email":"l@in.test","email_verified":true}),
            "li",
        )
        .await;
        assert!(i.email_verified);
    }

    #[tokio::test]
    async fn discord() {
        run(
            Provider::Discord,
            json!({"id":"12","username":"d","verified":false}),
            "12",
        )
        .await;
    }

    #[tokio::test]
    async fn yandex() {
        run(
            Provider::Yandex,
            json!({"id":"13","default_email":"y@ya.ru"}),
            "13",
        )
        .await;
    }

    #[tokio::test]
    async fn amazon() {
        run(
            Provider::Amazon,
            json!({"user_id":"amzn1.account.X","email":"a@amz.test"}),
            "amzn1.account.X",
        )
        .await;
    }

    #[tokio::test]
    async fn twitch() {
        let i = run(Provider::Twitch, json!({"sub":"tw","email":"t@tv.test","email_verified":true,"preferred_username":"tw_user"}), "tw").await;
        assert_eq!(
            (i.name.as_deref(), i.email_verified),
            (Some("tw_user"), true)
        );
    }

    #[tokio::test]
    async fn slack() {
        run(
            Provider::Slack,
            json!({"ok":true,"sub":"U1","email":"s@sl.test","email_verified":true}),
            "U1",
        )
        .await;
    }

    #[tokio::test]
    async fn spotify() {
        let i = run(
            Provider::Spotify,
            json!({"id":"sp","display_name":"S","images":[{"url":"img"}]}),
            "sp",
        )
        .await;
        assert_eq!(i.avatar_url.as_deref(), Some("img"));
    }

    #[tokio::test]
    async fn reddit() {
        run(Provider::Reddit, json!({"id":"rd","name":"r"}), "rd").await;
    }

    #[tokio::test]
    async fn mailru() {
        run(
            Provider::MailRu,
            json!({"id":"m1","email":"m@mail.ru","name":"M"}),
            "m1",
        )
        .await;
    }

    #[tokio::test]
    async fn bitbucket_reads_confirmed_email() {
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"AT"})))
            .mount(&server)
            .await;
        Mock::given(path("/user"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"uuid":"{b1}","display_name":"B"})),
            )
            .mount(&server)
            .await;
        Mock::given(path("/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"values":[{"email":"B@bb.test","is_primary":true,"is_confirmed":true}]}),
            ))
            .mount(&server)
            .await;
        let client = OAuthClient::new().register(
            ProviderConfig::new(Provider::Bitbucket, "c", "s", "https://app.test/cb")
                .with_endpoints(endpoints(&server, Some("/user"), Some("/emails"))),
        );
        let req = client.authorize(Provider::Bitbucket).unwrap();
        let cb = Callback::parse(&format!("code=c&state={}", req.pending.state));
        let i = client.complete(&cb, &req.pending).await.unwrap();
        assert_eq!(
            (i.subject.as_str(), i.email.as_deref(), i.email_verified),
            ("{b1}", Some("b@bb.test"), true)
        );
    }

    #[tokio::test]
    async fn telegram_has_no_redirect_flow() {
        let client = OAuthClient::new().register(ProviderConfig::new(
            Provider::Telegram,
            "bot",
            "",
            "https://a/cb",
        ));
        assert!(client.authorize(Provider::Telegram).is_err());
    }
}

mod features {
    use super::*;

    #[tokio::test]
    async fn discovery_and_refresh() {
        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": base,
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "userinfo_endpoint": format!("{base}/userinfo"),
                "jwks_uri": format!("{base}/jwks"),
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=rt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":"new","expires_in":3600})),
            )
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let ep = Endpoints::discover(&http, &format!("{base}/"))
            .await
            .unwrap();
        assert_eq!(ep.token, format!("{base}/token"));
        assert_eq!(ep.jwks.as_deref(), Some(format!("{base}/jwks").as_str()));

        let client = OAuthClient::new().register(
            ProviderConfig::new(Provider::GitLab, "c", "s", "https://a/cb").with_endpoints(ep),
        );
        let t = client.refresh(Provider::GitLab, "rt").await.unwrap();
        assert_eq!((t.access_token.as_str(), t.expires_in), ("new", Some(3600)));
    }

    #[test]
    fn endpoint_helpers() {
        let ms = Endpoints::microsoft_tenant("contoso.onmicrosoft.com");
        assert!(ms
            .authorize
            .contains("/contoso.onmicrosoft.com/oauth2/v2.0/authorize"));
        let gl = Endpoints::gitlab("https://git.example.com/");
        assert_eq!(gl.token, "https://git.example.com/oauth/token");
    }

    #[test]
    fn twitch_requests_userinfo_claims() {
        let client = OAuthClient::new().register(ProviderConfig::new(
            Provider::Twitch,
            "c",
            "s",
            "https://a/cb",
        ));
        let url = client.authorize(Provider::Twitch).unwrap().url;
        assert!(url
            .query_pairs()
            .any(|(k, v)| k == "claims" && v.contains("email_verified")));
    }
}

mod rethink {
    use super::*;

    async fn code_flow_with_claims(
        provider: Provider,
        claims: serde_json::Value,
    ) -> rega::Result<rega::ExternalIdentity> {
        let server = MockServer::start().await;
        let client = OAuthClient::new().register(
            ProviderConfig::new(provider, "cid", "s", "https://app.test/cb")
                .with_endpoints(endpoints_for(provider, &server, Some("/userinfo"))),
        );
        let req = client.authorize(provider).unwrap();
        let mut claims = claims;
        claims["aud"] = json!("cid");
        claims["exp"] = json!(4_000_000_000u64);
        claims["sub"] = json!("s1");
        claims["email"] = json!("e@x.test");
        claims["nonce"] = json!(req.pending.nonce.clone().unwrap());
        let id_token = format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()));
        Mock::given(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":"at","id_token": id_token})),
            )
            .mount(&server)
            .await;
        let cb = Callback::parse(&format!("code=c&state={}", req.pending.state));
        client.complete(&cb, &req.pending).await
    }

    #[tokio::test]
    async fn issuer_is_checked_without_signature_verification() {
        let tid = "11111111-2222-3333-4444-555555555555";
        let ms = |iss: String, tid: &str| {
            code_flow_with_claims(Provider::Microsoft, json!({"iss": iss, "tid": tid}))
        };
        assert!(
            ms(format!("https://login.microsoftonline.com/{tid}/v2.0"), tid)
                .await
                .is_ok()
        );
        assert!(ms("https://evil.test/x/v2.0".into(), tid).await.is_err());
        // A tid that is not a plain id must not be spliced into the expected issuer.
        assert!(ms(
            "https://login.microsoftonline.com/a/../b/v2.0".into(),
            "a/../b"
        )
        .await
        .is_err());
        assert!(
            ms(format!("https://login.microsoftonline.com/{tid}/v2.0"), "")
                .await
                .is_err()
        );

        let gl = |iss: &str| code_flow_with_claims(Provider::GitLab, json!({"iss": iss}));
        assert!(gl("https://gitlab.com").await.is_ok());
        assert!(gl("https://gitlab.com.evil.test").await.is_err());

        let g = |iss: &str| code_flow_with_claims(Provider::Google, json!({"iss": iss}));
        assert!(g("accounts.google.com").await.is_ok());
        assert!(g("https://accounts.google.com").await.is_ok());
        assert!(g("google.com").await.is_err());
    }

    #[tokio::test]
    async fn repeated_callback_parameters_are_rejected() {
        let client = OAuthClient::new().register(ProviderConfig::new(
            Provider::GitHub,
            "c",
            "s",
            "https://a/cb",
        ));
        let req = client.authorize(Provider::GitHub).unwrap();
        let cb = Callback::parse(&format!("code=good&state={0}&code=evil", req.pending.state));
        assert_eq!(cb.duplicate(), Some("code"));
        let err = client.complete(&cb, &req.pending).await.unwrap_err();
        assert!(err.to_string().contains("`code` is repeated"), "{err}");
    }

    #[test]
    fn debug_output_never_contains_secrets() {
        let cfg = ProviderConfig::new(Provider::Google, "cid", "TOP-SECRET", "https://a/cb");
        assert!(!format!("{cfg:?}").contains("TOP-SECRET"));

        let client = OAuthClient::new().register(cfg);
        assert!(!format!("{client:?}").contains("TOP-SECRET"));

        let req = client.authorize(Provider::Google).unwrap();
        let shown = format!("{req:?}");
        for secret in [
            req.pending.state.as_str(),
            req.pending.nonce.as_deref().unwrap(),
            req.pending.code_verifier.as_deref().unwrap(),
        ] {
            assert!(!shown.contains(secret), "{shown}");
        }

        let cb = Callback::parse("code=AUTH-CODE&state=STATE-VALUE");
        let shown = format!("{cb:?}");
        assert!(
            shown.contains("code")
                && !shown.contains("AUTH-CODE")
                && !shown.contains("STATE-VALUE")
        );

        let token: rega::TokenResponse = serde_json::from_value(json!({
            "access_token": "AT-VALUE", "refresh_token": "RT-VALUE", "id_token": "IDT-VALUE", "custom": "EXTRA-VALUE",
        }))
        .unwrap();
        let shown = format!("{token:?}");
        for secret in ["AT-VALUE", "RT-VALUE", "IDT-VALUE", "EXTRA-VALUE"] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }
}

mod custom_provider {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use rega::{ProfileMapper, ProviderId, ProviderSpec};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    fn signed(claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("test-kid".into());
        let key = EncodingKey::from_ec_pem(include_bytes!("apple_test_key.p8")).unwrap();
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }

    /// A self-hosted OpenID Connect server: discovery -> authorize -> callback
    /// -> signed id_token -> identity, under an id rega has never heard of.
    #[tokio::test]
    async fn own_oidc_provider_end_to_end() {
        let server = MockServer::start().await;
        let issuer = format!("{}/realms/acme", server.uri());
        Mock::given(path("/realms/acme/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/auth"),
                "token_endpoint": format!("{issuer}/token"),
                "userinfo_endpoint": format!("{issuer}/userinfo"),
                "jwks_uri": format!("{issuer}/certs"),
            })))
            .mount(&server)
            .await;
        Mock::given(path("/realms/acme/certs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(include_str!("test_jwks.json"), "application/json"),
            )
            .mount(&server)
            .await;

        let endpoints = Endpoints::discover(&reqwest::Client::new(), &issuer)
            .await
            .unwrap();
        let spec = ProviderSpec::oidc("Keycloak", endpoints);
        assert_eq!(spec.id.as_str(), "keycloak");
        let client = OAuthClient::new().register(
            ProviderConfig::custom(spec, "web", "s3cret", "https://app.test/cb")
                .with_signature_verification(),
        );
        assert_eq!(
            client
                .providers()
                .map(ProviderId::as_str)
                .collect::<Vec<_>>(),
            ["keycloak"]
        );

        let req = client.authorize("keycloak").unwrap();
        let q: std::collections::HashMap<_, _> = req.url.query_pairs().into_owned().collect();
        assert!(req.url.as_str().starts_with(&format!("{issuer}/auth?")));
        assert_eq!(q["scope"], "openid email profile");
        assert!(q.contains_key("code_challenge") && q.contains_key("nonce"));

        let claims = json!({
            "iss": issuer, "aud": "web", "exp": 4_000_000_000u64, "sub": "kc-7",
            "email": "Dev@Acme.test", "email_verified": true, "preferred_username": "dev",
            "nonce": req.pending.nonce.clone().unwrap(),
        });
        Mock::given(method("POST"))
            .and(path("/realms/acme/token"))
            .and(body_string_contains("client_secret=s3cret"))
            .and(body_string_contains("code_verifier="))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":"at","id_token": signed(&claims)})),
            )
            .mount(&server)
            .await;

        let cb = Callback::parse(&format!("code=c&state={}", req.pending.state));
        let identity = client.complete(&cb, &req.pending).await.unwrap();
        assert_eq!(identity.provider.as_str(), "keycloak");
        assert_eq!(identity.provider.builtin(), None);
        assert_eq!(
            (
                identity.subject.as_str(),
                identity.email.as_deref(),
                identity.email_verified,
                identity.name.as_deref()
            ),
            ("kc-7", Some("dev@acme.test"), true, Some("dev"))
        );

        // A token from another realm must not be accepted.
        let req = client.authorize("keycloak").unwrap();
        let mut evil = claims.clone();
        evil["iss"] = json!(format!("{}/realms/other", server.uri()));
        evil["nonce"] = json!(req.pending.nonce.clone().unwrap());
        server.reset().await;
        Mock::given(path("/realms/acme/certs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(include_str!("test_jwks.json"), "application/json"),
            )
            .mount(&server)
            .await;
        Mock::given(path("/realms/acme/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token":"at","id_token": signed(&evil)})),
            )
            .mount(&server)
            .await;
        let cb = Callback::parse(&format!("code=c&state={}", req.pending.state));
        assert!(matches!(
            client.complete(&cb, &req.pending).await,
            Err(rega::Error::IdToken(_))
        ));

        // The custom login is stored and found again under its own id.
        let accounts = Accounts::new(InMemoryStore::new());
        let first = accounts.sign_in(&identity).await.unwrap();
        assert!(matches!(first, SignInOutcome::Registered(_)));
        assert_eq!(
            accounts.sign_in(&identity).await.unwrap(),
            SignInOutcome::SignedIn(first.user_id().clone())
        );
    }

    /// A plain OAuth 2.0 provider with a hand-written profile mapping.
    #[tokio::test]
    async fn own_oauth2_provider_with_custom_mapper() {
        fn map(profile: serde_json::Value) -> rega::Result<rega::ExternalIdentity> {
            Ok(rega::ExternalIdentity {
                provider: ProviderId::new("ignored"),
                subject: profile["uid"].as_str().unwrap_or_default().to_owned(),
                email: None,
                email_verified: false,
                name: profile["nick"].as_str().map(str::to_owned),
                avatar_url: None,
                raw: profile,
            })
        }
        let server = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"AT"})))
            .mount(&server)
            .await;
        Mock::given(path("/me"))
            .and(header("authorization", "Bearer AT"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"uid":"u1","nick":"neo"})),
            )
            .mount(&server)
            .await;
        let spec = ProviderSpec::oauth2(
            "intranet",
            endpoints(&server, Some("/me"), None),
            ProfileMapper::Custom(map),
        );
        let client =
            OAuthClient::new().register(ProviderConfig::custom(spec, "c", "s", "https://a/cb"));
        let req = client.authorize("intranet").unwrap();
        let cb = Callback::parse(&format!("code=c&state={}", req.pending.state));
        let i = client.complete(&cb, &req.pending).await.unwrap();
        assert_eq!(
            (i.provider.as_str(), i.subject.as_str(), i.name.as_deref()),
            ("intranet", "u1", Some("neo"))
        );
    }

    #[tokio::test]
    async fn login_attempt_expires_by_the_injected_clock() {
        let now = Arc::new(AtomicU64::new(1_000_000));
        let clock = now.clone();
        let client = OAuthClient::new()
            .with_clock(move || clock.load(Ordering::Relaxed))
            .register(ProviderConfig::new(
                Provider::GitHub,
                "c",
                "s",
                "https://a/cb",
            ));
        let req = client.authorize(Provider::GitHub).unwrap();
        assert_eq!(req.pending.created_at, 1_000_000);
        let cb = Callback::parse(&format!("code=&state={}", req.pending.state));

        now.store(1_000_000 + 15 * 60, Ordering::Relaxed);
        assert!(matches!(
            client.complete(&cb, &req.pending).await,
            Err(rega::Error::MissingCode)
        ));
        now.store(1_000_000 + 15 * 60 + 1, Ordering::Relaxed);
        assert!(matches!(
            client.complete(&cb, &req.pending).await,
            Err(rega::Error::Expired)
        ));
    }

    #[test]
    fn builtin_specs_are_consistent() {
        for p in Provider::ALL {
            let spec = p.spec();
            assert_eq!(spec.id, p);
            assert_eq!(spec.id.builtin(), Some(p));
            assert_eq!(spec.pkce, p.supports_pkce());
            // A nonce is only useful when the id_token can be checked.
            assert!(!spec.nonce || spec.endpoints.issuer.is_some(), "{p}");
            assert_eq!(
                spec.endpoints.emails.is_some(),
                spec.email_list != rega::EmailList::None,
                "{p}"
            );
            if spec.redirect_flow {
                assert!(spec.endpoints.authorize.starts_with("https://"), "{p}");
                assert!(spec.endpoints.token.starts_with("https://"), "{p}");
            }
        }
    }

    #[test]
    fn network_errors_do_not_expose_third_party_types() {
        fn assert_source<E: std::error::Error + Send + Sync + 'static>() {}
        assert_source::<rega::Error>();
        let err: rega::Error = serde_json::from_str::<rega::TokenResponse>("{}")
            .unwrap_err()
            .into();
        assert!(matches!(err, rega::Error::InvalidResponse(_)));
    }
}
