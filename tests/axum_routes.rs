//! Full login through the axum routes against a mocked provider.
#![cfg(feature = "axum")]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::IntoResponse;
use rega::axum::AuthRoutes;
use rega::{Accounts, Endpoints, InMemoryStore, OAuthClient, Provider, ProviderConfig};
use serde_json::json;
use tower::ServiceExt;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn app() -> (axum::Router, MockServer) {
    let server = MockServer::start().await;
    Mock::given(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":"AT"})))
        .mount(&server)
        .await;
    Mock::given(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 5, "login": "octo"})))
        .mount(&server)
        .await;
    let endpoints = Endpoints {
        authorize: format!("{}/authorize", server.uri()),
        token: format!("{}/token", server.uri()),
        userinfo: Some(format!("{}/user", server.uri())),
        emails: None,
        jwks: None,
        revoke: None,
    };
    let oauth = OAuthClient::new().register(
        ProviderConfig::new(
            Provider::GitHub,
            "cid",
            "s",
            "https://app.test/auth/github/callback",
        )
        .with_endpoints(endpoints),
    );
    let app = AuthRoutes::new(oauth, Accounts::new(InMemoryStore::new()), [9u8; 32])
        .on_success(|s| format!("{}:{}", s.identity.subject, s.outcome.user_id()).into_response())
        .router();
    (app, server)
}

#[tokio::test]
async fn login_round_trip() {
    let (app, _server) = app().await;

    let start = app
        .clone()
        .oneshot(Request::get("/auth/github").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::SEE_OTHER);
    let location = start.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned();
    let cookie = start.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.contains("HttpOnly") && cookie.contains("Secure"));
    let state = url::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let cookie_pair = cookie.split(';').next().unwrap().to_owned();

    let done = app
        .clone()
        .oneshot(
            Request::get(format!("/auth/github/callback?code=c&state={state}"))
                .header(header::COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(done.status(), StatusCode::OK);
    assert!(done.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    let body = axum::body::to_bytes(done.into_body(), 1024).await.unwrap();
    assert_eq!(&body[..], b"5:1");

    // Without the cookie (or with a forged one) the callback is refused.
    for cookie in [None, Some("rega_pending=forged")] {
        let mut req = Request::get(format!("/auth/github/callback?code=c&state={state}"));
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn unknown_provider_is_404() {
    let (app, _server) = app().await;
    let resp = app
        .oneshot(Request::get("/auth/myspace").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
