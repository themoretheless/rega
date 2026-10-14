//! Ready-made [axum](https://docs.rs/axum) routes (feature `axum`).
//!
//! * `GET /auth/{provider}` — starts the login and redirects to the provider;
//!   the [`PendingAuth`] is sealed into an `HttpOnly` cookie.
//! * `GET|POST /auth/{provider}/callback` — finishes the login (POST covers
//!   Apple's `form_post`), signs the user in through [`Accounts`] and hands the
//!   result to your success handler, which typically creates the app session.
//!
//! ```no_run
//! # async fn demo() {
//! use axum::response::{IntoResponse, Redirect};
//! use rega::axum::AuthRoutes;
//! use rega::{Accounts, InMemoryStore, OAuthClient, Provider, ProviderConfig};
//!
//! let oauth = OAuthClient::new().register(ProviderConfig::new(
//!     Provider::GitHub, "id", "secret", "https://app.example/auth/github/callback",
//! ));
//! let app = AuthRoutes::new(oauth, Accounts::new(InMemoryStore::new()), [0u8; 32])
//!     .on_success(|signed_in| {
//!         // Create your session for signed_in.outcome.user_id() here.
//!         Redirect::to("/").into_response()
//!     })
//!     .router();
//! # let _: axum::Router = app;
//! # }
//! ```

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;

use crate::{
    AccountStore, Accounts, Callback, Error, ExternalIdentity, OAuthClient, PendingAuth, Provider,
    SignInOutcome,
};

const COOKIE: &str = "rega_pending";

/// Successful sign-in passed to the [`AuthRoutes::on_success`] handler.
#[derive(Debug, Clone)]
pub struct SignedIn {
    /// Whether the user signed in, was linked or registered.
    pub outcome: SignInOutcome,
    /// Profile returned by the provider.
    pub identity: ExternalIdentity,
}

type SuccessHandler = Arc<dyn Fn(SignedIn) -> Response + Send + Sync>;

/// Builder for the login routes.
pub struct AuthRoutes<S> {
    oauth: OAuthClient,
    accounts: Arc<Accounts<S>>,
    key: [u8; 32],
    on_success: SuccessHandler,
    secure_cookie: bool,
}

struct Shared<S> {
    oauth: OAuthClient,
    accounts: Arc<Accounts<S>>,
    key: [u8; 32],
    on_success: SuccessHandler,
    secure_cookie: bool,
}

impl<S: AccountStore + 'static> AuthRoutes<S> {
    /// `cookie_key` encrypts the login-state cookie; use 32 random bytes kept
    /// secret and stable across instances.
    pub fn new(oauth: OAuthClient, accounts: Accounts<S>, cookie_key: [u8; 32]) -> Self {
        Self {
            oauth,
            accounts: Arc::new(accounts),
            key: cookie_key,
            on_success: Arc::new(|_| Redirect::to("/").into_response()),
            secure_cookie: true,
        }
    }

    /// Response to send after a successful sign-in (default: redirect to `/`).
    pub fn on_success(
        mut self,
        handler: impl Fn(SignedIn) -> Response + Send + Sync + 'static,
    ) -> Self {
        self.on_success = Arc::new(handler);
        self
    }

    /// Drops the `Secure` cookie attribute — only for local development over
    /// plain HTTP. Apple's `form_post` callback never works without it.
    pub fn insecure_cookie_for_development(mut self) -> Self {
        self.secure_cookie = false;
        self
    }

    /// Router with `/auth/{provider}` and `/auth/{provider}/callback`; merge or
    /// nest it into your application.
    pub fn router(self) -> Router {
        let shared = Arc::new(Shared {
            oauth: self.oauth,
            accounts: self.accounts,
            key: self.key,
            on_success: self.on_success,
            secure_cookie: self.secure_cookie,
        });
        Router::new()
            .route("/auth/{provider}", get(start::<S>))
            .route(
                "/auth/{provider}/callback",
                get(callback::<S>).post(callback::<S>),
            )
            .with_state(shared)
    }
}

async fn start<S: AccountStore + 'static>(
    State(shared): State<Arc<Shared<S>>>,
    Path(provider): Path<String>,
) -> Response {
    let Ok(provider) = provider.parse::<Provider>() else {
        return (StatusCode::NOT_FOUND, "unknown provider").into_response();
    };
    let req = match shared.oauth.authorize(provider) {
        Ok(req) => req,
        Err(e) => return failure(&e),
    };
    let sealed = match req.pending.seal(&shared.key) {
        Ok(s) => s,
        Err(e) => return failure(&e),
    };
    // Apple posts the callback cross-site, which Lax cookies do not survive.
    let same_site = if provider == Provider::Apple && shared.secure_cookie {
        "None"
    } else {
        "Lax"
    };
    let secure = if shared.secure_cookie { "; Secure" } else { "" };
    let cookie = format!(
        "{COOKIE}={sealed}; Path=/auth; HttpOnly; SameSite={same_site}; Max-Age=900{secure}"
    );
    (
        [(header::SET_COOKIE, cookie)],
        Redirect::to(req.url.as_str()),
    )
        .into_response()
}

async fn callback<S: AccountStore + 'static>(
    State(shared): State<Arc<Shared<S>>>,
    Path(provider): Path<String>,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let params = if method == Method::POST {
        Callback::parse(std::str::from_utf8(&body).unwrap_or_default())
    } else {
        Callback::parse(query.as_deref().unwrap_or_default())
    };
    let pending =
        cookie_value(&headers, COOKIE).and_then(|v| PendingAuth::open(v, &shared.key).ok());
    let Some(pending) = pending.filter(|p| p.provider.as_str() == provider) else {
        return failure(&Error::StateMismatch);
    };

    let identity = match shared.oauth.complete(&params, &pending).await {
        Ok(identity) => identity,
        Err(e) => return failure(&e),
    };
    let outcome = match shared.accounts.sign_in(&identity).await {
        Ok(outcome) => outcome,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "sign-in failed").into_response(),
    };

    let mut response = (shared.on_success)(SignedIn { outcome, identity });
    let clear = format!("{COOKIE}=; Path=/auth; HttpOnly; Max-Age=0");
    if let Ok(value) = clear.parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// Maps errors to a status without leaking provider details to the browser.
fn failure(error: &Error) -> Response {
    let (status, message) = match error {
        Error::Provider { error, .. } if error == "access_denied" => {
            (StatusCode::FORBIDDEN, "login cancelled")
        }
        Error::StateMismatch | Error::Expired | Error::MissingCode => (
            StatusCode::BAD_REQUEST,
            "login session expired, please try again",
        ),
        Error::NotConfigured(_) | Error::Config(_) => {
            (StatusCode::NOT_FOUND, "provider not available")
        }
        _ => (StatusCode::BAD_GATEWAY, "login failed"),
    };
    (status, message).into_response()
}
