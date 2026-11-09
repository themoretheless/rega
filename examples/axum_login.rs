//! A runnable login server for trying rega against real providers.
//!
//! ```sh
//! GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... \
//!     cargo run --example axum_login --features axum
//! ```
//!
//! Then open <http://localhost:3000>. Every provider whose
//! `<NAME>_CLIENT_ID` / `<NAME>_CLIENT_SECRET` pair is set gets a login link.
//! Register `http://localhost:3000/auth/<name>/callback` as the redirect URI
//! in the provider's console (`BASE_URL` changes the origin, `PORT` the port).
//!
//! Supported names: every built-in provider with a redirect flow except
//! Apple (it needs a `.p8` key and HTTPS) — `GOOGLE`, `GITHUB`, `YANDEX`,
//! `MICROSOFT`, `DISCORD`, … — plus any OpenID Connect server through
//! `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` (served as `/auth/oidc`).
//!
//! Users are kept in memory and the page shown after login is the whole
//! "session": this is a test bench, not a template for production.

use std::env;

use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use rand::RngCore;
use rega::axum::AuthRoutes;
use rega::{
    Accounts, Endpoints, InMemoryStore, OAuthClient, Provider, ProviderConfig, ProviderSpec,
    SignInOutcome,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = env::var("PORT").unwrap_or_else(|_| "3000".into());
    let base_url = env::var("BASE_URL").unwrap_or_else(|_| format!("http://localhost:{port}"));
    let redirect = |name: &str| format!("{base_url}/auth/{name}/callback");

    let mut oauth = OAuthClient::new();
    for provider in Provider::ALL {
        let spec = provider.spec();
        let prefix = provider.as_str().to_uppercase();
        let (Ok(id), Ok(secret)) = (
            env::var(format!("{prefix}_CLIENT_ID")),
            env::var(format!("{prefix}_CLIENT_SECRET")),
        ) else {
            continue;
        };
        if !spec.redirect_flow || provider == Provider::Apple {
            eprintln!("{provider}: not supported by this example, skipped");
            continue;
        }
        oauth = oauth.register(ProviderConfig::new(
            provider,
            id,
            secret,
            redirect(provider.as_str()),
        ));
    }
    if let (Ok(issuer), Ok(id)) = (env::var("OIDC_ISSUER"), env::var("OIDC_CLIENT_ID")) {
        let endpoints = Endpoints::discover(&reqwest::Client::new(), &issuer).await?;
        let secret = env::var("OIDC_CLIENT_SECRET").unwrap_or_default();
        oauth = oauth.register(
            ProviderConfig::custom(
                ProviderSpec::oidc("oidc", endpoints),
                id,
                secret,
                redirect("oidc"),
            )
            .with_signature_verification(),
        );
    }

    let mut names: Vec<String> = oauth.providers().map(|p| p.to_string()).collect();
    names.sort();
    if names.is_empty() {
        eprintln!("No provider configured. Set e.g. GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.");
    }

    // A fresh key per run is fine here: it only protects a 15-minute cookie.
    let mut cookie_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut cookie_key);

    let mut routes = AuthRoutes::new(oauth, Accounts::new(InMemoryStore::new()), cookie_key).on_success(|signed_in| {
        let what = match &signed_in.outcome {
            SignInOutcome::SignedIn(_) => "signed in (known login)",
            SignInOutcome::Linked(_) => "linked to an existing user by verified email",
            SignInOutcome::Registered(_) => "registered as a new user",
        };
        let i = &signed_in.identity;
        Html(format!(
            "<h1>{what}</h1><p>local user id: {user}</p>\
             <ul><li>provider: {provider}</li><li>subject: {subject}</li><li>email: {email} (verified: {verified})</li>\
             <li>name: {name}</li></ul><p><a href=\"/\">back</a></p>",
            user = escape(signed_in.outcome.user_id()),
            provider = escape(i.provider.as_str()),
            subject = escape(&i.subject),
            email = escape(i.email.as_deref().unwrap_or("-")),
            verified = i.email_verified,
            name = escape(i.name.as_deref().unwrap_or("-")),
        ))
        .into_response()
    });
    if base_url.starts_with("http://") {
        routes = routes.insecure_cookie_for_development();
    }

    let index = Html(format!(
        "<h1>rega login test</h1><ul>{}</ul>",
        names
            .iter()
            .map(|n| format!("<li><a href=\"/auth/{n}\">Sign in with {n}</a></li>"))
            .collect::<String>()
    ));
    let app = Router::new()
        .route("/", get(move || async move { index }))
        .merge(routes.router());

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    println!(
        "listening on {base_url} with providers: {}",
        names.join(", ")
    );
    axum::serve(listener, app).await?;
    Ok(())
}

/// Profile fields come from the provider: escape them before putting them in HTML.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
