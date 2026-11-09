# Changelog

## Unreleased

### Security review (second pass)
- `Debug` no longer prints secrets: client secret, access/refresh/id tokens, `state`, `nonce`, PKCE verifier
  and callback values are redacted.
- **Behaviour change:** Facebook, Yandex and X emails are no longer treated as verified (those providers send
  no verification flag), so they do not auto-link to an existing account. Set `identity.email_verified`
  yourself to opt back in.
- The `id_token` issuer is now checked for Microsoft (per-tenant) and GitLab even without signature
  verification. **API change:** `Endpoints` gained the `issuer` field.
- Callbacks with a repeated parameter are rejected (`Callback::duplicate`).
- axum: the state cookie is scoped to the real mount point, so nested routers work; sign-in and login
  failures are logged through `tracing`.

### Integrations
- `axum` feature: `AuthRoutes` with `/auth/{provider}` and `/auth/{provider}/callback`
  (GET + POST for Apple), state in an encrypted `HttpOnly` cookie, safe error responses.
- `postgres` feature: `PgAccountStore` on sqlx + `migrations/0001_rega.sql`.
- TLS backend selectable: `rustls` (default) or `native-tls`.

### Security / fixes
- HTTP connect (5 s) and request (15 s) timeouts; provider responses capped at 1 MiB.
- `id_token` signature verification against provider JWKS (Google, Apple, Microsoft, GitLab):
  always on in `OAuthClient::verify_id_token`, opt-in for the code flow via
  `ProviderConfig::with_signature_verification`.
- `Error::Expired` for login attempts older than 15 minutes (was reported as `StateMismatch`).
- Facebook `appsecret_proof`, animated Discord avatars, emails trimmed and lower-cased everywhere.
- Real MSRV is 1.88 (current dependency tree); previously declared 1.80 did not build.

### Added
- 7 new providers: Twitch, Slack, Spotify, Reddit, Bitbucket, Mail.ru and Telegram
  (Login Widget, verified with `telegram::verify_login`) — 19 in total.
- `OAuthClient::refresh` for refresh tokens.
- `Endpoints::microsoft_tenant`, `Endpoints::gitlab` (self-hosted) and
  `Endpoints::discover` (any OpenID Connect issuer: Keycloak, Auth0, Okta, …).
- `cookie` feature: `PendingAuth::seal` / `open` (AES-256-GCM) to keep login state in a cookie.
- `OAuthClient::verify_id_token` for tokens from mobile Google / Apple SDKs.
- `OAuthClient::revoke` (RFC 7009), required by Apple on account deletion.
- End-to-end tests for every provider, property tests, rustdoc for the whole public API.
- CI: MSRV, docs, `cargo deny`, benchmark build.

## 0.1.0
- Initial release: 12 providers, account linking, `InMemoryStore`, benchmarks.
