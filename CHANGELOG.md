# Changelog

## Unreleased

### Security / fixes
- HTTP connect (5 s) and request (15 s) timeouts; provider responses capped at 1 MiB.
- `id_token` signature verification against provider JWKS (Google, Apple, Microsoft, GitLab):
  always on in `OAuthClient::verify_id_token`, opt-in for the code flow via
  `ProviderConfig::with_signature_verification`.
- `Error::Expired` for login attempts older than 15 minutes (was reported as `StateMismatch`).
- Facebook `appsecret_proof`, animated Discord avatars, emails trimmed and lower-cased everywhere.
- Real MSRV is 1.88 (current dependency tree); previously declared 1.80 did not build.

### Added
- `OAuthClient::verify_id_token` for tokens from mobile Google / Apple SDKs.
- `OAuthClient::revoke` (RFC 7009), required by Apple on account deletion.
- End-to-end tests for every provider, property tests, rustdoc for the whole public API.
- CI: MSRV, docs, `cargo deny`, benchmark build.

## 0.1.0
- Initial release: 12 providers, account linking, `InMemoryStore`, benchmarks.
