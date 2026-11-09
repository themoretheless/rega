# rega

Rust-библиотека для регистрации и входа через внешние аккаунты: OAuth 2.0 / OpenID Connect
(authorization code + PKCE + state + nonce), нормализованный профиль и привязка логинов к локальной учётке.

## Провайдеры

| Провайдер | `Provider::` | Скоупы по умолчанию | PKCE | Email считается подтверждённым |
|---|---|---|---|---|
| Google | `Google` | `openid email profile` | ✓ | по `email_verified` |
| Apple | `Apple` | `name email` (`form_post`) | — | по `email_verified` в `id_token` |
| Microsoft | `Microsoft` | `openid email profile` | ✓ | никогда (MS не гарантирует) |
| Facebook | `Facebook` | `email,public_profile` | ✓ | нет (Facebook не отдаёт флаг подтверждения) |
| GitHub | `GitHub` | `read:user user:email` | ✓ | primary+verified из `/user/emails` |
| X (Twitter) | `X` | `users.read tweet.read` | ✓ | нет; email приходит только со скоупом `users.email` |
| LinkedIn | `LinkedIn` | `openid profile email` | — | по `email_verified` |
| Discord | `Discord` | `identify email` | — | по `verified` |
| Яндекс ID | `Yandex` | `login:email login:info login:avatar` | ✓ | нет (флага подтверждения нет) |
| VK ID | `Vk` | `vkid.personal_info email` | ✓ | нет |
| GitLab | `GitLab` | `openid profile email` | ✓ | по `email_verified` |
| Amazon | `Amazon` | `profile` | ✓ | нет |
| Twitch | `Twitch` | `openid user:read:email` | — | по `email_verified` |
| Slack | `Slack` | `openid email profile` | — | по `email_verified` |
| Spotify | `Spotify` | `user-read-email user-read-private` | ✓ | нет |
| Reddit | `Reddit` | `identity` | — | email не отдаётся |
| Bitbucket | `Bitbucket` | `account email` | — | primary+confirmed из `/user/emails` |
| Mail.ru | `MailRu` | `userinfo` | — | нет |
| Telegram | `Telegram` | Login Widget, не OAuth | — | email не отдаётся |

Эндпоинты можно переопределить через `ProviderConfig::with_endpoints`. Готовые хелперы:
`Endpoints::microsoft_tenant("contoso.onmicrosoft.com")`, `Endpoints::gitlab("https://git.example.com")`.

### Свой провайдер

Любой OpenID Connect сервер (Keycloak, Auth0, Okta, Zitadel…) подключается как отдельный провайдер со своим
идентификатором — он же попадает в базу и в маршрут `/auth/keycloak`:

```rust
let endpoints = Endpoints::discover(&reqwest::Client::new(), "https://sso.example.com/realms/acme").await?;
let oauth = OAuthClient::new().register(
    ProviderConfig::custom(ProviderSpec::oidc("keycloak", endpoints), CLIENT_ID, SECRET, REDIRECT)
        .with_signature_verification(),
);
let req = oauth.authorize("keycloak")?;
```

Провайдер без OpenID Connect — `ProviderSpec::oauth2(id, endpoints, ProfileMapper::Custom(my_fn))`: вы задаёте
эндпоинты и функцию, которая превращает JSON профиля в `ExternalIdentity`. Остальные особенности (способ
аутентификации клиента, PKCE, формат запроса профиля) — публичные поля `ProviderSpec`.

## Cargo features

| Feature | Что даёт |
|---|---|
| `rustls` (по умолчанию) / `native-tls` | TLS-бэкенд HTTP-клиента |
| `cookie` | `PendingAuth::seal` / `open` — состояние входа в зашифрованной cookie (AES-256-GCM) |
| `axum` | Готовые маршруты `/auth/{provider}` и `/auth/{provider}/callback` (`rega::axum::AuthRoutes`) |
| `postgres` | `PgAccountStore` на sqlx + `migrations/0001_rega.sql` |

## Использование

```toml
[dependencies]
rega = { git = "https://github.com/themoretheless/rega" }
```

```rust
use rega::*;

let oauth = OAuthClient::new()
    .register(ProviderConfig::new(Provider::Google, GOOGLE_ID, GOOGLE_SECRET, "https://app.example/auth/google/callback"))
    .register(ProviderConfig::new(Provider::GitHub, GH_ID, GH_SECRET, "https://app.example/auth/github/callback"))
    .register(ProviderConfig::apple(
        "com.example.web", // Services ID
        AppleKey { team_id: TEAM_ID.into(), key_id: KEY_ID.into(), private_key_pem: P8.into() },
        "https://app.example/auth/apple/callback",
    ));

let accounts = Accounts::new(InMemoryStore::new()); // или PgAccountStore / своя реализация AccountStore

// 1. GET /auth/{provider} — редирект на провайдера
let req = oauth.authorize(Provider::Google)?;
// сохранить req.pending в сессии / зашифрованной HttpOnly-cookie (в нём PKCE verifier)
redirect_to(req.url);

// 2. GET /auth/{provider}/callback (Apple: POST, тело формы)
let pending: PendingAuth = session.take("pending")?;
let identity = oauth.complete(&Callback::parse(query_or_form_body), &pending).await?;

match accounts.sign_in(&identity).await? {
    SignInOutcome::SignedIn(user)   => { /* существующий пользователь */ }
    SignInOutcome::Linked(user)     => { /* новый провайдер привязан по подтверждённому email */ }
    SignInOutcome::Registered(user) => { /* создана новая учётка */ }
}

// «Подключить GitHub» в настройках профиля залогиненного пользователя
accounts.link(&user_id, &identity).await?;
// Отвязать (последний способ входа не удаляется, если нет пароля/passkey)
accounts.unlink(&user_id, &ExternalLogin::from(&identity), /* has_password */ false).await?;
```

## Другие возможности

```rust
// Вход из мобильного приложения: id_token из Google/Apple SDK, подпись проверяется по JWKS.
let identity = oauth.verify_id_token(Provider::Apple, &id_token, Some("com.example.ios"), None).await?;

// Проверка подписи id_token и в обычном веб-входе (по умолчанию выключена).
ProviderConfig::new(Provider::Google, id, secret, redirect).with_signature_verification();

// Обновление и отзыв токенов (Apple требует отзыв при удалении аккаунта).
let fresh = oauth.refresh(Provider::Google, &refresh_token).await?;
oauth.revoke(Provider::Apple, &refresh_token, Some("refresh_token")).await?;

// Telegram Login Widget.
let identity = rega::telegram::verify_login(&Callback::parse(query), BOT_TOKEN, 86_400)?;

// axum: всё целиком (feature "axum").
let app = rega::axum::AuthRoutes::new(oauth, accounts, cookie_key)
    .on_success(|s| /* создать сессию для s.outcome.user_id() */ Redirect::to("/").into_response())
    .router();
```

Сетевые настройки по умолчанию: таймаут соединения 5 с, запроса 15 с, ответ провайдера не больше 1 МБ,
вход должен быть завершён за 15 минут (иначе `Error::Expired`).

## Привязка аккаунтов

* Ключ логина — `(provider, subject)`, а не email: email у пользователя может меняться.
* `LinkPolicy::VerifiedEmail` (по умолчанию) автоматически привязывает новый провайдер к существующей учётке,
  только если email подтверждён **и** провайдером, **и** в вашей базе. Это защищает от захвата аккаунта
  через провайдера, где можно указать чужой email.
* `LinkPolicy::Never` — всегда новая учётка, привязка только явно через `Accounts::link`.

Своё хранилище — реализуйте трейт `AccountStore`. Тип идентификатора пользователя задаёте вы
(`type UserId`: `i64` у `PgAccountStore`, `String` у `InMemoryStore`). Пара `(provider, subject)` должна быть
уникальной, а `register` — атомарным: пользователь и его первый логин создаются вместе или не создаются вовсе
(при занятом логине возвращайте `StoreError::Conflict` — так обрабатываются гонки при первом входе).

Если вы сами доверяете email какого-то провайдера (например, Яндекса), выставьте `identity.email_verified = true`
перед `accounts.sign_in(&identity)` — это осознанное решение приложения, а не умолчание библиотеки.

## Проверка на настоящих провайдерах

Тесты библиотеки ходят на mock-сервер. Чтобы проверить вход вживую, есть запускаемый пример:

```sh
GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... cargo run --example axum_login --features axum
```

Откройте <http://localhost:3000>. Ссылка появляется для каждого провайдера, у которого заданы
`<ИМЯ>_CLIENT_ID` и `<ИМЯ>_CLIENT_SECRET` (`GOOGLE`, `GITHUB`, `YANDEX`, `MICROSOFT`, `DISCORD`…), а также
для своего OIDC-сервера через `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET`. В консоли провайдера
укажите redirect URI `http://localhost:3000/auth/<имя>/callback`.

## Особенности провайдеров

* **Apple** — `client_secret` это ES256-JWT из `.p8`-ключа; ключ парсится один раз, секрет кэшируется на час. Для удаления аккаунта используйте `revoke`. Имя пользователя Apple
  присылает только при первом входе (поле `user` в callback) — сохраните его сразу.
  Callback приходит POST'ом (`form_post`), поэтому cookie сессии должна быть `SameSite=None; Secure`.
* **id_token** (Google, Apple, Microsoft, GitLab, Twitch, Slack) проверяется по `iss`/`aud`/`exp`/`nonce`. Подпись в веб-входе по умолчанию не проверяется (включается `with_signature_verification`), в `verify_id_token` — проверяется всегда:
  токен получен напрямую с token endpoint по TLS с аутентификацией клиента (OIDC Core §3.1.3.7).
* **VK ID** — `device_id` из callback автоматически передаётся при обмене кода.
* **X** — email отдаётся только приложениям с доступом к нему: запросите скоуп явно —
  `ProviderConfig::new(Provider::X, …).with_scopes(["users.read", "tweet.read", "users.email"])`.
* **GitHub** — ошибки приходят как `200 OK` с `{"error": ...}`, библиотека это обрабатывает; `/user` и `/user/emails` запрашиваются параллельно.
* **Google, Microsoft, GitLab** — профиль берётся из `id_token`, без отдельного запроса к userinfo (MS/GitLab — если токен содержит `email`).

## Производительность

`cargo bench` (criterion, `benches/hot_paths.rs`), до/после оптимизаций:

| Операция | До | После |
|---|---|---|
| Apple `client_secret` | 44 µs (PEM + ES256 на каждый вход) | 76 ns (кэш, перевыпуск раз в час) |
| `find_by_verified_email`, 10k пользователей | 11 µs (перебор) | 0,37 µs (индекс; +40 ns на нормализацию email) |
| `sign_in` существующего, 10k пользователей | 414 ns | ~390 ns (включая нормализацию email) |
| `authorize` URL | 3,7 µs | 3,2 µs (один вызов ОС-RNG, статичная часть URL собирается при регистрации) |
| `verify_id_token` (JWKS из кэша, ES256) | — | 73 µs |

Сеть: Google, Microsoft и GitLab — на 1 HTTP-запрос меньше (профиль из `id_token`, у MS/GitLab — если в нём есть `email`, иначе userinfo), GitHub — 2 запроса профиля параллельно.

## Миграция 0.1 → 0.2

* Провайдер в `ExternalIdentity`, `ExternalLogin`, `PendingAuth` — теперь `ProviderId` (строка), а не enum
  `Provider`. Сравнение `identity.provider == Provider::Google` работает; для `match` используйте
  `identity.provider.builtin()`. В JSON и в базе это тот же текст, что `Provider::as_str()`.
* `ProviderConfig`: поля `provider` и `endpoints` переехали в `config.spec` (`config.provider()`,
  `config.spec.endpoints`); `with_endpoints` работает как раньше.
* `AccountStore`: вместо `create_user` — атомарный `register(user, login)`; появился `type UserId`.
  `SignInOutcome<U>` и `axum::SignedIn<U>` параметризованы этим типом. У `PgAccountStore` id — `i64`.
* `Error`: варианты `Http`, `Json`, `Jwt` заменены на `Network`, `InvalidResponse`, `IdToken`; enum помечен
  `#[non_exhaustive]` — в `match` нужна ветка `_`. То же для `Provider`.
* `OAuthClient::providers()` возвращает `&ProviderId`.

## Разработка

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo bench
```

`tests/apple_test_key.p8` — одноразовый тестовый ключ, не связанный ни с каким Apple-аккаунтом.

Лицензия: MIT.
