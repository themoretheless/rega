# rega

Rust-библиотека для регистрации и входа через внешние аккаунты: OAuth 2.0 / OpenID Connect
(authorization code + PKCE + state + nonce), нормализованный профиль и привязка логинов к локальной учётке.

## Провайдеры

| Провайдер | `Provider::` | Скоупы по умолчанию | PKCE | Email считается подтверждённым |
|---|---|---|---|---|
| Google | `Google` | `openid email profile` | ✓ | по `email_verified` |
| Apple | `Apple` | `name email` (`form_post`) | — | по `email_verified` в `id_token` |
| Microsoft | `Microsoft` | `openid email profile` | ✓ | никогда (MS не гарантирует) |
| Facebook | `Facebook` | `email,public_profile` | ✓ | да, если email отдан |
| GitHub | `GitHub` | `read:user user:email` | ✓ | primary+verified из `/user/emails` |
| X (Twitter) | `X` | `users.read tweet.read` | ✓ | `confirmed_email` (нужен скоуп `users.email`) |
| LinkedIn | `LinkedIn` | `openid profile email` | — | по `email_verified` |
| Discord | `Discord` | `identify email` | — | по `verified` |
| Яндекс ID | `Yandex` | `login:email login:info login:avatar` | ✓ | да, если email отдан |
| VK ID | `Vk` | `vkid.personal_info email` | ✓ | нет |
| GitLab | `GitLab` | `openid profile email` | ✓ | по `email_verified` |
| Amazon | `Amazon` | `profile` | ✓ | нет |

Эндпоинты переопределяются через `ProviderConfig::with_endpoints` (свой GitLab, конкретный тенант Microsoft).

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

let accounts = Accounts::new(InMemoryStore::new()); // замените на свою реализацию AccountStore

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

## Привязка аккаунтов

* Ключ логина — `(provider, subject)`, а не email: email у пользователя может меняться.
* `LinkPolicy::VerifiedEmail` (по умолчанию) автоматически привязывает новый провайдер к существующей учётке,
  только если email подтверждён **и** провайдером, **и** в вашей базе. Это защищает от захвата аккаунта
  через провайдера, где можно указать чужой email.
* `LinkPolicy::Never` — всегда новая учётка, привязка только явно через `Accounts::link`.

Своё хранилище — реализуйте трейт `AccountStore`; пара `(provider, subject)` должна быть уникальной
(при нарушении возвращайте `StoreError::Conflict` — так обрабатываются гонки при первом входе).

## Особенности провайдеров

* **Apple** — `client_secret` это ES256-JWT из `.p8`-ключа; ключ парсится один раз, секрет кэшируется на час. Имя пользователя Apple
  присылает только при первом входе (поле `user` в callback) — сохраните его сразу.
  Callback приходит POST'ом (`form_post`), поэтому cookie сессии должна быть `SameSite=None; Secure`.
* **id_token** (Google, Apple, Microsoft, GitLab) проверяется по `iss`/`aud`/`exp`/`nonce`. Подпись не проверяется:
  токен получен напрямую с token endpoint по TLS с аутентификацией клиента (OIDC Core §3.1.3.7).
* **VK ID** — `device_id` из callback автоматически передаётся при обмене кода.
* **GitHub** — ошибки приходят как `200 OK` с `{"error": ...}`, библиотека это обрабатывает; `/user` и `/user/emails` запрашиваются параллельно.
* **Google** — профиль берётся из `id_token`, без отдельного запроса к userinfo.

## Производительность

`cargo bench` (criterion, `benches/hot_paths.rs`), до/после оптимизаций:

| Операция | До | После |
|---|---|---|
| Apple `client_secret` | 44 µs (PEM + ES256 на каждый вход) | 76 ns (кэш, перевыпуск раз в час) |
| `find_by_verified_email`, 10k пользователей | 11 µs (перебор) | 0,33 µs (индекс) |
| `sign_in` существующего, 10k пользователей | 414 ns | 332 ns |
| `authorize` URL | 3,7 µs | 3,4 µs (один вызов ОС-RNG вместо трёх) |

Сеть: Google — на 1 HTTP-запрос меньше (профиль из `id_token`), GitHub — 2 запроса профиля параллельно.

## Разработка

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo bench
```

`tests/apple_test_key.p8` — одноразовый тестовый ключ, не связанный ни с каким Apple-аккаунтом.

Лицензия: MIT.
