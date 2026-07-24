# AGENTS.md

Инструкции для AI-агентов и разработчиков, работающих с этим репозиторием.

> Приватные заметки (доступы, процессы, предпочтения) — в `AGENTS_INTERNAL.md`;
> он в `.gitignore` и в репозиторий не коммитится.

## Обзор проекта

`jwt-service-app` — HTTP-сервис на Rust (actix-web) для выпуска, проверки и
отзыва JWT. Сервис **не хранит ключи сам**: за генерацию и хранение ключей
отвечает внешний `jwks-service-app`, к которому обращаются по HTTP. Отозванные/
активные токены отслеживаются по `jti` в Redis.

- Язык: Rust, edition 2021.
- Веб-фреймворк: actix-web 4.
- Крипта: `openssl` (подпись/проверка), поддержка RS256/384/512, ES256/384/512, EdDSA.
- Хранилище `jti`: Redis (`redis` crate, multiplexed async connection).
- OpenAPI: `utoipa`, спека отдаётся на `/api-docs/openapi.json`.

## Архитектура

Поток данных при выпуске токена (`POST /tokens`):

1. `handlers::create_token` читает заголовок `Host` (становится `iss`).
2. `JwtManager::generate_token` запрашивает приватный ключ у `KeyManager`.
3. `KeyManager` через `JwkService` (`src/jwk.rs`) ходит в `jwks-service-app`:
   получает существующий ключ по id или создаёт новый.
4. `TokenClaims::create_new` формирует claims, сохраняет `jti` в Redis с TTL.
5. `JsonWebToken::create_new` подписывает `header.claims` приватным ключом.

Проверка (`POST /tokens/verify`) — обратный путь: `JsonWebToken::from_string`
достаёт публичный ключ по `kid` из JWKS, проверяет подпись и claims
(`iss`, `aud`, `nbf`/`iat`/`exp`, наличие `jti` в Redis).

Отзыв (`DELETE /tokens/{jti}`) — просто удаляет `jti` из Redis.

### Карта модулей (`src/`)

| Файл | Назначение |
|------|-----------|
| `main.rs` | Точка входа, конфиг HTTP-сервера, CORS, роуты, OpenAPI (`ApiDoc`). |
| `handlers.rs` | HTTP-обработчики трёх эндпоинтов + аннотации `utoipa::path`. |
| `jwt.rs` | `JwtManager` — фасад для генерации и проверки токенов. |
| `models/jwt.rs` | `TokenClaims`, `TokenHeaders`, `JsonWebToken`, трейт `JtiStore`, ошибки. |
| `models/mod.rs` | DTO запросов/ответов (`ToSchema`) и структуры JWK/JWKS. |
| `key.rs` | `KeyManager` — получение приватного ключа и реконструкция публичного из JWK. |
| `jwk.rs` | `JwkService` — HTTP-клиент к `jwks-service-app`. |
| `redis.rs` | `RedisClient` — реализация трейта `JtiStore` поверх Redis. |
| `error.rs` | Общий `Error` с `ResponseError` для actix. |

## Команды

Локальная разработка обычно ведётся через Docker Compose (см. ниже), но crate
собирается и напрямую:

```bash
cargo build            # сборка
cargo build --release  # релизная сборка (как в prod-образе)
cargo run              # запуск (нужны Redis и jwks-service-app)
cargo clippy           # линт
cargo fmt              # форматирование
cargo audit            # проверка уязвимостей в зависимостях
```

Тестов в репозитории **нет**. Если добавляете фичу — добавляйте тесты
(`cargo test`); dev-образ уже включает `cargo-tarpaulin` для покрытия.

### Docker Compose (dev)

`deployments/dev/docker-compose.yml` поднимает весь стенд: сам сервис, Redis,
Redis Commander, Postgres, `jwks-service-app`, Swagger UI. Контейнер `app`
запускается с `tail -f /dev/null` — предполагается hot-reload через
`cargo watch` внутри контейнера (dev-образ ставит `cargo-watch`).

## Конфигурация (переменные окружения)

| Переменная | Дефолт | Назначение |
|-----------|--------|-----------|
| `HOST` | `127.0.0.1` | Адрес привязки. |
| `PORT` | `8080` | Порт. |
| `TOKEN_ALGORITHM` | `RS256` | Алгоритм подписи (см. `SUPPORTED_ALGORITHMS` в `key.rs`). |
| `TOKEN_EXPIRATION_SECONDS` | `3600` | TTL токена и записи `jti` в Redis по умолчанию (когда `ttl` не передан в запросе). |
| `TOKEN_TTL_MIN_SECONDS` | `1` | Нижняя граница кастомного `ttl` в теле `POST /tokens`. |
| `TOKEN_TTL_MAX_SECONDS` | `86400` | Верхняя граница кастомного `ttl` в теле `POST /tokens`. |
| `TOKEN_JKU` | — (нет) | Если задан, кладётся в заголовок `jku` и проверяется при верификации. |
| `REDIS_URL` | `redis://redis:6379` | Подключение к Redis. |
| `JWKS_SERVICE_URL` | `http://jwks-service-app:8080` | Базовый URL сервиса ключей. |
| `RUST_LOG` | — | Фильтр логов (`tracing-subscriber`, `EnvFilter`). |

`iss` токена берётся **из заголовка `Host` запроса**, а не из конфига.

## Соглашения и подводные камни

- **Доменный код (`key.rs`, `jwt.rs`, `models/jwt.rs`) обрабатывает ошибки через
  `Result`/`?`** и типы из `error.rs` / `models/jwt.rs` — без `.unwrap()`.
  Продолжайте в том же стиле; `.unwrap()`/`.expect()` остаются только в `main.rs`
  на старте (fail-fast при некорректной конфигурации).
- **Выпуск токена работает по fail-fast**: если `store_jti` не смог записать `jti`
  (например, Redis недоступен), `create_new` возвращает `JwtError::StoreError` и
  токен не отдаётся — это гарантирует консистентность с проверкой, которая
  требует наличия `jti`. Сохраняйте это поведение при изменениях.
- Ошибки наружу отдаются скупо: многие обработчики возвращают пустые
  `500`/`401`/`422` без тела. Не считайте, что клиент получает детали.
- Комментарии в коде местами на русском — это норма для проекта, продолжайте
  в том же стиле, если правите соседний код.
- Версия в `Cargo.toml` — это **триггер релиза**: пуш в `master` с изменением
  `Cargo.toml` запускает `release.yml`, который создаёт GitHub Release и
  дёргает `docker.yml` для сборки/публикации образов (`filipov/jwt-service-app`,
  `ghcr.io/filipov-dev/jwt-service-app`). Меняйте версию осознанно.
- CORS открыт настежь (`allow_any_origin`) — это преднамеренно для сервиса.

## Правила для агентов

- Соблюдайте существующую структуру модулей; новый крипто-/JWT-код держите в
  `key.rs` / `models/jwt.rs`, HTTP-слой — в `handlers.rs`.
- Перед завершением задачи прогоняйте `cargo build` и `cargo clippy`.
- **С каждым коммитом обязательно поднимайте версию** в `Cargo.toml` по semver,
  выбирая разряд по сути изменения:
  - **major** — сломана обратная совместимость (несовместимые изменения API,
    формата токенов, конфигурации и т.п.);
  - **minor** — новый функционал с сохранением обратной совместимости;
  - **patch** — багфикс (или иные изменения без нового функционала: рефакторинг,
    правки документации, CI).

  Учтите: пуш такого изменения в `master` запускает релиз и публикацию
  Docker-образов (см. «Соглашения и подводные камни»).
- Не коммитьте и не пушьте без явной просьбы пользователя.
- Не добавляйте секреты в репозиторий; креды CI лежат в GitHub Secrets.
- При добавлении эндпоинта не забудьте аннотацию `utoipa::path` и регистрацию
  схем/путей в `ApiDoc` (`main.rs`), иначе он не попадёт в OpenAPI.
