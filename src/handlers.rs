//! HTTP-обработчики публичного API.
//!
//! Модуль содержит эндпоинты:
//! - `POST /tokens` — выпуск токена ([`create_token`]);
//! - `POST /tokens/verify` — проверка токена ([`verify_token`]);
//! - `DELETE /tokens/{jti}` — отзыв токена ([`revoke_token`]);
//! - `GET /livez`, `GET /readyz` — пробы ([`livez`], [`readyz`]);
//! - `GET /metrics` — метрики Prometheus ([`metrics`]).
//!
//! Обработчики намеренно тонкие: вся доменная логика вынесена в
//! [`crate::jwt::JwtManager`] и модели. Значение claim `iss` (issuer) берётся
//! из HTTP-заголовка `Host` входящего запроса, а не из конфигурации.

use std::env;
use actix_web::{web, HttpResponse, get, post, delete};
use chrono::Utc;
use metrics_exporter_prometheus::PrometheusHandle;
use tracing::{debug, error, info};
use utoipa::path;

use crate::jwt::JwtManager;
use crate::key::KeyManager;
use crate::redis::RedisClient;
use crate::error::*;
use crate::models::{ErrorResponse, ReadinessResponse, TokenRequest, TokenResponse, TokenVerifyRequest};
use crate::models::jwt::{JtiStore, JwtError};

#[utoipa::path(
    post,
    path = "/tokens",
    request_body = TokenRequest,
    security(("totp" = [])),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse, description = "Уровень 3: отсутствует/некорректен TOTP-код"),
        (status = 422, body = ErrorResponse),
        (status = 429, body = ErrorResponse, description = "Превышен глобальный cap эндпоинта (если включён)"),
        (status = 500, body = ErrorResponse)
    )
)]
/// Выпускает новый JWT.
///
/// Тело запроса — [`TokenRequest`] с `sub` (subject), `aud` (audience) и
/// необязательным `ttl` (кастомное время жизни в секундах). Issuer (`iss`)
/// подставляется из заголовка `Host`. При выпуске генерируется `jti` и
/// сохраняется в Redis с TTL, равным времени жизни токена.
///
/// # Ответы
/// - `200 OK` — [`TokenResponse`] с подписанным токеном;
/// - `422 Unprocessable Entity` — некорректные входные данные (например, пустой
///   `aud`, невалидный `TOKEN_EXPIRATION_SECONDS` или `ttl` вне допустимых
///   границ);
/// - `400 Bad Request` — отсутствует/некорректен заголовок `Host`;
/// - `500 Internal Server Error` — прочие ошибки (недоступность JWKS и т.п.).
#[post("/tokens")]
pub async fn create_token(
    req: web::Json<TokenRequest>,
    redis: web::Data<RedisClient>,
    keys: web::Data<KeyManager>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    create_token_impl(req, redis, keys, host).await
}

/// Реализация [`create_token`], обобщённая по хранилищу `jti` ([`JtiStore`]).
///
/// Вынесена отдельно, чтобы в интеграционных тестах подставлять in-memory-хранилище
/// вместо [`RedisClient`] (для которого в CI нет реального Redis). Продакшн-обработчик
/// [`create_token`] вызывает её с [`RedisClient`], поведение при этом не меняется.
pub async fn create_token_impl<S: JtiStore + 'static>(
    req: web::Json<TokenRequest>,
    store: web::Data<S>,
    keys: web::Data<KeyManager>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let host_header = host.headers().get("Host")
        .ok_or(Error::Validation("Missing Host header".into()))?
        .to_str()
        .map_err(|_| Error::Validation("Invalid Host header".into()))?;

    match JwtManager::generate_token(
        &host_header,
        &req.sub,
        &req.aud,
        req.ttl,
        &keys,
        store,
    ).await {
        Ok(token) => {
            crate::metrics::record_token_issued();
            Ok(HttpResponse::Ok().json(TokenResponse { token }))
        }
        Err(e) => {
            // Уровень по вине: некорректный запрос клиента (422) — DEBUG,
            // отказ зависимости/внутренний сбой (500) — ERROR.
            match e {
                JwtError::UnprocessableEntity => {
                    debug!("Некорректные параметры запроса токена: {}", e);
                    Err(Error::Unprocessable(
                        "Invalid token request parameters".into(),
                    ))
                }
                _ => {
                    error!("Не удалось выпустить токен: {}", e);
                    Err(Error::Internal(e.to_string()))
                }
            }
        }
    }
}

#[utoipa::path(
    post,
    path = "/tokens/verify",
    request_body = TokenVerifyRequest,
    security(("proxy_secret" = [])),
    responses(
        (status = 200),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse, description = "Уровень 2: нет proxy-secret, либо токен невалиден/истёк"),
        (status = 429, body = ErrorResponse, description = "Превышен per-IP лимит запросов")
    )
)]
/// Проверяет валидность JWT.
///
/// Тело запроса — [`TokenVerifyRequest`] с самим `token` и ожидаемым
/// `audience`. Проверяются подпись (по публичному ключу из JWKS, найденному по
/// `kid`), совпадение `iss` с заголовком `Host`, вхождение `audience` в `aud`,
/// временные границы (`nbf`/`iat`/`exp`) и наличие `jti` в Redis (не отозван).
///
/// # Ответы
/// - `200 OK` — токен валиден, в теле возвращаются его claims;
/// - `401 Unauthorized` — любая ошибка проверки (намеренно без деталей);
/// - `400 Bad Request` — отсутствует/некорректен заголовок `Host`.
#[post("/tokens/verify")]
pub async fn verify_token(
    request: web::Json<TokenVerifyRequest>,
    redis: web::Data<RedisClient>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    verify_token_impl(request, redis, host).await
}

/// Реализация [`verify_token`], обобщённая по хранилищу `jti` ([`JtiStore`]).
///
/// Как и [`create_token_impl`], вынесена для подмены хранилища в тестах.
pub async fn verify_token_impl<S: JtiStore + 'static>(
    request: web::Json<TokenVerifyRequest>,
    store: web::Data<S>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let host_header = host.headers().get("Host")
        .ok_or(Error::Validation("Missing Host header".into()))?
        .to_str()
        .map_err(|_| Error::Validation("Invalid Host header".into()))?;

    match JwtManager::verify_token(&request.token, host_header, &request.audience, store).await {
        Ok(v) => {
            crate::metrics::record_token_verified(true);
            Ok(HttpResponse::Ok().json(v))
        }
        Err(e) => {
            crate::metrics::record_token_verified(false);
            // Детали проверки наружу намеренно не раскрываем, чтобы не давать
            // подсказок атакующему — единый ответ на любую причину.
            //
            // Уровень DEBUG: протухший/отозванный/подделанный токен — штатное
            // событие публичной ручки, а не сбой сервиса. Иначе любой такой
            // запрос поднимал бы ERROR-алерты в проде.
            debug!("Проверка токена не удалась: {}", e);
            Err(Error::Unauthorized("Invalid or expired token".into()))
        }
    }
}

#[utoipa::path(
    delete,
    path = "/tokens/{jti}",
    security(("totp" = [])),
    responses(
        (status = 204),
        (status = 401, body = ErrorResponse, description = "Уровень 3: отсутствует/некорректен TOTP-код"),
        (status = 404, body = ErrorResponse),
        (status = 429, body = ErrorResponse, description = "Превышен глобальный cap эндпоинта (если включён)")
    )
)]
/// Отзывает токен по его идентификатору `jti`.
///
/// Удаляет запись `jti` из Redis; после этого проверка соответствующего токена
/// в [`verify_token`] будет неуспешной. Операция идемпотентна.
///
/// # Ответы
/// - `204 No Content` — всегда, даже если `jti` не существовал. Ошибка Redis
///   логируется, но наружу не пробрасывается.
#[delete("/tokens/{jti}")]
pub async fn revoke_token(
    jti: web::Path<String>,
    redis: web::Data<RedisClient>,
) -> Result<HttpResponse, Error> {
    revoke_token_impl(jti, redis).await
}

/// Реализация [`revoke_token`], обобщённая по хранилищу `jti` ([`JtiStore`]).
///
/// Как и [`create_token_impl`], вынесена для подмены хранилища в тестах.
pub async fn revoke_token_impl<S: JtiStore + 'static>(
    jti: web::Path<String>,
    store: web::Data<S>,
) -> Result<HttpResponse, Error> {
    match store.delete_jti(&jti).await {
        Ok(_) => {
            crate::metrics::record_token_revoked();
            info!("Токен отозван");
        }
        Err(e) => {
            // Отказ хранилища — наша вина, ERROR.
            error!("Не удалось отозвать токен: {}", e);
        }
    };

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "Метрики в текстовом формате Prometheus", content_type = "text/plain")
    )
)]
/// Отдаёт метрики в формате экспозиции Prometheus.
///
/// Уровень доступа 4: статический Bearer-токен (`AUTH_METRICS_TOKEN`) — его
/// нативно умеют слать Prometheus (`authorization: {credentials_file}`), Zabbix
/// `agent2` и OTel Collector, через который метрики забирает Monium.
///
/// Токен — не замена сетевой изоляции: ручку всё равно не стоит публиковать
/// наружу, метрики раскрывают операционную картину (объём трафика, доли отказов,
/// латентности зависимостей).
///
/// Роут регистрируется в `main.rs` (не через атрибут-макрос), потому что ручка
/// оборачивается auth-middleware уровня 4.
pub async fn metrics(handle: web::Data<PrometheusHandle>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(handle.render())
}

#[utoipa::path(
    get,
    path = "/livez",
    responses(
        (status = 200, description = "Процесс жив")
    )
)]
/// Liveness-проба: подтверждает, что процесс жив.
///
/// Всегда возвращает `200 OK` без тела. Зависимости не проверяются — для этого
/// служит [`readyz`]. Предназначен для liveness-проверки оркестратора.
#[get("/livez")]
pub async fn livez() -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[utoipa::path(
    get,
    path = "/readyz",
    responses(
        (status = 200, body = ReadinessResponse, description = "Все зависимости доступны"),
        (status = 503, body = ReadinessResponse, description = "Одна из зависимостей недоступна")
    )
)]
/// Readiness-проба: проверяет доступность зависимостей.
///
/// Пингует Redis и запрашивает JWKS у `jwks-service-app`
/// (`GET /.well-known/jwks.json`). Возвращает `200 OK`, если обе зависимости
/// доступны, иначе `503 Service Unavailable`. В обоих случаях тело —
/// [`ReadinessResponse`] с детализацией по каждой зависимости.
#[get("/readyz")]
pub async fn readyz(
    redis: web::Data<RedisClient>,
    keys: web::Data<KeyManager>,
) -> HttpResponse {
    let redis_ok = redis.ping().await.is_ok();
    let jwks_ok = keys.check_jwks().await.is_ok();

    let body = ReadinessResponse {
        status: if redis_ok && jwks_ok { "ok" } else { "unavailable" }.into(),
        redis: redis_ok,
        jwks: jwks_ok,
    };

    if redis_ok && jwks_ok {
        HttpResponse::Ok().json(body)
    } else {
        HttpResponse::ServiceUnavailable().json(body)
    }
}

#[cfg(test)]
mod tests {
    //! Тесты HTTP-слоя: health/readiness и полный жизненный цикл токенов.
    //!
    //! `livez` не зависит от окружения. Для `readyz` зависимости (Redis и
    //! `jwks-service-app`) направляются на заведомо недоступные адреса, чтобы
    //! детерминированно проверить ветку `503` без реальной инфраструктуры.
    //!
    //! Эндпоинты токенов проверяются через `actix_web::test`: хранилище `jti`
    //! подменяется in-memory-моком [`MockStore`] (Redis не нужен), а сервис ключей
    //! `jwks-service-app` поднимается как HTTP-мок ([`wiremock`]) — так тесты
    //! проходят в CI без реальной инфраструктуры. Часть проверок конструирует токены
    //! напрямую (истёкший, с чужой подписью), чего нельзя добиться через публичный API.
    //!
    //! Обработчики регистрируются через обобщённые `*_impl`-реализации
    //! ([`create_token_impl`] и др.) с подстановкой [`MockStore`]; продакшн-обёртки
    //! (`create_token` и т.п.) идентичны им, но жёстко завязаны на [`RedisClient`].

    // `env_guard` намеренно держит std-`MutexGuard` через `.await`: `#[actix_web::test]`
    // запускает каждый тест на отдельном однопоточном рантайме, задача с потока не
    // мигрирует и одна на рантайм — так лок сериализует тесты по общим переменным
    // окружения без риска дедлока. Async-Mutex здесь избыточен.
    #![allow(clippy::await_holding_lock)]

    use super::*;
    use actix_web::{test, App};
    use actix_web::http::StatusCode;
    use actix_web::http::header::HeaderValue;
    use std::collections::HashSet;
    use std::sync::Mutex;
    use parking_lot::Mutex as PlMutex;
    use openssl::pkey::{PKey, Private};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};
    use crate::models::TokenResponse;
    use crate::models::jwt::{JsonWebToken, JtiError, TokenClaims, TokenHeaders};

    /// Тесты токенов правят процесс-глобальные переменные окружения
    /// (`JWKS_SERVICE_URL`, `TOKEN_ALGORITHM`, ...) и адрес JWKS-мока, поэтому
    /// выполняются строго последовательно. `readyz` тоже трогает `JWKS_SERVICE_URL`,
    /// так что берёт тот же лок. Восстанавливаемся после «отравления» (`into_inner`),
    /// чтобы паника одного теста не роняла остальные.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// In-memory реализация [`JtiStore`] для тестов HTTP-слоя.
    struct MockStore {
        jtis: PlMutex<HashSet<String>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self { jtis: PlMutex::new(HashSet::new()) }
        }
    }

    impl JtiStore for MockStore {
        async fn store_jti(&self, jti: &str, _ttl: u64) -> Result<(), JtiError> {
            self.jtis.lock().insert(jti.to_string());
            Ok(())
        }

        async fn check_jti(&self, jti: &str) -> Result<bool, JtiError> {
            Ok(self.jtis.lock().contains(jti))
        }

        async fn delete_jti(&self, jti: &str) -> Result<(), JtiError> {
            self.jtis.lock().remove(jti);
            Ok(())
        }
    }

    /// Тестовый ключ Ed25519 и его JWK-представление.
    ///
    /// `EdDSA` выбран потому, что подпись/проверка идут без явного дайджеста —
    /// ровно как в [`JsonWebToken::to_string`] / `from_string`, что гарантирует
    /// round-trip (см. также юнит-тесты в `models/jwt.rs`).
    struct TestKey {
        pkey: PKey<Private>,
        kid: String,
        /// Приватный ключ в base64url(PKCS#8 DER) — формат поля `private_key` JWK.
        private_b64: String,
        /// Сырой публичный ключ в base64url — компонент `x` JWK для OKP.
        x_b64: String,
    }

    fn make_key(kid: &str) -> TestKey {
        let pkey = PKey::generate_ed25519().unwrap();
        let pkcs8 = pkey.private_key_to_pkcs8().unwrap();
        let raw_public = pkey.raw_public_key().unwrap();
        TestKey {
            kid: kid.to_string(),
            private_b64: URL_SAFE_NO_PAD.encode(&pkcs8),
            x_b64: URL_SAFE_NO_PAD.encode(&raw_public),
            pkey,
        }
    }

    /// Поднимает HTTP-мок `jwks-service-app`, отдающий приватный ключ при выпуске
    /// (`POST /jwks`) и публичный — при проверке (`GET /.well-known/jwks.json`).
    async fn start_jwks_mock(key: &TestKey) -> MockServer {
        let server = MockServer::start().await;

        let jwk_data = json!({
            "id": key.kid, "kty": "OKP", "alg": "EdDSA", "kid": key.kid,
            "crv": "Ed25519", "x": key.x_b64, "y": null, "n": null, "e": null,
            "private_key": key.private_b64,
        });
        Mock::given(method("POST")).and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwk_data))
            .mount(&server).await;

        let jwks = json!({ "keys": [ {
            "kty": "OKP", "alg": "EdDSA", "kid": key.kid, "crv": "Ed25519",
            "x": key.x_b64, "y": null, "n": null, "e": null,
        } ] });
        Mock::given(method("GET")).and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server).await;

        server
    }

    /// Настраивает окружение под тестовый JWKS-мок с алгоритмом `EdDSA` и
    /// дефолтными границами TTL. Требует удержания [`env_guard`].
    fn set_jwks_env(server: &MockServer) {
        env::set_var("JWKS_SERVICE_URL", server.uri());
        env::set_var("TOKEN_ALGORITHM", "EdDSA");
        env::remove_var("TOKEN_JKU");
        env::remove_var("TOKEN_EXPIRATION_SECONDS");
        env::remove_var("TOKEN_TTL_MIN_SECONDS");
        env::remove_var("TOKEN_TTL_MAX_SECONDS");
    }

    /// Собирает тестовое приложение с эндпоинтами токенов поверх [`MockStore`].
    ///
    /// Оформлено макросом, чтобы не выписывать громоздкий тип
    /// `App<impl ServiceFactory<...>>`. `KeyManager` конструируется здесь и читает
    /// `JWKS_SERVICE_URL` — вызывать после [`set_jwks_env`].
    macro_rules! token_app {
        ($store:expr) => {{
            let keys = web::Data::new(KeyManager::new("EdDSA".to_string()));
            App::new()
                .app_data($store)
                .app_data(keys)
                .route("/tokens", web::post().to(create_token_impl::<MockStore>))
                .route("/tokens/verify", web::post().to(verify_token_impl::<MockStore>))
                .route("/tokens/{jti}", web::delete().to(revoke_token_impl::<MockStore>))
        }};
    }

    /// Достаёт `jti` из сегмента claims сериализованного токена.
    fn jti_of(token: &str) -> String {
        let claims_segment = token.split('.').nth(1).expect("нет сегмента claims");
        TokenClaims::from_base64(claims_segment.to_string())
            .expect("claims не декодируются")
            .jti
    }

    #[actix_web::test]
    async fn livez_returns_200() {
        let app = test::init_service(App::new().service(livez)).await;
        let req = test::TestRequest::get().uri("/livez").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn metrics_returns_prometheus_exposition() {
        // Локальный recorder: глобальный ставится один раз на процесс и в тестах
        // недоступен (см. `metrics.rs`).
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        ::metrics::with_local_recorder(&recorder, || {
            crate::metrics::record_token_issued();
        });

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(handle))
                .route("/metrics", web::get().to(super::metrics)),
        )
        .await;
        let req = test::TestRequest::get().uri("/metrics").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(content_type.starts_with("text/plain"));

        let body = test::read_body(resp).await;
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("jwt_tokens_issued_total"));
    }

    #[actix_web::test]
    async fn readyz_reports_503_when_dependencies_unavailable() {
        let _guard = env_guard();

        // Порт 1 гарантированно недоступен — и Redis, и JWKS быстро падают с
        // «connection refused» независимо от окружения.
        env::set_var("REDIS_URL", "redis://127.0.0.1:1");
        env::set_var("JWKS_SERVICE_URL", "http://127.0.0.1:1");

        let redis = RedisClient::new().unwrap();
        let keys = KeyManager::new("RS256".to_string());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(redis))
                .app_data(web::Data::new(keys))
                .service(readyz),
        )
        .await;

        let req = test::TestRequest::get().uri("/readyz").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body: ReadinessResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, "unavailable");
        assert!(!body.redis);
        assert!(!body.jwks);
    }

    // --- Эндпоинты токенов ---

    /// Сквозной сценарий: выпуск → verify(ok) → revoke → verify(fail).
    #[actix_web::test]
    async fn token_lifecycle_issue_verify_revoke_verify() {
        let _guard = env_guard();
        let key = make_key("test-key-1");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store.clone())).await;

        // Выпуск.
        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "user1", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let issued: TokenResponse = test::read_body_json(resp).await;
        let jti = jti_of(&issued.token);

        // Проверка выпущенного токена — успех.
        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": issued.token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Отзыв.
        let req = test::TestRequest::delete()
            .uri(&format!("/tokens/{}", jti))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Повторная проверка того же токена — теперь отказ (jti отозван).
        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": issued.token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// `ttl` ниже нижней границы (дефолт — 1 секунда) → 422.
    #[actix_web::test]
    async fn create_token_rejects_ttl_below_min() {
        let _guard = env_guard();
        let key = make_key("k");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "u", "aud": ["api1"], "ttl": 0 }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// `ttl` выше верхней границы (дефолт — 86400 секунд) → 422.
    #[actix_web::test]
    async fn create_token_rejects_ttl_above_max() {
        let _guard = env_guard();
        let key = make_key("k");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "u", "aud": ["api1"], "ttl": 100_000 }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Пустой `aud` → 422.
    #[actix_web::test]
    async fn create_token_rejects_empty_audience() {
        let _guard = env_guard();
        let key = make_key("k");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "u", "aud": [] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Отсутствует заголовок `Host` → 400 (проверяется до обращения к JWKS).
    #[actix_web::test]
    async fn create_token_missing_host_returns_400() {
        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .set_json(json!({ "sub": "u", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Невалидный (не-ASCII) заголовок `Host` → 400.
    #[actix_web::test]
    async fn create_token_invalid_host_returns_400() {
        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            // 0xFF — не декодируется в ASCII, `to_str()` вернёт ошибку.
            .insert_header(("Host", HeaderValue::from_bytes(&[0xFF, 0xFE]).unwrap()))
            .set_json(json!({ "sub": "u", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Проверка истёкшего токена → 401. `jti` в хранилище присутствует, чтобы
    /// единственной причиной отказа был `exp` в прошлом.
    #[actix_web::test]
    async fn verify_rejects_expired_token() {
        let _guard = env_guard();
        let key = make_key("test-key-1");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        store.store_jti("expired-jti", 3600).await.unwrap();
        let app = test::init_service(token_app!(store.clone())).await;

        let now = Utc::now().timestamp() as usize;
        let headers = TokenHeaders::create_new(key.kid.clone());
        let claims = TokenClaims {
            iss: "example.com".into(),
            sub: "u".into(),
            aud: vec!["api1".into()],
            exp: now - 10,
            iat: now - 3600,
            nbf: now - 3600,
            jti: "expired-jti".into(),
        };
        let token = JsonWebToken::create_new(headers, claims, key.pkey.clone())
            .to_string()
            .unwrap();

        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Проверка токена с чужой подписью → 401. Токен подписан ключом атакующего,
    /// но с тем же `kid`; публичный ключ из JWKS его не подтверждает.
    #[actix_web::test]
    async fn verify_rejects_forged_signature() {
        let _guard = env_guard();
        let key = make_key("test-key-1");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        store.store_jti("forged-jti", 3600).await.unwrap();
        let app = test::init_service(token_app!(store.clone())).await;

        let attacker = make_key("test-key-1");
        let now = Utc::now().timestamp() as usize;
        let headers = TokenHeaders::create_new(key.kid.clone());
        let claims = TokenClaims {
            iss: "example.com".into(),
            sub: "u".into(),
            aud: vec!["api1".into()],
            exp: now + 3600,
            iat: now,
            nbf: now,
            jti: "forged-jti".into(),
        };
        let token = JsonWebToken::create_new(headers, claims, attacker.pkey.clone())
            .to_string()
            .unwrap();

        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Проверка синтаксически битого токена → 401 (без обращения к JWKS).
    #[actix_web::test]
    async fn verify_rejects_malformed_token() {
        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": "not-a-jwt", "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Отзыв несуществующего `jti` идемпотентен → всегда 204.
    #[actix_web::test]
    async fn revoke_unknown_jti_returns_204() {
        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::delete()
            .uri("/tokens/does-not-exist")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}