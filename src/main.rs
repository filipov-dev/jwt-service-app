//! Точка входа `jwt-service-app`.
//!
//! HTTP-сервис на actix-web для выпуска, проверки и отзыва JWT. Сервис не
//! хранит криптографические ключи сам — за них отвечает внешний
//! `jwks-service-app` (см. [`jwk::JwkService`]). Идентификаторы токенов (`jti`)
//! отслеживаются в Redis (см. [`redis::RedisClient`]).
//!
//! Здесь конфигурируется и запускается HTTP-сервер: логирование (`tracing`),
//! CORS, общие данные приложения (Redis-клиент и менеджер ключей), маршруты и
//! выдача OpenAPI-спецификации.
//!
//! Конфигурация — через переменные окружения (`HOST`, `PORT`,
//! `TOKEN_ALGORITHM`, и т.д.), полный список см. в `AGENTS.md`.

use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use std::env;
use std::rc::Rc;
use tracing::info;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

mod auth;
mod error;
mod handlers;
mod issuer;
mod jwk;
mod jwt;
mod key;
mod logging;
mod metrics;
mod models;
mod rate_limit;
mod redis;
mod sentry_glitchtip;
mod server;
mod tracing_otel;

use crate::auth::{Auth, AuthConfig, AuthLevel};
use crate::handlers::metrics as metrics_handler;
use crate::handlers::{
    create_token_impl, livez, readyz, refresh_token_impl, revoke_subject_tokens_impl,
    revoke_token_impl, verify_token_impl,
};
use crate::key::KeyManager;
use crate::logging::{init_subscriber, RequestLog};
use crate::models::{
    ErrorResponse, ReadinessResponse, RefreshRequest, RevokeGroupResponse, TokenRequest,
    TokenResponse,
};
use crate::rate_limit::{RateLimit, RateLimitConfig};
use crate::redis::RedisClient;
use crate::server::ServerConfig;

/// Корневой описатель OpenAPI-документации.
///
/// Перечисляет пути (эндпоинты) и компоненты-схемы, из которых `utoipa`
/// генерирует OpenAPI-спецификацию. При добавлении нового эндпоинта его нужно
/// зарегистрировать здесь в `paths(...)`, а новые DTO — в `components(schemas(...))`,
/// иначе они не попадут в спеку.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::create_token,
        handlers::verify_token,
        handlers::refresh_token,
        handlers::revoke_token,
        handlers::revoke_subject_tokens,
        handlers::livez,
        handlers::readyz,
        handlers::metrics
    ),
    components(schemas(
        TokenRequest,
        TokenResponse,
        ErrorResponse,
        ReadinessResponse,
        RefreshRequest,
        RevokeGroupResponse
    )),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

/// Регистрирует security-схемы для уровней доступа 2 и 3.
///
/// Уровень 2 (`proxy_secret`) и уровень 3 (`totp`) требуют заголовка-`apiKey`.
/// Имена заголовков — дефолтные (`X-Proxy-Secret` / `X-TOTP-Code`); при их
/// переопределении через env обновите и описание в OpenAPI. Уровень 1 (health,
/// OpenAPI) защиты не требует и схем не имеет.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        // `components` уже создан, т.к. в схеме есть зарегистрированные DTO.
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "proxy_secret",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "X-Proxy-Secret",
                    "Уровень 2: статический секрет, проставляемый обратным прокси. \
                     Прокси ОБЯЗАН затирать клиентскую версию заголовка.",
                ))),
            );
            components.add_security_scheme(
                "totp",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "X-TOTP-Code",
                    "Уровень 3: текущий TOTP-код (RFC 6238) на общем секрете.",
                ))),
            );
            components.add_security_scheme(
                "metrics_token",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some(
                            "Уровень 4: статический Bearer-токен для скрейпа /metrics \
                             (AUTH_METRICS_TOKEN).",
                        ))
                        .build(),
                ),
            );
        }
    }
}

/// Рестриктивный CORS для НЕ-публичных ручек.
///
/// Не «отключённый», а именно запрещающий: список разрешённых origin'ов пуст,
/// поэтому любой кросс-доменный запрос из браузера отклоняется CORS'ом (preflight
/// `OPTIONS` получает отказ, у простых запросов нет `Access-Control-Allow-Origin`).
/// Запросы без заголовка `Origin` (internal app-to-app, `curl`) проходят как
/// обычно. Вешается на все ручки, кроме `POST /tokens/verify` — единственной
/// публичной ручки под «разрешающим» CORS. `Cors` не `Clone`, поэтому строим
/// свежий экземпляр на каждый `.wrap`.
fn deny_cors() -> Cors {
    Cors::default()
}

/// Регистрирует все ручки API с их уровнями доступа, CORS и rate-limit.
///
/// Вынесено из фабрики приложения не ради красоты: привязка ручки к уровню
/// доступа — это то, что раньше проверялось только чтением кода глазами, и
/// именно так в сервис однажды попал `POST /tokens/refresh` на уровне 2 вместо 3
/// (JWT-28). Теперь ту же функцию вызывает тест и проверяет уровни на живом
/// приложении.
///
/// Обобщена по хранилищу, чтобы тест подставлял in-memory-мок вместо Redis.
///
/// **ВАЖНО о CORS.** «Разрешающий» CORS навешивается ТОЧЕЧНО только на
/// `/tokens/verify` — это ЕДИНСТВЕННАЯ публичная ручка, которую имеет смысл
/// дёргать из браузера. На все остальные вешается `deny_cors()`: он не отключён,
/// а запрещает кросс-доменные запросы. При добавлении новых ручек НЕ вешайте на
/// них разрешающий CORS без явного решения.
fn configure_api<S: crate::models::jwt::JtiStore + 'static>(
    cfg: &mut web::ServiceConfig,
    auth: Rc<AuthConfig>,
    verify_limiter: Option<crate::rate_limit::PerIpLimiter>,
    internal_limiter: Option<crate::rate_limit::GlobalLimiter>,
    cors_origins: &[String],
) {
    let cors = {
        let base = Cors::default()
            .allowed_methods(vec!["POST"])
            .allow_any_header()
            .max_age(3600);
        if cors_origins.is_empty() {
            base.allow_any_origin()
        } else {
            cors_origins
                .iter()
                .fold(base, |cors, origin| cors.allowed_origin(origin))
        }
    };

    cfg
        // Уровень 3 (TOTP): выпуск токенов. Глобальный cap — внутри auth
        // (последний `.wrap` — внешний), поэтому потолок расходуют только
        // запросы, прошедшие TOTP: неаутентифицированный флуд не исчерпает cap.
        .service(
            web::resource("/tokens")
                .wrap(RateLimit::global(internal_limiter.clone()))
                .wrap(Auth::<S>::new(AuthLevel::Totp, auth.clone()))
                .wrap(deny_cors())
                .route(web::post().to(create_token_impl::<S>)),
        )
        // Уровень 2 (proxy-secret): проверка токена. Регистрируется до
        // `/tokens/{jti}`, чтобы путь `/tokens/verify` не поглотился шаблоном.
        // Per-IP лимит — снаружи auth (`.wrap` ниже — внешнее), чтобы флуд
        // отсекался ещё до проверки proxy-secret. CORS — самый внешний слой:
        // preflight-запрос `OPTIONS` (без proxy-secret) должен обработаться
        // CORS'ом раньше, чем его отклонят auth или rate-limit.
        .service(
            web::resource("/tokens/verify")
                .wrap(Auth::<S>::new(AuthLevel::ProxySecret, auth.clone()))
                .wrap(RateLimit::per_ip(verify_limiter.clone()))
                .wrap(cors)
                .route(web::post().to(verify_token_impl::<S>)),
        )
        // Уровень 3 (TOTP): обмен refresh-токена. Это операция ВЫПУСКА, просто
        // с другим основанием — вместо «доверенный бэкенд попросил» действует
        // «предъявлен валидный refresh». Раз `POST /tokens` закрыт TOTP,
        // перевыпуск обязан быть там же: proxy-secret статичен и вызывающего
        // не аутентифицирует, так что на уровне 2 украденный refresh давал бы
        // вечную цепочку токенов любому, кто дотянулся через прокси.
        .service(
            web::resource("/tokens/refresh")
                .wrap(RateLimit::global(internal_limiter.clone()))
                .wrap(Auth::<S>::new(AuthLevel::Totp, auth.clone()))
                .wrap(deny_cors())
                .route(web::post().to(refresh_token_impl::<S>)),
        )
        .service(
            web::resource("/tokens/{jti}")
                .wrap(RateLimit::global(internal_limiter.clone()))
                .wrap(Auth::<S>::new(AuthLevel::Totp, auth.clone()))
                .wrap(deny_cors())
                .route(web::delete().to(revoke_token_impl::<S>)),
        )
        // Уровень 3 (TOTP): массовый отзыв токенов субъекта. Обвязка та же,
        // что у поштучного отзыва, — это операция того же класса, только
        // разрушительнее, и внешнему миру её видеть незачем.
        .service(
            web::resource("/subjects/{sub}/tokens")
                .wrap(RateLimit::global(internal_limiter.clone()))
                .wrap(Auth::<S>::new(AuthLevel::Totp, auth.clone()))
                .wrap(deny_cors())
                .route(web::delete().to(revoke_subject_tokens_impl::<S>)),
        );

    // Уровень 4 (Bearer-токен): скрейп метрик. Регистрируется до открытого
    // scope, иначе тот перехватил бы путь.
    //
    // Роут появляется ТОЛЬКО если задан `AUTH_METRICS_TOKEN`. Не задан —
    // ручку не публикуем вовсе, и путь отдаёт штатный `404` (его подхватит
    // открытый scope ниже). Отдавать `401` не стали намеренно: так наружу
    // не виден даже факт существования ручки.
    if auth.metrics_enabled() {
        cfg.service(
            web::resource("/metrics")
                .wrap(Auth::<S>::new(AuthLevel::MetricsToken, auth.clone()))
                .wrap(deny_cors())
                .route(web::get().to(metrics_handler)),
        );
    }

    // Уровень 1 (открыто): health-пробы и OpenAPI. Тот же middleware, но
    // валидатор `Open` пропускает всё. Регистрируется последним — scope с
    // пустым префиксом матчит любой путь, поэтому ресурсы токенов выше
    // имеют приоритет.
    cfg.service(
        web::scope("")
            .wrap(Auth::<S>::new(AuthLevel::Open, auth.clone()))
            .wrap(deny_cors())
            .route("/api-docs/openapi.json", web::get().to(openapi_spec))
            .service(livez)
            .service(readyz),
    );
}

/// Отдаёт OpenAPI-спецификацию в формате JSON.
///
/// Обслуживает `GET /api-docs/openapi.json`; используется внешним Swagger UI
/// (см. `deployments/dev/docker-compose.yml`).
pub async fn openapi_spec() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(ApiDoc::openapi().to_json().unwrap())
}

/// Инициализирует и запускает HTTP-сервер.
///
/// Порядок действий:
/// 1. Читает алгоритм подписи из `TOKEN_ALGORITHM` (по умолчанию `RS256`).
/// 2. Настраивает `tracing`-логирование (формат из `LOG_FORMAT`, фильтр из
///    `RUST_LOG`; см. [`logging::init_subscriber`]).
/// 3. Читает `HOST`/`PORT` для привязки.
/// 4. Создаёт Redis-клиент и менеджер ключей (падает с паникой, если Redis
///    недоступен на старте).
/// 5. Поднимает `HttpServer`: на публичную ручку `/tokens/verify` навешивает
///    разрешающий CORS, на остальные — запрещающий (`deny_cors`), и регистрирует
///    маршруты, включая выдачу OpenAPI. Число воркеров и таймауты соединений
///    берутся из [`ServerConfig`], а не из дефолтов actix (см. `server.rs`).
///
/// # Panics
///
/// Паникует, если `PORT` не парсится в `u16`, если не удалось подключиться к
/// Redis, установить глобальный subscriber `tracing` или если не заданы
/// обязательные секреты уровней доступа (`AUTH_PROXY_SECRET`/`AUTH_TOTP_SECRET`,
/// см. [`AuthConfig::from_env`]).
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let algorithm = env::var("TOKEN_ALGORITHM").unwrap_or("RS256".into());

    // Логирование и трейсинг: формат (`LOG_FORMAT`), уровни (`RUST_LOG`) и
    // опциональный OTLP-экспорт (`OTEL_EXPORTER_OTLP_ENDPOINT`). Провайдер держим
    // живым до конца работы и завершаем после остановки сервера — иначе последние
    // span'ы не досылаются.
    let telemetry = init_subscriber();

    // Prometheus-recorder ставится один раз на процесс; handle рендерит текст
    // экспозиции в обработчике `/metrics` (см. `metrics.rs`).
    let metrics_handle = crate::metrics::init_recorder();

    let host = env::var("HOST").unwrap_or("127.0.0.1".into());
    let port = env::var("PORT")
        .unwrap_or("8080".into())
        .parse::<u16>()
        .unwrap();

    // Здесь только разбор `REDIS_URL`: само соединение открывается при первой
    // команде и дальше переиспользуется (см. `RedisClient::connection`).
    // Недоступный на старте Redis не роняет процесс — об этом сообщает `/readyz`.
    let redis_client = RedisClient::new().expect("Invalid REDIS_URL");
    let key_manager = KeyManager::new(algorithm);

    // Конфигурация уровней доступа собирается один раз. Секреты уровней 2 и 3
    // обязательны: без них сервис не стартует (fail-fast). Копия оборачивается в
    // `Rc` внутри фабрики приложения на каждый worker-поток.
    let auth_config =
        AuthConfig::from_env().unwrap_or_else(|e| panic!("Некорректная конфигурация доступа: {e}"));

    // Уровень 4 опционален (в отличие от 2 и 3): без токена метрики просто не
    // публикуются. Предупреждаем, чтобы это не выглядело как «метрики сломались».
    if !auth_config.metrics_enabled() {
        tracing::warn!(
            "AUTH_METRICS_TOKEN не задан: уровень 4 недоступен, ручка GET /metrics \
             не опубликована (ответ 404). Задайте токен, чтобы включить скрейп метрик."
        );
    }

    // Конфигурация rate limiting. В отличие от auth, ошибки не фатальны —
    // деградируем к безопасным дефолтам с предупреждением (см. `rate_limit.rs`).
    // Лимитеры строятся один раз и общие на все worker-потоки (внутри `Arc`).
    let rate_limit_config = RateLimitConfig::from_env();
    rate_limit_config.log_summary();
    let verify_limiter = rate_limit_config.build_verify();
    let internal_limiter = rate_limit_config.build_internal();
    // Фоновая чистка устаревших per-IP записей — один поток на процесс.
    if let Some(limiter) = &verify_limiter {
        limiter.spawn_cleanup();
    }

    // Аллоулист issuer'ов: пусто/не задано → любой `Host` (текущее поведение),
    // задано → выпуск и проверка только для перечисленных значений.
    crate::issuer::log_summary();

    // Список origin'ов для CORS. Пусто/не задано → `allow_any_origin` (текущее
    // поведение, чтобы не ломать деплои); задано → только перечисленные origin'ы.
    let cors_origins: Vec<String> = env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Число воркеров и таймауты соединений: на дефолтах actix воркеров было бы
    // по числу ядер ХОСТА (см. `server.rs`), а медленный клиент мог удерживать
    // воркер сколь угодно долго.
    let server_config = ServerConfig::from_env();
    server_config.log_summary();

    info!("Starting server on {}:{}", host, port);

    HttpServer::new(move || {
        App::new()
            // Per-request логирование — самый внешний слой: span с `request_id`
            // покрывает auth/rate-limit/CORS и обработчик (см. `logging.rs`).
            .wrap(RequestLog)
            .app_data(web::Data::new(redis_client.clone()))
            .app_data(web::Data::new(key_manager.clone()))
            .app_data(web::Data::new(metrics_handle.clone()))
            .configure(|cfg| {
                configure_api::<RedisClient>(
                    cfg,
                    Rc::new(auth_config.clone()),
                    verify_limiter.clone(),
                    internal_limiter.clone(),
                    &cors_origins,
                )
            })
    })
    .workers(server_config.workers)
    .client_request_timeout(server_config.client_request_timeout)
    .keep_alive(server_config.keep_alive)
    .bind((host, port))?
    .run()
    .await?;

    // Сервер остановлен — досылаем накопленные span'ы (если трейсинг включён).
    // Guard GlitchTip досылает свои события сам при уничтожении `telemetry`.
    if let Some(provider) = telemetry.tracer_provider {
        crate::tracing_otel::shutdown(provider);
    }
    if let Some(provider) = telemetry.logger_provider {
        crate::tracing_otel::shutdown_logs(provider);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Тесты привязки ручек к уровням доступа.
    //!
    //! Проверяется не «закрыта ли ручка вообще», а **каким именно уровнем** она
    //! закрыта. Разница принципиальна: тест «без кредов → 401» проходит и для
    //! уровня 2, и для уровня 3, поэтому в JWT-28 обмен refresh-токена доехал до
    //! ревью на уровне 2 при полностью зелёном прогоне.
    //!
    //! Приём: на internal-ручки (уровень 3) шлём запрос с **валидным
    //! proxy-secret, но без TOTP**. Если ручка стоит на уровне 2, такой запрос
    //! пройдёт auth — и тест упадёт.

    // Обоснование то же, что и в `handlers.rs`: `env_guard` намеренно держит
    // std-`MutexGuard` через `.await`. `#[actix_web::test]` запускает каждый тест
    // на отдельном однопоточном рантайме, задача с потока не мигрирует и одна на
    // рантайм — лок сериализует тесты по общим переменным окружения без риска
    // дедлока. Async-Mutex здесь избыточен.
    #![allow(clippy::await_holding_lock)]

    use super::*;
    use actix_web::http::StatusCode;
    use actix_web::test;
    use parking_lot::Mutex as PlMutex;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use crate::models::jwt::{JtiError, JtiStore, RefreshRecord};

    const PROXY_SECRET: &str = "test-proxy-secret";
    const TOTP_SECRET: &str = "MRSWGYLSMUQGO33WNFXGO4ZAOBWGKYLSFVRW63LOMNXW2ZI";

    /// Глобальная блокировка окружения: `AuthConfig::from_env` читает переменные
    /// процесса, а тесты бегут параллельно.
    ///
    /// Guard берётся через функцию, как в `handlers.rs`: так он не «виден»
    /// clippy как удерживаемый через `await`, и заодно снимается отравление
    /// мьютекса паникой одного теста.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Хранилище-заглушка: до обработчиков в этих тестах дело не доходит, всё
    /// решает auth-слой.
    #[derive(Default)]
    struct StubStore {
        jtis: PlMutex<HashSet<String>>,
        groups: PlMutex<HashMap<String, HashSet<String>>>,
    }

    impl JtiStore for StubStore {
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

        async fn add_to_group(
            &self,
            group: &str,
            jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            self.groups
                .lock()
                .entry(group.to_string())
                .or_default()
                .insert(jti.to_string());
            Ok(())
        }

        async fn revoke_group(&self, group: &str) -> Result<u64, JtiError> {
            Ok(self.groups.lock().remove(group).unwrap_or_default().len() as u64)
        }

        async fn store_refresh(
            &self,
            _id: &str,
            _record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            Ok(())
        }

        async fn get_refresh(&self, _id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Ok(None)
        }

        async fn mark_refresh_used(&self, _id: &str) -> Result<bool, JtiError> {
            Ok(false)
        }

        async fn claim_totp_code(&self, _hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            Ok(true)
        }
    }

    /// Готовит окружение и собирает конфигурацию доступа.
    fn auth_config(with_metrics_token: bool) -> Rc<AuthConfig> {
        env::set_var("AUTH_PROXY_SECRET", PROXY_SECRET);
        env::set_var("AUTH_TOTP_SECRET", TOTP_SECRET);
        env::remove_var("AUTH_PROXY_SECRET_HEADER");
        env::remove_var("AUTH_TOTP_HEADER");

        if with_metrics_token {
            env::set_var("AUTH_METRICS_TOKEN", "test-metrics-token");
        } else {
            env::remove_var("AUTH_METRICS_TOKEN");
        }

        Rc::new(AuthConfig::from_env().expect("конфигурация доступа собирается"))
    }

    /// Собирает приложение с теми же роутами, что и прод, поверх заглушки.
    macro_rules! api_app {
        ($auth:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new(StubStore::default()))
                    .app_data(web::Data::new(KeyManager::new("RS256".to_string())))
                    // Лимитеры выключены: здесь проверяется auth, а не 429.
                    .configure(|cfg| configure_api::<StubStore>(cfg, $auth, None, None, &[])),
            )
        };
    }

    /// Ручки уровня 3 и способ их дёрнуть.
    fn internal_endpoints() -> Vec<(&'static str, &'static str)> {
        vec![
            ("POST", "/tokens"),
            ("POST", "/tokens/refresh"),
            ("DELETE", "/tokens/some-jti"),
            ("DELETE", "/subjects/user1/tokens"),
        ]
    }

    #[actix_web::test]
    async fn internal_endpoints_require_totp_not_proxy_secret() {
        let _guard = env_guard();
        let auth = auth_config(false);
        let app = api_app!(auth).await;

        for (method, path) in internal_endpoints() {
            // Валидный proxy-secret, но без TOTP: для уровня 3 этого мало.
            let req = match method {
                "POST" => test::TestRequest::post(),
                _ => test::TestRequest::delete(),
            }
            .uri(path)
            .insert_header(("X-Proxy-Secret", PROXY_SECRET))
            .insert_header(("Host", "example.com"))
            .set_json(serde_json::json!({}))
            .to_request();

            let resp = test::call_service(&app, req).await;

            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path} обязан требовать TOTP (уровень 3), а не proxy-secret"
            );
        }
    }

    #[actix_web::test]
    async fn internal_endpoints_reject_requests_without_credentials() {
        let _guard = env_guard();
        let auth = auth_config(false);
        let app = api_app!(auth).await;

        for (method, path) in internal_endpoints() {
            let req = match method {
                "POST" => test::TestRequest::post(),
                _ => test::TestRequest::delete(),
            }
            .uri(path)
            .insert_header(("Host", "example.com"))
            .set_json(serde_json::json!({}))
            .to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {path}");
        }
    }

    #[actix_web::test]
    async fn verify_accepts_proxy_secret() {
        let _guard = env_guard();
        let auth = auth_config(false);
        let app = api_app!(auth).await;

        // Тело намеренно неполное: пройдя auth, запрос упрётся в разбор JSON и
        // получит 400. Отличить это от 401 важно — валидный по форме, но
        // невалидный по сути токен обработчик тоже отвергает с 401, и такой
        // ответ был бы неотличим от отказа auth.
        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("X-Proxy-Secret", PROXY_SECRET))
            .insert_header(("Host", "example.com"))
            .set_json(serde_json::json!({}))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "/tokens/verify должен принимать proxy-secret (уровень 2) и падать уже на разборе тела"
        );
    }

    #[actix_web::test]
    async fn verify_rejects_request_without_proxy_secret() {
        let _guard = env_guard();
        let auth = auth_config(false);
        let app = api_app!(auth).await;

        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(serde_json::json!({ "token": "not-a-jwt", "audience": "api1" }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn open_endpoints_need_no_credentials() {
        let _guard = env_guard();
        let auth = auth_config(false);
        let app = api_app!(auth).await;

        for path in ["/livez", "/api-docs/openapi.json"] {
            let req = test::TestRequest::get().uri(path).to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{path} — уровень 1");
        }
    }

    #[actix_web::test]
    async fn metrics_route_is_absent_without_token() {
        let _guard = env_guard();
        let auth = auth_config(false);
        let app = api_app!(auth).await;

        // Без `AUTH_METRICS_TOKEN` ручка не публикуется вовсе: 404, а не 401 —
        // так наружу не виден даже факт её существования.
        let req = test::TestRequest::get().uri("/metrics").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn metrics_requires_bearer_token() {
        let _guard = env_guard();
        let auth = auth_config(true);
        let app = api_app!(auth).await;

        // Опубликована, но закрыта уровнем 4: proxy-secret и TOTP тут не подходят.
        let req = test::TestRequest::get()
            .uri("/metrics")
            .insert_header(("X-Proxy-Secret", PROXY_SECRET))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
