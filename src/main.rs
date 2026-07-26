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

use std::env;
use std::rc::Rc;
use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use tracing::info;
use utoipa::{Modify, OpenApi};
use utoipa::openapi::security::{
    ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme,
};

mod auth;
mod error;
mod handlers;
mod key;
mod logging;
mod metrics;
mod rate_limit;
mod sentry_glitchtip;
mod tracing_otel;
mod redis;
mod models;
mod jwk;
mod jwt;

use crate::auth::{Auth, AuthConfig, AuthLevel};
use crate::logging::{init_subscriber, RequestLog};
use crate::rate_limit::{RateLimit, RateLimitConfig};
use crate::handlers::{
    create_token_impl, verify_token_impl, revoke_token_impl, livez, readyz,
};
use crate::handlers::metrics as metrics_handler;
use crate::key::KeyManager;
use crate::redis::RedisClient;
use crate::models::{ErrorResponse, ReadinessResponse, TokenResponse, TokenRequest};

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
        handlers::revoke_token,
        handlers::livez,
        handlers::readyz,
        handlers::metrics
    ),
    components(schemas(
        TokenRequest,
        TokenResponse,
        ErrorResponse,
        ReadinessResponse
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
///    маршруты, включая выдачу OpenAPI.
///
/// # Panics
///
/// Паникует, если `PORT` не парсится в `u16`, если не удалось подключиться к
/// Redis, установить глобальный subscriber `tracing` или если не заданы
/// обязательные секреты уровней доступа (`AUTH_PROXY_SECRET`/`AUTH_TOTP_SECRET`,
/// см. [`AuthConfig::from_env`]).
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let algorithm = env::var("TOKEN_ALGORITHM")
        .unwrap_or("RS256".into());

    // Логирование и трейсинг: формат (`LOG_FORMAT`), уровни (`RUST_LOG`) и
    // опциональный OTLP-экспорт (`OTEL_EXPORTER_OTLP_ENDPOINT`). Провайдер держим
    // живым до конца работы и завершаем после остановки сервера — иначе последние
    // span'ы не досылаются.
    let telemetry = init_subscriber();

    // Prometheus-recorder ставится один раз на процесс; handle рендерит текст
    // экспозиции в обработчике `/metrics` (см. `metrics.rs`).
    let metrics_handle = crate::metrics::init_recorder();

    let host = env::var("HOST")
        .unwrap_or("127.0.0.1".into());
    let port = env::var("PORT")
        .unwrap_or("8080".into())
        .parse::<u16>().unwrap();

    let redis_client = RedisClient::new()
        .expect("Failed to connect to Redis");
    let key_manager = KeyManager::new(algorithm);

    // Конфигурация уровней доступа собирается один раз. Секреты уровней 2 и 3
    // обязательны: без них сервис не стартует (fail-fast). Копия оборачивается в
    // `Rc` внутри фабрики приложения на каждый worker-поток.
    let auth_config = AuthConfig::from_env()
        .unwrap_or_else(|e| panic!("Некорректная конфигурация доступа: {e}"));

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

    // Список origin'ов для CORS. Пусто/не задано → `allow_any_origin` (текущее
    // поведение, чтобы не ломать деплои); задано → только перечисленные origin'ы.
    let cors_origins: Vec<String> = env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    info!("Starting server on {}:{}", host, port);

    HttpServer::new(move || {
        // ВАЖНО: «разрешающий» CORS навешивается ТОЧЕЧНО только на `/tokens/verify`
        // (см. ниже) — это ЕДИНСТВЕННАЯ публичная ручка, которую имеет смысл дёргать
        // из браузера. На все остальные ручки (health, OpenAPI, выпуск/отзыв токенов)
        // вешается `deny_cors()` — он не отключён, а запрещает кросс-доменные запросы
        // из браузера. При добавлении новых ручек НЕ вешайте на них разрешающий CORS
        // без явного решения: под ним должна оставаться ровно одна публичная ручка.
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

        let auth = Rc::new(auth_config.clone());

        App::new()
            // Per-request логирование — самый внешний слой: span с `request_id`
            // покрывает auth/rate-limit/CORS и обработчик (см. `logging.rs`).
            .wrap(RequestLog)
            .app_data(web::Data::new(redis_client.clone()))
            .app_data(web::Data::new(key_manager.clone()))
            .app_data(web::Data::new(metrics_handle.clone()))
            // Уровень 3 (TOTP): выпуск и отзыв токенов. Глобальный cap — внутри auth
            // (последний `.wrap` — внешний), поэтому потолок расходуют только
            // запросы, прошедшие TOTP: неаутентифицированный флуд не исчерпает cap.
            .service(
                web::resource("/tokens")
                    .wrap(RateLimit::global(internal_limiter.clone()))
                    .wrap(Auth::new(AuthLevel::Totp, auth.clone()))
                    .wrap(deny_cors())
                    .route(web::post().to(create_token_impl::<RedisClient>)),
            )
            // Уровень 2 (proxy-secret): проверка токена. Регистрируется до
            // `/tokens/{jti}`, чтобы путь `/tokens/verify` не поглотился шаблоном.
            // Per-IP лимит — снаружи auth (`.wrap` ниже — внешнее), чтобы флуд
            // отсекался ещё до проверки proxy-secret. CORS — самый внешний слой:
            // preflight-запрос `OPTIONS` (без proxy-secret) должен обработаться
            // CORS'ом раньше, чем его отклонят auth или rate-limit.
            .service(
                web::resource("/tokens/verify")
                    .wrap(Auth::new(AuthLevel::ProxySecret, auth.clone()))
                    .wrap(RateLimit::per_ip(verify_limiter.clone()))
                    .wrap(cors)
                    .route(web::post().to(verify_token_impl::<RedisClient>)),
            )
            .service(
                web::resource("/tokens/{jti}")
                    .wrap(RateLimit::global(internal_limiter.clone()))
                    .wrap(Auth::new(AuthLevel::Totp, auth.clone()))
                    .wrap(deny_cors())
                    .route(web::delete().to(revoke_token_impl::<RedisClient>)),
            )
            // Уровень 4 (Bearer-токен): скрейп метрик. Регистрируется до открытого
            // scope, иначе тот перехватил бы путь.
            //
            // Роут появляется ТОЛЬКО если задан `AUTH_METRICS_TOKEN`. Не задан —
            // ручку не публикуем вовсе, и путь отдаёт штатный `404` (его подхватит
            // открытый scope ниже). Отдавать `401` не стали намеренно: так наружу
            // не виден даже факт существования ручки. `configure` нужен потому, что
            // обычная цепочка `.service()` не позволяет регистрировать условно.
            .configure(|cfg| {
                if auth.metrics_enabled() {
                    cfg.service(
                        web::resource("/metrics")
                            .wrap(Auth::new(AuthLevel::MetricsToken, auth.clone()))
                            .wrap(deny_cors())
                            .route(web::get().to(metrics_handler)),
                    );
                }
            })
            // Уровень 1 (открыто): health-пробы и OpenAPI. Тот же middleware, но
            // валидатор `Open` пропускает всё. Регистрируется последним — scope с
            // пустым префиксом матчит любой путь, поэтому ресурсы токенов выше
            // имеют приоритет.
            .service(
                web::scope("")
                    .wrap(Auth::new(AuthLevel::Open, auth.clone()))
                    .wrap(deny_cors())
                    .route("/api-docs/openapi.json", web::get().to(openapi_spec))
                    .service(livez)
                    .service(readyz),
            )
    })
        .bind((host, port))?
        .run()
        .await?;

    // Сервер остановлен — досылаем накопленные span'ы (если трейсинг включён).
    // Guard GlitchTip досылает свои события сам при уничтожении `telemetry`.
    if let Some(provider) = telemetry.tracer_provider {
        crate::tracing_otel::shutdown(provider);
    }

    Ok(())
}