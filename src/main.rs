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
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use utoipa::{Modify, OpenApi};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};

mod auth;
mod error;
mod handlers;
mod key;
mod redis;
mod models;
mod jwk;
mod jwt;

use crate::auth::{Auth, AuthConfig, AuthLevel};
use crate::handlers::{
    create_token_impl, verify_token_impl, revoke_token_impl, livez, readyz,
};
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
        handlers::readyz
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
        }
    }
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
/// 2. Настраивает `tracing`-логирование (pretty, с фильтром из окружения).
/// 3. Читает `HOST`/`PORT` для привязки.
/// 4. Создаёт Redis-клиент и менеджер ключей (падает с паникой, если Redis
///    недоступен на старте).
/// 5. Поднимает `HttpServer` с CORS (открыт для всех источников) и регистрирует
///    маршруты, включая выдачу OpenAPI.
///
/// # Panics
///
/// Паникует, если `PORT` не парсится в `u16`, если не удалось подключиться к
/// Redis или установить глобальный subscriber `tracing`.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let algorithm = env::var("TOKEN_ALGORITHM")
        .unwrap_or("RS256".into());

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("jwt_service_app=info".parse().unwrap()))
        .with_ansi(true)
        .pretty()
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    let host = env::var("HOST")
        .unwrap_or("127.0.0.1".into());
    let port = env::var("PORT")
        .unwrap_or("8080".into())
        .parse::<u16>().unwrap();

    let redis_client = RedisClient::new()
        .expect("Failed to connect to Redis");
    let key_manager = KeyManager::new(algorithm);

    // Конфигурация уровней доступа собирается один раз (здесь же логируются
    // предупреждения об отсутствующих секретах); копия оборачивается в `Rc`
    // внутри фабрики приложения на каждый worker-поток.
    let auth_config = AuthConfig::from_env();

    info!("Starting server on {}:{}", host, port);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "POST", "DELETE"])
            .allow_any_header()
            .max_age(3600);

        let auth = Rc::new(auth_config.clone());

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(redis_client.clone()))
            .app_data(web::Data::new(key_manager.clone()))
            // Уровень 3 (TOTP): выпуск и отзыв токенов.
            .service(
                web::resource("/tokens")
                    .wrap(Auth::new(AuthLevel::Totp, auth.clone()))
                    .route(web::post().to(create_token_impl::<RedisClient>)),
            )
            // Уровень 2 (proxy-secret): проверка токена. Регистрируется до
            // `/tokens/{jti}`, чтобы путь `/tokens/verify` не поглотился шаблоном.
            .service(
                web::resource("/tokens/verify")
                    .wrap(Auth::new(AuthLevel::ProxySecret, auth.clone()))
                    .route(web::post().to(verify_token_impl::<RedisClient>)),
            )
            .service(
                web::resource("/tokens/{jti}")
                    .wrap(Auth::new(AuthLevel::Totp, auth.clone()))
                    .route(web::delete().to(revoke_token_impl::<RedisClient>)),
            )
            // Уровень 1 (открыто): health-пробы и OpenAPI. Тот же middleware, но
            // валидатор `Open` пропускает всё. Регистрируется последним — scope с
            // пустым префиксом матчит любой путь, поэтому ресурсы токенов выше
            // имеют приоритет.
            .service(
                web::scope("")
                    .wrap(Auth::new(AuthLevel::Open, auth.clone()))
                    .route("/api-docs/openapi.json", web::get().to(openapi_spec))
                    .service(livez)
                    .service(readyz),
            )
    })
        .bind((host, port))?
        .run()
        .await
}