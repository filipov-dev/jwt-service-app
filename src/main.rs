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
use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use utoipa::OpenApi;

mod error;
mod handlers;
mod key;
mod redis;
mod models;
mod jwk;
mod jwt;

use crate::handlers::{create_token, verify_token, revoke_token};
use crate::key::KeyManager;
use crate::redis::RedisClient;
use crate::models::{ErrorResponse, TokenResponse, TokenRequest};

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
        handlers::revoke_token
    ),
    components(schemas(
        TokenRequest,
        TokenResponse,
        ErrorResponse
    ))
)]
struct ApiDoc;

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

    info!("Starting server on {}:{}", host, port);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "POST", "DELETE"])
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(redis_client.clone()))
            .app_data(web::Data::new(key_manager.clone()))
            .route("/api-docs/openapi.json", web::get().to(openapi_spec))
            .service(create_token)
            .service(verify_token)
            .service(revoke_token)
    })
        .bind((host, port))?
        .run()
        .await
}