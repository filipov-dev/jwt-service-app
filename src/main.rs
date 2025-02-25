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

/// Endpoint to provide OpenAPI specification
pub async fn openapi_spec() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(ApiDoc::openapi().to_json().unwrap())
}

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