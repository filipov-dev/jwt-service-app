use std::env;
use actix_web::{web, HttpResponse, post, delete};
use chrono::Utc;
use tracing::error;
use utoipa::path;

use crate::jwt::JwtManager;
use crate::key::KeyManager;
use crate::redis::RedisClient;
use crate::error::*;
use crate::models::{ErrorResponse, TokenRequest, TokenResponse, TokenVerifyRequest};
use crate::models::jwt::{JtiStore, JwtError};

#[utoipa::path(
    post,
    path = "/tokens",
    request_body = TokenRequest,
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, body = ErrorResponse)
    )
)]
#[post("/tokens")]
pub async fn create_token(
    req: web::Json<TokenRequest>,
    redis: web::Data<RedisClient>,
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
        &keys,
        redis,
    ).await {
        Ok(token) => {
            Ok(HttpResponse::Ok().json(TokenResponse { token }))
        }
        Err(e) => {
            error!("Error: {}", e);

            match e {
                JwtError::UnprocessableEntity => {
                    Ok(HttpResponse::UnprocessableEntity().finish())
                }
                _ => {
                    Ok(HttpResponse::InternalServerError().finish())
                }
            }
        }
    }
}

#[utoipa::path(
    post,
    path = "/tokens/verify",
    request_body = TokenVerifyRequest,
    responses(
        (status = 200),
        (status = 401, body = ErrorResponse)
    )
)]
#[post("/tokens/verify")]
pub async fn verify_token(
    request: web::Json<TokenVerifyRequest>,
    redis: web::Data<RedisClient>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let host_header = host.headers().get("Host")
        .ok_or(Error::Validation("Missing Host header".into()))?
        .to_str()
        .map_err(|_| Error::Validation("Invalid Host header".into()))?;

    match JwtManager::verify_token(&request.token, host_header, &request.audience, redis).await {
        Ok(v) => { Ok(HttpResponse::Ok().json(v)) }
        Err(_) => { Ok(HttpResponse::Unauthorized().finish()) }
    }
}

#[utoipa::path(
    delete,
    path = "/tokens/{jti}",
    responses(
        (status = 204),
        (status = 404, body = ErrorResponse)
    )
)]
#[delete("/tokens/{jti}")]
pub async fn revoke_token(
    jti: web::Path<String>,
    redis: web::Data<RedisClient>,
) -> Result<HttpResponse, Error> {
    match redis.delete_jti(&jti).await {
        Ok(_) => (),
        Err(e) => {
            error!("{}", e);
        }
    };

    Ok(HttpResponse::NoContent().finish())
}