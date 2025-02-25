use actix_web::{HttpResponse, ResponseError};
use jsonwebtoken::errors::Error as JwtError;
use redis::RedisError;
use reqwest::Error as ReqwestError;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("JWT error: {0}")]
    Jwt(#[from] JwtError),
    #[error("Redis error: {0}")]
    Redis(#[from] RedisError),
    #[error("HTTP error: {0}")]
    Reqwest(#[from] ReqwestError),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Not Found: {0}")]
    NotFound(String),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        match self {
            Error::Validation(msg) => HttpResponse::BadRequest().json(json!({ "error": msg })),
            Error::Unauthorized(msg) => HttpResponse::Unauthorized().json(json!({ "error": msg })),
            Error::NotFound(msg) => HttpResponse::NotFound().json(json!({ "error": msg })),
            _ => HttpResponse::InternalServerError().json(json!({ "error": "Internal server error" })),
        }
    }
}