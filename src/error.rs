//! Общий тип ошибки HTTP-слоя.
//!
//! [`Error`] агрегирует ошибки нижележащих слоёв (JWT, Redis, HTTP-клиент) и
//! реализует [`ResponseError`], сопоставляя каждый вариант с HTTP-статусом.
//! Тело ответа всегда структурировано ([`ErrorResponse`]). Внутренние причины
//! (Redis/reqwest/JWT) наружу не раскрываются — клиент получает обобщённое
//! «Internal server error».

use actix_web::{HttpResponse, ResponseError};
use redis::RedisError;
use reqwest::Error as ReqwestError;
use thiserror::Error;

use crate::models::ErrorResponse;
use crate::models::jwt::JwtError;

/// Ошибка уровня приложения, преобразуемая в HTTP-ответ.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Unprocessable entity: {0}")]
    Unprocessable(String),
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
    /// Отображает вариант ошибки в HTTP-ответ со структурированным телом
    /// [`ErrorResponse`].
    ///
    /// `Validation` → 400, `Unprocessable` → 422, `Unauthorized` → 401,
    /// `NotFound` → 404. Остальные варианты (`Jwt`, `Redis`, `Reqwest`,
    /// `Internal`) считаются внутренними и возвращают 500 с обобщённым
    /// сообщением — детали наружу не раскрываются.
    fn error_response(&self) -> HttpResponse {
        match self {
            Error::Validation(msg) => HttpResponse::BadRequest().json(ErrorResponse::new(msg)),
            Error::Unprocessable(msg) => {
                HttpResponse::UnprocessableEntity().json(ErrorResponse::new(msg))
            }
            Error::Unauthorized(msg) => HttpResponse::Unauthorized().json(ErrorResponse::new(msg)),
            Error::NotFound(msg) => HttpResponse::NotFound().json(ErrorResponse::new(msg)),
            _ => HttpResponse::InternalServerError()
                .json(ErrorResponse::new("Internal server error")),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Проверяем маппинг вариантов [`Error`] в HTTP-ответ: статус,
    //! структурированное тело [`ErrorResponse`] и отсутствие утечки внутренних
    //! деталей в 500.

    use super::*;
    use actix_web::body::to_bytes;
    use actix_web::http::StatusCode;

    /// Прогоняет ошибку через [`ResponseError::error_response`] и разбирает
    /// статус и тело ответа.
    async fn render(err: Error) -> (StatusCode, ErrorResponse) {
        let resp = err.error_response();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body()).await.unwrap();
        let body: ErrorResponse = serde_json::from_slice(&bytes).unwrap();
        (status, body)
    }

    #[actix_web::test]
    async fn validation_maps_to_400_with_message() {
        let (status, body) = render(Error::Validation("Missing Host header".into())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.error, "Missing Host header");
        assert!(body.details.is_none());
    }

    #[actix_web::test]
    async fn unprocessable_maps_to_422_with_message() {
        let (status, body) = render(Error::Unprocessable("Invalid token request parameters".into()))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.error, "Invalid token request parameters");
    }

    #[actix_web::test]
    async fn unauthorized_maps_to_401_with_message() {
        let (status, body) =
            render(Error::Unauthorized("Invalid or expired token".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body.error, "Invalid or expired token");
    }

    #[actix_web::test]
    async fn not_found_maps_to_404_with_message() {
        let (status, body) = render(Error::NotFound("Token not found".into())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body.error, "Token not found");
    }

    #[actix_web::test]
    async fn internal_maps_to_500_without_leaking_details() {
        // Внутренняя причина не должна попасть в тело ответа.
        let (status, body) = render(Error::Internal("redis://secret-dsn".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "Internal server error");
        assert!(!body.error.contains("secret"));
    }

    #[actix_web::test]
    async fn jwt_error_maps_to_500_generic() {
        let (status, body) = render(Error::Jwt(JwtError::BadSignature)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "Internal server error");
    }
}
