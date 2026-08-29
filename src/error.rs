//! The shared error type of the HTTP layer.
//!
//! [`Error`] aggregates the errors of the layers below (JWT, the `jti` store,
//! the HTTP client) and implements [`ResponseError`], mapping each variant to an
//! HTTP status. The response body is always structured ([`ErrorResponse`]).
//! Internal causes (the store, reqwest, JWT) are never exposed — the client gets
//! a generic "Internal server error".
//!
//! The module **knows nothing** about the concrete storage backend: what arrives
//! here is a [`JtiError`] from the [`JtiStore`](crate::models::jwt::JtiStore)
//! trait, not a `redis::RedisError`. Otherwise swapping the backend would drag
//! the HTTP layer along.

use actix_web::{HttpResponse, ResponseError};
use reqwest::Error as ReqwestError;
use thiserror::Error;

use crate::models::jwt::{JtiError, JwtError};
use crate::models::ErrorResponse;

/// An application-level error convertible into an HTTP response.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Unprocessable entity: {0}")]
    Unprocessable(String),
    #[error("JWT error: {0}")]
    Jwt(#[from] JwtError),
    #[error("Store error: {0}")]
    Store(#[from] JtiError),
    #[error("HTTP error: {0}")]
    Reqwest(#[from] ReqwestError),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    // No handler returns 404 yet, but the variant completes the mapping of
    // errors to statuses (400/401/404/422) and is covered by the
    // `error_response` test.
    #[allow(dead_code)]
    #[error("Not Found: {0}")]
    NotFound(String),
}

impl ResponseError for Error {
    /// Maps an error variant to an HTTP response with a structured body
    /// ([`ErrorResponse`]).
    ///
    /// `Validation` → 400, `Unprocessable` → 422, `Unauthorized` → 401,
    /// `Forbidden` → 403, `NotFound` → 404. The remaining variants (`Jwt`,
    /// `Store`, `Reqwest`, `Internal`) are treated as internal and return 500
    /// with a generic message — no detail is exposed.
    fn error_response(&self) -> HttpResponse {
        match self {
            Error::Validation(msg) => HttpResponse::BadRequest().json(ErrorResponse::new(msg)),
            Error::Unprocessable(msg) => {
                HttpResponse::UnprocessableEntity().json(ErrorResponse::new(msg))
            }
            Error::Unauthorized(msg) => HttpResponse::Unauthorized().json(ErrorResponse::new(msg)),
            Error::Forbidden(msg) => HttpResponse::Forbidden().json(ErrorResponse::new(msg)),
            Error::NotFound(msg) => HttpResponse::NotFound().json(ErrorResponse::new(msg)),
            _ => HttpResponse::InternalServerError()
                .json(ErrorResponse::new("Internal server error")),
        }
    }
}

#[cfg(test)]
mod tests {
    //! We check the mapping of [`Error`] variants to an HTTP response: the
    //! status, the structured [`ErrorResponse`] body and the absence of any leak
    //! of internal detail into a 500.

    use super::*;
    use actix_web::body::to_bytes;
    use actix_web::http::StatusCode;

    /// Runs an error through [`ResponseError::error_response`] and parses the
    /// status and the body of the response.
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
        let (status, body) = render(Error::Unprocessable(
            "Invalid token request parameters".into(),
        ))
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.error, "Invalid token request parameters");
    }

    #[actix_web::test]
    async fn unauthorized_maps_to_401_with_message() {
        let (status, body) = render(Error::Unauthorized("Invalid or expired token".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body.error, "Invalid or expired token");
    }

    #[actix_web::test]
    async fn forbidden_maps_to_403_with_message() {
        let (status, body) = render(Error::Forbidden("Issuer not allowed".into())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body.error, "Issuer not allowed");
    }

    #[actix_web::test]
    async fn not_found_maps_to_404_with_message() {
        let (status, body) = render(Error::NotFound("Token not found".into())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body.error, "Token not found");
    }

    #[actix_web::test]
    async fn internal_maps_to_500_without_leaking_details() {
        // The internal cause must not reach the response body.
        let (status, body) = render(Error::Internal("redis://secret-dsn".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "Internal server error");
        assert!(!body.error.contains("secret"));
    }

    #[actix_web::test]
    async fn store_error_maps_to_500_generic() {
        let (status, body) = render(Error::Store(JtiError::BadConnection)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "Internal server error");
    }

    #[actix_web::test]
    async fn jwt_error_maps_to_500_generic() {
        let (status, body) = render(Error::Jwt(JwtError::BadSignature)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "Internal server error");
    }
}
