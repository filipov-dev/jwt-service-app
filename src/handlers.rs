//! HTTP-обработчики публичного API.
//!
//! Модуль содержит три эндпоинта:
//! - `POST /tokens` — выпуск токена ([`create_token`]);
//! - `POST /tokens/verify` — проверка токена ([`verify_token`]);
//! - `DELETE /tokens/{jti}` — отзыв токена ([`revoke_token`]).
//!
//! Обработчики намеренно тонкие: вся доменная логика вынесена в
//! [`crate::jwt::JwtManager`] и модели. Значение claim `iss` (issuer) берётся
//! из HTTP-заголовка `Host` входящего запроса, а не из конфигурации.

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
        (status = 400, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
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
        redis,
    ).await {
        Ok(token) => {
            Ok(HttpResponse::Ok().json(TokenResponse { token }))
        }
        Err(e) => {
            error!("Не удалось выпустить токен: {}", e);

            // Внутреннюю причину не раскрываем: `UnprocessableEntity` → 422 с
            // осмысленным сообщением, всё остальное → 500 с обобщённым текстом.
            match e {
                JwtError::UnprocessableEntity => Err(Error::Unprocessable(
                    "Invalid token request parameters".into(),
                )),
                _ => Err(Error::Internal(e.to_string())),
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
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse)
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
    let host_header = host.headers().get("Host")
        .ok_or(Error::Validation("Missing Host header".into()))?
        .to_str()
        .map_err(|_| Error::Validation("Invalid Host header".into()))?;

    match JwtManager::verify_token(&request.token, host_header, &request.audience, redis).await {
        Ok(v) => Ok(HttpResponse::Ok().json(v)),
        Err(e) => {
            // Детали проверки наружу намеренно не раскрываем, чтобы не давать
            // подсказок атакующему — единый ответ на любую причину.
            error!("Проверка токена не удалась: {}", e);
            Err(Error::Unauthorized("Invalid or expired token".into()))
        }
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
    match redis.delete_jti(&jti).await {
        Ok(_) => (),
        Err(e) => {
            error!("{}", e);
        }
    };

    Ok(HttpResponse::NoContent().finish())
}