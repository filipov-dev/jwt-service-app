//! Модели данных приложения.
//!
//! Здесь собраны:
//! - DTO публичного API ([`TokenRequest`], [`TokenVerifyRequest`],
//!   [`TokenResponse`], [`ErrorResponse`]) — они помечены `ToSchema` и попадают
//!   в OpenAPI;
//! - структуры представления ключей ([`Jwk`], [`Jwks`], [`JwkData`]),
//!   используемые при обмене с `jwks-service-app`.
//!
//! Внутреннее представление самого токена (claims, заголовки, подпись) вынесено
//! в подмодуль [`jwt`].

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub mod jwt;

/// Тело запроса на выпуск токена (`POST /tokens`).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenRequest {
    #[schema(example = "user123")]
    pub sub: String,

    #[schema(example = json!(["api1", "api2"]))]
    pub aud: Vec<String>,

    /// Необязательное кастомное время жизни токена в секундах.
    ///
    /// Если не задано, используется `TOKEN_EXPIRATION_SECONDS`. При наличии
    /// значение проверяется на границы `TOKEN_TTL_MIN_SECONDS` /
    /// `TOKEN_TTL_MAX_SECONDS`; выход за них — `422 Unprocessable Entity`.
    #[schema(example = 3600, nullable = true)]
    #[serde(default)]
    pub ttl: Option<u64>,
}

/// Тело запроса на проверку токена (`POST /tokens/verify`).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenVerifyRequest {
    /// Проверяемый токен целиком (`header.payload.signature`).
    #[schema(example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub token: String,

    /// Ожидаемый получатель; должен присутствовать в claim `aud` токена.
    #[schema(example = "api1")]
    pub audience: String,
}

/// Успешный ответ на выпуск токена.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenResponse {
    /// Подписанный JWT.
    #[schema(example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub token: String,
}

/// Унифицированное тело ответа об ошибке.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    /// Краткое сообщение об ошибке.
    pub error: String,
    /// Необязательные детали.
    #[schema(nullable = true)]
    pub details: Option<String>,
}

impl ErrorResponse {
    /// Создаёт тело ошибки только с сообщением, без деталей.
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            details: None,
        }
    }
}

/// Ответ readiness-проверки (`GET /readyz`).
///
/// `status` — агрегированное состояние (`"ok"`/`"unavailable"`), поля `redis` и
/// `jwks` отражают доступность соответствующей зависимости.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ReadinessResponse {
    /// Агрегированный статус: `"ok"`, если все зависимости доступны, иначе
    /// `"unavailable"`.
    #[schema(example = "ok")]
    pub status: String,
    /// Доступность Redis.
    pub redis: bool,
    /// Доступность сервиса ключей (`jwks-service-app`).
    pub jwks: bool,
}

/// Полное представление ключа, включая приватную часть.
///
/// Возвращается сервисом `jwks-service-app` при запросе/создании ключа и
/// используется для подписи токенов. **Не** отдаётся наружу клиентам API.
#[derive(Debug, Serialize, Deserialize)]
pub struct JwkData {
    /// Unique key identifier.
    pub id: String,
    /// Key type (e.g., "RSA").
    pub kty: String,
    /// Algorithm used with the key (e.g., "RS256").
    pub alg: String,
    /// Key ID.
    pub kid: String,
    /// Contain the subtype of the key (from the "JSON Web Elliptic Curve" registry).
    pub crv: Option<String>,
    /// Contain the public key encoded using the base64url [RFC4648] encoding
    pub x: Option<String>,
    pub y: Option<String>,
    /// Key modulus in Base64 format.
    pub n: Option<String>,
    /// Public exponent in Base64 format.
    pub e: Option<String>,
    /// Private key in Base64 format.
    pub private_key: String,
}

/// Публичное представление ключа (JSON Web Key), без приватной части.
///
/// Набор полей зависит от типа ключа: для RSA заполнены `n`/`e`, для EC —
/// `crv`/`x`/`y`, для OKP (EdDSA) — `crv`/`x`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (e.g., "RSA").
    pub kty: String,
    /// Algorithm used with the key (e.g., "RS256").
    pub alg: String,
    /// Key ID.
    pub kid: String,
    /// Contain the subtype of the key (from the "JSON Web Elliptic Curve" registry).
    pub crv: Option<String>,
    /// Contain the public key encoded using the base64url [RFC4648] encoding
    pub x: Option<String>,
    pub y: Option<String>,
    /// Key modulus in Base64 format.
    pub n: Option<String>,
    /// Public exponent in Base64 format.
    pub e: Option<String>,
}

/// Набор публичных ключей — ответ эндпоинта `.well-known/jwks.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    /// Список доступных публичных ключей.
    pub keys: Vec<Jwk>,
}