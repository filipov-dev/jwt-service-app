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

    /// Выдать вместе с токеном refresh-токен для продления сессии.
    ///
    /// По умолчанию `false` — контракт существующих клиентов не меняется, а
    /// refresh появляется только у тех, кто его осознанно попросил.
    #[schema(example = false)]
    #[serde(default)]
    pub refresh: bool,
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

    /// Refresh-токен, если он запрашивался.
    ///
    /// Непрозрачная строка, а не JWT: разбирать её клиенту незачем, она лишь
    /// предъявляется в `POST /tokens/refresh`. Отсутствует в ответе, когда
    /// refresh не запрашивали.
    #[schema(nullable = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Тело запроса на обмен refresh-токена (`POST /tokens/refresh`).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RefreshRequest {
    /// Refresh-токен, полученный при выпуске или предыдущем обмене.
    pub refresh_token: String,
}

/// Результат массового отзыва токенов субъекта.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RevokeGroupResponse {
    /// Сколько активных токенов было отозвано.
    ///
    /// Уже истёкшие в счёт не идут: они и так невалидны, отзывать их незачем.
    #[schema(example = 3)]
    pub revoked: u64,
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
// `Clone` нужен кешу JWKS: ключ отдаётся наружу копией, чтобы не держать
// блокировку кеша на время сборки `PKey` (см. `jwk.rs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    /// Список доступных публичных ключей.
    pub keys: Vec<Jwk>,
}

#[cfg(test)]
mod tests {
    //! Тесты сериализации DTO.
    //!
    //! Проверяется то, что видит клиент: форма JSON и поведение дефолтов.
    //! Обе вещи — часть публичного контракта, а не деталь реализации.

    use super::*;
    use serde_json::json;

    #[test]
    fn token_response_omits_refresh_when_absent() {
        let response = TokenResponse {
            token: "header.payload.signature".to_string(),
            refresh_token: None,
        };

        let value = serde_json::to_value(&response).unwrap();

        // Ключа быть не должно вовсе — не `null`. Иначе прежние клиенты увидели
        // бы в ответе новое поле, которого не ждали (см. `skip_serializing_if`).
        assert_eq!(value, json!({ "token": "header.payload.signature" }));
        assert!(!value.as_object().unwrap().contains_key("refresh_token"));
    }

    #[test]
    fn token_response_includes_refresh_when_present() {
        let response = TokenResponse {
            token: "header.payload.signature".to_string(),
            refresh_token: Some("refresh-id".to_string()),
        };

        let value = serde_json::to_value(&response).unwrap();

        assert_eq!(value["refresh_token"], "refresh-id");
    }

    #[test]
    fn token_request_defaults_are_optional() {
        // Минимальное тело: ни `ttl`, ни `refresh` клиент присылать не обязан.
        let request: TokenRequest =
            serde_json::from_value(json!({ "sub": "user1", "aud": ["api1"] })).unwrap();

        assert_eq!(request.sub, "user1");
        assert_eq!(request.aud, vec!["api1".to_string()]);
        assert!(request.ttl.is_none());
        assert!(!request.refresh, "refresh по умолчанию выключен");
    }

    #[test]
    fn token_request_reads_explicit_values() {
        let request: TokenRequest = serde_json::from_value(
            json!({ "sub": "user1", "aud": ["api1"], "ttl": 60, "refresh": true }),
        )
        .unwrap();

        assert_eq!(request.ttl, Some(60));
        assert!(request.refresh);
    }

    #[test]
    fn jwk_keeps_unset_components_as_none() {
        // OKP-ключ (EdDSA): заполнены `crv`/`x`, компоненты RSA отсутствуют.
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "OKP", "alg": "EdDSA", "kid": "kid-1",
            "crv": "Ed25519", "x": "AAAA",
        }))
        .unwrap();

        assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
        assert!(jwk.n.is_none());
        assert!(jwk.e.is_none());
        assert!(jwk.y.is_none());
    }

    #[test]
    fn jwks_parses_empty_key_list() {
        // Пустой список — штатный ответ сервиса ключей до выпуска первого ключа.
        let jwks: Jwks = serde_json::from_value(json!({ "keys": [] })).unwrap();
        assert!(jwks.keys.is_empty());
    }

    #[test]
    fn error_response_has_no_details_by_default() {
        let error = ErrorResponse::new("Invalid token");

        assert_eq!(error.error, "Invalid token");
        assert!(error.details.is_none());
    }
}
