//! Application data models.
//!
//! Gathered here are:
//! - the public API DTOs ([`TokenRequest`], [`TokenVerifyRequest`],
//!   [`TokenResponse`], [`ErrorResponse`]) — they carry `ToSchema` and reach the
//!   OpenAPI spec;
//! - the key representation structures ([`Jwk`], [`Jwks`], [`JwkData`]) used
//!   when talking to `jwks-service-app`.
//!
//! The internal representation of the token itself (claims, headers, signature)
//! lives in the [`jwt`] submodule.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub mod jwt;

/// Body of a token issue request (`POST /tokens`).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenRequest {
    #[schema(example = "user123")]
    pub sub: String,

    #[schema(example = json!(["api1", "api2"]))]
    pub aud: Vec<String>,

    /// Optional custom token lifetime in seconds.
    ///
    /// When unset, `TOKEN_EXPIRATION_SECONDS` is used. When present, the value
    /// is checked against the `TOKEN_TTL_MIN_SECONDS` /
    /// `TOKEN_TTL_MAX_SECONDS` bounds; going outside them gives
    /// `422 Unprocessable Entity`.
    #[schema(example = 3600, nullable = true)]
    #[serde(default)]
    pub ttl: Option<u64>,

    /// Issue a refresh token alongside the access token to renew the session.
    ///
    /// `false` by default — the contract of existing clients does not change and
    /// a refresh token only appears for those who deliberately asked for one.
    #[schema(example = false)]
    #[serde(default)]
    pub refresh: bool,

    /// Arbitrary claims that end up in the token payload alongside the
    /// registered ones (roles, scope, tenant, an internal id).
    ///
    /// The reserved names (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`)
    /// **cannot** be overridden — an attempt gives `422`. Otherwise a client
    /// could substitute `exp` and bypass the `TOKEN_TTL_MIN_SECONDS` /
    /// `TOKEN_TTL_MAX_SECONDS` bounds.
    ///
    /// The limits on the number of keys and the total size come from
    /// `TOKEN_CLAIMS_MAX_COUNT` and `TOKEN_CLAIMS_MAX_BYTES`: a token travels in
    /// headers, and a bloated payload breaks proxies.
    #[schema(example = json!({"role": "admin", "scope": ["read", "write"]}))]
    #[serde(default)]
    pub claims: serde_json::Map<String, serde_json::Value>,
}

/// Body of a token verification request (`POST /tokens/verify`).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenVerifyRequest {
    /// The whole token being verified (`header.payload.signature`).
    #[schema(example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub token: String,

    /// The expected recipient; must be present in the token's `aud` claim.
    #[schema(example = "api1")]
    pub audience: String,
}

/// A successful response to a token issue request.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenResponse {
    /// The signed JWT.
    #[schema(example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub token: String,

    /// The refresh token, when one was requested.
    ///
    /// An opaque string rather than a JWT: the client has no reason to parse it,
    /// it is only presented to `POST /tokens/refresh`. Absent from the response
    /// when no refresh token was requested.
    #[schema(nullable = true)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Body of a refresh token exchange request (`POST /tokens/refresh`).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RefreshRequest {
    /// The refresh token received on issue or on a previous exchange.
    pub refresh_token: String,
}

/// The result of a bulk revocation of a subject's tokens.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RevokeGroupResponse {
    /// How many active tokens were revoked.
    ///
    /// Already expired ones do not count: they are invalid anyway and there is
    /// nothing to revoke.
    #[schema(example = 3)]
    pub revoked: u64,
}

/// The unified body of an error response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    /// A short error message.
    pub error: String,
    /// Optional details.
    #[schema(nullable = true)]
    pub details: Option<String>,
}

impl ErrorResponse {
    /// Builds an error body with a message only, without details.
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            details: None,
        }
    }
}

/// The response of the readiness check (`GET /readyz`).
///
/// `status` is the aggregated state (`"ok"`/`"degraded"`/`"unavailable"`), and
/// the `redis` and `jwks` fields report readiness to serve requests per
/// dependency.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ReadinessResponse {
    /// The aggregated status: `"ok"` — every dependency is available,
    /// `"degraded"` — we can serve but the key service is not answering itself
    /// (a snapshot from memory), `"unavailable"` — we cannot serve.
    #[schema(example = "ok")]
    pub status: String,
    /// Redis availability.
    pub redis: bool,
    /// Readiness with respect to the key service: it answered **or** memory
    /// holds a usable JWKS snapshot that verification is served from without it.
    pub jwks: bool,
    /// The key service did not answer and `jwks` rests on a stale snapshot.
    /// This is temporary degradation: once the snapshot stops being usable,
    /// `jwks` turns `false`.
    pub jwks_stale: bool,
}

/// The full representation of a key, including its private part.
///
/// Returned by `jwks-service-app` when a key is requested or created, and used
/// to sign tokens. **Never** exposed to API clients.
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

/// The public representation of a key (a JSON Web Key), without the private part.
///
/// Which fields are populated depends on the key type: RSA fills `n`/`e`, EC
/// fills `crv`/`x`/`y`, OKP (EdDSA) fills `crv`/`x`.
// `Clone` is needed by the JWKS cache: the key is handed out as a copy so that
// the cache lock is not held while a `PKey` is assembled (see `jwk.rs`).
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

/// A set of public keys — the response of the `.well-known/jwks.json` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    /// The list of available public keys.
    pub keys: Vec<Jwk>,
}

#[cfg(test)]
mod tests {
    //! DTO serialisation tests.
    //!
    //! What is checked is what the client sees: the shape of the JSON and the
    //! behaviour of the defaults. Both are part of the public contract rather
    //! than an implementation detail.

    use super::*;
    use serde_json::json;

    #[test]
    fn token_response_omits_refresh_when_absent() {
        let response = TokenResponse {
            token: "header.payload.signature".to_string(),
            refresh_token: None,
        };

        let value = serde_json::to_value(&response).unwrap();

        // The key must be absent entirely — not `null`. Otherwise existing
        // clients would see a new field in the response they did not expect (see
        // `skip_serializing_if`).
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
        // A minimal body: the client need not send either `ttl` or `refresh`.
        let request: TokenRequest =
            serde_json::from_value(json!({ "sub": "user1", "aud": ["api1"] })).unwrap();

        assert_eq!(request.sub, "user1");
        assert_eq!(request.aud, vec!["api1".to_string()]);
        assert!(request.ttl.is_none());
        assert!(!request.refresh, "refresh is off by default");
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
        // An OKP key (EdDSA): `crv`/`x` are filled and the RSA components are absent.
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
        // An empty list is the normal response of the key service before the first key is issued.
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
