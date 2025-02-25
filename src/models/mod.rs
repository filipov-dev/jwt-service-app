use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use serde_json::json;

pub mod jwt;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenRequest {
    #[schema(example = "user123")]
    pub sub: String,

    #[schema(example = json!(["api1", "api2"]))]
    pub aud: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenVerifyRequest {
    #[schema(example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub token: String,

    #[schema(example = "api1")]
    pub audience: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenResponse {
    #[schema(example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    #[schema(nullable = true)]
    pub details: Option<String>,
}

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

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}