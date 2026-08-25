//! jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
//!
//! Dependencies:
//!
//! ```toml
//! totp-rs = { version = "5", features = ["otpauth"] }
//! reqwest = { version = "0.12", features = ["json", "blocking"] }
//! serde = { version = "1", features = ["derive"] }
//! ```
//!
//! Env: `AUTH_TOTP_SECRET` (base32), `JWT_SERVICE_URL` (default
//! `http://localhost:8080`).
//! See README.md for endpoints, error codes and client rules.

use std::env;

use reqwest::blocking::{Client as HttpClient, Response};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

/// Sent as the Host header, becomes the `iss` claim.
const ISSUER_HOST: &str = "example.com";

/// Reply of an issue or refresh call.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    /// Signed JWT: `header.payload.signature`.
    pub token: String,
    /// Present only when a refresh token was requested.
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Reply of a bulk revoke call.
#[derive(Debug, Deserialize)]
pub struct RevokeGroupResponse {
    /// Number of revoked tokens.
    pub revoked: u64,
}

/// Body of an issue request.
#[derive(Debug, Serialize)]
struct IssueRequest<'a> {
    sub: &'a str,
    aud: &'a [String],
    refresh: bool,
    /// Custom claims; the field is omitted when empty.
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    claims: serde_json::Map<String, serde_json::Value>,
}

/// Client of the token service.
pub struct Client {
    base_url: String,
    secret: String,
    http: HttpClient,
}

impl Client {
    /// Builds a client from the environment.
    ///
    /// # Panics
    /// If `AUTH_TOTP_SECRET` is not set.
    pub fn from_env() -> Self {
        Self {
            base_url: env::var("JWT_SERVICE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".into()),
            secret: env::var("AUTH_TOTP_SECRET").expect("AUTH_TOTP_SECRET is required"),
            http: HttpClient::new(),
        }
    }

    /// Fresh TOTP code: SHA-1, 6 digits, 30-second step.
    fn totp_code(&self) -> Result<String, Box<dyn std::error::Error>> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(self.secret.clone()).to_bytes()?,
        )?;

        Ok(totp.generate_current()?)
    }

    /// Sends a level 3 request with a code computed right before the call.
    ///
    /// `body` is `None` for requests without one.
    fn request<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let mut builder = self
            .http
            .request(method, format!("{}{path}", self.base_url))
            .header("X-TOTP-Code", self.totp_code()?)
            .header("Host", ISSUER_HOST);

        if let Some(body) = body {
            builder = builder.json(body);
        }

        Ok(builder.send()?)
    }

    /// `POST /tokens`
    pub fn issue_token(
        &self,
        sub: &str,
        aud: &[String],
        with_refresh: bool,
        claims: serde_json::Map<String, serde_json::Value>,
    ) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        let payload = IssueRequest {
            sub,
            aud,
            refresh: with_refresh,
            claims,
        };

        let response = self.request(Method::POST, "/tokens", Some(&payload))?;
        if !response.status().is_success() {
            return Err(format!("issue failed: {}", response.status()).into());
        }

        Ok(response.json()?)
    }

    /// `POST /tokens/refresh` — returns a new pair; the old refresh token is dead.
    pub fn refresh_tokens(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        let payload = serde_json::json!({ "refresh_token": refresh_token });

        let response = self.request(Method::POST, "/tokens/refresh", Some(&payload))?;
        if !response.status().is_success() {
            return Err(format!("refresh failed: {}", response.status()).into());
        }

        Ok(response.json()?)
    }

    /// `DELETE /tokens/{jti}` — idempotent.
    pub fn revoke_token(&self, jti: &str) -> Result<(), Box<dyn std::error::Error>> {
        let response =
            self.request::<()>(Method::DELETE, &format!("/tokens/{jti}"), None)?;

        if !response.status().is_success() {
            return Err(format!("revoke failed: {}", response.status()).into());
        }

        Ok(())
    }

    /// `DELETE /subjects/{sub}/tokens` — returns the number of revoked tokens.
    pub fn revoke_subject(&self, sub: &str) -> Result<u64, Box<dyn std::error::Error>> {
        let response =
            self.request::<()>(Method::DELETE, &format!("/subjects/{sub}/tokens"), None)?;

        if !response.status().is_success() {
            return Err(format!("bulk revoke failed: {}", response.status()).into());
        }

        let body: RevokeGroupResponse = response.json()?;
        Ok(body.revoked)
    }
}

/// Issue -> refresh -> revoke.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::from_env();

    let mut claims = serde_json::Map::new();
    claims.insert("role".into(), serde_json::json!("admin"));

    let issued = client.issue_token("svc-a", &["svc-b".to_string()], true, claims)?;
    println!("issued: {}...", &issued.token[..32]);

    let refresh = issued.refresh_token.expect("refresh was requested");
    let refreshed = client.refresh_tokens(&refresh)?;
    println!("refreshed: {}...", &refreshed.token[..32]);

    println!("revoked: {}", client.revoke_subject("svc-a")?);

    Ok(())
}
