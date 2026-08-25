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
//! Env:
//! - `AUTH_TOTP_SECRET` — shared TOTP secret, base32 (required);
//! - `JWT_SERVICE_URL` — service base URL, default `http://localhost:8080`.
//!
//! **The code is recomputed before every request.** With replay protection on
//! (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a code it has already
//! seen with `401`, even while that code is still inside its time window.

use std::env;

use reqwest::blocking::{Client as HttpClient, Response};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

/// Sent as the Host header and becomes the `iss` claim. Must be the same on
/// issue and on verify, or the token will not verify.
const ISSUER_HOST: &str = "example.com";

/// Reply of an issue or a refresh call.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    /// Signed JWT: `header.payload.signature`.
    pub token: String,
    /// Refresh token; present only if it was requested.
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Reply of a bulk revoke call.
#[derive(Debug, Deserialize)]
pub struct RevokeGroupResponse {
    /// How many active tokens were revoked; expired ones do not count.
    pub revoked: u64,
}

/// Body of an issue request.
#[derive(Debug, Serialize)]
struct IssueRequest<'a> {
    sub: &'a str,
    aud: &'a [String],
    refresh: bool,
    /// Custom claims; the field is omitted when there are none.
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    claims: serde_json::Map<String, serde_json::Value>,
}

/// Client of the token service, covering all four level 3 endpoints.
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

    /// Fresh code for right now: SHA-1, 6 digits, 30-second step.
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

    /// Sends a level 3 request.
    ///
    /// `body` is `None` for requests without one (revocation).
    fn request<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        // Computed here rather than reused: one code, one request.
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

    /// Issues an access token (`POST /tokens`).
    ///
    /// # Arguments
    /// - `sub` — subject the token is issued to (`sub` claim);
    /// - `aud` — audience (`aud` claim); must not be empty;
    /// - `with_refresh` — also return a refresh token for extending the session;
    /// - `claims` — custom claims (role, scope, tenant). They sit next to the
    ///   registered ones, so the consumer reads `role`, not `extra.role`.
    ///   Reserved names (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) are
    ///   rejected with `422` — change lifetime through `ttl`, not `exp`. Count
    ///   and size are capped server-side.
    ///
    /// # Errors
    /// `401` bad code, `422` bad parameters or forbidden claim, `500` JWKS or
    /// Redis unavailable.
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

    /// Exchanges a refresh token for a new pair (`POST /tokens/refresh`).
    ///
    /// The old token dies on exchange: store the new one and drop the previous.
    ///
    /// # Warning
    /// Never retry an exchange with the old token when the reply is lost. A
    /// second presentation reads as theft, and the server revokes the **whole
    /// family** — refresh tokens and the access tokens issued from them. Issue
    /// a new pair instead.
    ///
    /// # Errors
    /// `401` — token unknown, expired or already used.
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

    /// Revokes one token by its `jti` (`DELETE /tokens/{jti}`).
    ///
    /// Idempotent: revoking an unknown `jti` is success too — the desired state
    /// holds either way.
    ///
    /// # Errors
    /// `500` — store unreachable, the token is **not** revoked: retry.
    pub fn revoke_token(&self, jti: &str) -> Result<(), Box<dyn std::error::Error>> {
        let response =
            self.request::<()>(Method::DELETE, &format!("/tokens/{jti}"), None)?;

        if !response.status().is_success() {
            return Err(format!("revoke failed: {}", response.status()).into());
        }

        Ok(())
    }

    /// Revokes every active token of a subject.
    ///
    /// Endpoint `DELETE /subjects/{sub}/tokens`. The compromise path: tokens
    /// cannot be killed one by one because the caller does not know their `jti`.
    ///
    /// Returns the number of revoked tokens; expired ones do not count.
    ///
    /// # Errors
    /// `500` — store unreachable, nothing was revoked.
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

/// Full token lifecycle: issue, refresh, bulk revoke.
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
