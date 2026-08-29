//! Multi-level access control for the endpoints.
//!
//! Implements a single auth middleware ([`Auth`]) with four levels
//! ([`AuthLevel`]); the level is chosen when a route is registered in `main.rs`,
//! and the only difference between levels is the validator:
//!
//! - **Level 1 — [`AuthLevel::Open`]**: no protection (`/livez`, `/readyz`, the
//!   OpenAPI spec). Always lets requests through.
//! - **Level 2 — [`AuthLevel::ProxySecret`]**: a static secret header set only
//!   by the reverse proxy. Constant-time comparison ([`ProxyValidator`]).
//! - **Level 3 — [`AuthLevel::Totp`]**: internal app-to-app over TOTP
//!   (RFC 6238, [`TotpValidator`]).
//! - **Level 4 — [`AuthLevel::MetricsToken`]**: scraping `/metrics` with a
//!   static bearer token ([`MetricsValidator`]).
//!
//! The crypto (HMAC for TOTP, the constant-time comparison) goes through
//! `openssl`, already among the dependencies. The configuration comes entirely
//! from the environment ([`AuthConfig::from_env`]).
//!
//! **Protection of the main endpoints is mandatory.** The level 2 and level 3
//! secrets (`AUTH_PROXY_SECRET`, `AUTH_TOTP_SECRET`) are required: when either
//! is missing, [`AuthConfig::from_env`] returns an error and the service **does
//! not start** (fail-fast at startup, as with the rest of the critical
//! configuration). These levels cannot be turned off.
//!
//! **Level 4 is the exception: it is optional.** Metrics are auxiliary, and the
//! whole token service should not go down over their configuration. Without
//! `AUTH_METRICS_TOKEN` the service starts and the `/metrics` route is not
//! registered at all — the path returns `404`. A missing token **never means
//! open access**: in that state [`MetricsValidator`] rejects everything.
//!
//! ## Replay protection (level 3)
//!
//! A TOTP code is by itself replayable within its validity window. That is
//! closed by the `AUTH_TOTP_REPLAY_PROTECTION` flag: a fingerprint of the
//! presented code is reserved in the store with `SET NX` and a TTL equal to the
//! window, and a second presentation gets `401`.
//!
//! - **Off by default.** Turning it on adds a Redis dependency to the auth layer
//!   that it otherwise does not have; silently changing the behaviour of running
//!   deployments would be wrong. Enable it explicitly in production.
//! - **What goes into the store is not the code but its HMAC** under the first
//!   active secret. A bare hash would hide nothing: a code is 6–8 digits and is
//!   brute-forced instantly.
//! - **An unavailable store does not close the door** (fail-open). Both level 3
//!   endpoints go to Redis anyway: without it issuing fails at `store_jti`, and
//!   revocation is a Redis command in itself. A replayed code achieves nothing
//!   while the store is down, and failing closed would only add one more reason
//!   for the service to refuse requests.

use std::env;
use std::future::{ready, Future, Ready};
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;

use actix_web::body::EitherBody;
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::HeaderMap;
use actix_web::{Error, HttpResponse};
use chrono::Utc;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

use crate::models::jwt::JtiStore;
use crate::models::ErrorResponse;

/// The access level of an endpoint. It decides which validator the middleware applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthLevel {
    /// Level 1 — no protection. Lets any request through.
    Open,
    /// Level 2 — the static proxy secret header.
    ProxySecret,
    /// Level 3 — internal app-to-app over TOTP.
    Totp,
    /// Level 4 — scraping the metrics with a static bearer token.
    ///
    /// A separate level rather than a reuse of level 2 or 3: monitoring systems
    /// cannot do TOTP (they do not compute one-time codes), and `X-Proxy-Secret`
    /// is stripped by the proxy by contract. Bearer, on the other hand, is
    /// natively supported by Prometheus (`authorization: {credentials_file}`),
    /// by Zabbix `agent2` and by the OTel Collector (through which Monium
    /// scrapes the metrics).
    MetricsToken,
}

impl AuthLevel {
    /// The string name of the level for logs and tracing (written into the request span).
    fn as_str(self) -> &'static str {
        match self {
            AuthLevel::Open => "open",
            AuthLevel::ProxySecret => "proxy_secret",
            AuthLevel::Totp => "totp",
            AuthLevel::MetricsToken => "metrics_token",
        }
    }
}

/// Reads a `u64` from an environment variable, falling back to `default`.
fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Decodes a base32 string (RFC 4648, the `A–Z2–7` alphabet) into bytes.
///
/// Case-insensitive; whitespace and `=` padding are ignored. Returns `None` when
/// a character outside the alphabet is found. TOTP secrets are base32 by
/// convention (compatible with Google Authenticator and most libraries).
fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();

    for ch in input.chars() {
        if ch.is_whitespace() || ch == '=' {
            continue;
        }
        let up = ch.to_ascii_uppercase() as u8;
        let value = ALPHABET.iter().position(|&a| a == up)? as u64;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }

    Some(out)
}

/// Picks the `MessageDigest` by the TOTP hash name (SHA-1 by default).
fn digest_by_name(name: &str) -> MessageDigest {
    match name.trim().to_ascii_uppercase().as_str() {
        "SHA256" | "SHA-256" => MessageDigest::sha256(),
        "SHA512" | "SHA-512" => MessageDigest::sha512(),
        _ => MessageDigest::sha1(),
    }
}

/// Computes the HOTP code (RFC 4226) for a secret and a counter.
///
/// Returns a string of `digits` decimal digits (zero-padded). The basis for
/// TOTP: the counter is the number of the time window.
///
/// # Errors
/// Propagates an `openssl::error::ErrorStack` when the HMAC could not be built.
fn hotp(
    secret: &[u8],
    counter: u64,
    digits: u32,
    digest: MessageDigest,
) -> Result<String, openssl::error::ErrorStack> {
    let key = PKey::hmac(secret)?;
    let mut signer = Signer::new(digest, &key)?;
    signer.update(&counter.to_be_bytes())?;
    let hs = signer.sign_to_vec()?;

    // Dynamic truncation per RFC 4226 §5.3.
    let offset = (hs[hs.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(hs[offset]) & 0x7f) << 24)
        | (u32::from(hs[offset + 1]) << 16)
        | (u32::from(hs[offset + 2]) << 8)
        | u32::from(hs[offset + 3]);

    let otp = bin % 10u32.pow(digits);
    Ok(format!("{otp:0width$}", width = digits as usize))
}

/// The level 2 validator: a static secret header from the reverse proxy.
///
/// The secret is mandatory and guaranteed to be set (see
/// [`AuthConfig::from_env`], which does not let the service start without it).
#[derive(Clone)]
pub struct ProxyValidator {
    /// The header name (`X-Proxy-Secret` by default).
    header: String,
    /// The expected secret.
    secret: Vec<u8>,
}

impl ProxyValidator {
    /// Checks the request header. The secret comparison is constant-time
    /// (`openssl::memcmp::eq`, on top of a preliminary length check).
    pub fn validate(&self, headers: &HeaderMap) -> bool {
        match headers.get(self.header.as_str()) {
            Some(provided) => {
                let provided = provided.as_bytes();
                // `openssl::memcmp::eq` panics on differing lengths — the length
                // first, then a constant-time comparison of the contents.
                provided.len() == self.secret.len() && openssl::memcmp::eq(provided, &self.secret)
            }
            None => false,
        }
    }
}

/// The level 4 validator: a static bearer token for scraping the metrics.
///
/// The token is **optional**, unlike the level 2 and level 3 secrets: without it
/// the service starts and the `/metrics` route is simply not registered (see
/// `main.rs`), so the path returns a plain `404`. The validator still answers
/// `false` to every request — a safeguard in case the route is registered past
/// this check: **a missing secret must never mean open access**.
#[derive(Clone)]
pub struct MetricsValidator {
    /// The expected token (without the `Bearer ` prefix); `None` means the level is unavailable.
    token: Option<Vec<u8>>,
}

impl MetricsValidator {
    /// Checks the `Authorization: Bearer <token>` header.
    ///
    /// The scheme (`Bearer`) is compared case-insensitively, as RFC 7235
    /// requires; the token itself constant-time (`openssl::memcmp::eq` on top of
    /// a length check).
    pub fn validate(&self, headers: &HeaderMap) -> bool {
        // The token is not configured — the level is unavailable, there is nobody to let through.
        let Some(expected) = self.token.as_deref() else {
            return false;
        };

        let Some(value) = headers.get("Authorization") else {
            return false;
        };
        let Ok(value) = value.to_str() else {
            return false;
        };

        let Some((scheme, provided)) = value.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return false;
        }

        let provided = provided.trim().as_bytes();
        provided.len() == expected.len() && openssl::memcmp::eq(provided, expected)
    }
}

/// The level 3 validator: TOTP (RFC 6238).
///
/// The active secrets are mandatory and guaranteed to be non-empty (see
/// [`AuthConfig::from_env`], which does not let the service start without them).
#[derive(Clone)]
pub struct TotpValidator {
    /// The name of the header carrying the code (`X-TOTP-Code` by default).
    header: String,
    /// The active secrets (1 or 2 — the second is needed during a rotation).
    secrets: Vec<Vec<u8>>,
    /// The window step in seconds (30 by default).
    step: u64,
    /// The number of digits in the code (6–8, 6 by default).
    digits: u32,
    /// Tolerance in windows in both directions (1 by default) — it compensates for clock drift.
    skew: u64,
    /// The HMAC hash (SHA-1/256/512).
    digest: MessageDigest,
}

impl TotpValidator {
    /// Returns the fingerprint of the presented code — the key for replay
    /// protection.
    ///
    /// It is an HMAC under the first active secret rather than a bare hash: the
    /// code itself is only 6–8 digits and is brute-forced instantly, so a SHA of
    /// it would hide nothing. With an HMAC the contents of Redis are useless to
    /// anyone without the secret.
    ///
    /// `None` when there is no header with a code — there is nothing to check.
    pub fn code_fingerprint(&self, headers: &HeaderMap) -> Option<String> {
        let provided = headers.get(self.header.as_str())?.as_bytes();
        let secret = self.secrets.first()?;

        let key = PKey::hmac(secret).ok()?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key).ok()?;
        signer.update(provided).ok()?;
        let digest = signer.sign_to_vec().ok()?;

        Some(digest.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// How many seconds the fingerprint of a code is kept in the store.
    ///
    /// Exactly the window in which the code would still be accepted: the current
    /// step plus `skew` in both directions. Keeping it longer is pointless — the
    /// code stops passing validation anyway and the records would occupy memory.
    pub fn replay_window_seconds(&self) -> u64 {
        self.step * (2 * self.skew + 1)
    }

    /// Validates the TOTP code from the header as of `now` (Unix time, seconds).
    ///
    /// The code is accepted when it matches the expected one for at least one
    /// active secret within the `[counter - skew, counter + skew]` window. The
    /// windows and secrets are iterated without an early exit — so as not to
    /// leak a timing signal about which window or secret matched. The codes are
    /// compared in constant time.
    pub fn validate(&self, headers: &HeaderMap, now: u64) -> bool {
        let Some(provided) = headers.get(self.header.as_str()) else {
            return false;
        };
        let provided = provided.as_bytes();

        let counter = now / self.step;
        let low = counter.saturating_sub(self.skew);
        let high = counter.saturating_add(self.skew);

        let mut matched = false;
        for secret in &self.secrets {
            for c in low..=high {
                if let Ok(code) = hotp(secret, c, self.digits, self.digest) {
                    let code = code.as_bytes();
                    if provided.len() == code.len() && openssl::memcmp::eq(provided, code) {
                        matched = true;
                    }
                }
            }
        }
        matched
    }
}

/// The full access level configuration assembled from the environment.
///
/// Cheap to clone (short strings and byte vectors) — in `main.rs` a copy is
/// wrapped in an `Rc` inside the application factory for each worker thread.
#[derive(Clone)]
pub struct AuthConfig {
    proxy: ProxyValidator,
    totp: TotpValidator,
    metrics: MetricsValidator,
    /// Whether TOTP replay protection is on
    /// (`AUTH_TOTP_REPLAY_PROTECTION`).
    totp_replay_protection: bool,
}

impl AuthConfig {
    /// Whether TOTP replay protection is on.
    pub fn totp_replay_protection(&self) -> bool {
        self.totp_replay_protection
    }

    /// The fingerprint of the presented TOTP code and how long it lives in the store.
    ///
    /// `None` when there is no header with a code or the fingerprint could not be computed.
    pub fn totp_replay_claim(&self, headers: &HeaderMap) -> Option<(String, u64)> {
        let fingerprint = self.totp.code_fingerprint(headers)?;
        Some((fingerprint, self.totp.replay_window_seconds()))
    }
    /// Assembles the configuration from environment variables.
    ///
    /// The level 2 and level 3 secrets are **mandatory**: when
    /// `AUTH_PROXY_SECRET` or `AUTH_TOTP_SECRET` is missing (or the TOTP secret
    /// does not parse as base32), an `Err` with the list of problems is returned
    /// and the service must not start (see the call site in `main.rs`). A level
    /// cannot be turned off.
    ///
    /// The variables:
    /// - `AUTH_PROXY_SECRET` — the level 2 secret (mandatory; compared byte by byte);
    /// - `AUTH_PROXY_SECRET_HEADER` (default `X-Proxy-Secret`);
    /// - `AUTH_TOTP_SECRET` — the base32 level 3 secret (mandatory);
    /// - `AUTH_TOTP_SECRET_NEXT` — a second base32 secret during a rotation (optional);
    /// - `AUTH_TOTP_HEADER` (default `X-TOTP-Code`);
    /// - `AUTH_TOTP_STEP_SECONDS` (default 30), `AUTH_TOTP_DIGITS` (6–8, default 6),
    ///   `AUTH_TOTP_ALGORITHM` (SHA1/SHA256/SHA512, default SHA1),
    ///   `AUTH_TOTP_SKEW_STEPS` (default 1).
    ///
    /// # Errors
    /// A string listing every configuration problem (joined by `; `) when at
    /// least one mandatory secret is missing or invalid.
    pub fn from_env() -> Result<Self, String> {
        let mut errors: Vec<String> = Vec::new();

        // --- Level 2: the proxy secret (mandatory) ---
        let proxy_header =
            env::var("AUTH_PROXY_SECRET_HEADER").unwrap_or_else(|_| "X-Proxy-Secret".into());
        let proxy_secret = env::var("AUTH_PROXY_SECRET").ok().filter(|s| !s.is_empty());
        if proxy_secret.is_none() {
            errors.push(
                "AUTH_PROXY_SECRET is not set (mandatory for level 2 — the proxy secret)".into(),
            );
        }

        // --- Level 3: TOTP (at least one secret is mandatory) ---
        let totp_header = env::var("AUTH_TOTP_HEADER").unwrap_or_else(|_| "X-TOTP-Code".into());
        let mut secrets = Vec::new();
        for var in ["AUTH_TOTP_SECRET", "AUTH_TOTP_SECRET_NEXT"] {
            match env::var(var) {
                Ok(raw) if !raw.trim().is_empty() => match base32_decode(&raw) {
                    Some(bytes) if !bytes.is_empty() => secrets.push(bytes),
                    _ => errors.push(format!("{var} is not valid base32")),
                },
                _ => {}
            }
        }
        if secrets.is_empty() {
            errors.push("AUTH_TOTP_SECRET is not set (mandatory for level 3 — TOTP)".into());
        }

        // --- Level 4: the metrics token (OPTIONAL) ---
        // Unlike levels 2 and 3, a missing token is not fatal: metrics are an
        // auxiliary function, and the whole token service should not go down over
        // their configuration. Without the token the `/metrics` route is not
        // registered (see `main.rs`) and the path returns `404`.
        let metrics_token = env::var("AUTH_METRICS_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        if !errors.is_empty() {
            return Err(errors.join("; "));
        }

        let digits = env_u64("AUTH_TOTP_DIGITS", 6).clamp(6, 8) as u32;
        let step = env_u64("AUTH_TOTP_STEP_SECONDS", 30).max(1);
        let skew = env_u64("AUTH_TOTP_SKEW_STEPS", 1);
        let digest =
            digest_by_name(&env::var("AUTH_TOTP_ALGORITHM").unwrap_or_else(|_| "SHA1".into()));

        // TOTP replay protection. OFF by default: turning it on adds a Redis
        // dependency to the auth layer that it does not have, and silently
        // changing the behaviour of running deployments that way would be wrong.
        // Enable it explicitly in production.
        let totp_replay_protection = env::var("AUTH_TOTP_REPLAY_PROTECTION")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        Ok(Self {
            proxy: ProxyValidator {
                header: proxy_header,
                // Checked above: with `None` we would already have returned `Err`.
                secret: proxy_secret.expect("proxy secret present").into_bytes(),
            },
            totp: TotpValidator {
                header: totp_header,
                secrets,
                step,
                digits,
                skew,
                digest,
            },
            metrics: MetricsValidator {
                token: metrics_token.map(String::into_bytes),
            },
            totp_replay_protection,
        })
    }

    /// Allows or rejects a request for the given level based on its headers.
    /// Whether level 4 is available (whether the metrics token is set).
    ///
    /// `main.rs` uses it to decide whether to register the `/metrics` route:
    /// without a token the endpoint is not published at all and the path returns
    /// `404`.
    pub fn metrics_enabled(&self) -> bool {
        self.metrics.token.is_some()
    }

    pub fn authorize(&self, level: AuthLevel, headers: &HeaderMap) -> bool {
        match level {
            AuthLevel::Open => true,
            AuthLevel::ProxySecret => self.proxy.validate(headers),
            AuthLevel::Totp => self
                .totp
                .validate(headers, Utc::now().timestamp().max(0) as u64),
            AuthLevel::MetricsToken => self.metrics.validate(headers),
        }
    }
}

/// The middleware factory: it wraps a route in a check of the given [`AuthLevel`].
///
/// Registered through `.wrap(Auth::new(level, config))` on a specific resource.
/// It is parameterised by the store type: TOTP replay protection
/// (`AUTH_TOTP_REPLAY_PROTECTION`) pulls the store out of `app_data` by that
/// type. In tests an in-memory mock is substituted for Redis.
pub struct Auth<St> {
    level: AuthLevel,
    config: Rc<AuthConfig>,
    _store: PhantomData<St>,
}

impl<St> Auth<St> {
    /// Creates a middleware factory for level `level` with the shared configuration.
    pub fn new(level: AuthLevel, config: Rc<AuthConfig>) -> Self {
        Self {
            level,
            config,
            _store: PhantomData,
        }
    }
}

impl<S, B, St> Transform<S, ServiceRequest> for Auth<St>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
    St: JtiStore + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AuthMiddleware<S, St>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware {
            service: Rc::new(service),
            level: self.level,
            config: self.config.clone(),
            _store: PhantomData,
        }))
    }
}

/// The middleware itself: it checks access before calling the inner service.
pub struct AuthMiddleware<S, St> {
    service: Rc<S>,
    level: AuthLevel,
    config: Rc<AuthConfig>,
    _store: PhantomData<St>,
}

impl<S, B, St> Service<ServiceRequest> for AuthMiddleware<S, St>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
    St: JtiStore + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Write the access level into the request span (the field is declared in
        // `RequestLog`; with no span it is a no-op, which is safe in unit tests).
        tracing::Span::current().record("access_level", self.level.as_str());

        let authorized = self.config.authorize(self.level, req.headers());
        let service = self.service.clone();
        let level = self.level;

        // Replay protection: we reserve the fingerprint of the code in the store.
        // Only for level 3, only when it is on, and only when the code actually
        // passed validation — otherwise junk codes would fill Redis up.
        let replay_claim =
            if authorized && level == AuthLevel::Totp && self.config.totp_replay_protection() {
                self.config
                    .totp_replay_claim(req.headers())
                    .zip(req.app_data::<actix_web::web::Data<St>>().cloned())
            } else {
                None
            };

        Box::pin(async move {
            let mut authorized = authorized;

            if let Some(((fingerprint, ttl), store)) = replay_claim {
                match store.claim_totp_code(&fingerprint, ttl).await {
                    // The code is presented for the first time — all good.
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!("TOTP code reused");
                        authorized = false;
                    }
                    Err(e) => {
                        // Fail-open, deliberately. Both level 3 endpoints go to
                        // Redis anyway: without it `POST /tokens` fails at
                        // `store_jti`, and revocation is a Redis command in
                        // itself. So a replayed code achieves nothing while the
                        // store is down, while failing closed would only add one
                        // more reason for the service to refuse requests.
                        tracing::warn!(
                            "The TOTP replay check is unavailable ({e}), letting the request through"
                        );
                    }
                }
            }

            if authorized {
                let res = service.call(req).await?;
                Ok(res.map_into_left_body())
            } else {
                // A denial is a security signal (secret guessing, a wrong TOTP,
                // a client that forgot the header). WARN level: not a service
                // failure, but worth looking at. The secret or code itself is NOT
                // logged.
                tracing::warn!(access_level = level.as_str(), "Access denied");
                crate::metrics::record_auth_denied(level.as_str());

                // One terse response with no details — as on the other endpoints.
                let (req, _payload) = req.into_parts();
                let response = HttpResponse::Unauthorized()
                    .json(ErrorResponse::new("Unauthorized"))
                    .map_into_right_body();
                Ok(ServiceResponse::new(req, response))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    //! Tests of the validators and the TOTP primitives.
    //!
    //! `hotp` is checked against the RFC 4226 test vectors (the secret
    //! `"12345678901234567890"`), `base32_decode` against an RFC 4648 vector,
    //! and the validators for success and refusal, the TOTP window bounds and
    //! the behaviour without a secret. The tests of the middleware wrapper live
    //! in `handlers.rs` (the full HTTP stack).

    use super::*;
    use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
    use parking_lot::Mutex;
    use std::collections::HashSet;

    use crate::models::jwt::{JtiError, RefreshRecord};

    /// The secret from the RFC 4226 test vectors (an ASCII string).
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    /// A store for the middleware tests.
    ///
    /// Every operation except reserving a TOTP code is a stub: the auth layer
    /// never calls them. `claim_totp_code` works for real, or the replay
    /// protection tests would be checking emptiness.
    #[derive(Default)]
    struct NoopStore {
        used_codes: Mutex<HashSet<String>>,
        /// Simulate an unavailable store (to check fail-open).
        unavailable: bool,
    }

    impl NoopStore {
        fn unavailable() -> Self {
            Self {
                used_codes: Mutex::new(HashSet::new()),
                unavailable: true,
            }
        }
    }

    impl JtiStore for NoopStore {
        async fn ping(&self) -> Result<(), JtiError> {
            Ok(())
        }

        async fn store_jti(&self, _jti: &str, _ttl: u64) -> Result<(), JtiError> {
            Ok(())
        }

        async fn check_jti(&self, _jti: &str) -> Result<bool, JtiError> {
            Ok(true)
        }

        async fn delete_jti(&self, _jti: &str) -> Result<(), JtiError> {
            Ok(())
        }

        async fn add_to_group(
            &self,
            _group: &str,
            _jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            Ok(())
        }

        async fn revoke_group(&self, _group: &str) -> Result<u64, JtiError> {
            Ok(0)
        }

        async fn store_refresh(
            &self,
            _id: &str,
            _record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            Ok(())
        }

        async fn get_refresh(&self, _id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Ok(None)
        }

        async fn mark_refresh_used(&self, _id: &str) -> Result<bool, JtiError> {
            Ok(true)
        }

        async fn claim_totp_code(&self, hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            if self.unavailable {
                return Err(JtiError::BadConnection);
            }

            Ok(self.used_codes.lock().insert(hash.to_string()))
        }
    }

    /// Builds a `HeaderMap` with a single header.
    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        h
    }

    /// A level 4 validator with a known token.
    fn metrics_validator() -> MetricsValidator {
        MetricsValidator {
            token: Some(b"scrape-token".to_vec()),
        }
    }

    #[test]
    fn metrics_accepts_valid_bearer_token() {
        let v = metrics_validator();
        assert!(v.validate(&headers_with("Authorization", "Bearer scrape-token")));
    }

    #[test]
    fn metrics_scheme_is_case_insensitive() {
        // RFC 7235: the scheme name is case-insensitive.
        let v = metrics_validator();
        assert!(v.validate(&headers_with("Authorization", "bearer scrape-token")));
        assert!(v.validate(&headers_with("Authorization", "BEARER scrape-token")));
    }

    #[test]
    fn metrics_rejects_wrong_or_missing_token() {
        let v = metrics_validator();
        assert!(!v.validate(&HeaderMap::new()));
        assert!(!v.validate(&headers_with("Authorization", "Bearer wrong-token")));
        // A correct token prefix must not pass (the comparison is over the full length).
        assert!(!v.validate(&headers_with("Authorization", "Bearer scrape")));
        assert!(!v.validate(&headers_with("Authorization", "Bearer ")));
    }

    #[test]
    fn metrics_rejects_other_schemes_and_raw_token() {
        let v = metrics_validator();
        // The Basic scheme and a bare token without a scheme are not accepted.
        assert!(!v.validate(&headers_with("Authorization", "Basic scrape-token")));
        assert!(!v.validate(&headers_with("Authorization", "scrape-token")));
    }

    // --- HOTP: the RFC 4226 test vectors (Appendix D) ---

    #[test]
    fn hotp_matches_rfc4226_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            let got = hotp(RFC_SECRET, counter as u64, 6, MessageDigest::sha1()).unwrap();
            assert_eq!(
                &got, want,
                "HOTP disagrees with RFC 4226 at counter={counter}"
            );
        }
    }

    // --- base32 ---

    #[test]
    fn base32_decodes_rfc4648_vector() {
        // RFC 4648: "foo" => "MZXW6" (without padding).
        assert_eq!(base32_decode("MZXW6").unwrap(), b"foo");
        // Case-insensitive, ignoring padding and whitespace.
        assert_eq!(base32_decode("mzxw6===").unwrap(), b"foo");
        assert_eq!(base32_decode("MZ XW6").unwrap(), b"foo");
    }

    #[test]
    fn base32_rejects_invalid_alphabet() {
        // '1', '8' and '0' are not in the base32 alphabet.
        assert!(base32_decode("1808").is_none());
    }

    // --- ProxyValidator ---

    fn proxy(secret: &str) -> ProxyValidator {
        ProxyValidator {
            header: "X-Proxy-Secret".into(),
            secret: secret.as_bytes().to_vec(),
        }
    }

    #[test]
    fn proxy_accepts_correct_secret() {
        let v = proxy("s3cr3t");
        assert!(v.validate(&headers_with("X-Proxy-Secret", "s3cr3t")));
    }

    #[test]
    fn proxy_rejects_wrong_and_missing_secret() {
        let v = proxy("s3cr3t");
        assert!(!v.validate(&headers_with("X-Proxy-Secret", "nope")));
        assert!(!v.validate(&HeaderMap::new()));
        // A different length — memcmp must not panic.
        assert!(!v.validate(&headers_with("X-Proxy-Secret", "short")));
    }

    // --- TotpValidator ---

    fn totp(secrets: Vec<&[u8]>, skew: u64) -> TotpValidator {
        TotpValidator {
            header: "X-TOTP-Code".into(),
            secrets: secrets.into_iter().map(|s| s.to_vec()).collect(),
            step: 30,
            digits: 6,
            skew,
            digest: MessageDigest::sha1(),
        }
    }

    /// The expected code for the window containing the moment `now`.
    fn code_at(secret: &[u8], now: u64, step: u64) -> String {
        hotp(secret, now / step, 6, MessageDigest::sha1()).unwrap()
    }

    #[test]
    fn totp_accepts_current_code() {
        let v = totp(vec![RFC_SECRET], 1);
        let now = 1_700_000_000;
        let code = code_at(RFC_SECRET, now, 30);
        // The validator takes its own "now", so we check through a direct call with `now`.
        assert!(v.validate(&headers_with("X-TOTP-Code", &code), now));
    }

    #[test]
    fn totp_rejects_wrong_and_missing_code() {
        let v = totp(vec![RFC_SECRET], 1);
        let now = 1_700_000_000;
        assert!(!v.validate(&headers_with("X-TOTP-Code", "000000"), now));
        assert!(!v.validate(&HeaderMap::new(), now));
    }

    #[test]
    fn totp_accepts_within_skew_and_rejects_outside() {
        let v = totp(vec![RFC_SECRET], 1);
        let now = 1_700_000_000;
        // The code of the previous window is accepted at skew=1.
        let prev = code_at(RFC_SECRET, now - 30, 30);
        assert!(v.validate(&headers_with("X-TOTP-Code", &prev), now));
        // A code two windows away is outside skew=1 and is rejected.
        let far = code_at(RFC_SECRET, now + 60, 30);
        assert!(!v.validate(&headers_with("X-TOTP-Code", &far), now));
    }

    #[test]
    fn totp_supports_secret_rotation() {
        // Two active secrets: a code from either is accepted.
        let old = b"old-secret-000000000".as_slice();
        let new = b"new-secret-111111111".as_slice();
        let v = totp(vec![old, new], 1);
        let now = 1_700_000_000;

        assert!(v.validate(&headers_with("X-TOTP-Code", &code_at(old, now, 30)), now));
        assert!(v.validate(&headers_with("X-TOTP-Code", &code_at(new, now, 30)), now));
    }

    // --- AuthConfig::from_env: the secrets are mandatory ---

    /// Serialises the tests that touch the process-global `AUTH_*` variables and
    /// clears them before and after (recovering from a lock poisoned by a panic).
    fn with_clean_auth_env<T>(f: impl FnOnce() -> T) -> T {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        const VARS: &[&str] = &[
            "AUTH_PROXY_SECRET",
            "AUTH_PROXY_SECRET_HEADER",
            "AUTH_TOTP_SECRET",
            "AUTH_TOTP_SECRET_NEXT",
            "AUTH_TOTP_HEADER",
            "AUTH_TOTP_DIGITS",
            "AUTH_TOTP_STEP_SECONDS",
            "AUTH_TOTP_ALGORITHM",
            "AUTH_TOTP_SKEW_STEPS",
            "AUTH_METRICS_TOKEN",
        ];
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for v in VARS {
            env::remove_var(v);
        }
        let result = f();
        for v in VARS {
            env::remove_var(v);
        }
        result
    }

    #[test]
    fn from_env_errors_when_both_secrets_missing() {
        with_clean_auth_env(|| {
            // `let-else` rather than `unwrap_err()` so as not to require `Debug`
            // on `AuthConfig` (it holds secrets — they have no place in Debug output).
            let Err(err) = AuthConfig::from_env() else {
                panic!("a configuration error was expected");
            };
            assert!(err.contains("AUTH_PROXY_SECRET"), "{err}");
            assert!(err.contains("AUTH_TOTP_SECRET"), "{err}");
        });
    }

    #[test]
    fn from_env_errors_when_only_totp_missing() {
        with_clean_auth_env(|| {
            env::set_var("AUTH_PROXY_SECRET", "s3cr3t");
            let Err(err) = AuthConfig::from_env() else {
                panic!("a configuration error was expected");
            };
            assert!(err.contains("AUTH_TOTP_SECRET"), "{err}");
            assert!(!err.contains("AUTH_PROXY_SECRET"), "{err}");
        });
    }

    #[test]
    fn from_env_ok_without_metrics_token() {
        // Level 4 is OPTIONAL, unlike levels 2 and 3: without a token the service
        // starts, the level is simply unavailable (the `/metrics` route is not published).
        with_clean_auth_env(|| {
            env::set_var("AUTH_PROXY_SECRET", "s3cr3t");
            env::set_var("AUTH_TOTP_SECRET", "MZXW6");
            let cfg =
                AuthConfig::from_env().expect("the config must assemble without a metrics token");
            assert!(!cfg.metrics_enabled(), "level 4 must be unavailable");
        });
    }

    #[test]
    fn metrics_validator_rejects_everything_without_token() {
        // A missing secret NEVER means open access: the validator rejects
        // everything even if the route ends up registered.
        let v = MetricsValidator { token: None };
        assert!(!v.validate(&HeaderMap::new()));
        assert!(!v.validate(&headers_with("Authorization", "Bearer whatever")));
        assert!(!v.validate(&headers_with("Authorization", "Bearer ")));
    }

    #[test]
    fn from_env_ok_with_both_secrets() {
        with_clean_auth_env(|| {
            env::set_var("AUTH_PROXY_SECRET", "s3cr3t");
            env::set_var("AUTH_TOTP_SECRET", "MZXW6"); // base32("foo")
            env::set_var("AUTH_METRICS_TOKEN", "m3trics");
            let cfg = AuthConfig::from_env().expect("the config must assemble");
            assert_eq!(cfg.proxy.secret, b"s3cr3t");
            assert_eq!(cfg.totp.secrets, vec![b"foo".to_vec()]);
            assert_eq!(cfg.metrics.token.as_deref(), Some(b"m3trics".as_slice()));
        });
    }

    #[test]
    fn from_env_errors_on_invalid_base32() {
        with_clean_auth_env(|| {
            env::set_var("AUTH_PROXY_SECRET", "s3cr3t");
            env::set_var("AUTH_TOTP_SECRET", "10108"); // 0, 1 and 8 are outside the base32 alphabet
            let Err(err) = AuthConfig::from_env() else {
                panic!("a configuration error was expected");
            };
            assert!(err.contains("base32"), "{err}");
        });
    }

    #[test]
    fn from_env_supports_two_secrets_for_rotation() {
        with_clean_auth_env(|| {
            env::set_var("AUTH_PROXY_SECRET", "s3cr3t");
            env::set_var("AUTH_TOTP_SECRET", "MZXW6");
            env::set_var("AUTH_TOTP_SECRET_NEXT", "MZXW6");
            env::set_var("AUTH_METRICS_TOKEN", "m3trics");
            let cfg = AuthConfig::from_env().expect("the config must assemble");
            assert_eq!(cfg.totp.secrets.len(), 2);
        });
    }

    // --- Integration: the middleware over the full actix HTTP stack ---

    mod middleware {
        //! We run every level through the real actix stack: a trivial handler
        //! wrapped in [`Auth`] must return `200` with a valid credential and
        //! `401` with a missing or wrong one. That is how we check that the
        //! middleware really does intercept the request before the handler.

        use super::*;
        use actix_web::http::StatusCode;
        use actix_web::{test, web, App, HttpResponse};
        use chrono::Utc;

        /// The TOTP secret for the integration runs.
        const SECRET: &[u8] = b"12345678901234567890";

        /// A configuration with explicit validators (the environment is not involved).
        fn config(proxy_secret: &str, totp_secrets: Vec<&[u8]>) -> AuthConfig {
            AuthConfig {
                proxy: ProxyValidator {
                    header: "X-Proxy-Secret".into(),
                    secret: proxy_secret.as_bytes().to_vec(),
                },
                totp: TotpValidator {
                    header: "X-TOTP-Code".into(),
                    secrets: totp_secrets.into_iter().map(|s| s.to_vec()).collect(),
                    step: 30,
                    digits: 6,
                    skew: 1,
                    digest: MessageDigest::sha1(),
                },
                metrics: MetricsValidator {
                    token: Some(b"metrics-token".to_vec()),
                },
                totp_replay_protection: false,
            }
        }

        /// The same, but with TOTP replay protection enabled.
        fn config_with_replay_protection(
            proxy_secret: &str,
            totp_secrets: Vec<&[u8]>,
        ) -> AuthConfig {
            AuthConfig {
                totp_replay_protection: true,
                ..config(proxy_secret, totp_secrets)
            }
        }

        /// An application with a store in `app_data` — needed by replay protection.
        macro_rules! guarded_app_with_store {
            ($level:expr, $config:expr, $store:expr) => {
                test::init_service(
                    App::new()
                        .app_data(actix_web::web::Data::new($store))
                        .service(
                            web::resource("/x")
                                .wrap(Auth::<NoopStore>::new($level, Rc::new($config)))
                                .route(web::get().to(|| async { HttpResponse::Ok().body("ok") })),
                        ),
                )
                .await
            };
        }

        /// Brings up an application with a single GET route `/x` wrapped in level `level`.
        macro_rules! guarded_app {
            ($level:expr, $config:expr) => {
                test::init_service(
                    App::new().service(
                        web::resource("/x")
                            .wrap(Auth::<NoopStore>::new($level, Rc::new($config)))
                            .route(web::get().to(|| async { HttpResponse::Ok().body("ok") })),
                    ),
                )
                .await
            };
        }

        /// A TOTP code for the current window and the given secret.
        fn current_code(secret: &[u8]) -> String {
            let now = Utc::now().timestamp().max(0) as u64;
            hotp(secret, now / 30, 6, MessageDigest::sha1()).unwrap()
        }

        #[actix_web::test]
        async fn open_level_passes_without_credentials() {
            let app = guarded_app!(AuthLevel::Open, config("s3cr3t", vec![SECRET]));
            let req = test::TestRequest::get().uri("/x").to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn proxy_level_accepts_valid_secret() {
            let app = guarded_app!(AuthLevel::ProxySecret, config("s3cr3t", vec![SECRET]));
            let req = test::TestRequest::get()
                .uri("/x")
                .insert_header(("X-Proxy-Secret", "s3cr3t"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn proxy_level_rejects_missing_and_wrong_secret() {
            let app = guarded_app!(AuthLevel::ProxySecret, config("s3cr3t", vec![SECRET]));

            let req = test::TestRequest::get().uri("/x").to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::UNAUTHORIZED
            );

            let req = test::TestRequest::get()
                .uri("/x")
                .insert_header(("X-Proxy-Secret", "wrong"))
                .to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }

        #[actix_web::test]
        async fn totp_level_accepts_valid_code() {
            let app = guarded_app!(AuthLevel::Totp, config("s3cr3t", vec![SECRET]));
            let req = test::TestRequest::get()
                .uri("/x")
                .insert_header(("X-TOTP-Code", current_code(SECRET)))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn totp_level_rejects_missing_and_wrong_code() {
            let app = guarded_app!(AuthLevel::Totp, config("s3cr3t", vec![SECRET]));

            let req = test::TestRequest::get().uri("/x").to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::UNAUTHORIZED
            );

            let req = test::TestRequest::get()
                .uri("/x")
                .insert_header(("X-TOTP-Code", "000000"))
                .to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }

        #[actix_web::test]
        async fn totp_code_is_rejected_on_second_use() {
            let app = guarded_app_with_store!(
                AuthLevel::Totp,
                config_with_replay_protection("s3cr3t", vec![SECRET]),
                NoopStore::default()
            );
            let code = current_code(SECRET);

            // The first presentation of the code goes through...
            let req = test::TestRequest::get()
                .uri("/x")
                .insert_header(("X-TOTP-Code", code.clone()))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);

            // ...and a repeat of the same code is rejected, though the window is still open.
            let req = test::TestRequest::get()
                .uri("/x")
                .insert_header(("X-TOTP-Code", code))
                .to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }

        #[actix_web::test]
        async fn totp_replay_protection_is_off_by_default() {
            // The default does not change the behaviour of running deployments:
            // the code is replayable, as it was before the protection appeared.
            let app = guarded_app_with_store!(
                AuthLevel::Totp,
                config("s3cr3t", vec![SECRET]),
                NoopStore::default()
            );
            let code = current_code(SECRET);

            for _ in 0..2 {
                let req = test::TestRequest::get()
                    .uri("/x")
                    .insert_header(("X-TOTP-Code", code.clone()))
                    .to_request();
                assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            }
        }

        #[actix_web::test]
        async fn totp_replay_check_fails_open_when_store_unavailable() {
            // An unavailable store must not close the door: both level 3
            // endpoints go to Redis anyway, so a replayed code achieves nothing
            // while the store is down.
            let app = guarded_app_with_store!(
                AuthLevel::Totp,
                config_with_replay_protection("s3cr3t", vec![SECRET]),
                NoopStore::unavailable()
            );
            let code = current_code(SECRET);

            for _ in 0..2 {
                let req = test::TestRequest::get()
                    .uri("/x")
                    .insert_header(("X-TOTP-Code", code.clone()))
                    .to_request();
                assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            }
        }

        #[actix_web::test]
        async fn totp_fingerprint_differs_per_code() {
            // The fingerprint is an HMAC under the secret rather than a bare
            // hash: the contents of Redis are useless to anyone without it.
            let cfg = config_with_replay_protection("s3cr3t", vec![SECRET]);

            let mut first = HeaderMap::new();
            first.insert(
                HeaderName::from_static("x-totp-code"),
                HeaderValue::from_static("111111"),
            );
            let mut second = HeaderMap::new();
            second.insert(
                HeaderName::from_static("x-totp-code"),
                HeaderValue::from_static("222222"),
            );

            let (a, ttl) = cfg.totp_replay_claim(&first).unwrap();
            let (b, _) = cfg.totp_replay_claim(&second).unwrap();

            assert_ne!(a, b);
            assert_ne!(a, "111111", "the code must not end up in the key as is");
            // The window: a step of 30 s and skew 1 in both directions — three steps.
            assert_eq!(ttl, 90);
        }

        #[actix_web::test]
        async fn totp_replay_claim_is_none_without_header() {
            let cfg = config_with_replay_protection("s3cr3t", vec![SECRET]);
            assert!(cfg.totp_replay_claim(&HeaderMap::new()).is_none());
        }
    }
}
