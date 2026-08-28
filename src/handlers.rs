//! The HTTP handlers of the public API.
//!
//! The module holds the endpoints:
//! - `POST /tokens` — issuing a token ([`create_token`]);
//! - `POST /tokens/verify` — verifying a token ([`verify_token`]);
//! - `DELETE /tokens/{jti}` — revoking a token ([`revoke_token`]);
//! - `POST /tokens/refresh` — exchanging a refresh token ([`refresh_token`]);
//! - `DELETE /subjects/{sub}/tokens` — bulk revocation of a subject's tokens
//!   ([`revoke_subject_tokens`]);
//! - `GET /livez`, `GET /readyz` — the probes ([`livez`], [`readyz`]);
//! - `GET /metrics` — the Prometheus metrics ([`metrics`]).
//!
//! The handlers that work with the `jti` store are generic over the [`JtiStore`]
//! trait and know nothing about the concrete backend (Redis): the store type is
//! supplied when the routes are registered in `main.rs`, and the tests pass an
//! in-memory mock. That is why the routes are assembled by hand
//! (`web::resource(...)`) rather than with the actix attribute macros — those
//! cannot handle generic handlers.
//!
//! The handlers are deliberately thin: all the domain logic lives in
//! [`crate::jwt::JwtManager`] and the models. The value of the `iss` claim (the
//! issuer) comes from the `Host` HTTP header of the incoming request rather than
//! from the configuration; the set of acceptable values is constrained by the
//! allowlist (see [`crate::issuer`]).

use actix_web::{get, web, HttpResponse};
use metrics_exporter_prometheus::PrometheusHandle;
use tracing::{debug, error, info, warn};

use crate::error::*;
use crate::jwt::JwtManager;
use crate::key::KeyManager;
use crate::models::jwt::{subject_group, JtiStore, JwtError};
use crate::models::{
    ErrorResponse, ReadinessResponse, RefreshRequest, RevokeGroupResponse, TokenRequest,
    TokenResponse, TokenVerifyRequest,
};

/// Extracts the `Host` header — the value of the future `iss` claim.
///
/// The common part of every endpoint that deals with the issuer: issuing, the
/// refresh exchange and verification. A missing or non-ASCII header is a client
/// error (`400`).
fn host_header(req: &actix_web::HttpRequest) -> Result<&str, Error> {
    req.headers()
        .get("Host")
        .ok_or(Error::Validation("Missing Host header".into()))?
        .to_str()
        .map_err(|_| Error::Validation("Invalid Host header".into()))
}

/// Extracts the `Host` for the token **issuing** endpoints and checks it against
/// the issuer allowlist (`TOKEN_ISSUER_ALLOWLIST`, see [`crate::issuer`]).
///
/// The refusal is explicit (`403`): issuing is called by a trusted internal
/// client, from which there is no reason to hide the configuration of the
/// instance, and an indistinguishable refusal would have to be debugged blind.
/// An empty allowlist forbids nothing — the previous behaviour.
fn issuer_for_issuance(req: &actix_web::HttpRequest) -> Result<&str, Error> {
    let host = host_header(req)?;
    if !crate::issuer::is_allowed(host) {
        warn!(
            "Issuance refused: issuer '{}' is not in {}",
            host,
            crate::issuer::ALLOWLIST_VAR
        );
        return Err(Error::Forbidden("Issuer not allowed".into()));
    }
    Ok(host)
}

#[utoipa::path(
    post,
    path = "/tokens",
    request_body = TokenRequest,
    security(("totp" = [])),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse, description = "Level 3: the TOTP code is missing or invalid"),
        (status = 403, body = ErrorResponse, description = "`Host` is outside `TOKEN_ISSUER_ALLOWLIST` (when it is set)"),
        (status = 422, body = ErrorResponse),
        (status = 429, body = ErrorResponse, description = "The global cap of the endpoint was exceeded (when enabled)"),
        (status = 500, body = ErrorResponse)
    )
)]
/// Issues a new JWT.
///
/// The request body is a [`TokenRequest`] with `sub` (the subject), `aud` (the
/// audience) and an optional `ttl` (a custom lifetime in seconds). The issuer
/// (`iss`) is taken from the `Host` header. On issue a `jti` is generated and
/// stored in Redis with a TTL equal to the token lifetime.
///
/// # Responses
/// - `200 OK` — a [`TokenResponse`] with the signed token;
/// - `422 Unprocessable Entity` — invalid input (an empty `aud`, an invalid
///   `TOKEN_EXPIRATION_SECONDS` or a `ttl` outside the allowed bounds, for
///   example);
/// - `400 Bad Request` — the `Host` header is missing or invalid;
/// - `403 Forbidden` — `Host` is not in `TOKEN_ISSUER_ALLOWLIST` (when it is set);
/// - `500 Internal Server Error` — other errors (an unavailable JWKS and so on).
///
/// Generic over the `jti` store ([`JtiStore`]) — see the note about the seam at
/// the top of the module.
pub async fn create_token<S: JtiStore + 'static>(
    req: web::Json<TokenRequest>,
    store: web::Data<S>,
    keys: web::Data<KeyManager>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let host_header = issuer_for_issuance(&host)?;

    let issued = if req.refresh {
        JwtManager::generate_token_pair(
            host_header,
            &req.sub,
            &req.aud,
            req.ttl,
            req.claims.clone(),
            &keys,
            store,
        )
        .await
        .map(|(token, refresh)| (token, Some(refresh)))
    } else {
        JwtManager::generate_token(
            host_header,
            &req.sub,
            &req.aud,
            req.ttl,
            req.claims.clone(),
            &keys,
            store,
        )
        .await
        .map(|token| (token, None))
    };

    match issued {
        // The name `refresh` deliberately differs from the field: the exchange
        // handler below is called `refresh_token`, and a variable of the same
        // name would shadow it.
        Ok((token, refresh)) => {
            crate::metrics::record_token_issued();
            Ok(HttpResponse::Ok().json(TokenResponse {
                token,
                refresh_token: refresh,
            }))
        }
        Err(e) => {
            // The level follows the fault: an invalid client request (422) is
            // DEBUG, a dependency failure or internal error (500) is ERROR.
            match e {
                JwtError::UnprocessableEntity => {
                    debug!("Invalid token request parameters: {}", e);
                    Err(Error::Unprocessable(
                        "Invalid token request parameters".into(),
                    ))
                }
                _ => {
                    error!("Failed to issue a token: {}", e);
                    Err(Error::Internal(e.to_string()))
                }
            }
        }
    }
}

#[utoipa::path(
    post,
    path = "/tokens/verify",
    request_body = TokenVerifyRequest,
    security(("proxy_secret" = [])),
    responses(
        (status = 200),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse, description = "Level 2: no proxy secret, or the token is invalid or expired"),
        (status = 429, body = ErrorResponse, description = "The per-IP request limit was exceeded")
    )
)]
/// Verifies a JWT.
///
/// The request body is a [`TokenVerifyRequest`] with the `token` itself and the
/// expected `audience`. What is checked: the signature (against the public key
/// from the JWKS found by `kid`), that `iss` matches the `Host` header (and that
/// it is acceptable per the issuer allowlist), that `audience` is in `aud`, the
/// time bounds (`nbf`/`iat`/`exp`) and the presence of the `jti` in Redis (not
/// revoked).
///
/// # Responses
/// - `200 OK` — the token is valid and its claims are returned in the body;
/// - `401 Unauthorized` — any verification failure (deliberately without
///   details), including a `Host` outside `TOKEN_ISSUER_ALLOWLIST`;
/// - `400 Bad Request` — the `Host` header is missing or invalid.
///
/// Generic over the `jti` store ([`JtiStore`]).
pub async fn verify_token<S: JtiStore + 'static>(
    request: web::Json<TokenVerifyRequest>,
    store: web::Data<S>,
    keys: web::Data<KeyManager>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let host_header = host_header(&host)?;

    // Verification is a public endpoint: we do not reveal the reason for a
    // refusal, and the response is the same as for an expired token. An issuer
    // outside the allowlist means the token was issued by a different
    // installation, even if the signature was made with the shared key.
    if !crate::issuer::is_allowed(host_header) {
        debug!(
            "Token verification refused: issuer '{}' is not in {}",
            host_header,
            crate::issuer::ALLOWLIST_VAR
        );
        return Err(Error::Unauthorized("Invalid or expired token".into()));
    }

    match JwtManager::verify_token(&request.token, host_header, &request.audience, &keys, store)
        .await
    {
        Ok(v) => {
            crate::metrics::record_token_verified(true);
            Ok(HttpResponse::Ok().json(v))
        }
        Err(e) => {
            crate::metrics::record_token_verified(false);
            // The details of the check are deliberately not revealed, so as not
            // to give an attacker any hints — one response for every reason.
            //
            // DEBUG level: an expired, revoked or forged token is a normal event
            // for a public endpoint rather than a service failure. Otherwise
            // every such request would raise ERROR alerts in production.
            debug!("Token verification failed: {}", e);
            Err(Error::Unauthorized("Invalid or expired token".into()))
        }
    }
}

#[utoipa::path(
    delete,
    path = "/tokens/{jti}",
    security(("totp" = [])),
    responses(
        (status = 204, description = "The token was revoked. Idempotent: a `jti` that does not exist also gives 204"),
        (status = 401, body = ErrorResponse, description = "Level 3: the TOTP code is missing or invalid"),
        (status = 429, body = ErrorResponse, description = "The global cap of the endpoint was exceeded (when enabled)"),
        (status = 500, body = ErrorResponse, description = "The store is unavailable — the revocation was NOT performed")
    )
)]
/// Revokes a token by its `jti` identifier.
///
/// It deletes the `jti` record from Redis; after that, verifying the
/// corresponding token in [`verify_token`] fails.
///
/// # Responses
/// - `204 No Content` — the token was revoked. **Idempotent**: a `jti` that does
///   not exist also gives `204`, because the desired state has been reached —
///   there is no such token;
/// - `500 Internal Server Error` — the store is unavailable and the revocation
///   was **not** performed. Telling this case apart from success is mandatory:
///   the caller is revoking a compromised token and must learn that the attempt
///   failed.
///
/// Generic over the `jti` store ([`JtiStore`]).
pub async fn revoke_token<S: JtiStore + 'static>(
    jti: web::Path<String>,
    store: web::Data<S>,
) -> Result<HttpResponse, Error> {
    match store.delete_jti(&jti).await {
        Ok(_) => {
            crate::metrics::record_token_revoked();
            info!("Token revoked");
            Ok(HttpResponse::NoContent().finish())
        }
        Err(e) => {
            // A store failure is our fault, ERROR.
            //
            // The error used to be swallowed and a `204` went out anyway: the
            // caller considered a compromised token revoked and did not retry,
            // while the token stayed active. A silent "success" here is more
            // dangerous than an honest error.
            error!("Failed to revoke the token: {}", e);
            Err(Error::Internal("Failed to revoke token".into()))
        }
    }
}

#[utoipa::path(
    delete,
    path = "/subjects/{sub}/tokens",
    params(("sub" = String, Path, description = "The subject (the `sub` claim) whose tokens are revoked")),
    security(("totp" = [])),
    responses(
        (status = 200, body = RevokeGroupResponse),
        (status = 401, body = ErrorResponse, description = "Level 3: the TOTP code is missing or invalid"),
        (status = 429, body = ErrorResponse, description = "The global cap of the endpoint was exceeded (when enabled)"),
        (status = 500, body = ErrorResponse, description = "The store is unavailable — the revocation was NOT performed")
    )
)]
/// Revokes every active token of a subject.
///
/// Needed on compromise: the caller cannot kill the tokens one by one through
/// `DELETE /tokens/{jti}` — it does not know their `jti` values.
///
/// # Responses
/// - `200 OK` — a [`RevokeGroupResponse`] with the number of revoked tokens
///   (already expired ones do not count, they are invalid anyway);
/// - `500 Internal Server Error` — the store is unavailable. Unlike
///   `DELETE /tokens/{jti}`, the error is **not** swallowed: a silent "success"
///   for a failed revocation of compromised tokens is more dangerous than an
///   honest error.
///
/// Generic over the `jti` store ([`JtiStore`]).
pub async fn revoke_subject_tokens<S: JtiStore + 'static>(
    sub: web::Path<String>,
    store: web::Data<S>,
) -> Result<HttpResponse, Error> {
    match store.revoke_group(&subject_group(&sub)).await {
        Ok(revoked) => {
            for _ in 0..revoked {
                crate::metrics::record_token_revoked();
            }
            info!(revoked, "Every token of the subject was revoked");
            Ok(HttpResponse::Ok().json(RevokeGroupResponse { revoked }))
        }
        Err(e) => {
            // A store failure is our fault, ERROR.
            error!("Failed to revoke the subject's tokens: {}", e);
            Err(Error::Internal("Failed to revoke subject tokens".into()))
        }
    }
}

#[utoipa::path(
    post,
    path = "/tokens/refresh",
    request_body = RefreshRequest,
    security(("totp" = [])),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse, description = "Level 3: no TOTP code, or the refresh token is unknown or already used"),
        (status = 429, body = ErrorResponse, description = "The global cap of the endpoint was exceeded (when enabled)"),
        (status = 500, body = ErrorResponse)
    )
)]
/// Exchanges a refresh token for a new access + refresh pair.
///
/// The old refresh token stops working after the exchange: a new one from the
/// same family is issued. Presenting an already-used token means a leak — the
/// whole family is then killed, the access tokens issued through it included
/// (see [`crate::jwt::JwtManager::refresh`]).
///
/// Access level 3 (TOTP), like `POST /tokens`: an exchange is issuing a token,
/// it just rests on a presented refresh token rather than on a request from a
/// trusted backend. The endpoint is called by the same internal client that
/// issues tokens; the end application never talks to the service directly.
///
/// # Responses
/// - `200 OK` — a [`TokenResponse`] with a new `token` and `refresh_token`;
/// - `401 Unauthorized` — the token is unknown, expired or already used (the
///   details are not revealed, as with token verification);
/// - `403 Forbidden` — `Host` is not in `TOKEN_ISSUER_ALLOWLIST` (when it is set);
/// - `400 Bad Request` — the `Host` header is missing or invalid.
///
/// Generic over the `jti` store ([`JtiStore`]).
pub async fn refresh_token<S: JtiStore + 'static>(
    request: web::Json<RefreshRequest>,
    store: web::Data<S>,
    keys: web::Data<KeyManager>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let host_header = issuer_for_issuance(&host)?;

    match JwtManager::refresh_token_pair(&request.refresh_token, host_header, &keys, store).await {
        Ok((token, refresh)) => {
            crate::metrics::record_token_issued();
            Ok(HttpResponse::Ok().json(TokenResponse {
                token,
                refresh_token: Some(refresh),
            }))
        }
        Err(JwtError::NotValid) => {
            // The reason is not revealed: an unknown, an expired and a replayed
            // token are indistinguishable from the outside — as with the
            // verification of an access token.
            debug!("The refresh token exchange failed");
            Err(Error::Unauthorized("Invalid refresh token".into()))
        }
        Err(e) => {
            error!("Failed to exchange the refresh token: {}", e);
            Err(Error::Internal(e.to_string()))
        }
    }
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "The metrics in the Prometheus text format", content_type = "text/plain")
    )
)]
/// Serves the metrics in the Prometheus exposition format.
///
/// Access level 4: a static bearer token (`AUTH_METRICS_TOKEN`) — one that
/// Prometheus (`authorization: {credentials_file}`), Zabbix `agent2` and the
/// OTel Collector through which Monium scrapes the metrics can all send
/// natively.
///
/// The token is not a substitute for network isolation: the endpoint still
/// should not be exposed publicly, as metrics reveal the operational picture
/// (traffic volume, failure ratios, dependency latencies).
///
/// The route is registered in `main.rs` (not through an attribute macro),
/// because the endpoint is wrapped in the level 4 auth middleware and published
/// **conditionally**: without `AUTH_METRICS_TOKEN` it does not exist at all and
/// the path returns `404`.
pub async fn metrics(handle: web::Data<PrometheusHandle>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(handle.render())
}

#[utoipa::path(
    get,
    path = "/livez",
    responses(
        (status = 200, description = "The process is alive")
    )
)]
/// Liveness probe: it confirms that the process is alive.
///
/// It always returns `200 OK` with no body. Dependencies are not checked — that
/// is what [`readyz`] is for. Intended for the orchestrator's liveness check.
#[get("/livez")]
pub async fn livez() -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[utoipa::path(
    get,
    path = "/readyz",
    responses(
        (status = 200, body = ReadinessResponse, description = "The service is ready to serve requests (`ok` or `degraded`)"),
        (status = 503, body = ReadinessResponse, description = "Requests cannot be served: Redis is unavailable, or the key service has neither answered nor left a usable snapshot")
    )
)]
/// Readiness probe: whether the pod can serve requests.
///
/// It pings the `jti` store and requests the JWKS from `jwks-service-app`
/// (`GET /.well-known/jwks.json`). It returns `200 OK` when we can serve and
/// `503 Service Unavailable` otherwise. In both cases the body is a
/// [`ReadinessResponse`] with a breakdown per dependency.
///
/// **The probe asks not "is the dependency alive" but "can we answer".** The
/// difference concerns only the key service: while a usable JWKS snapshot is in
/// memory, verification works without it (see [`crate::jwk`]), so there is no
/// reason to take the pod out of the load balancer — otherwise the stale cache
/// would not help in exactly the outage it was built for: readiness would kill
/// the pods within ten seconds and traffic would never reach the snapshot in
/// memory. That state is honestly reported as `degraded`, and once the snapshot
/// stops being usable the pod leaves the load balancer on its own.
///
/// The store gets no such leniency: without it the `jti` cannot be checked, so a
/// revoked token would become valid — that is not degradation but a hole.
///
/// Generic over the `jti` store ([`JtiStore`]): the probe reaches it through
/// [`JtiStore::ping`] rather than a concrete backend.
pub async fn readyz<S: JtiStore + 'static>(
    store: web::Data<S>,
    keys: web::Data<KeyManager>,
) -> HttpResponse {
    let store_ok = store.ping().await.is_ok();

    let jwks_live = keys.check_jwks().await.is_ok();
    // The key service did not answer, but the snapshot in memory still serves verification.
    let jwks_stale = !jwks_live && keys.has_servable_jwks_snapshot();
    let jwks_ok = jwks_live || jwks_stale;

    let ready = store_ok && jwks_ok;

    let body = ReadinessResponse {
        status: match (ready, jwks_stale) {
            (false, _) => "unavailable",
            (true, true) => "degraded",
            (true, false) => "ok",
        }
        .into(),
        // The response field really is called `redis` — that is the public
        // contract of the probe, which dashboards and alerts depend on; renaming
        // it would break them for the sake of cosmetics.
        redis: store_ok,
        jwks: jwks_ok,
        jwks_stale,
    };

    if ready {
        HttpResponse::Ok().json(body)
    } else {
        HttpResponse::ServiceUnavailable().json(body)
    }
}

#[cfg(test)]
mod tests {
    //! HTTP layer tests: health/readiness and the full token life cycle.
    //!
    //! `livez` does not depend on the environment. For `readyz` the dependencies
    //! (Redis and `jwks-service-app`) are pointed at deliberately unreachable
    //! addresses so that the `503` branch is checked deterministically without
    //! real infrastructure.
    //!
    //! The token endpoints are exercised through `actix_web::test`: the `jti`
    //! store is replaced by the in-memory [`MockStore`] (no Redis needed) and
    //! the key service `jwks-service-app` is brought up as an HTTP mock
    //! ([`wiremock`]) — that way the tests run in CI without real
    //! infrastructure. Some checks construct tokens directly (expired, signed by
    //! someone else), which cannot be achieved through the public API.
    //!
    //! The handlers are generic over the store, so the tests register the same
    //! functions as production ([`create_token`] and the rest) — just with
    //! [`MockStore`] instead of Redis. There are no separate "test"
    //! implementations.

    // `env_guard` deliberately holds a std `MutexGuard` across `.await`:
    // `#[actix_web::test]` runs every test on its own single-threaded runtime,
    // the task does not migrate between threads and there is one per runtime — so
    // the lock serialises the tests over the shared environment variables without
    // a risk of deadlock. An async Mutex would be overkill here.
    #![allow(clippy::await_holding_lock)]

    use super::*;
    use crate::models::jwt::{JsonWebToken, JtiError, RefreshRecord, TokenClaims, TokenHeaders};
    use crate::models::TokenResponse;
    use crate::redis::RedisClient;
    use actix_web::http::header::HeaderValue;
    use actix_web::http::StatusCode;
    use actix_web::{test, App};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use chrono::Utc;
    use openssl::pkey::{PKey, Private};
    use parking_lot::Mutex as PlMutex;
    use serde_json::json;
    use std::collections::{HashMap, HashSet};
    use std::env;
    use std::sync::Mutex;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The token tests modify process-global environment variables
    /// (`JWKS_SERVICE_URL`, `TOKEN_ALGORITHM`, ...) and the address of the JWKS
    /// mock, so they run strictly sequentially. `readyz` touches
    /// `JWKS_SERVICE_URL` too and therefore takes the same lock. We recover from
    /// poisoning (`into_inner`) so that a panic in one test does not take the
    /// rest down.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// An in-memory implementation of [`JtiStore`] for the HTTP layer tests.
    ///
    /// The groups are maintained for real (`group -> set of jti`), or the bulk
    /// revocation tests would only be checking the response code rather than the
    /// revocation itself.
    struct MockStore {
        jtis: PlMutex<HashSet<String>>,
        groups: PlMutex<HashMap<String, HashSet<String>>>,
        /// The refresh token records and the used flag.
        refreshes: PlMutex<HashMap<String, (RefreshRecord, bool)>>,
        /// The fingerprints of the TOTP codes already presented.
        used_codes: PlMutex<HashSet<String>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                jtis: PlMutex::new(HashSet::new()),
                groups: PlMutex::new(HashMap::new()),
                refreshes: PlMutex::new(HashMap::new()),
                used_codes: PlMutex::new(HashSet::new()),
            }
        }
    }

    impl JtiStore for MockStore {
        async fn ping(&self) -> Result<(), JtiError> {
            Ok(())
        }

        async fn store_jti(&self, jti: &str, _ttl: u64) -> Result<(), JtiError> {
            self.jtis.lock().insert(jti.to_string());
            Ok(())
        }

        async fn check_jti(&self, jti: &str) -> Result<bool, JtiError> {
            Ok(self.jtis.lock().contains(jti))
        }

        async fn delete_jti(&self, jti: &str) -> Result<(), JtiError> {
            self.jtis.lock().remove(jti);
            Ok(())
        }

        async fn add_to_group(
            &self,
            group: &str,
            jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            self.groups
                .lock()
                .entry(group.to_string())
                .or_default()
                .insert(jti.to_string());
            Ok(())
        }

        async fn revoke_group(&self, group: &str) -> Result<u64, JtiError> {
            let members = self.groups.lock().remove(group).unwrap_or_default();

            let mut refreshes = self.refreshes.lock();
            let mut jtis = self.jtis.lock();

            // The family group holds both `jti` values and the keys of refresh
            // records — we kill both, exactly as `DEL` does in Redis.
            let revoked = members
                .iter()
                .filter(|member| {
                    let refresh_removed = member
                        .strip_prefix("refresh:")
                        .is_some_and(|id| refreshes.remove(id).is_some());
                    jtis.remove(*member) || refresh_removed
                })
                .count();

            Ok(revoked as u64)
        }

        async fn store_refresh(
            &self,
            id: &str,
            record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            self.refreshes
                .lock()
                .insert(id.to_string(), (record.clone(), false));
            Ok(())
        }

        async fn get_refresh(&self, id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Ok(self
                .refreshes
                .lock()
                .get(id)
                .map(|(record, _)| record.clone()))
        }

        async fn mark_refresh_used(&self, id: &str) -> Result<bool, JtiError> {
            let mut refreshes = self.refreshes.lock();

            match refreshes.get_mut(id) {
                // Already used — a repeat presentation.
                Some((_, true)) => Ok(false),
                Some((_, used)) => {
                    *used = true;
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        async fn claim_totp_code(&self, hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            // `insert` returns false when the element was already there — that is the replay.
            Ok(self.used_codes.lock().insert(hash.to_string()))
        }
    }

    /// A [`JtiStore`] where every operation fails: it simulates an unavailable
    /// store.
    ///
    /// Needed where what is checked is not the result of an operation but the
    /// honesty of the response on failure: `MockStore` always succeeds and does
    /// not cover that branch.
    struct UnavailableStore;

    impl JtiStore for UnavailableStore {
        async fn ping(&self) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn store_jti(&self, _jti: &str, _ttl: u64) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn check_jti(&self, _jti: &str) -> Result<bool, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn delete_jti(&self, _jti: &str) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn add_to_group(
            &self,
            _group: &str,
            _jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn revoke_group(&self, _group: &str) -> Result<u64, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn store_refresh(
            &self,
            _id: &str,
            _record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn get_refresh(&self, _id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn mark_refresh_used(&self, _id: &str) -> Result<bool, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn claim_totp_code(&self, _hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            Err(JtiError::BadConnection)
        }
    }

    /// A test Ed25519 key and its JWK representation.
    ///
    /// `EdDSA` was chosen because signing and verification go without an
    /// explicit digest — exactly as in [`JsonWebToken::to_string`] /
    /// `from_string`, which guarantees the round trip (see also the unit tests
    /// in `models/jwt.rs`).
    struct TestKey {
        pkey: PKey<Private>,
        kid: String,
        /// The private key as base64url(PKCS#8 DER) — the format of the JWK `private_key` field.
        private_b64: String,
        /// The raw public key as base64url — the `x` component of an OKP JWK.
        x_b64: String,
    }

    fn make_key(kid: &str) -> TestKey {
        let pkey = PKey::generate_ed25519().unwrap();
        let pkcs8 = pkey.private_key_to_pkcs8().unwrap();
        let raw_public = pkey.raw_public_key().unwrap();
        TestKey {
            kid: kid.to_string(),
            private_b64: URL_SAFE_NO_PAD.encode(&pkcs8),
            x_b64: URL_SAFE_NO_PAD.encode(&raw_public),
            pkey,
        }
    }

    /// Brings up an HTTP mock of `jwks-service-app` that serves the private key
    /// on issue (`POST /jwks`) and the public one on verification
    /// (`GET /.well-known/jwks.json`).
    async fn start_jwks_mock(key: &TestKey) -> MockServer {
        let server = MockServer::start().await;

        let jwk_data = json!({
            "id": key.kid, "kty": "OKP", "alg": "EdDSA", "kid": key.kid,
            "crv": "Ed25519", "x": key.x_b64, "y": null, "n": null, "e": null,
            "private_key": key.private_b64,
        });
        Mock::given(method("POST"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwk_data))
            .mount(&server)
            .await;

        let jwks = json!({ "keys": [ {
            "kty": "OKP", "alg": "EdDSA", "kid": key.kid, "crv": "Ed25519",
            "x": key.x_b64, "y": null, "n": null, "e": null,
        } ] });
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;

        server
    }

    /// Points the environment at the test JWKS mock with the `EdDSA` algorithm
    /// and the default TTL bounds. Requires [`env_guard`] to be held.
    fn set_jwks_env(server: &MockServer) {
        env::set_var("JWKS_SERVICE_URL", server.uri());
        env::set_var("TOKEN_ALGORITHM", "EdDSA");
        env::remove_var("TOKEN_JKU");
        env::remove_var("TOKEN_EXPIRATION_SECONDS");
        env::remove_var("TOKEN_TTL_MIN_SECONDS");
        env::remove_var("TOKEN_TTL_MAX_SECONDS");
        env::remove_var(crate::issuer::ALLOWLIST_VAR);
    }

    /// Assembles a test application with the token endpoints over [`MockStore`].
    ///
    /// It is a macro so that the unwieldy `App<impl ServiceFactory<...>>` type
    /// does not have to be spelled out. `KeyManager` is constructed here and
    /// reads `JWKS_SERVICE_URL` — call it after [`set_jwks_env`].
    macro_rules! token_app {
        ($store:expr) => {{
            let keys = web::Data::new(KeyManager::new("EdDSA".to_string()));
            App::new()
                .app_data($store)
                .app_data(keys)
                .route("/tokens", web::post().to(create_token::<MockStore>))
                .route("/tokens/verify", web::post().to(verify_token::<MockStore>))
                .route("/tokens/{jti}", web::delete().to(revoke_token::<MockStore>))
                .route(
                    "/subjects/{sub}/tokens",
                    web::delete().to(revoke_subject_tokens::<MockStore>),
                )
                .route(
                    "/tokens/refresh",
                    web::post().to(refresh_token::<MockStore>),
                )
        }};
    }

    /// Issues a token for the subject `$sub` through the test application.
    ///
    /// A macro rather than a function: the application type from `init_service`
    /// cannot be written out without a pile of generics (the same reason as for
    /// `token_app!`).
    macro_rules! issue_token {
        ($app:expr, $sub:expr) => {{
            let req = test::TestRequest::post()
                .uri("/tokens")
                .insert_header(("Host", "example.com"))
                .set_json(json!({ "sub": $sub, "aud": ["api1"] }))
                .to_request();
            let resp = test::call_service($app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let issued: TokenResponse = test::read_body_json(resp).await;
            issued.token
        }};
    }

    /// Extracts the `jti` from the claims segment of a serialised token.
    fn jti_of(token: &str) -> String {
        let claims_segment = token.split('.').nth(1).expect("no claims segment");
        TokenClaims::from_base64(claims_segment.to_string())
            .expect("the claims do not decode")
            .jti
    }

    #[actix_web::test]
    async fn livez_returns_200() {
        let app = test::init_service(App::new().service(livez)).await;
        let req = test::TestRequest::get().uri("/livez").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn metrics_route_absent_gives_404() {
        // Without a token the route is not registered (see `main.rs`) — the path
        // must behave like any non-existent one: 404, not 401. That way its very
        // existence is invisible from the outside.
        let app = test::init_service(App::new().service(livez)).await;

        for req in [
            test::TestRequest::get().uri("/metrics").to_request(),
            test::TestRequest::get()
                .uri("/metrics")
                .insert_header(("Authorization", "Bearer anything"))
                .to_request(),
        ] {
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
    }

    #[actix_web::test]
    async fn metrics_returns_prometheus_exposition() {
        // A local recorder: the global one is installed once per process and is
        // unavailable in tests (see `metrics.rs`).
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        ::metrics::with_local_recorder(&recorder, || {
            crate::metrics::record_token_issued();
        });

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(handle))
                .route("/metrics", web::get().to(super::metrics)),
        )
        .await;
        let req = test::TestRequest::get().uri("/metrics").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(content_type.starts_with("text/plain"));

        let body = test::read_body(resp).await;
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("jwt_tokens_issued_total"));
    }

    #[actix_web::test]
    async fn readyz_reports_ready_over_arbitrary_store() {
        let _guard = env_guard();

        // The probe reaches the store through the trait rather than Redis: with
        // any working `JtiStore` and a live key service the pod is ready. That is
        // the seam check — `readyz` used to be nailed to `RedisClient` and such a
        // test was impossible.
        let key = make_key("kid-ready-ok");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let keys = KeyManager::new("EdDSA".to_string());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(MockStore::new()))
                .app_data(web::Data::new(keys))
                .route("/readyz", web::get().to(readyz::<MockStore>)),
        )
        .await;

        let req = test::TestRequest::get().uri("/readyz").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: ReadinessResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, "ok");
        assert!(body.redis);
        assert!(body.jwks);
        assert!(!body.jwks_stale);
    }

    #[actix_web::test]
    async fn readyz_reports_503_when_store_ping_fails() {
        let _guard = env_guard();

        // The key service is alive and only the store fails: without it the `jti`
        // cannot be checked, so a revoked token would become valid — that is not
        // degradation but a reason to leave the load balancer.
        let key = make_key("kid-ready-nostore");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let keys = KeyManager::new("EdDSA".to_string());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(UnavailableStore))
                .app_data(web::Data::new(keys))
                .route("/readyz", web::get().to(readyz::<UnavailableStore>)),
        )
        .await;

        let req = test::TestRequest::get().uri("/readyz").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body: ReadinessResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, "unavailable");
        assert!(!body.redis);
        assert!(body.jwks);
    }

    #[actix_web::test]
    async fn readyz_reports_503_when_dependencies_unavailable() {
        let _guard = env_guard();

        // Port 1 is guaranteed to be unreachable — both Redis and the JWKS fail
        // fast with "connection refused" regardless of the environment.
        env::set_var("REDIS_URL", "redis://127.0.0.1:1");
        env::set_var("JWKS_SERVICE_URL", "http://127.0.0.1:1");

        let redis = RedisClient::new().unwrap();
        let keys = KeyManager::new("RS256".to_string());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(redis))
                .app_data(web::Data::new(keys))
                .route("/readyz", web::get().to(readyz::<RedisClient>)),
        )
        .await;

        let req = test::TestRequest::get().uri("/readyz").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body: ReadinessResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, "unavailable");
        assert!(!body.redis);
        assert!(!body.jwks);
    }

    #[actix_web::test]
    async fn readyz_counts_jwks_as_ready_while_snapshot_serves() {
        let _guard = env_guard();

        let key = make_key("kid-ready");
        let server = MockServer::start().await;

        // The key service answers exactly once — that warms the cache up — and is
        // down from then on.
        let jwks = json!({ "keys": [ {
            "kty": "OKP", "alg": "EdDSA", "kid": key.kid, "crv": "Ed25519",
            "x": key.x_b64, "y": null, "n": null, "e": null,
        } ] });
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        env::set_var("REDIS_URL", "redis://127.0.0.1:1");
        set_jwks_env(&server);
        env::remove_var("JWKS_CACHE_TTL_SECONDS");
        env::remove_var("JWKS_CACHE_STALE_GRACE_SECONDS");

        let redis = RedisClient::new().unwrap();
        let keys = KeyManager::new("EdDSA".to_string());

        // The snapshot lands in memory during verification rather than through
        // the probe: `check_jwks` deliberately goes to the network past the cache.
        assert!(keys.get_public_key(&key.kid).await.is_ok());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(redis))
                .app_data(web::Data::new(keys))
                .route("/readyz", web::get().to(readyz::<RedisClient>)),
        )
        .await;

        let req = test::TestRequest::get().uri("/readyz").to_request();
        let resp = test::call_service(&app, req).await;

        // Redis is unavailable in this test, so the pod is not ready anyway — but
        // as far as the key service goes, readiness rests on the snapshot, and it
        // is visible that it rests on exactly that.
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body: ReadinessResponse = test::read_body_json(resp).await;
        assert!(body.jwks);
        assert!(body.jwks_stale);
        assert!(!body.redis);
    }

    // --- The token endpoints ---

    /// The end-to-end scenario: issue → verify(ok) → revoke → verify(fail).
    #[actix_web::test]
    async fn token_lifecycle_issue_verify_revoke_verify() {
        let _guard = env_guard();
        let key = make_key("test-key-1");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store.clone())).await;

        // Issue.
        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "user1", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let issued: TokenResponse = test::read_body_json(resp).await;
        let jti = jti_of(&issued.token);

        // Verifying the issued token — success.
        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": issued.token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Revocation.
        let req = test::TestRequest::delete()
            .uri(&format!("/tokens/{}", jti))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Verifying the same token again — now a refusal (the jti is revoked).
        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": issued.token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// A `ttl` below the lower bound (1 second by default) → 422.
    #[actix_web::test]
    async fn create_token_rejects_ttl_below_min() {
        let _guard = env_guard();
        let key = make_key("k");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "u", "aud": ["api1"], "ttl": 0 }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// A `ttl` above the upper bound (86400 seconds by default) → 422.
    #[actix_web::test]
    async fn create_token_rejects_ttl_above_max() {
        let _guard = env_guard();
        let key = make_key("k");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "u", "aud": ["api1"], "ttl": 100_000 }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// An empty `aud` → 422.
    #[actix_web::test]
    async fn create_token_rejects_empty_audience() {
        let _guard = env_guard();
        let key = make_key("k");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "u", "aud": [] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// A missing `Host` header → 400 (checked before the JWKS is contacted).
    #[actix_web::test]
    async fn create_token_missing_host_returns_400() {
        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .set_json(json!({ "sub": "u", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// An invalid (non-ASCII) `Host` header → 400.
    #[actix_web::test]
    async fn create_token_invalid_host_returns_400() {
        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            // 0xFF does not decode as ASCII, so `to_str()` returns an error.
            .insert_header(("Host", HeaderValue::from_bytes(&[0xFF, 0xFE]).unwrap()))
            .set_json(json!({ "sub": "u", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// The issuer allowlist: a `Host` outside the list does not issue a token
    /// (403) while a listed one does.
    ///
    /// This is the hole being closed: an instance `a.example.com` that shares
    /// keys with `b.example.com` must not sign tokens with someone else's `iss`.
    #[actix_web::test]
    async fn create_token_rejects_issuer_outside_allowlist() {
        let _guard = env_guard();
        let key = make_key("kid-allowlist");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);
        env::set_var(crate::issuer::ALLOWLIST_VAR, "a.example.com");

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "b.example.com"))
            .set_json(json!({ "sub": "u", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "a.example.com"))
            .set_json(json!({ "sub": "u", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        env::remove_var(crate::issuer::ALLOWLIST_VAR);
    }

    /// An empty allowlist is the previous behaviour: any `Host` issues a token.
    #[actix_web::test]
    async fn create_token_allows_any_issuer_without_allowlist() {
        let _guard = env_guard();
        let key = make_key("kid-no-allowlist");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "whatever.example.net"))
            .set_json(json!({ "sub": "u", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Verifying a token with a `Host` outside the allowlist → 401, like any
    /// other verification refusal: a public endpoint does not reveal the reason.
    #[actix_web::test]
    async fn verify_rejects_issuer_outside_allowlist() {
        let _guard = env_guard();
        let key = make_key("kid-allowlist-verify");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        // The token was issued while there were no constraints...
        let token = issue_token!(&app, "user1");

        // ...and after the allowlist was enabled its issuer became foreign.
        env::set_var(crate::issuer::ALLOWLIST_VAR, "other.example.com");
        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        env::remove_var(crate::issuer::ALLOWLIST_VAR);
    }

    /// Verifying an expired token → 401. The `jti` is present in the store so
    /// that the only reason for the refusal is an `exp` in the past.
    #[actix_web::test]
    async fn verify_rejects_expired_token() {
        let _guard = env_guard();
        let key = make_key("test-key-1");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        store.store_jti("expired-jti", 3600).await.unwrap();
        let app = test::init_service(token_app!(store.clone())).await;

        let now = Utc::now().timestamp() as usize;
        let headers = TokenHeaders::create_new(key.kid.clone());
        let claims = TokenClaims {
            iss: "example.com".into(),
            sub: "u".into(),
            aud: vec!["api1".into()],
            exp: now - 10,
            iat: now - 3600,
            nbf: now - 3600,
            jti: "expired-jti".into(),
            extra: Default::default(),
        };
        let token = JsonWebToken::create_new(headers, claims, key.pkey.clone())
            .to_string()
            .unwrap();

        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Verifying a token with a foreign signature → 401. The token is signed
    /// with the attacker's key but carries the same `kid`; the public key from
    /// the JWKS does not confirm it.
    #[actix_web::test]
    async fn verify_rejects_forged_signature() {
        let _guard = env_guard();
        let key = make_key("test-key-1");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        store.store_jti("forged-jti", 3600).await.unwrap();
        let app = test::init_service(token_app!(store.clone())).await;

        let attacker = make_key("test-key-1");
        let now = Utc::now().timestamp() as usize;
        let headers = TokenHeaders::create_new(key.kid.clone());
        let claims = TokenClaims {
            iss: "example.com".into(),
            sub: "u".into(),
            aud: vec!["api1".into()],
            exp: now + 3600,
            iat: now,
            nbf: now,
            jti: "forged-jti".into(),
            extra: Default::default(),
        };
        let token = JsonWebToken::create_new(headers, claims, attacker.pkey.clone())
            .to_string()
            .unwrap();

        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Verifying a syntactically corrupt token → 401 (without contacting the JWKS).
    #[actix_web::test]
    async fn verify_rejects_malformed_token() {
        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": "not-a-jwt", "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Revoking a `jti` that does not exist is idempotent → always 204.
    #[actix_web::test]
    async fn revoke_unknown_jti_returns_204() {
        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::delete()
            .uri("/tokens/does-not-exist")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[actix_web::test]
    async fn revoke_reports_store_failure_instead_of_204() {
        // The store is unavailable — the revocation was not performed and the
        // client must learn that. The previous behaviour (always `204`) meant
        // the caller considered a compromised token killed and did not retry.
        let store = web::Data::new(UnavailableStore);
        let app = test::init_service(App::new().app_data(store).route(
            "/tokens/{jti}",
            web::delete().to(revoke_token::<UnavailableStore>),
        ))
        .await;

        let req = test::TestRequest::delete()
            .uri("/tokens/some-jti")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[actix_web::test]
    async fn revoking_subject_kills_all_its_tokens() {
        let _guard = env_guard();
        let key = make_key("kid-bulk");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store.clone())).await;

        // Three tokens for one subject and one for another.
        let mut tokens = Vec::new();
        for _ in 0..3 {
            tokens.push(issue_token!(&app, "victim"));
        }
        let bystander = issue_token!(&app, "bystander");

        let req = test::TestRequest::delete()
            .uri("/subjects/victim/tokens")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: RevokeGroupResponse = test::read_body_json(resp).await;
        assert_eq!(body.revoked, 3);

        // The subject's tokens no longer pass verification...
        for token in &tokens {
            assert!(!store.check_jti(&jti_of(token)).await.unwrap());
        }
        // ...while the other one is untouched.
        assert!(store.check_jti(&jti_of(&bystander)).await.unwrap());
    }

    #[actix_web::test]
    async fn revoking_unknown_subject_is_idempotent() {
        let _guard = env_guard();
        let key = make_key("kid-none");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::delete()
            .uri("/subjects/nobody/tokens")
            .to_request();
        let resp = test::call_service(&app, req).await;

        // There is nothing to revoke — that is not an error.
        assert_eq!(resp.status(), StatusCode::OK);
        let body: RevokeGroupResponse = test::read_body_json(resp).await;
        assert_eq!(body.revoked, 0);
    }

    /// Issues an access + refresh pair through the test application.
    macro_rules! issue_pair {
        ($app:expr, $sub:expr) => {{
            let req = test::TestRequest::post()
                .uri("/tokens")
                .insert_header(("Host", "example.com"))
                .set_json(json!({ "sub": $sub, "aud": ["api1"], "refresh": true }))
                .to_request();
            let resp = test::call_service($app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let issued: TokenResponse = test::read_body_json(resp).await;
            let refresh = issued.refresh_token.clone().expect("no refresh token");
            (issued.token, refresh)
        }};
    }

    /// Exchanges a refresh token, returning the whole response.
    macro_rules! exchange {
        ($app:expr, $refresh:expr) => {{
            let req = test::TestRequest::post()
                .uri("/tokens/refresh")
                .insert_header(("Host", "example.com"))
                .set_json(json!({ "refresh_token": $refresh }))
                .to_request();
            test::call_service($app, req).await
        }};
    }

    #[actix_web::test]
    async fn refresh_is_absent_unless_requested() {
        let _guard = env_guard();
        let key = make_key("kid-norefresh");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "user1", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // The contract of existing clients has not changed: the field is absent from the response.
        let issued: TokenResponse = test::read_body_json(resp).await;
        assert!(issued.refresh_token.is_none());
    }

    #[actix_web::test]
    async fn refresh_rotates_and_old_token_stops_working() {
        let _guard = env_guard();
        let key = make_key("kid-rotate");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store.clone())).await;

        let (_access, refresh) = issue_pair!(&app, "user1");

        // The exchange hands out a new pair...
        let resp = exchange!(&app, &refresh);
        assert_eq!(resp.status(), StatusCode::OK);
        let refreshed: TokenResponse = test::read_body_json(resp).await;
        let new_refresh = refreshed.refresh_token.expect("no new refresh token");
        assert_ne!(new_refresh, refresh);

        // ...and the new access token is valid.
        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": refreshed.token, "audience": "api1" }))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn reused_refresh_kills_the_whole_family() {
        let _guard = env_guard();
        let key = make_key("kid-reuse");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store.clone())).await;

        let (first_access, refresh) = issue_pair!(&app, "user1");

        // A legitimate exchange.
        let resp = exchange!(&app, &refresh);
        assert_eq!(resp.status(), StatusCode::OK);
        let refreshed: TokenResponse = test::read_body_json(resp).await;
        let new_refresh = refreshed.refresh_token.expect("no new refresh token");

        // Presenting the old token again is a sign of theft.
        let resp = exchange!(&app, &refresh);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // The whole family is killed: the issued access tokens...
        assert!(!store.check_jti(&jti_of(&first_access)).await.unwrap());
        assert!(!store.check_jti(&jti_of(&refreshed.token)).await.unwrap());

        // ...and the refresh token handed out in the legitimate exchange.
        let resp = exchange!(&app, &new_refresh);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn unknown_refresh_is_rejected() {
        let _guard = env_guard();
        let key = make_key("kid-unknown-refresh");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let resp = exchange!(&app, "no-such-token");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// A refresh token exchange is issuing, so a `Host` outside the allowlist is
    /// rejected just as explicitly (403) as for `POST /tokens`.
    #[actix_web::test]
    async fn refresh_rejects_issuer_outside_allowlist() {
        let _guard = env_guard();
        let key = make_key("kid-allowlist-refresh");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let (_access, refresh) = issue_pair!(&app, "user1");

        // The exchange macro sends `Host: example.com` — now outside the list.
        env::set_var(crate::issuer::ALLOWLIST_VAR, "other.example.com");
        let resp = exchange!(&app, &refresh);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        env::remove_var(crate::issuer::ALLOWLIST_VAR);
    }

    #[actix_web::test]
    async fn custom_claims_land_in_issued_token() {
        let _guard = env_guard();
        let key = make_key("kid-claims");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({
                "sub": "user1",
                "aud": ["api1"],
                "claims": { "role": "admin", "tenant": 42 }
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let issued: TokenResponse = test::read_body_json(resp).await;

        // We parse the payload and check that the claims sit alongside the
        // registered ones — the consumer of the token looks for `role`, not
        // `extra.role`.
        let payload = issued.token.split('.').nth(1).expect("no claims segment");
        let decoded = URL_SAFE_NO_PAD.decode(payload).expect("base64url");
        let value: serde_json::Value = serde_json::from_slice(&decoded).expect("JSON");

        assert_eq!(value["role"], "admin");
        assert_eq!(value["tenant"], 42);
        assert_eq!(value["sub"], "user1");
    }

    #[actix_web::test]
    async fn reserved_custom_claim_gives_422() {
        let _guard = env_guard();
        let key = make_key("kid-reserved");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        // Substituting `exp` would bypass the TTL bounds — the endpoint must refuse.
        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({
                "sub": "user1",
                "aud": ["api1"],
                "claims": { "exp": 9999999999u64 }
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[actix_web::test]
    async fn token_without_claims_is_unchanged() {
        let _guard = env_guard();
        let key = make_key("kid-noclaims");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        // The contract of existing clients: without a `claims` field the payload
        // stays exactly as it was before this feature appeared.
        let token = issue_token!(&app, "user1");
        let payload = token.split('.').nth(1).expect("no claims segment");
        let decoded = URL_SAFE_NO_PAD.decode(payload).expect("base64url");
        let value: serde_json::Value = serde_json::from_slice(&decoded).expect("JSON");

        let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 7, "extra fields in the payload: {keys:?}");
    }
}
