//! The entry point of `jwt-service-app`.
//!
//! An actix-web HTTP service for issuing, verifying and revoking JWTs. The
//! service does not store cryptographic keys itself — that is the job of the
//! external `jwks-service-app` (see [`jwk::JwkService`]). Token identifiers
//! (`jti`) are tracked in Redis (see [`redis::RedisClient`]).
//!
//! This is where the HTTP server is configured and started: logging
//! (`tracing`), CORS, the shared application data (the Redis client and the key
//! manager), the routes and serving the OpenAPI specification.
//!
//! Configuration goes through environment variables (`HOST`, `PORT`,
//! `TOKEN_ALGORITHM` and so on); the full list is in `AGENTS.md`.

use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use std::env;
use std::rc::Rc;
use tracing::info;
use utoipa::OpenApi;

mod auth;
mod error;
mod handlers;
mod issuer;
mod jwk;
mod jwt;
mod key;
mod logging;
mod metrics;
mod models;
mod openapi;
mod rate_limit;
mod redis;
mod sentry_glitchtip;
mod server;
mod tracing_otel;

use crate::auth::{Auth, AuthConfig, AuthLevel};
use crate::handlers::metrics as metrics_handler;
use crate::handlers::{
    create_token, livez, readyz, refresh_token, revoke_subject_tokens, revoke_token, verify_token,
};
use crate::key::KeyManager;
use crate::logging::{init_subscriber, RequestLog};
use crate::rate_limit::{RateLimit, RateLimitConfig};
use crate::redis::RedisClient;
use crate::server::ServerConfig;

/// Restrictive CORS for the NON-public endpoints.
///
/// Not "disabled" but denying: the list of allowed origins is empty, so any
/// cross-origin browser request is rejected by CORS (a preflight `OPTIONS` is
/// refused, and simple requests get no `Access-Control-Allow-Origin`). Requests
/// without an `Origin` header (internal app-to-app, `curl`) go through as usual.
/// It is installed on every endpoint except `POST /tokens/verify`, the single
/// public endpoint under "permissive" CORS. `Cors` is not `Clone`, so a fresh
/// instance is built for each `.wrap`.
fn deny_cors() -> Cors {
    Cors::default()
}

/// Registers every API endpoint with its access level, CORS and rate limit.
///
/// This was extracted from the application factory for a reason: the binding of
/// an endpoint to an access level used to be verified only by reading the code,
/// and that is how `POST /tokens/refresh` once ended up on level 2 instead of
/// level 3 (JWT-28). Now the same function is called by a test that checks the
/// levels against a live application.
///
/// It is generic over the store so that the test can substitute an in-memory
/// mock for Redis.
///
/// **IMPORTANT about CORS.** Permissive CORS is installed SPECIFICALLY on
/// `/tokens/verify` only — that is the ONLY public endpoint worth calling from a
/// browser. Everything else gets `deny_cors()`: it is not disabled but forbids
/// cross-origin requests. When adding new endpoints do NOT put permissive CORS
/// on them without an explicit decision.
fn configure_api<S: crate::models::jwt::JtiStore + 'static>(
    cfg: &mut web::ServiceConfig,
    auth: Rc<AuthConfig>,
    verify_limiter: Option<crate::rate_limit::PerIpLimiter>,
    internal_limiter: Option<crate::rate_limit::GlobalLimiter>,
    cors_origins: &[String],
) {
    let cors = {
        let base = Cors::default()
            .allowed_methods(vec!["POST"])
            .allow_any_header()
            .max_age(3600);
        if cors_origins.is_empty() {
            base.allow_any_origin()
        } else {
            cors_origins
                .iter()
                .fold(base, |cors, origin| cors.allowed_origin(origin))
        }
    };

    cfg
        // Level 3 (TOTP): issuing tokens. The global cap sits inside auth (the
        // last `.wrap` is the outermost), so only requests that passed TOTP
        // consume the ceiling: an unauthenticated flood cannot drain the cap.
        .service(
            web::resource("/tokens")
                .wrap(RateLimit::global(internal_limiter.clone()))
                .wrap(Auth::<S>::new(AuthLevel::Totp, auth.clone()))
                .wrap(deny_cors())
                .route(web::post().to(create_token::<S>)),
        )
        // Level 2 (proxy secret): token verification. Registered before
        // `/tokens/{jti}` so that the `/tokens/verify` path is not swallowed by
        // the pattern. The per-IP limit sits outside auth (the `.wrap` below is
        // the outer one) so that a flood is cut off before the proxy secret is
        // checked. CORS is the outermost layer: a preflight `OPTIONS` (which
        // carries no proxy secret) must be handled by CORS before auth or the
        // rate limiter rejects it.
        .service(
            web::resource("/tokens/verify")
                .wrap(Auth::<S>::new(AuthLevel::ProxySecret, auth.clone()))
                .wrap(RateLimit::per_ip(verify_limiter.clone()))
                .wrap(cors)
                .route(web::post().to(verify_token::<S>)),
        )
        // Level 3 (TOTP): the refresh token exchange. This is an ISSUING
        // operation, just on different grounds — instead of "a trusted backend
        // asked" it is "a valid refresh token was presented". Since
        // `POST /tokens` is behind TOTP, re-issuing has to be there too: the
        // proxy secret is static and does not authenticate the caller, so at
        // level 2 a stolen refresh token would give anyone who can reach through
        // the proxy an endless chain of tokens.
        .service(
            web::resource("/tokens/refresh")
                .wrap(RateLimit::global(internal_limiter.clone()))
                .wrap(Auth::<S>::new(AuthLevel::Totp, auth.clone()))
                .wrap(deny_cors())
                .route(web::post().to(refresh_token::<S>)),
        )
        .service(
            web::resource("/tokens/{jti}")
                .wrap(RateLimit::global(internal_limiter.clone()))
                .wrap(Auth::<S>::new(AuthLevel::Totp, auth.clone()))
                .wrap(deny_cors())
                .route(web::delete().to(revoke_token::<S>)),
        )
        // Level 3 (TOTP): bulk revocation of a subject's tokens. The same
        // wrapping as the single revocation — it is an operation of the same
        // class, only more destructive, and the outside world has no reason to
        // see it.
        .service(
            web::resource("/subjects/{sub}/tokens")
                .wrap(RateLimit::global(internal_limiter.clone()))
                .wrap(Auth::<S>::new(AuthLevel::Totp, auth.clone()))
                .wrap(deny_cors())
                .route(web::delete().to(revoke_subject_tokens::<S>)),
        );

    // Level 4 (bearer token): scraping the metrics. Registered before the open
    // scope, which would otherwise intercept the path.
    //
    // The route appears ONLY when `AUTH_METRICS_TOKEN` is set. When it is not,
    // the endpoint is not published at all and the path returns a plain `404`
    // (picked up by the open scope below). Returning `401` was deliberately
    // avoided: that way the very existence of the endpoint is invisible from the
    // outside.
    if auth.metrics_enabled() {
        cfg.service(
            web::resource("/metrics")
                .wrap(Auth::<S>::new(AuthLevel::MetricsToken, auth.clone()))
                .wrap(deny_cors())
                .route(web::get().to(metrics_handler)),
        );
    }

    // Level 1 (open): the health probes and the OpenAPI spec. The same
    // middleware, but the `Open` validator lets everything through. Registered
    // last — a scope with an empty prefix matches any path, so the token
    // resources above take precedence.
    cfg.service(
        web::scope("")
            .wrap(Auth::<S>::new(AuthLevel::Open, auth.clone()))
            .wrap(deny_cors())
            .route("/api-docs/openapi.json", web::get().to(openapi_spec))
            .service(livez)
            .route("/readyz", web::get().to(readyz::<S>)),
    );
}

/// Serves the OpenAPI specification as JSON.
///
/// Handles `GET /api-docs/openapi.json`; used by the external Swagger UI (see
/// `deployments/dev/docker-compose.yml`).
pub async fn openapi_spec() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(crate::openapi::ApiDoc::openapi().to_json().unwrap())
}

/// Initialises and starts the HTTP server.
///
/// The order of operations:
/// 1. Read the signature algorithm from `TOKEN_ALGORITHM` (`RS256` by default).
/// 2. Set up `tracing` logging (the format from `LOG_FORMAT`, the filter from
///    `RUST_LOG`; see [`logging::init_subscriber`]).
/// 3. Read `HOST`/`PORT` for binding.
/// 4. Create the Redis client and the key manager (panics when Redis is
///    unavailable at startup).
/// 5. Start the `HttpServer`: install permissive CORS on the public
///    `/tokens/verify` endpoint and denying CORS (`deny_cors`) on the rest, and
///    register the routes, the OpenAPI endpoint included. The worker count, the
///    connection timeouts and the drain period on shutdown come from
///    [`ServerConfig`] rather than from the actix defaults (see `server.rs`).
///
/// # Panics
///
/// Panics when `PORT` does not parse as a `u16`, when Redis cannot be reached,
/// when the global `tracing` subscriber cannot be installed, or when the
/// mandatory access level secrets are missing
/// (`AUTH_PROXY_SECRET`/`AUTH_TOTP_SECRET`, see [`AuthConfig::from_env`]).
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let algorithm = env::var("TOKEN_ALGORITHM").unwrap_or("RS256".into());

    // Logging and tracing: the format (`LOG_FORMAT`), the levels (`RUST_LOG`)
    // and the optional OTLP export (`OTEL_EXPORTER_OTLP_ENDPOINT`). The provider
    // is kept alive until the end and shut down after the server stops —
    // otherwise the last spans are never flushed.
    let telemetry = init_subscriber();

    // The Prometheus recorder is installed once per process; the handle renders
    // the exposition text in the `/metrics` handler (see `metrics.rs`).
    let metrics_handle = crate::metrics::init_recorder();

    let host = env::var("HOST").unwrap_or("127.0.0.1".into());
    let port = env::var("PORT")
        .unwrap_or("8080".into())
        .parse::<u16>()
        .unwrap();

    // Only `REDIS_URL` is parsed here: the connection itself is opened on the
    // first command and reused from then on (see `RedisClient::connection`).
    // A Redis that is unavailable at startup does not bring the process down —
    // `/readyz` reports it.
    let redis_client = RedisClient::new().expect("Invalid REDIS_URL");
    let key_manager = KeyManager::new(algorithm);

    // The access level configuration is assembled once. The level 2 and level 3
    // secrets are mandatory: without them the service does not start
    // (fail-fast). A copy is wrapped in an `Rc` inside the application factory
    // for each worker thread.
    let auth_config =
        AuthConfig::from_env().unwrap_or_else(|e| panic!("Invalid access configuration: {e}"));

    // Level 4 is optional (unlike 2 and 3): without a token the metrics are
    // simply not published. We warn so that it does not look like "the metrics
    // broke".
    if !auth_config.metrics_enabled() {
        tracing::warn!(
            "AUTH_METRICS_TOKEN is not set: level 4 is unavailable and the GET /metrics endpoint \
             is not published (it answers 404). Set the token to enable metrics scraping."
        );
    }

    // The rate limiting configuration. Unlike auth, errors here are not fatal —
    // we degrade to safe defaults with a warning (see `rate_limit.rs`). The
    // limiters are built once and shared by every worker thread (inside `Arc`).
    let rate_limit_config = RateLimitConfig::from_env();
    rate_limit_config.log_summary();
    let verify_limiter = rate_limit_config.build_verify();
    let internal_limiter = rate_limit_config.build_internal();
    // Background sweeping of stale per-IP entries — one thread per process.
    if let Some(limiter) = &verify_limiter {
        limiter.spawn_cleanup();
    }

    // The issuer allowlist: empty or unset means any `Host` (the current
    // behaviour), set means issuing and verification only for the listed values.
    crate::issuer::log_summary();

    // The list of CORS origins. Empty or unset means `allow_any_origin` (the
    // current behaviour, so that deployments are not broken); set means only the
    // listed origins.
    let cors_origins: Vec<String> = env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // The worker count and the connection timeouts: at the actix defaults there
    // would be one worker per HOST core (see `server.rs`), and a slow client
    // could hold a worker for as long as it liked.
    let server_config = ServerConfig::from_env();
    server_config.log_summary();

    info!("Starting server on {}:{}", host, port);

    HttpServer::new(move || {
        App::new()
            // Per-request logging is the outermost layer: the span with the
            // `request_id` covers auth, rate limiting, CORS and the handler (see
            // `logging.rs`).
            .wrap(RequestLog)
            .app_data(web::Data::new(redis_client.clone()))
            .app_data(web::Data::new(key_manager.clone()))
            .app_data(web::Data::new(metrics_handle.clone()))
            .configure(|cfg| {
                configure_api::<RedisClient>(
                    cfg,
                    Rc::new(auth_config.clone()),
                    verify_limiter.clone(),
                    internal_limiter.clone(),
                    &cors_origins,
                )
            })
    })
    .workers(server_config.workers)
    .client_request_timeout(server_config.client_request_timeout)
    .keep_alive(server_config.keep_alive)
    // Draining connections on shutdown. The actix default (30 s) coincides with
    // terminationGracePeriodSeconds in the k8s manifest, that is, SIGKILL
    // arrives exactly as the timeout runs out — here it is deliberately shorter
    // so that there is time to flush the telemetry below (see `server.rs`).
    .shutdown_timeout(server_config.shutdown_timeout.as_secs())
    .bind((host, port))?
    .run()
    .await?;

    // The server has stopped — flush the accumulated spans (when tracing is on).
    // The GlitchTip guard flushes its own events when `telemetry` is destroyed.
    if let Some(provider) = telemetry.tracer_provider {
        crate::tracing_otel::shutdown(provider);
    }
    if let Some(provider) = telemetry.logger_provider {
        crate::tracing_otel::shutdown_logs(provider);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Tests of the binding of endpoints to access levels.
    //!
    //! What is checked is not "is the endpoint protected at all" but **which
    //! level** protects it. The difference is fundamental: a "no credentials →
    //! 401" test passes for level 2 and level 3 alike, which is how in JWT-28
    //! the refresh token exchange reached review on level 2 with a fully green
    //! run.
    //!
    //! The technique: send the internal endpoints (level 3) a request with a
    //! **valid proxy secret but no TOTP**. If an endpoint sits on level 2, such
    //! a request passes auth — and the test fails.

    // The reasoning is the same as in `handlers.rs`: `env_guard` deliberately
    // holds a std `MutexGuard` across `.await`. `#[actix_web::test]` runs every
    // test on its own single-threaded runtime, the task does not migrate between
    // threads and there is one per runtime — the lock serialises the tests over
    // the shared environment variables without a risk of deadlock. An async
    // Mutex would be overkill here.
    #![allow(clippy::await_holding_lock)]

    use super::*;
    use actix_web::http::StatusCode;
    use actix_web::test;
    use parking_lot::Mutex as PlMutex;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use crate::models::jwt::{JtiError, JtiStore, RefreshRecord};

    const PROXY_SECRET: &str = "test-proxy-secret";
    const TOTP_SECRET: &str = "MRSWGYLSMUQGO33WNFXGO4ZAOBWGKYLSFVRW63LOMNXW2ZI";

    /// A global environment lock: `AuthConfig::from_env` reads process variables
    /// while the tests run in parallel.
    ///
    /// The guard is taken through a function, as in `handlers.rs`: that way
    /// clippy does not "see" it as held across an `await`, and it also clears
    /// the mutex poisoning left by a panicking test.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A stub store: these tests never reach the handlers, everything is decided
    /// by the auth layer.
    #[derive(Default)]
    struct StubStore {
        jtis: PlMutex<HashSet<String>>,
        groups: PlMutex<HashMap<String, HashSet<String>>>,
    }

    impl JtiStore for StubStore {
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
            Ok(self.groups.lock().remove(group).unwrap_or_default().len() as u64)
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
            Ok(false)
        }

        async fn claim_totp_code(&self, _hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            Ok(true)
        }
    }

    /// Prepares the environment and assembles the access configuration.
    fn auth_config(with_metrics_token: bool) -> Rc<AuthConfig> {
        env::set_var("AUTH_PROXY_SECRET", PROXY_SECRET);
        env::set_var("AUTH_TOTP_SECRET", TOTP_SECRET);
        env::remove_var("AUTH_PROXY_SECRET_HEADER");
        env::remove_var("AUTH_TOTP_HEADER");

        if with_metrics_token {
            env::set_var("AUTH_METRICS_TOKEN", "test-metrics-token");
        } else {
            env::remove_var("AUTH_METRICS_TOKEN");
        }

        Rc::new(AuthConfig::from_env().expect("the access configuration assembles"))
    }

    /// Assembles an application with the same routes as production over the stub.
    macro_rules! api_app {
        ($auth:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new(StubStore::default()))
                    .app_data(web::Data::new(KeyManager::new("RS256".to_string())))
                    // The limiters are off: what is checked here is auth, not 429.
                    .configure(|cfg| configure_api::<StubStore>(cfg, $auth, None, None, &[])),
            )
        };
    }

    /// The level 3 endpoints and how to call them.
    fn internal_endpoints() -> Vec<(&'static str, &'static str)> {
        vec![
            ("POST", "/tokens"),
            ("POST", "/tokens/refresh"),
            ("DELETE", "/tokens/some-jti"),
            ("DELETE", "/subjects/user1/tokens"),
        ]
    }

    #[actix_web::test]
    async fn internal_endpoints_require_totp_not_proxy_secret() {
        let _guard = env_guard();
        let auth = auth_config(false);
        let app = api_app!(auth).await;

        for (method, path) in internal_endpoints() {
            // A valid proxy secret but no TOTP: not enough for level 3.
            let req = match method {
                "POST" => test::TestRequest::post(),
                _ => test::TestRequest::delete(),
            }
            .uri(path)
            .insert_header(("X-Proxy-Secret", PROXY_SECRET))
            .insert_header(("Host", "example.com"))
            .set_json(serde_json::json!({}))
            .to_request();

            let resp = test::call_service(&app, req).await;

            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path} must require TOTP (level 3), not the proxy secret"
            );
        }
    }

    #[actix_web::test]
    async fn internal_endpoints_reject_requests_without_credentials() {
        let _guard = env_guard();
        let auth = auth_config(false);
        let app = api_app!(auth).await;

        for (method, path) in internal_endpoints() {
            let req = match method {
                "POST" => test::TestRequest::post(),
                _ => test::TestRequest::delete(),
            }
            .uri(path)
            .insert_header(("Host", "example.com"))
            .set_json(serde_json::json!({}))
            .to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {path}");
        }
    }

    #[actix_web::test]
    async fn verify_accepts_proxy_secret() {
        let _guard = env_guard();
        let auth = auth_config(false);
        let app = api_app!(auth).await;

        // The body is deliberately incomplete: having passed auth, the request
        // runs into JSON parsing and gets a 400. Telling that apart from a 401
        // matters — a token that is well-formed but invalid in substance is also
        // rejected by the handler with a 401, and such a response would be
        // indistinguishable from an auth refusal.
        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("X-Proxy-Secret", PROXY_SECRET))
            .insert_header(("Host", "example.com"))
            .set_json(serde_json::json!({}))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "/tokens/verify must accept the proxy secret (level 2) and fail on parsing the body"
        );
    }

    #[actix_web::test]
    async fn verify_rejects_request_without_proxy_secret() {
        let _guard = env_guard();
        let auth = auth_config(false);
        let app = api_app!(auth).await;

        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(serde_json::json!({ "token": "not-a-jwt", "audience": "api1" }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn open_endpoints_need_no_credentials() {
        let _guard = env_guard();
        let auth = auth_config(false);
        let app = api_app!(auth).await;

        for path in ["/livez", "/api-docs/openapi.json"] {
            let req = test::TestRequest::get().uri(path).to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{path} — level 1");
        }
    }

    #[actix_web::test]
    async fn metrics_route_is_absent_without_token() {
        let _guard = env_guard();
        let auth = auth_config(false);
        let app = api_app!(auth).await;

        // Without `AUTH_METRICS_TOKEN` the endpoint is not published at all: 404
        // rather than 401 — that way its very existence is invisible from the
        // outside.
        let req = test::TestRequest::get().uri("/metrics").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn metrics_requires_bearer_token() {
        let _guard = env_guard();
        let auth = auth_config(true);
        let app = api_app!(auth).await;

        // Published but behind level 4: neither the proxy secret nor TOTP fits here.
        let req = test::TestRequest::get()
            .uri("/metrics")
            .insert_header(("X-Proxy-Secret", PROXY_SECRET))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
