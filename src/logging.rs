//! Logging initialisation and the per-request middleware.
//!
//! The foundation of observability: a single setup of the `tracing` subscriber
//! (the format is picked through the environment) and the [`RequestLog`]
//! middleware, which opens a structured span with a `request_id` for every
//! request and, on completion, writes one line with the method, path, status and
//! latency.
//!
//! ## What is NOT logged
//!
//! We deliberately **do not** write request or response headers and bodies —
//! they hold secrets (`X-Proxy-Secret`, `X-TOTP-Code`) and the tokens
//! themselves. Only the method, path, status, latency, `request_id` and a
//! best-effort client IP reach the log.
//!
//! ## Format
//!
//! `LOG_FORMAT=json` gives line-delimited JSON for machine collection
//! (Monium/ELK and the like); any other value (the default) gives the
//! human-readable `pretty` format with ANSI. Levels are filtered through
//! `RUST_LOG` (`EnvFilter`), with `jwt_service_app=info` as the default.
//!
//! ## Level policy
//!
//! `tracing` has five levels: `TRACE < DEBUG < INFO < WARN < ERROR`. There is no
//! separate `CRITICAL`/`FATAL` — fatal situations in this service are expressed
//! as a panic at startup (fail-fast on invalid configuration), not as a log
//! level.
//!
//! The level is chosen **by who is at fault and what follows**, not by how
//! "serious" the text sounds:
//!
//! - **ERROR** — the service could not do its job: a dependency failure (Redis,
//!   JWKS), a crypto failure while signing, invalid key material. It needs the
//!   on-call engineer's attention and is a suitable source of alerts.
//! - **WARN** — degradation or a security signal, but the request was handled:
//!   configuration problems (with a fallback to the default), access denied
//!   (401), the rate limit firing (429).
//! - **INFO** — lifecycle and business events: server start, the configuration
//!   summary, request completion (`request completed`), a token revoked.
//! - **DEBUG** — the client's fault and internal detail: a corrupt, expired or
//!   forged token, parameters out of bounds, the steps of a JWKS call.
//!   **Important:** client errors are deliberately NOT at ERROR — otherwise any
//!   malformed request would raise false alerts.
//! - **TRACE** — unused.
//!
//! An error is logged by the layer that knows the **cause** (for example
//! `jwk.rs` logs a JWKS failure at ERROR); the layers above record the outcome
//! at DEBUG so that duplicates are not multiplied.

use std::env;
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::time::Instant;

use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::Error;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};
use uuid::Uuid;

/// Name of the end-to-end request identifier header (lower case — a requirement
/// of `HeaderName::from_static`).
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Maximum accepted length of an externally supplied `X-Request-Id`.
const REQUEST_ID_MAX_LEN: usize = 128;

/// Initialises the global `tracing` subscriber.
///
/// It is assembled from layers over a shared `Registry` — that is the single
/// telemetry bus:
/// - the level filter (`RUST_LOG`, default `jwt_service_app=info`);
/// - log output (`LOG_FORMAT`: `json` gives line-delimited JSON, otherwise
///   `pretty`);
/// - an optional OpenTelemetry layer when `OTEL_EXPORTER_OTLP_ENDPOINT` is set
///   (see [`crate::tracing_otel`]);
/// - an optional GlitchTip layer when `GLITCHTIP_DSN` is set
///   (see [`crate::sentry_glitchtip`]).
///
/// Returns a [`Telemetry`] — the live resources (the trace provider and the
/// GlitchTip guard) that must be kept until the process ends, or the last spans
/// and events are never flushed.
///
/// # Panics
///
/// Panics when a global subscriber is already installed (call it once at
/// startup — fail-fast).
pub fn init_subscriber() -> Telemetry {
    // IMPORTANT: the default applies only when `RUST_LOG` is unset. Writing
    // `from_default_env().add_directive("jwt_service_app=info")` is wrong — the
    // added directive overrides the target of the same name from `RUST_LOG`, and
    // the crate level sticks at `info` forever (DEBUG becomes unreachable).
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("jwt_service_app=info"));

    // The json and pretty layers differ in type — unify them with `.boxed()`.
    let fmt_layer = match env::var("LOG_FORMAT")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "json" => tracing_subscriber::fmt::layer().json().boxed(),
        _ => tracing_subscriber::fmt::layer()
            .pretty()
            .with_ansi(true)
            .boxed(),
    };

    let (provider, otel_status) = crate::tracing_otel::init_tracer_provider();
    let otel_layer = provider.as_ref().map(crate::tracing_otel::layer);

    // Logs over OTLP are a separate signal with a separate flag: where an agent
    // already collects stdout, duplicating them over the network is pointless.
    let (logger_provider, otel_logs_status) = crate::tracing_otel::init_logger_provider();
    let otel_logs_layer = logger_provider
        .as_ref()
        .map(crate::tracing_otel::logs_layer);

    // GlitchTip: the client is installed before the subscriber, and the layer
    // splits events across the channels (issues / logs / performance) — see
    // `sentry_glitchtip`.
    let (sentry_guard, sentry_status) = crate::sentry_glitchtip::init();
    let sentry_layer = sentry_guard
        .as_ref()
        .map(|_| crate::sentry_glitchtip::layer(sentry_status.logs_enabled()));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .with(otel_logs_layer)
        .with(sentry_layer)
        .init();

    // The statuses are printed only now: before `.init()` there was nowhere to write.
    otel_status.log();
    otel_logs_status.log();
    sentry_status.log();

    Telemetry {
        tracer_provider: provider,
        logger_provider,
        sentry_guard,
    }
}

/// The live telemetry resources that must be kept until the process ends.
///
/// `sentry_guard` flushes the accumulated events when destroyed, so it must not
/// be dropped right after initialisation; `tracer_provider` is shut down
/// explicitly through [`crate::tracing_otel::shutdown`].
pub struct Telemetry {
    pub tracer_provider: Option<SdkTracerProvider>,
    /// The OTLP log provider; shut down through
    /// [`crate::tracing_otel::shutdown_logs`], or the last logs are never flushed.
    pub logger_provider: Option<SdkLoggerProvider>,
    /// There is no need to read this field — it exists for RAII: GlitchTip
    /// events are flushed when the guard is destroyed. Drop it early and the
    /// accumulated events are lost.
    #[allow(dead_code)]
    pub sentry_guard: Option<sentry::ClientInitGuard>,
}

/// Checks that an externally supplied `X-Request-Id` is safe to reuse: non-empty,
/// no longer than [`REQUEST_ID_MAX_LEN`] and made only of ASCII letters, digits,
/// `-` and `_`. Otherwise we generate our own (protection against log injection
/// and junk values).
fn is_valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= REQUEST_ID_MAX_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The middleware factory for per-request logging. Installed once at the `App`
/// level (the outermost layer) so that the span covers auth, rate limiting, CORS
/// and the handler.
pub struct RequestLog;

impl<S, B> Transform<S, ServiceRequest> for RequestLog
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestLogMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestLogMiddleware {
            service: Rc::new(service),
        }))
    }
}

/// The middleware itself: it opens the span and logs the outcome of the request.
pub struct RequestLogMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for RequestLogMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        // Take the incoming `X-Request-Id` when it is valid, otherwise generate a new one.
        let request_id = req
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .filter(|s| is_valid_request_id(s))
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let method = req.method().to_string();
        let path = req.path().to_string();
        // A best-effort client IP (honouring actix realip); the exact rate-limit
        // key with trusted proxies stays inside `rate_limit.rs`.
        let client_ip = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("-")
            .to_string();

        // `access_level` is filled in by the auth middleware from the inside
        // (see `auth.rs`), and `status`/`latency_ms` on completion below. We
        // declare them empty.
        let span = tracing::info_span!(
            "http_request",
            request_id = %request_id,
            method = %method,
            path = %path,
            client_ip = %client_ip,
            access_level = tracing::field::Empty,
            status = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
        );

        // If the calling service sent a `traceparent`, we continue its trace —
        // otherwise the span becomes the root of a new one (see `tracing_otel`).
        // A failure to stitch is no reason to refuse the request: we write it at
        // DEBUG and continue without a parent.
        if let Err(e) = span.set_parent(crate::tracing_otel::extract_parent_context(req.headers()))
        {
            tracing::debug!("Could not link the span to the incoming trace: {e}");
        }

        let response_id = request_id;

        Box::pin(
            async move {
                let start = Instant::now();
                let mut res = service.call(req).await?;
                let elapsed = start.elapsed();
                let status = res.status().as_u16();
                let latency_ms = elapsed.as_millis() as u64;

                let span = tracing::Span::current();
                span.record("status", status);
                span.record("latency_ms", latency_ms);

                // The request metric is written right here: the status and the
                // latency are already computed and a second middleware pass is
                // not needed. The label carries the route TEMPLATE
                // (`/tokens/{jti}`), not the actual path — otherwise every `jti`
                // would spawn its own series (see `metrics.rs`).
                let endpoint = res
                    .request()
                    .match_pattern()
                    .unwrap_or_else(|| "unmatched".to_string());
                crate::metrics::record_http_request(&method, &endpoint, status, elapsed);

                // Echo the `X-Request-Id` header back for end-to-end tracing.
                if let Ok(value) = HeaderValue::from_str(&response_id) {
                    res.response_mut()
                        .headers_mut()
                        .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
                }

                tracing::info!(status, latency_ms, "request completed");
                Ok(res)
            }
            .instrument(span),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test as actix_test;
    use actix_web::{web, App, HttpResponse};

    async fn ok() -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    #[test]
    fn validates_request_id() {
        assert!(is_valid_request_id("abc-123_DEF"));
        assert!(!is_valid_request_id(""));
        assert!(!is_valid_request_id("has space"));
        assert!(!is_valid_request_id("inject\nline"));
        assert!(!is_valid_request_id(&"x".repeat(REQUEST_ID_MAX_LEN + 1)));
    }

    #[actix_web::test]
    async fn generates_request_id_when_absent() {
        let app =
            actix_test::init_service(App::new().wrap(RequestLog).route("/", web::get().to(ok)))
                .await;
        let req = actix_test::TestRequest::get().uri("/").to_request();
        let res = actix_test::call_service(&app, req).await;

        let rid = res
            .headers()
            .get(REQUEST_ID_HEADER)
            .expect("X-Request-Id must be present in the response");
        // A generated id is a valid UUID.
        assert!(Uuid::parse_str(rid.to_str().unwrap()).is_ok());
    }

    #[actix_web::test]
    async fn propagates_valid_incoming_request_id() {
        let app =
            actix_test::init_service(App::new().wrap(RequestLog).route("/", web::get().to(ok)))
                .await;
        let req = actix_test::TestRequest::get()
            .uri("/")
            .insert_header((REQUEST_ID_HEADER, "trace-42"))
            .to_request();
        let res = actix_test::call_service(&app, req).await;

        assert_eq!(
            res.headers()
                .get(REQUEST_ID_HEADER)
                .unwrap()
                .to_str()
                .unwrap(),
            "trace-42"
        );
    }

    #[actix_web::test]
    async fn replaces_invalid_incoming_request_id() {
        let app =
            actix_test::init_service(App::new().wrap(RequestLog).route("/", web::get().to(ok)))
                .await;
        let req = actix_test::TestRequest::get()
            .uri("/")
            .insert_header((REQUEST_ID_HEADER, "bad value!"))
            .to_request();
        let res = actix_test::call_service(&app, req).await;

        let rid = res
            .headers()
            .get(REQUEST_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_ne!(rid, "bad value!");
        assert!(Uuid::parse_str(rid).is_ok());
    }
}
