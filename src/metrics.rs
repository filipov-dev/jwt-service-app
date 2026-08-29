//! Metrics in the Prometheus format.
//!
//! The facade is the `metrics` crate and the renderer is
//! `metrics-exporter-prometheus`. The exporter's own HTTP listener is not used:
//! the exposition text is served through actix on `GET /metrics` (see
//! `handlers::metrics`) so that we neither open a second port nor pull in
//! hyper/rustls.
//!
//! ## Who reads this
//!
//! - **Prometheus** / **Yandex Managed Prometheus** — a direct scrape of
//!   `/metrics`.
//! - **Zabbix** — the same way through `agent2` with the prometheus plugin; no
//!   separate exporter is needed.
//! - **Monium** (Yandex Cloud) — through Prometheus compatibility.
//!
//! ## Cardinality
//!
//! Labels carry the **route template** (`/tokens/{jti}`), not the actual path:
//! otherwise every `jti` would spawn its own series and Prometheus would
//! balloon. Nothing client-supplied (tokens, secrets, IPs) ends up in a label.
//!
//! ## Naming
//!
//! By Prometheus convention: counters carry the `_total` suffix and latency
//! histograms are in seconds with the `_seconds` suffix.

use std::time::Duration;

use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Bucket bounds of the latency histograms (seconds): from 1 ms to 10 s.
const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Installs the global recorder and returns a handle for rendering the
/// exposition.
///
/// The handle goes into `app_data` and is used by the `/metrics` handler. Call
/// it once at startup.
///
/// # Panics
///
/// Panics if the recorder is already installed (like the rest of the startup
/// configuration — fail-fast).
pub fn init_recorder() -> PrometheusHandle {
    let builder = PrometheusBuilder::new()
        .set_buckets(LATENCY_BUCKETS)
        .expect("a non-empty bucket list");

    builder
        .install_recorder()
        .expect("failed to install the Prometheus recorder")
}

/// Records a completed HTTP request: a counter by (method, route, status) and a
/// latency histogram.
///
/// `endpoint` is the route template (for example `/tokens/{jti}`), see the note
/// on cardinality in the module documentation.
pub fn record_http_request(method: &str, endpoint: &str, status: u16, latency: Duration) {
    let labels = [
        ("method", method.to_string()),
        ("endpoint", endpoint.to_string()),
    ];

    counter!(
        "http_requests_total",
        "method" => method.to_string(),
        "endpoint" => endpoint.to_string(),
        "status" => status.to_string(),
    )
    .increment(1);

    histogram!("http_request_duration_seconds", &labels).record(latency.as_secs_f64());
}

/// A token was issued (`POST /tokens`).
pub fn record_token_issued() {
    counter!("jwt_tokens_issued_total").increment(1);
}

/// A token was revoked (`DELETE /tokens/{jti}`).
pub fn record_token_revoked() {
    counter!("jwt_tokens_revoked_total").increment(1);
}

/// The outcome of a token verification (`POST /tokens/verify`).
///
/// `success = false` is a normal outcome of a public endpoint (expired or
/// forged), not a service failure; it is split out by a label so that a failure
/// ratio can be plotted.
pub fn record_token_verified(success: bool) {
    counter!(
        "jwt_tokens_verified_total",
        "result" => if success { "success" } else { "failure" },
    )
    .increment(1);
}

/// Access denied (401) at the given level (`open`/`proxy_secret`/`totp`).
pub fn record_auth_denied(level: &str) {
    counter!("jwt_auth_denied_total", "level" => level.to_string()).increment(1);
}

/// The rate limit fired (429).
pub fn record_rate_limited() {
    counter!("jwt_rate_limit_exceeded_total").increment(1);
}

/// Duration of a call to `jwks-service-app`.
///
/// `operation` is the short name of the operation (`public_keys`,
/// `private_key`), `success` is whether the call succeeded.
pub fn record_jwks_request(operation: &str, success: bool, latency: Duration) {
    histogram!(
        "jwks_request_duration_seconds",
        "operation" => operation.to_string(),
        "success" => success.to_string(),
    )
    .record(latency.as_secs_f64());
}

/// A lookup in the JWKS cache.
///
/// - `hit` — the key was served from memory, no network call;
/// - `miss` — it was not in the cache, so we went to `jwks-service-app`;
/// - `throttled` — the `kid` is unknown but it is too early to refresh
///   (protection against a flood of non-existent `kid` values), the request was
///   rejected without a network call;
/// - `stale` — the key service is unavailable and the key was served from an
///   outdated snapshot (stale-while-revalidate).
///
/// The `hit` share is the main measure of cache efficiency; a noticeable stream
/// of `throttled` means the service is being hit with junk `kid` values, and any
/// `stale` means `jwks-service-app` is down and we are running on memory: that
/// is worth an alert, because past `JWKS_CACHE_STALE_MAX_SECONDS` verification
/// starts failing.
pub fn record_jwks_cache(result: &str) {
    counter!("jwks_cache_total", "result" => result.to_string()).increment(1);
}

/// Duration of a Redis command (`store_jti`, `check_jti`, `delete_jti`, `ping`).
pub fn record_redis_command(command: &str, success: bool, latency: Duration) {
    histogram!(
        "redis_command_duration_seconds",
        "command" => command.to_string(),
        "success" => success.to_string(),
    )
    .record(latency.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recorder is global and installed once per process; the tests check
    /// that rendering works and that metrics reach the exposition.
    #[test]
    fn renders_recorded_metrics() {
        // `install_recorder` may have already run in another test — we use a
        // local recorder through `PrometheusBuilder::build_recorder`, which does
        // not touch global state.
        let recorder = PrometheusBuilder::new()
            .set_buckets(LATENCY_BUCKETS)
            .unwrap()
            .build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, || {
            record_http_request("GET", "/livez", 200, Duration::from_millis(5));
            record_token_issued();
            record_token_verified(false);
            record_auth_denied("totp");
            record_rate_limited();
        });

        let rendered = handle.render();

        assert!(rendered.contains("http_requests_total"));
        assert!(rendered.contains("endpoint=\"/livez\""));
        assert!(rendered.contains("status=\"200\""));
        assert!(rendered.contains("http_request_duration_seconds"));
        assert!(rendered.contains("jwt_tokens_issued_total"));
        assert!(rendered.contains("result=\"failure\""));
        assert!(rendered.contains("level=\"totp\""));
        assert!(rendered.contains("jwt_rate_limit_exceeded_total"));
    }

    #[test]
    fn latency_buckets_are_sorted_and_positive() {
        assert!(LATENCY_BUCKETS.windows(2).all(|w| w[0] < w[1]));
        assert!(LATENCY_BUCKETS.iter().all(|&b| b > 0.0));
    }
}
