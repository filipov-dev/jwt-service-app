//! The HTTP client for the external key service `jwks-service-app`.
//!
//! [`JwkService`] encapsulates every call to the key service:
//! - `GET /.well-known/jwks.json` — the list of public keys;
//! - `GET /jwks/{id}` — a specific key (with its private part);
//! - `POST /jwks` — creating a new key for a given algorithm.
//!
//! The base URL comes from `JWKS_SERVICE_URL`.

use parking_lot::RwLock;
use reqwest::Client;
use serde_json::json;
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

use tracing::{debug, error};

use crate::metrics::{record_jwks_cache, record_jwks_request};
use crate::models::{Jwk, JwkData, Jwks};
use crate::tracing_otel::inject_context;

/// How long the JWKS cache is considered fresh (`JWKS_CACHE_TTL_SECONDS`).
///
/// Five minutes is a compromise: keys in `jwks-service-app` live for days
/// (`KEY_EXPIRATION_SECONDS`), so being minutes behind is safe, while keeping a
/// revoked key in memory any longer is undesirable. `0` disables the cache
/// entirely and restores the previous behaviour — useful while debugging.
const DEFAULT_CACHE_TTL_SECONDS: u64 = 300;

/// The overall timeout of a request to the key service (`JWKS_REQUEST_TIMEOUT_MS`).
///
/// Two seconds comfortably cover the longest operation — generating a key — and
/// are noticeably below a typical client timeout of 5–10 s: the client gets a
/// meaningful error instead of being cut off by its own timeout.
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 2000;

/// The connection timeout to the key service (`JWKS_CONNECT_TIMEOUT_MS`).
///
/// The JWKS lives in the same network, so half a second to establish a
/// connection is already an anomaly.
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 500;

/// How long an idle connection is kept in the pool.
///
/// The pool exists so that we do not pay for a TCP handshake on every cache
/// refresh; holding a connection for more than a minute is pointless — refreshes
/// are rarer than that.
const POOL_IDLE_TIMEOUT_SECONDS: u64 = 60;

/// The minimum interval between unscheduled cache refreshes triggered by an
/// unknown `kid` (`JWKS_CACHE_MISS_REFRESH_SECONDS`).
///
/// Without it the cache would not close the main overload scenario: a stream of
/// tokens with random `kid` values would miss the cache and be translated to the
/// JWKS one to one — exactly what we are moving away from.
const DEFAULT_MISS_REFRESH_SECONDS: u64 = 10;

/// How long a snapshot may be served **beyond** its TTL while the key service is
/// unavailable (`JWKS_CACHE_STALE_GRACE_SECONDS`).
///
/// It counts from the TTL rather than from the moment of the snapshot: the
/// maximum age of a usable snapshot is
/// `JWKS_CACHE_TTL_SECONDS + JWKS_CACHE_STALE_GRACE_SECONDS`.
///
/// Ten seconds is a deliberately stingy grace: it covers a network blip and a
/// restart of `jwks-service-app`, that is, everything that fixes itself. A long
/// grace extends the life of a revoked key by exactly as much, while revocation
/// of individual tokens through the `jti` in Redis keeps working meanwhile. `0`
/// disables serving stale snapshots entirely — the behaviour before JWT-50.
const DEFAULT_STALE_GRACE_SECONDS: u64 = 10;

/// Builds the HTTP client for the key service with timeouts.
///
/// Without them `reqwest` waits for a response indefinitely, and a hung — not
/// crashed, but hanging — JWKS would hold actix workers until the OS TCP
/// timeout, that is, for tens of minutes. The cache (JWT-25) reduced the call
/// rate but does not protect against a single hung request.
///
/// Not fail-fast: if the client somehow fails to build, we take the default one
/// — without timeouts but working. Telemetry and settings of this kind must not
/// be a cause of service unavailability.
fn build_client() -> Client {
    let request_timeout = env_millis("JWKS_REQUEST_TIMEOUT_MS", DEFAULT_REQUEST_TIMEOUT_MS);
    let connect_timeout = env_millis("JWKS_CONNECT_TIMEOUT_MS", DEFAULT_CONNECT_TIMEOUT_MS);

    Client::builder()
        .timeout(Duration::from_millis(request_timeout))
        .connect_timeout(Duration::from_millis(connect_timeout))
        .pool_idle_timeout(Duration::from_secs(POOL_IDLE_TIMEOUT_SECONDS))
        .build()
        .unwrap_or_else(|e| {
            tracing::warn!(
                "JWKS: could not build an HTTP client with timeouts ({e}), using the default one"
            );
            Client::new()
        })
}

/// Reads milliseconds from an environment variable, falling back to `default`.
fn env_millis(name: &str, default: u64) -> u64 {
    env_u64(name, default)
}

/// Reads seconds from an environment variable, falling back to `default`.
fn env_seconds(name: &str, default: u64) -> u64 {
    env_u64(name, default)
}

/// The shared parsing of a `u64` from an environment variable.
///
/// Not fail-fast: like the rest of the cache and telemetry settings, a malformed
/// value gives a warning and the default rather than bringing the service down.
fn env_u64(name: &str, default: u64) -> u64 {
    match env::var(name) {
        Err(_) => default,
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!("{name}: invalid value {raw:?}, using the default {default}");
                default
            }
        },
    }
}

/// The state of the public key cache.
struct CacheState {
    /// The last successfully fetched key set and the moment it was fetched.
    entry: Option<(Jwks, Instant)>,
    /// The moment of the last trip to the JWKS (successful or not) — for
    /// throttling refreshes triggered by a miss.
    last_attempt: Option<Instant>,
    /// The moment of the last **failed** trip; cleared by a successful one. It
    /// tells "too early to refresh" apart from "the key service is down":
    /// serving a stale snapshot is only allowed in the second case.
    last_failure: Option<Instant>,
}

/// Errors of interaction with the key service.
#[derive(Error, Debug)]
pub enum JwkError {
    #[error("Bad connection")]
    BadConnection,
    #[error("Bad response")]
    BadResponse,
    #[error("NotFound")]
    NotFound,
}

/// The key service client built on `reqwest`.
///
/// The instance is created **once per process** and cloned afterwards: `client`
/// carries the connection pool, and `cache` and `refresh_lock` sit behind an
/// `Arc`, so every copy shares one cache and one pool. `JwkService` must not be
/// created per request — that is exactly how a trip to the JWKS on every
/// verification came about.
#[derive(Clone)]
pub struct JwkService {
    client: Client,
    /// The base URL of the service (`JWKS_SERVICE_URL`).
    url: String,
    /// The public key cache, shared by every clone.
    cache: Arc<RwLock<CacheState>>,
    /// The refresh lock: under load one request goes to the JWKS rather than as
    /// many as missed simultaneously. It is asynchronous — it is held across an
    /// `await` for the duration of the HTTP request, where `parking_lot` cannot
    /// be used.
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
    /// The lifetime of a cache snapshot.
    cache_ttl: Duration,
    /// The minimum interval between refreshes triggered by a miss.
    miss_refresh_interval: Duration,
    /// The grace beyond the TTL within which a snapshot is still served while
    /// the key service is unavailable.
    stale_grace: Duration,
}

impl JwkService {
    /// Creates the client; the base URL comes from `JWKS_SERVICE_URL`
    /// (`http://jwks-service-app:8080` by default).
    pub fn new() -> Self {
        let url = env::var("JWKS_SERVICE_URL").unwrap_or("http://jwks-service-app:8080".into());

        let cache_ttl = Duration::from_secs(env_seconds(
            "JWKS_CACHE_TTL_SECONDS",
            DEFAULT_CACHE_TTL_SECONDS,
        ));
        let stale_grace = Duration::from_secs(env_seconds(
            "JWKS_CACHE_STALE_GRACE_SECONDS",
            DEFAULT_STALE_GRACE_SECONDS,
        ));

        Self {
            client: build_client(),
            url,
            cache: Arc::new(RwLock::new(CacheState {
                entry: None,
                last_attempt: None,
                last_failure: None,
            })),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            cache_ttl,
            miss_refresh_interval: Duration::from_secs(env_seconds(
                "JWKS_CACHE_MISS_REFRESH_SECONDS",
                DEFAULT_MISS_REFRESH_SECONDS,
            )),
            stale_grace,
        }
    }

    /// Checks that the key service is available (`GET /.well-known/jwks.json`).
    ///
    /// Used by the readiness check (`GET /readyz`): it is enough that the list
    /// of public keys was requested and parsed successfully.
    ///
    /// # Errors
    /// - [`JwkError::BadConnection`] — the service is unavailable;
    /// - [`JwkError::BadResponse`] — an invalid response.
    pub async fn health_check(&self) -> Result<(), JwkError> {
        self.public_keys().await.map(|_| ())
    }

    /// Fetches every key.
    #[tracing::instrument(name = "jwks.public_keys", skip(self), err(level = "debug"))]
    async fn public_keys(&self) -> Result<Jwks, JwkError> {
        let url = format!("{}/.well-known/jwks.json", self.url);
        debug!("JWKS: requesting the public keys ({})", url);
        let started = Instant::now();

        // Propagate the trace context: the JWKS call lands in the same trace.
        let response = match inject_context(self.client.get(&url)).send().await {
            Ok(v) => v,
            Err(e) => {
                // An external dependency failure — ERROR.
                error!("JWKS is unavailable ({}): {}", url, e);
                record_jwks_request("public_keys", false, started.elapsed());
                return Err(JwkError::BadConnection);
            }
        };

        match response.json().await {
            Ok(v) => {
                record_jwks_request("public_keys", true, started.elapsed());
                Ok(v)
            }
            Err(e) => {
                error!("JWKS returned an invalid response ({}): {}", url, e);
                record_jwks_request("public_keys", false, started.elapsed());
                Err(JwkError::BadResponse)
            }
        }
    }

    /// Returns the public key for a `kid`, from the cache where possible.
    ///
    /// The order:
    /// 1. **A hit** — a fresh cache contains the `kid` and no network call is made.
    /// 2. **A miss** — we take the refresh lock and check the cache once more:
    ///    another request may have filled it while we waited.
    /// 3. When it is too early to refresh (`JWKS_CACHE_MISS_REFRESH_SECONDS`) we
    ///    try to serve a stale snapshot; with a fresh cache that lacks the `kid`
    ///    we refuse without touching the network, or a stream of random `kid`
    ///    values would again be translated to the JWKS one to one.
    /// 4. Otherwise we go to the JWKS, refresh the cache and look in it.
    /// 5. If the trip failed we serve the last known snapshot
    ///    (stale-while-revalidate) until its age exceeds
    ///    `JWKS_CACHE_STALE_MAX_SECONDS`.
    ///
    /// # Errors
    /// - [`JwkError::NotFound`] — the key is neither in the cache nor in a fresh
    ///   JWKS response, or a refresh is currently throttled;
    /// - [`JwkError::BadConnection`] / [`JwkError::BadResponse`] — from the
    ///   request to the JWKS, when there is no usable stale snapshot.
    pub async fn public_key(&self, kid: &str) -> Result<Jwk, JwkError> {
        if let Some(jwk) = self.lookup_fresh(kid) {
            record_jwks_cache("hit");
            return Ok(jwk);
        }

        // Single-flight: under load one request goes to the JWKS for the whole
        // burst of misses while the rest wait here and take the ready cache.
        let _guard = self.refresh_lock.lock().await;

        if let Some(jwk) = self.lookup_fresh(kid) {
            record_jwks_cache("hit");
            return Ok(jwk);
        }

        if !self.allow_refresh_on_miss() {
            // It is too early to refresh. If the previous trip failed, another
            // one right now would achieve nothing — we serve a stale snapshot
            // without touching the network. That is not only better than a
            // refusal: otherwise the requests would queue up, each with its own
            // timeout against a downed JWKS, and verification would be down
            // anyway — on latency this time.
            if self.refresh_recently_failed() {
                if let Some(jwk) = self.serve_stale(kid) {
                    return Ok(jwk);
                }
            }

            if self.cache_is_fresh() {
                // The cache is fresh and the key is not in it — we refuse without
                // touching the network. To the client this is indistinguishable
                // from "key not found".
                record_jwks_cache("throttled");
                debug!(
                    "JWKS: kid {} is unknown, the cache refresh is throttled",
                    kid
                );
                return Err(JwkError::NotFound);
            }

            // There is no usable snapshot at all — nothing to protect here, go to the network.
        }

        let jwks = match self.fetch_and_store().await {
            Ok(jwks) => jwks,
            Err(e) => {
                // The key service did not answer but a working snapshot is in
                // memory — serve it instead of taking verification down entirely.
                return match self.serve_stale(kid) {
                    Some(jwk) => Ok(jwk),
                    None => {
                        record_jwks_cache("miss");
                        Err(e)
                    }
                };
            }
        };

        record_jwks_cache("miss");

        jwks.keys
            .iter()
            .find(|jwk| jwk.kid == kid)
            .cloned()
            .ok_or(JwkError::NotFound)
    }

    /// Serves a `kid` from a stale snapshot while that snapshot is still usable.
    ///
    /// A deliberate trade: an unavailable `jwks-service-app` must not take
    /// verification down for the whole outage while a working key snapshot is in
    /// memory. The price is that a revoked key keeps being considered valid for
    /// a while, which is why the grace is bounded by
    /// `JWKS_CACHE_STALE_GRACE_SECONDS` and the degradation itself is visible in
    /// the log (WARN) and in the `jwks_cache_total{result="stale"}` metric.
    fn serve_stale(&self, kid: &str) -> Option<Jwk> {
        let (jwk, age) = self.lookup_stale(kid)?;

        record_jwks_cache("stale");
        // WARN rather than INFO: this is degradation and it must be visible in the logs.
        tracing::warn!(
            "JWKS is unavailable: key {} served from a stale snapshot (age {} s, limit {} s)",
            kid,
            age.as_secs(),
            self.servable_max_age().as_secs()
        );

        Some(jwk)
    }

    /// Whether the last trip to the JWKS failed recently enough that repeating
    /// it right now is pointless.
    ///
    /// The mark is cleared by a successful refresh, so a "recent failure" means
    /// the key service really is unavailable rather than junk `kid` throttling.
    fn refresh_recently_failed(&self) -> bool {
        self.cache
            .read()
            .last_failure
            .is_some_and(|at| at.elapsed() < self.miss_refresh_interval)
    }

    /// The maximum age of a snapshot that can still serve verification: the TTL
    /// plus the grace.
    ///
    /// With a zero TTL the cache is off entirely — there are no usable snapshots
    /// at all — and a zero grace disables serving stale snapshots: past the TTL a
    /// snapshot immediately stops being usable.
    fn servable_max_age(&self) -> Duration {
        if self.cache_ttl.is_zero() {
            return Duration::ZERO;
        }

        self.cache_ttl.saturating_add(self.stale_grace)
    }

    /// Whether memory holds a snapshot the service can still serve verification
    /// from (fresh or within the grace).
    ///
    /// Needed by the readiness probe: while such a snapshot exists, an
    /// unavailable `jwks-service-app` does not yet mean the pod should leave the
    /// load balancer. An empty snapshot does not count — it has no keys anyway.
    pub fn has_servable_snapshot(&self) -> bool {
        let servable_max_age = self.servable_max_age();

        self.cache
            .read()
            .entry
            .as_ref()
            .is_some_and(|(jwks, fetched_at)| {
                !jwks.keys.is_empty() && fetched_at.elapsed() < servable_max_age
            })
    }

    /// Looks a `kid` up in the last snapshot, even a stale one, as long as it is
    /// still usable. Returns the key together with the age of the snapshot.
    fn lookup_stale(&self, kid: &str) -> Option<(Jwk, Duration)> {
        let state = self.cache.read();
        let (jwks, fetched_at) = state.entry.as_ref()?;
        let age = fetched_at.elapsed();

        if age >= self.servable_max_age() {
            return None;
        }

        jwks.keys
            .iter()
            .find(|jwk| jwk.kid == kid)
            .cloned()
            .map(|jwk| (jwk, age))
    }

    /// Looks a `kid` up in the cache while it is still fresh. `None` means a miss or a stale cache.
    fn lookup_fresh(&self, kid: &str) -> Option<Jwk> {
        let state = self.cache.read();
        let (jwks, fetched_at) = state.entry.as_ref()?;

        if fetched_at.elapsed() >= self.cache_ttl {
            return None;
        }

        jwks.keys.iter().find(|jwk| jwk.kid == kid).cloned()
    }

    /// Whether the cache holds a snapshot that has not gone stale (regardless of a specific `kid`).
    fn cache_is_fresh(&self) -> bool {
        self.cache
            .read()
            .entry
            .as_ref()
            .is_some_and(|(_, fetched_at)| fetched_at.elapsed() < self.cache_ttl)
    }

    /// Whether a refresh triggered by a miss is allowed right now; it records the attempt.
    ///
    /// It throttles not only a flood of unknown `kid` values but also repeated
    /// trips to an unavailable JWKS: a successful trip makes the cache fresh, so
    /// "an attempt just happened and the cache is not fresh" means it failed.
    fn allow_refresh_on_miss(&self) -> bool {
        let mut state = self.cache.write();

        match state.last_attempt {
            Some(at) if at.elapsed() < self.miss_refresh_interval => false,
            _ => {
                state.last_attempt = Some(Instant::now());
                true
            }
        }
    }

    /// Requests the JWKS and puts the result into the cache.
    async fn fetch_and_store(&self) -> Result<Jwks, JwkError> {
        {
            // Record the attempt before the request: if the JWKS is down,
            // throttling stops us hammering it in a loop.
            let mut state = self.cache.write();
            state.last_attempt = Some(Instant::now());
        }

        let jwks = match self.public_keys().await {
            Ok(jwks) => jwks,
            Err(e) => {
                // Mark the failure: while it is recent, repeated trips are
                // throttled and requests are served from the stale snapshot.
                self.cache.write().last_failure = Some(Instant::now());
                return Err(e);
            }
        };

        let mut state = self.cache.write();
        state.entry = Some((jwks.clone(), Instant::now()));
        state.last_failure = None;

        Ok(jwks)
    }

    /// Returns the private key for `id`, creating a new one for the `alg`
    /// algorithm when no key with that `id` exists (or `id` is empty).
    pub async fn private_key(&self, id: &str, alg: &str) -> Result<JwkData, JwkError> {
        // There is no identifier yet — the first key in the lifetime of the process.
        if id.is_empty() {
            return self.create_key(alg).await;
        }

        match self.get_key(id).await {
            Ok(v) => Ok(v),
            // The key really is absent — create a new one.
            Err(JwkError::NotFound) => self.create_key(alg).await,
            // An unavailable or failing key service, however, is NOT a reason to
            // spawn keys: `BadConnection` and `BadResponse` used to land here
            // too, so a brief network glitch led to a new key being created,
            // litter in the store and the active `kid` changing for no reason.
            Err(e) => Err(e),
        }
    }

    /// Creates a new key in the service for the given algorithm.
    ///
    /// For `EdDSA` the service is given the concrete curve `Ed25519` (the key
    /// service works with curve names rather than a general algorithm name).
    async fn create_key(&self, alg: &str) -> Result<JwkData, JwkError> {
        let url = format!("{}/jwks", self.url);

        let alg = if alg == "EdDSA" { "Ed25519" } else { alg };

        debug!("JWKS: requesting a private key (alg={})", alg);
        let started = Instant::now();

        let response = match inject_context(self.client.post(&url))
            .json(&json!({
                "alg": alg
            }))
            .send()
            .await
        {
            Ok(v) => v,
            Err(e) => {
                error!("JWKS is unavailable while requesting a private key: {}", e);
                record_jwks_request("private_key", false, started.elapsed());
                return Err(JwkError::BadConnection);
            }
        };

        match response.json().await {
            Ok(v) => {
                record_jwks_request("private_key", true, started.elapsed());
                Ok(v)
            }
            Err(e) => {
                error!("JWKS returned an invalid private key: {}", e);
                record_jwks_request("private_key", false, started.elapsed());
                Err(JwkError::BadResponse)
            }
        }
    }

    /// Fetches a key from the service by its `id`.
    ///
    /// # Errors
    /// - [`JwkError::NotFound`] — **only** a `404` response, that is, the key
    ///   really does not exist;
    /// - [`JwkError::BadResponse`] — any other unsuccessful status (`5xx` and
    ///   the rest) or an unreadable body;
    /// - [`JwkError::BadConnection`] — the service is unavailable.
    ///
    /// The distinction matters: the caller ([`JwkService::private_key`]) creates
    /// a new key on `NotFound`, so "the service answered 500" must under no
    /// circumstances look like "there is no key".
    async fn get_key(&self, id: &str) -> Result<JwkData, JwkError> {
        let url = format!("{}/jwks/{}", self.url, id);
        let started = Instant::now();

        let response = match inject_context(self.client.get(&url)).send().await {
            Ok(v) => v,
            Err(e) => {
                error!("JWKS is unavailable while requesting key {}: {}", id, e);
                record_jwks_request("get_key", false, started.elapsed());
                return Err(JwkError::BadConnection);
            }
        };

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            debug!("JWKS: key {} not found", id);
            record_jwks_request("get_key", true, started.elapsed());
            return Err(JwkError::NotFound);
        }

        if !response.status().is_success() {
            error!(
                "JWKS returned {} for the request of key {}",
                response.status(),
                id
            );
            record_jwks_request("get_key", false, started.elapsed());
            return Err(JwkError::BadResponse);
        }

        match response.json().await {
            Ok(v) => {
                record_jwks_request("get_key", true, started.elapsed());
                Ok(v)
            }
            Err(e) => {
                error!("JWKS returned an invalid key {}: {}", id, e);
                record_jwks_request("get_key", false, started.elapsed());
                Err(JwkError::BadResponse)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests of the public key cache.
    //!
    //! `jwks-service-app` is brought up as an HTTP mock ([`wiremock`]), and the
    //! number of requests that actually went out is checked through
    //! `received_requests` — that is the whole point: before the cache every
    //! verification produced its own request.

    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    impl JwkService {
        /// A constructor for the tests: the URL and the timings are set
        /// explicitly, bypassing the environment.
        ///
        /// It cannot be done through env: the process variables are shared while
        /// the tests run in parallel.
        fn for_test(url: String, cache_ttl: Duration, miss_refresh_interval: Duration) -> Self {
            Self::for_test_with_client(Client::new(), url, cache_ttl, miss_refresh_interval)
        }

        /// The same, but with a pre-built client — needed by the timeout tests.
        fn for_test_with_client(
            client: Client,
            url: String,
            cache_ttl: Duration,
            miss_refresh_interval: Duration,
        ) -> Self {
            Self {
                client,
                url,
                cache: Arc::new(RwLock::new(CacheState {
                    entry: None,
                    last_attempt: None,
                    last_failure: None,
                })),
                refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
                cache_ttl,
                miss_refresh_interval,
                stale_grace: Duration::from_secs(DEFAULT_STALE_GRACE_SECONDS),
            }
        }

        /// Sets the grace beyond the TTL (the production one by default in tests).
        fn with_stale_grace(mut self, stale_grace: Duration) -> Self {
            self.stale_grace = stale_grace;
            self
        }

        /// Ages the contents of the cache by `age`.
        ///
        /// Otherwise the staleness test would have to wait out the TTL for real.
        /// The mark of the last refresh attempt is shifted together with the
        /// snapshot: without that, throttling would not let the refresh reach the
        /// network and the test would be checking the wrong thing.
        fn backdate_cache(&self, age: Duration) {
            let mut state = self.cache.write();

            if let Some((_, fetched_at)) = state.entry.as_mut() {
                *fetched_at = fetched_at
                    .checked_sub(age)
                    .expect("the test time shift must stay within the monotonic clock");
            }

            state.last_attempt = state.last_attempt.and_then(|at| at.checked_sub(age));
            state.last_failure = state.last_failure.and_then(|at| at.checked_sub(age));
        }
    }

    /// Brings up a JWKS mock with a single key, `kid-1`.
    async fn start_jwks_mock() -> MockServer {
        let server = MockServer::start().await;

        let jwks = json!({ "keys": [ {
            "kty": "OKP", "alg": "EdDSA", "kid": "kid-1", "crv": "Ed25519",
            "x": "AAAA", "y": null, "n": null, "e": null,
        } ] });

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;

        server
    }

    async fn requests_to(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    #[actix_web::test]
    async fn repeated_lookups_hit_cache_and_do_not_refetch() {
        let server = start_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        for _ in 0..10 {
            assert!(service.public_key("kid-1").await.is_ok());
        }

        // The headline number of this work: ten verifications, one trip to the JWKS.
        assert_eq!(requests_to(&server).await, 1);
    }

    #[actix_web::test]
    async fn unknown_kid_refreshes_when_interval_passed() {
        let server = start_jwks_mock().await;
        // A zero interval — a refresh on a miss is always allowed.
        let service = JwkService::for_test(server.uri(), Duration::from_secs(300), Duration::ZERO);

        // Warm the cache up with a known key.
        assert!(service.public_key("kid-1").await.is_ok());
        assert_eq!(requests_to(&server).await, 1);

        // An unknown `kid` is a reason to refresh: that is how a key that
        // appeared after the last refresh is picked up (rotation).
        assert!(matches!(
            service.public_key("kid-unknown").await,
            Err(JwkError::NotFound)
        ));
        assert_eq!(requests_to(&server).await, 2);
    }

    #[actix_web::test]
    async fn unknown_kid_is_throttled_right_after_refresh() {
        let server = start_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(300),
        );

        assert!(service.public_key("kid-1").await.is_ok());
        assert_eq!(requests_to(&server).await, 1);

        // The cache was just refreshed and the key is not in it — so it is not in
        // the JWKS either and another trip would achieve nothing. A stream of
        // random `kid` values stops here and never reaches the network.
        for _ in 0..5 {
            assert!(matches!(
                service.public_key("kid-unknown").await,
                Err(JwkError::NotFound)
            ));
        }
        assert_eq!(requests_to(&server).await, 1);
    }

    #[actix_web::test]
    async fn expired_cache_is_refreshed() {
        let server = start_jwks_mock().await;
        // A zero TTL means the cache is off: every request goes to the network
        // (the previous behaviour, kept for debugging).
        let service = JwkService::for_test(server.uri(), Duration::ZERO, Duration::from_secs(300));

        for _ in 0..3 {
            assert!(service.public_key("kid-1").await.is_ok());
        }

        assert_eq!(requests_to(&server).await, 3);
    }

    #[actix_web::test]
    async fn concurrent_misses_share_a_single_refresh() {
        let server = start_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        // Twenty simultaneous misses on a cold cache must converge into one
        // request: the refresh lock lets the first through while the rest take
        // the ready result.
        let mut handles = Vec::new();
        for _ in 0..20 {
            let service = service.clone();
            handles.push(actix_web::rt::spawn(async move {
                service.public_key("kid-1").await.is_ok()
            }));
        }

        for handle in handles {
            assert!(handle.await.unwrap());
        }

        assert_eq!(requests_to(&server).await, 1);
    }

    #[actix_web::test]
    async fn hanging_jwks_is_cut_off_by_timeout() {
        let server = MockServer::start().await;

        // The mock answers with a delay deliberately larger than the client
        // timeout: that is what a hung (rather than crashed) key service looks
        // like — the nastiest case, because without a timeout the worker would
        // wait for the OS timeout.
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "keys": [] }))
                    .set_delay(Duration::from_secs(5)),
            )
            .mount(&server)
            .await;

        let client = Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let service = JwkService::for_test_with_client(
            client,
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        let started = Instant::now();
        let result = service.public_key("kid-1").await;
        let elapsed = started.elapsed();

        assert!(matches!(result, Err(JwkError::BadConnection)));
        // We stayed within the timeout instead of waiting five seconds for the mock.
        assert!(
            elapsed < Duration::from_secs(2),
            "the request should have been cut off by the timeout, but took {elapsed:?}"
        );
    }

    /// A JWKS mock that answers exactly once and then fails with `500`: that is
    /// what a key service that went down after the cache warmed up looks like.
    async fn start_dying_jwks_mock() -> MockServer {
        let server = MockServer::start().await;

        let jwks = json!({ "keys": [ {
            "kty": "OKP", "alg": "EdDSA", "kid": "kid-1", "crv": "Ed25519",
            "x": "AAAA", "y": null, "n": null, "e": null,
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

        server
    }

    #[actix_web::test]
    async fn stale_snapshot_is_served_when_jwks_is_down() {
        let server = start_dying_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        assert!(service.public_key("kid-1").await.is_ok());

        // The snapshot has gone stale (TTL 300 s) but is within the grace
        // (another 10 s), and the key service is down by that point.
        service.backdate_cache(Duration::from_secs(305));

        // The headline requirement: a downed JWKS does not take verification
        // down while a working key snapshot is in memory.
        assert!(service.public_key("kid-1").await.is_ok());
        // A refresh attempt was still made — serving a stale snapshot does not
        // replace it but backs it up.
        assert_eq!(requests_to(&server).await, 2);
    }

    #[actix_web::test]
    async fn too_old_snapshot_is_refused() {
        let server = start_dying_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        )
        .with_stale_grace(Duration::from_secs(10));

        assert!(service.public_key("kid-1").await.is_ok());

        // 320 s is the TTL (300) plus the grace (10) plus another ten on top.
        // Past that we refuse: otherwise a revoked key would be considered valid
        // indefinitely.
        service.backdate_cache(Duration::from_secs(320));

        assert!(matches!(
            service.public_key("kid-1").await,
            Err(JwkError::BadResponse)
        ));
    }

    #[actix_web::test]
    async fn stale_serving_can_be_disabled() {
        let server = start_dying_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        )
        .with_stale_grace(Duration::ZERO);

        assert!(service.public_key("kid-1").await.is_ok());
        service.backdate_cache(Duration::from_secs(305));

        // A zero grace is the previous behaviour: an unavailable JWKS means a refusal.
        assert!(matches!(
            service.public_key("kid-1").await,
            Err(JwkError::BadResponse)
        ));
    }

    #[actix_web::test]
    async fn down_jwks_is_not_hammered_while_stale_snapshot_serves() {
        let server = start_dying_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        assert!(service.public_key("kid-1").await.is_ok());
        service.backdate_cache(Duration::from_secs(305));

        for _ in 0..5 {
            assert!(service.public_key("kid-1").await.is_ok());
        }

        // One failed trip for the whole throttling interval: without it every
        // request would wait out the timeout of a downed JWKS, and verify would
        // be down anyway — on latency this time.
        assert_eq!(requests_to(&server).await, 2);
    }

    #[actix_web::test]
    async fn live_jwks_is_refreshed_even_when_refresh_is_throttled() {
        let server = start_jwks_mock().await;
        // The TTL is shorter than the throttling interval: there is a stale
        // snapshot and a refresh is formally "too early".
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(1),
            Duration::from_secs(300),
        );

        assert!(service.public_key("kid-1").await.is_ok());
        service.backdate_cache(Duration::from_secs(2));

        assert!(service.public_key("kid-1").await.is_ok());

        // A stale snapshot is insurance for the duration of an outage rather than
        // a replacement for a live service: while the JWKS answers, the cache is refreshed.
        assert_eq!(requests_to(&server).await, 2);
    }

    #[actix_web::test]
    async fn snapshot_stays_servable_until_grace_runs_out() {
        let server = start_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        )
        .with_stale_grace(Duration::from_secs(10));

        // An empty cache is not enough for the readiness probe.
        assert!(!service.has_servable_snapshot());

        assert!(service.public_key("kid-1").await.is_ok());
        assert!(service.has_servable_snapshot());

        // Stale but within the grace — we can still serve verification.
        service.backdate_cache(Duration::from_secs(305));
        assert!(service.has_servable_snapshot());

        // Past the grace we cannot, and readiness must show it.
        service.backdate_cache(Duration::from_secs(10));
        assert!(!service.has_servable_snapshot());
    }

    #[actix_web::test]
    async fn disabled_cache_has_no_servable_snapshot() {
        let server = start_jwks_mock().await;
        // A zero TTL means the cache is off: there is nothing to serve from
        // memory even right after a successful request.
        let service = JwkService::for_test(server.uri(), Duration::ZERO, Duration::from_secs(10));

        assert!(service.public_key("kid-1").await.is_ok());

        assert!(!service.has_servable_snapshot());
    }

    /// A key service mock for the issuing scenarios: `GET /jwks/{id}` answers
    /// with the given status and `POST /jwks` always succeeds.
    async fn start_key_mock(get_status: u16) -> MockServer {
        let server = MockServer::start().await;

        let key = json!({
            "id": "kid-new", "kty": "OKP", "alg": "EdDSA", "kid": "kid-new",
            "crv": "Ed25519", "x": "AAAA", "y": null, "n": null, "e": null,
            "private_key": "AAAA",
        });

        Mock::given(method("GET"))
            .and(path("/jwks/kid-1"))
            .respond_with(ResponseTemplate::new(get_status))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(key))
            .mount(&server)
            .await;

        server
    }

    async fn post_requests(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == wiremock::http::Method::POST)
            .count()
    }

    #[actix_web::test]
    async fn missing_key_is_created() {
        // 404 — the key really is absent, a new one can and must be issued.
        let server = start_key_mock(404).await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        let key = service.private_key("kid-1", "EdDSA").await;

        assert!(key.is_ok());
        assert_eq!(post_requests(&server).await, 1);
    }

    #[actix_web::test]
    async fn server_error_does_not_create_a_key() {
        // 500 — a key service failure. It used to be indistinguishable from "no
        // key", and a new key was issued on every such response.
        let server = start_key_mock(500).await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        let key = service.private_key("kid-1", "EdDSA").await;

        assert!(matches!(key, Err(JwkError::BadResponse)));
        assert_eq!(post_requests(&server).await, 0);
    }

    #[actix_web::test]
    async fn unreachable_service_does_not_create_a_key() {
        // The network is unavailable: port 1 is guaranteed to have no listener.
        let service = JwkService::for_test(
            "http://127.0.0.1:1".to_string(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        let key = service.private_key("kid-1", "EdDSA").await;

        assert!(matches!(key, Err(JwkError::BadConnection)));
    }

    #[actix_web::test]
    async fn existing_key_is_reused() {
        let server = MockServer::start().await;
        let key = json!({
            "id": "kid-1", "kty": "OKP", "alg": "EdDSA", "kid": "kid-1",
            "crv": "Ed25519", "x": "AAAA", "y": null, "n": null, "e": null,
            "private_key": "AAAA",
        });
        Mock::given(method("GET"))
            .and(path("/jwks/kid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(key))
            .mount(&server)
            .await;

        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        assert!(service.private_key("kid-1", "EdDSA").await.is_ok());
        // The key was found — there is no reason to issue a new one.
        assert_eq!(post_requests(&server).await, 0);
    }
}
