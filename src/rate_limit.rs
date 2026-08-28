//! Rate limiting.
//!
//! The algorithm is a token bucket (GCRA) from the [`governor`] crate (MIT); the
//! actix wrapper `actix-governor` (GPL-3.0) is deliberately kept out because of
//! its copyleft on publicly distributed Docker images — the middleware here is
//! our own, modelled on [`crate::auth`]. Exceeding the limit gives
//! `429 Too Many Requests` (a terse [`ErrorResponse`] body and a `Retry-After`
//! header in seconds).
//!
//! The model matches the access levels (see `AGENTS.md`):
//!
//! - **`POST /tokens/verify` (level 2, public behind a proxy) — per-IP.** The
//!   key is the client IP and the limit applies to each address independently.
//!   The middleware sits **outside** auth so that a flood is cut off before the
//!   secret is checked.
//! - **`POST /tokens` / `DELETE /tokens/{jti}` (level 3, internal) — an optional
//!   global cap.** Not per-IP (there is one client) but a shared ceiling per
//!   endpoint: defense in depth against a leaked TOTP secret and backpressure
//!   for JWKS and Redis. It sits **inside** auth — only requests that passed
//!   TOTP consume the cap, otherwise an unauthenticated flood would drain it and
//!   lock out the real client.
//!
//! ## The client IP behind a reverse proxy
//!
//! The peer address of a connection behind a proxy is always the address of the
//! proxy, so the real client IP comes from `X-Forwarded-For`. But that header is
//! forgeable by the client, so it is trusted **only when the peer is in the list
//! of trusted proxies** (`RATE_LIMIT_TRUSTED_PROXIES`, an IP or a CIDR). XFF is
//! parsed right to left — the first address that is not a trusted proxy is the
//! client (which handles a chain of proxies correctly). When the list is empty
//! or the peer is untrusted, XFF is ignored and the peer address serves as the
//! key — the safe default.

use std::env;
use std::future::{ready, Future, Ready};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use actix_web::body::EitherBody;
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderMap, RETRY_AFTER};
use actix_web::{Error, HttpResponse};
use governor::clock::{Clock, DefaultClock, QuantaInstant};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::state::{InMemoryState, NotKeyed};
use governor::{NotUntil, Quota, RateLimiter};
use tracing::{info, warn};

use crate::models::ErrorResponse;

/// A keyed limiter (by IP) over the default state store and clock.
type KeyedLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;
/// A direct limiter (a single bucket) for the global ceiling.
type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Interval between sweeps of stale per-IP entries (`retain_recent`).
///
/// It bounds memory growth on the public endpoint when many distinct IPs appear.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

/// Reads a `u64` from an environment variable, falling back to `default`.
fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// Reads a `u32` from an environment variable, falling back to `default`.
fn env_u32(key: &str, default: u32) -> u32 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// Reads a boolean flag (`1/true/yes/on` is true, `0/false/no/off/""` is false).
///
/// An unrecognised value gives `default` with a warning in the log.
fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Err(_) => default,
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" | "" => false,
            other => {
                warn!("{key}: unrecognised boolean value '{other}', using {default}");
                default
            }
        },
    }
}

/// Normalises an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to IPv4 — so that
/// the peer/XFF addresses and the trusted proxy entries are compared within one
/// family.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Groups IPv6 by the `/56` prefix (like the default governor extractor): one
/// client usually gets a `/56`, and limiting the subnet makes more sense than
/// limiting a single address. IPv4 is returned unchanged.
fn group_v6(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[7..16].fill(0);
            IpAddr::V6(octets.into())
        }
        v4 => v4,
    }
}

/// Whether the first `prefix` bits of two addresses of the same length match.
fn prefix_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let whole = (prefix / 8) as usize;
    if a[..whole] != b[..whole] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[whole] & mask) == (b[whole] & mask)
}

/// The address range of a trusted proxy: a single IP or a CIDR (`10.0.0.0/8`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parses `"IP"` or `"IP/prefix"`. `None` when the address or prefix is invalid.
    fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        let (addr_str, prefix) = match input.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (input, None),
        };
        let addr: IpAddr = canonical(addr_str.parse().ok()?);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => {
                let p: u8 = p.parse().ok()?;
                if p > max {
                    return None;
                }
                p
            }
            None => max,
        };
        Some(Self { addr, prefix })
    }

    /// Whether `ip` (assumed already normalised) falls into the range.
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => prefix_match(&a.octets(), &b.octets(), self.prefix),
            (IpAddr::V6(a), IpAddr::V6(b)) => prefix_match(&a.octets(), &b.octets(), self.prefix),
            _ => false,
        }
    }
}

/// Whether the address is trusted (falls into at least one range of the list).
fn ip_is_trusted(ip: IpAddr, trusted: &[Cidr]) -> bool {
    trusted.iter().any(|c| c.contains(ip))
}

/// Parses one `X-Forwarded-For` entry (a bare IP or `IP:port`) into an address.
fn parse_forwarded_ip(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim();
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(canonical(ip));
    }
    // An `IPv4:port` is possible — strip the port (for `[IPv6]:port` the parsing
    // above has already failed, but such entries are unusual in XFF).
    entry
        .rsplit_once(':')
        .and_then(|(host, _)| host.parse::<IpAddr>().ok())
        .map(canonical)
}

/// Picks the client IP out of `X-Forwarded-For` when the peer is trusted.
///
/// It walks right to left and returns the first address that is not a trusted
/// proxy (the real client behind a chain of proxies). When every entry is
/// trusted it returns the leftmost one; when the header is absent it returns
/// `None` (the caller then picks the peer).
fn client_from_forwarded(headers: &HeaderMap, header: &str, trusted: &[Cidr]) -> Option<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    for value in headers.get_all(header) {
        if let Ok(text) = value.to_str() {
            for part in text.split(',') {
                if let Some(ip) = parse_forwarded_ip(part) {
                    ips.push(ip);
                }
            }
        }
    }
    ips.iter()
        .rev()
        .find(|ip| !ip_is_trusted(**ip, trusted))
        .copied()
        .or_else(|| ips.first().copied())
}

/// The resulting per-IP limiter key for a request.
///
/// XFF is honoured **only** when the peer is trusted; otherwise the peer address
/// is used. The result is grouped by `/56` for IPv6.
fn resolve_key_ip(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    header: &str,
    trusted: &[Cidr],
) -> Option<IpAddr> {
    let peer = canonical(peer?);
    let ip = if ip_is_trusted(peer, trusted) {
        client_from_forwarded(headers, header, trusted).unwrap_or(peer)
    } else {
        peer
    };
    Some(group_v6(ip))
}

/// Builds a quota: `per_second` refills per second with a burst capacity of
/// `burst`. The values are clamped to a minimum of 1 so that the quota is valid.
fn quota(per_second: u64, burst: u32) -> Quota {
    let per_second = per_second.max(1);
    let burst = NonZeroU32::new(burst.max(1)).expect("burst >= 1");
    let period = Duration::from_nanos(1_000_000_000 / per_second);
    Quota::with_period(period)
        .expect("period > 0")
        .allow_burst(burst)
}

/// Seconds until the next allowed request (for the `Retry-After` header), never
/// below 1.
fn retry_after_secs(negative: NotUntil<QuantaInstant>) -> u64 {
    negative
        .wait_time_from(DefaultClock::default().now())
        .as_secs()
        .max(1)
}

/// The rate limiting configuration assembled from the environment.
///
/// Every parameter is optional and has a sensible default; configuration errors
/// (an unparsable CIDR, for example) are not fatal — we degrade to the safe mode
/// with a warning in the log.
pub struct RateLimitConfig {
    verify_enabled: bool,
    verify_per_second: u64,
    verify_burst: u32,
    internal_enabled: bool,
    internal_per_second: u64,
    internal_burst: u32,
    trusted: Arc<Vec<Cidr>>,
    forwarded_header: String,
}

impl RateLimitConfig {
    /// Reads the configuration from the environment.
    ///
    /// The variables:
    /// - `RATE_LIMIT_VERIFY_ENABLED` (default `true`) — the per-IP limit on `/tokens/verify`;
    /// - `RATE_LIMIT_VERIFY_PER_SECOND` (default 10), `RATE_LIMIT_VERIFY_BURST` (default 20);
    /// - `RATE_LIMIT_INTERNAL_ENABLED` (default `false`) — the global cap on the internal endpoints;
    /// - `RATE_LIMIT_INTERNAL_PER_SECOND` (default 50), `RATE_LIMIT_INTERNAL_BURST` (default 100);
    /// - `RATE_LIMIT_TRUSTED_PROXIES` — the list of trusted proxies (IP/CIDR, comma-separated);
    /// - `RATE_LIMIT_FORWARDED_HEADER` (default `X-Forwarded-For`) — the header carrying the client IP.
    pub fn from_env() -> Self {
        let trusted_raw = env::var("RATE_LIMIT_TRUSTED_PROXIES").unwrap_or_default();
        let mut trusted = Vec::new();
        for entry in trusted_raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            match Cidr::parse(entry) {
                Some(cidr) => trusted.push(cidr),
                None => {
                    warn!("RATE_LIMIT_TRUSTED_PROXIES: could not parse the IP/CIDR '{entry}', skipping")
                }
            }
        }

        Self {
            verify_enabled: env_bool("RATE_LIMIT_VERIFY_ENABLED", true),
            verify_per_second: env_u64("RATE_LIMIT_VERIFY_PER_SECOND", 10),
            verify_burst: env_u32("RATE_LIMIT_VERIFY_BURST", 20),
            internal_enabled: env_bool("RATE_LIMIT_INTERNAL_ENABLED", false),
            internal_per_second: env_u64("RATE_LIMIT_INTERNAL_PER_SECOND", 50),
            internal_burst: env_u32("RATE_LIMIT_INTERNAL_BURST", 100),
            trusted: Arc::new(trusted),
            forwarded_header: env::var("RATE_LIMIT_FORWARDED_HEADER")
                .unwrap_or_else(|_| "X-Forwarded-For".into()),
        }
    }

    /// Writes a summary of the active configuration to the log (no secrets — there are none here).
    pub fn log_summary(&self) {
        if self.verify_enabled {
            info!(
                "Rate limit /tokens/verify: per-IP {}/s, burst {}, trusted proxies: {}",
                self.verify_per_second,
                self.verify_burst,
                self.trusted.len()
            );
            if self.trusted.is_empty() {
                warn!(
                    "RATE_LIMIT_TRUSTED_PROXIES is empty: X-Forwarded-For is ignored and the key is the peer address. \
                     Behind a reverse proxy set the list of trusted proxies, or every client shares one limit."
                );
            }
        } else {
            warn!("Rate limit /tokens/verify is disabled (RATE_LIMIT_VERIFY_ENABLED=false)");
        }
        if self.internal_enabled {
            info!(
                "Rate limit on the internal endpoints: global cap {}/s, burst {}",
                self.internal_per_second, self.internal_burst
            );
        }
    }

    /// Builds the per-IP limiter for `/tokens/verify` when it is enabled.
    pub fn build_verify(&self) -> Option<PerIpLimiter> {
        if !self.verify_enabled {
            return None;
        }
        Some(PerIpLimiter {
            limiter: Arc::new(RateLimiter::keyed(quota(
                self.verify_per_second,
                self.verify_burst,
            ))),
            trusted: self.trusted.clone(),
            forwarded_header: Arc::from(self.forwarded_header.as_str()),
        })
    }

    /// Builds the global cap for the internal endpoints when it is enabled.
    pub fn build_internal(&self) -> Option<GlobalLimiter> {
        if !self.internal_enabled {
            return None;
        }
        Some(GlobalLimiter {
            limiter: Arc::new(RateLimiter::direct(quota(
                self.internal_per_second,
                self.internal_burst,
            ))),
        })
    }
}

/// The per-IP limiter (for the public endpoint). Cheap to clone — an `Arc` inside.
#[derive(Clone)]
pub struct PerIpLimiter {
    limiter: Arc<KeyedLimiter>,
    trusted: Arc<Vec<Cidr>>,
    forwarded_header: Arc<str>,
}

impl PerIpLimiter {
    /// Starts a background thread that periodically sweeps stale per-IP entries.
    /// Call it once at startup (the limiter is shared by every worker thread).
    pub fn spawn_cleanup(&self) {
        let limiter = self.limiter.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(CLEANUP_INTERVAL);
            limiter.retain_recent();
        });
    }
}

/// The global limiter (a single bucket per endpoint). Cheap to clone.
#[derive(Clone)]
pub struct GlobalLimiter {
    limiter: Arc<DirectLimiter>,
}

/// The checking strategy of a particular middleware instance.
enum Strategy {
    /// The limit is off — let everything through.
    Disabled,
    /// Per-IP, keyed by the client.
    PerIp {
        limiter: Arc<KeyedLimiter>,
        trusted: Arc<Vec<Cidr>>,
        forwarded_header: Arc<str>,
    },
    /// A single global ceiling.
    Global { limiter: Arc<DirectLimiter> },
}

impl Strategy {
    /// `Ok(())` means let it through; `Err(secs)` means reject with `Retry-After: secs`.
    fn check(&self, req: &ServiceRequest) -> Result<(), u64> {
        match self {
            Strategy::Disabled => Ok(()),
            Strategy::Global { limiter } => limiter.check().map_err(retry_after_secs),
            Strategy::PerIp {
                limiter,
                trusted,
                forwarded_header,
            } => {
                let peer = req.peer_addr().map(|addr| addr.ip());
                match resolve_key_ip(peer, req.headers(), forwarded_header, trusted) {
                    Some(ip) => limiter.check_key(&ip).map_err(retry_after_secs),
                    // The IP could not be determined (no peer address) —
                    // fail-open: the request is protected by the proxy secret at
                    // the auth layer anyway.
                    None => Ok(()),
                }
            }
        }
    }
}

/// The rate limiting middleware factory. Installed with `.wrap(...)` on a resource.
pub struct RateLimit {
    strategy: Rc<Strategy>,
}

impl RateLimit {
    /// The per-IP limit for the public endpoint. `None` means pass through (the limit is off).
    pub fn per_ip(limiter: Option<PerIpLimiter>) -> Self {
        let strategy = match limiter {
            Some(l) => Strategy::PerIp {
                limiter: l.limiter,
                trusted: l.trusted,
                forwarded_header: l.forwarded_header,
            },
            None => Strategy::Disabled,
        };
        Self {
            strategy: Rc::new(strategy),
        }
    }

    /// The global cap for an internal endpoint. `None` means pass through (the cap is off).
    pub fn global(limiter: Option<GlobalLimiter>) -> Self {
        let strategy = match limiter {
            Some(l) => Strategy::Global { limiter: l.limiter },
            None => Strategy::Disabled,
        };
        Self {
            strategy: Rc::new(strategy),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimit
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = RateLimitMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitMiddleware {
            service: Rc::new(service),
            strategy: self.strategy.clone(),
        }))
    }
}

/// The middleware itself: it checks the limit before calling the inner service.
pub struct RateLimitMiddleware<S> {
    service: Rc<S>,
    strategy: Rc<Strategy>,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let decision = self.strategy.check(&req);
        let service = self.service.clone();

        Box::pin(async move {
            match decision {
                Ok(()) => {
                    let res = service.call(req).await?;
                    Ok(res.map_into_left_body())
                }
                Err(retry_after) => {
                    // The limit firing is not a service failure, but it is worth
                    // looking at (a flood, a client stuck in a loop, a limit set
                    // too low) → WARN.
                    warn!(retry_after, "Request rate limit exceeded");
                    crate::metrics::record_rate_limited();

                    // A terse response with no details — as on the other endpoints.
                    let (req, _payload) = req.into_parts();
                    let response = HttpResponse::TooManyRequests()
                        .insert_header((RETRY_AFTER, retry_after))
                        .json(ErrorResponse::new("Too Many Requests"))
                        .map_into_right_body();
                    Ok(ServiceResponse::new(req, response))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    //! Tests of CIDR parsing, of extracting the IP from behind a proxy and of
    //! the middleware over the full actix stack (429 on exceeding the limit,
    //! independence of the buckets per IP, trusting XFF only behind a trusted
    //! proxy).

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn cidrs(entries: &[&str]) -> Vec<Cidr> {
        entries
            .iter()
            .map(|e| Cidr::parse(e).expect("valid cidr"))
            .collect()
    }

    // --- Cidr ---

    #[test]
    fn cidr_parses_single_ip_and_range() {
        assert_eq!(
            Cidr::parse("10.0.0.1"),
            Some(Cidr {
                addr: "10.0.0.1".parse().unwrap(),
                prefix: 32
            })
        );
        assert_eq!(
            Cidr::parse("10.0.0.0/8"),
            Some(Cidr {
                addr: "10.0.0.0".parse().unwrap(),
                prefix: 8
            })
        );
        assert_eq!(
            Cidr::parse("::1"),
            Some(Cidr {
                addr: "::1".parse().unwrap(),
                prefix: 128
            })
        );
        assert_eq!(Cidr::parse("2001:db8::/32").map(|c| c.prefix), Some(32));
    }

    #[test]
    fn cidr_rejects_garbage_and_overlong_prefix() {
        assert_eq!(Cidr::parse("not-an-ip"), None);
        assert_eq!(Cidr::parse("10.0.0.0/33"), None);
        assert_eq!(Cidr::parse("::/129"), None);
    }

    #[test]
    fn cidr_contains_respects_prefix() {
        let net = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(net.contains("10.255.1.2".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        // Different families do not intersect.
        assert!(!net.contains("::1".parse().unwrap()));

        let net = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(net.contains("192.168.1.200".parse().unwrap()));
        assert!(!net.contains("192.168.2.1".parse().unwrap()));

        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:abcd::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
    }

    // --- resolve_key_ip ---

    fn xff(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(
                actix_web::http::header::HeaderName::from_static("x-forwarded-for"),
                actix_web::http::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn key_uses_peer_when_no_trusted_proxies() {
        // XFF is present but the trusted list is empty → it cannot be trusted, key = peer.
        let key = resolve_key_ip(
            Some(ip("203.0.113.9")),
            &xff(&["1.2.3.4"]),
            "X-Forwarded-For",
            &[],
        );
        assert_eq!(key, Some(ip("203.0.113.9")));
    }

    #[test]
    fn key_ignores_forwarded_from_untrusted_peer() {
        // The peer is not in the trusted list — XFF could have been forged, take the peer.
        let trusted = cidrs(&["10.0.0.0/8"]);
        let key = resolve_key_ip(
            Some(ip("203.0.113.9")),
            &xff(&["1.2.3.4"]),
            "X-Forwarded-For",
            &trusted,
        );
        assert_eq!(key, Some(ip("203.0.113.9")));
    }

    #[test]
    fn key_takes_client_from_forwarded_behind_trusted_proxy() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        // Peer = a trusted proxy; XFF = "the client".
        let key = resolve_key_ip(
            Some(ip("10.0.0.5")),
            &xff(&["198.51.100.7"]),
            "X-Forwarded-For",
            &trusted,
        );
        assert_eq!(key, Some(ip("198.51.100.7")));
    }

    #[test]
    fn key_skips_trusted_hops_in_forwarded_chain() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        // A chain: client, proxyA(10.x), proxyB(10.x); every internal hop is
        // trusted, so right to left the first untrusted one is the client.
        let headers = xff(&["198.51.100.7, 10.0.0.9, 10.0.0.5"]);
        let key = resolve_key_ip(Some(ip("10.0.0.5")), &headers, "X-Forwarded-For", &trusted);
        assert_eq!(key, Some(ip("198.51.100.7")));
    }

    #[test]
    fn key_groups_ipv6_to_56() {
        let a = resolve_key_ip(
            Some(ip("2001:db8:1:2:3:4:5:6")),
            &HeaderMap::new(),
            "X-Forwarded-For",
            &[],
        );
        let b = resolve_key_ip(
            Some(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")),
            &HeaderMap::new(),
            "X-Forwarded-For",
            &[],
        );
        // Both addresses are in the same /56 → one key. /56 = 7 bytes: the low
        // byte of the 4th hextet (byte 7) is zeroed, so both reduce to
        // 2001:db8:1::.
        assert_eq!(a, b);
        assert_eq!(
            a,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0)))
        );
    }

    #[test]
    fn parse_forwarded_ip_handles_bare_and_port() {
        assert_eq!(parse_forwarded_ip("1.2.3.4"), Some(ip("1.2.3.4")));
        assert_eq!(parse_forwarded_ip(" 1.2.3.4:5678 "), Some(ip("1.2.3.4")));
        assert_eq!(parse_forwarded_ip("::1"), Some(ip("::1")));
        assert_eq!(parse_forwarded_ip("garbage"), None);
    }

    #[test]
    fn canonical_unmaps_v4_mapped_v6() {
        let mapped = IpAddr::V6(Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped());
        assert_eq!(canonical(mapped), ip("1.2.3.4"));
    }

    // --- Middleware integration over actix ---

    mod middleware {
        use super::*;
        use actix_web::http::StatusCode;
        use actix_web::{test, web, App, HttpResponse};
        use std::net::SocketAddr;

        /// An application with an `/x` endpoint wrapped in the per-IP limiter.
        macro_rules! per_ip_app {
            ($limiter:expr) => {
                test::init_service(
                    App::new().service(
                        web::resource("/x")
                            .wrap(RateLimit::per_ip($limiter))
                            .route(web::get().to(|| async { HttpResponse::Ok().body("ok") })),
                    ),
                )
                .await
            };
        }

        fn per_ip(per_second: u64, burst: u32, trusted: &[&str]) -> PerIpLimiter {
            PerIpLimiter {
                limiter: Arc::new(RateLimiter::keyed(quota(per_second, burst))),
                trusted: Arc::new(cidrs(trusted)),
                forwarded_header: Arc::from("X-Forwarded-For"),
            }
        }

        fn peer(ip: &str) -> SocketAddr {
            format!("{ip}:12345").parse().unwrap()
        }

        #[actix_web::test]
        async fn returns_429_after_burst_exhausted() {
            let app = per_ip_app!(Some(per_ip(1, 2, &[])));
            // burst=2: two requests go through, the third gets a 429.
            for _ in 0..2 {
                let req = test::TestRequest::get()
                    .uri("/x")
                    .peer_addr(peer("203.0.113.1"))
                    .to_request();
                assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            }
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("203.0.113.1"))
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(resp.headers().contains_key(RETRY_AFTER));
        }

        #[actix_web::test]
        async fn buckets_are_independent_per_ip() {
            let app = per_ip_app!(Some(per_ip(1, 1, &[])));
            // The first IP has drained its bucket.
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("203.0.113.1"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("203.0.113.1"))
                .to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::TOO_MANY_REQUESTS
            );
            // A different IP has its own bucket and goes through.
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("203.0.113.2"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn forwarded_client_gets_own_bucket_behind_trusted_proxy() {
            let app = per_ip_app!(Some(per_ip(1, 1, &["10.0.0.0/8"])));
            // Both requests come from the same proxy peer (10.0.0.5) but XFF names different clients.
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("10.0.0.5"))
                .insert_header(("X-Forwarded-For", "198.51.100.1"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            // The same client → 429 (the bucket is drained).
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("10.0.0.5"))
                .insert_header(("X-Forwarded-For", "198.51.100.1"))
                .to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::TOO_MANY_REQUESTS
            );
            // A different client behind the same proxy → its own bucket, goes through.
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("10.0.0.5"))
                .insert_header(("X-Forwarded-For", "198.51.100.2"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn spoofed_forwarded_from_untrusted_peer_is_ignored() {
            let app = per_ip_app!(Some(per_ip(1, 1, &["10.0.0.0/8"])));
            // The peer is untrusted but tries to forge XFF with different IPs —
            // the key is still the peer, so the second request gets a 429 despite
            // the changed XFF.
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("203.0.113.9"))
                .insert_header(("X-Forwarded-For", "1.1.1.1"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("203.0.113.9"))
                .insert_header(("X-Forwarded-For", "2.2.2.2"))
                .to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::TOO_MANY_REQUESTS
            );
        }

        #[actix_web::test]
        async fn disabled_limiter_passes_through() {
            let app = per_ip_app!(None);
            for _ in 0..5 {
                let req = test::TestRequest::get()
                    .uri("/x")
                    .peer_addr(peer("203.0.113.1"))
                    .to_request();
                assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            }
        }

        #[actix_web::test]
        async fn global_cap_limits_regardless_of_ip() {
            let limiter = GlobalLimiter {
                limiter: Arc::new(RateLimiter::direct(quota(1, 2))),
            };
            let app = test::init_service(
                App::new().service(
                    web::resource("/x")
                        .wrap(RateLimit::global(Some(limiter)))
                        .route(web::get().to(|| async { HttpResponse::Ok().body("ok") })),
                ),
            )
            .await;
            // burst=2 for the whole endpoint: any two requests are fine, the third gets a 429, even from another IP.
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("203.0.113.1"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("203.0.113.2"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("203.0.113.3"))
                .to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::TOO_MANY_REQUESTS
            );
        }
    }
}
