//! HTTP server parameters: the worker count and the connection timeouts.
//!
//! Everything that used to be left at the actix defaults is gathered here in
//! [`ServerConfig::from_env`] and applied from a single place in `main.rs`.
//!
//! ## Why the worker count cannot be left at the default
//!
//! The actix default is "as many logical cores as the process can see", that is,
//! the cores of the **host**. In `deployments/prod/k8s/deployment.yaml` the CPU
//! limit is deliberately absent (throttling hurts the latency tails of the
//! cryptography), and `requests.cpu` has no effect on the visible core count at
//! all. On a 64-core node that would start 64 worker threads with their own
//! stacks and connection pools — all of which had to fit into a 256Mi memory
//! limit, not counting the extra context switches.
//!
//! So the default is computed **from the quota, not from the core count**:
//!
//! 1. there is a cgroup CPU quota (v2 `cpu.max`, v1 `cpu.cfs_quota_us`) — take
//!    it, rounding up to a whole worker;
//! 2. there is no quota (or it could not be read — not Linux, no access to
//!    cgroupfs) — take [`DEFAULT_MAX_WORKERS`] rather than the core count:
//!    predictable memory consumption matters more than guessing the CPU share
//!    from the environment.
//!
//! An explicit `SERVER_WORKERS` always beats auto-detection.
//!
//! ## Why the timeouts are set explicitly
//!
//! Behind a reverse proxy it is the proxy that cuts slow clients off, but the
//! image is distributed publicly and gets deployed directly too, so limiting the
//! time to receive the request headers (`client_request_timeout`) and the idle
//! time of a keep-alive connection is not a tuning detail but protection of the
//! workers against being held.
//!
//! ## Why shutdown_timeout is smaller than the grace period
//!
//! On shutdown actix stops accepting connections and gives the workers
//! `shutdown_timeout` to finish the requests in flight. The default is 30
//! seconds, and `terminationGracePeriodSeconds` in
//! `deployments/prod/k8s/deployment.yaml` is exactly the same: SIGKILL arrives
//! in the very second the drain runs out. There is no room left for finishing
//! the last request or for flushing telemetry — and telemetry is sent **after**
//! `run()` returns (the OTel provider and the GlitchTip guard in `main.rs`).
//!
//! So the default here is [`DEFAULT_SHUTDOWN_TIMEOUT_SECONDS`], comfortably
//! below the grace period. The values are linked: change one and recompute the
//! other, or the timeout is useless (the pod is killed earlier) or the drain
//! ends in an immediate SIGKILL.

use std::env;
use std::fs;
use std::time::Duration;

use tracing::{info, warn};

/// Ceiling on the worker count when the CPU quota could not be determined.
///
/// Exactly the case this work was started for: without a CPU limit in the
/// manifest there is no quota, and the actix default would fan out to the node's
/// core count.
const DEFAULT_MAX_WORKERS: usize = 4;

/// Default timeout for receiving the request headers (matches the actix default).
const DEFAULT_CLIENT_REQUEST_TIMEOUT_MS: u64 = 5_000;

/// Default idle timeout of a keep-alive connection (the actix default).
const DEFAULT_KEEP_ALIVE_SECONDS: u64 = 5;

/// Default time allowed to drain requests on shutdown.
///
/// Deliberately below the `terminationGracePeriodSeconds: 30` of the k8s
/// manifest: the remaining seconds go to flushing telemetry after the server
/// stops.
const DEFAULT_SHUTDOWN_TIMEOUT_SECONDS: u64 = 25;

/// Path to the CPU quota in cgroup v2 (`<quota|max> <period>` in microseconds).
const CGROUP_V2_CPU_MAX: &str = "/sys/fs/cgroup/cpu.max";
/// Path to the CPU quota in cgroup v1 (microseconds; `-1` means no quota).
const CGROUP_V1_CPU_QUOTA: &str = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us";
/// Path to the scheduler period in cgroup v1 (microseconds).
const CGROUP_V1_CPU_PERIOD: &str = "/sys/fs/cgroup/cpu/cpu.cfs_period_us";

/// How the worker count was chosen — for the log message only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkersSource {
    /// Set explicitly through `SERVER_WORKERS`.
    Explicit,
    /// Computed from the cgroup CPU quota.
    Quota,
    /// There is no quota — the [`DEFAULT_MAX_WORKERS`] ceiling applied.
    Fallback,
}

/// HTTP server parameters applied to [`actix_web::HttpServer`].
#[derive(Debug, Clone, Copy)]
pub struct ServerConfig {
    /// Number of worker threads.
    pub workers: usize,
    /// Time allowed to receive the request headers; `Duration::ZERO` means no limit.
    pub client_request_timeout: Duration,
    /// Idle time of a keep-alive connection; `Duration::ZERO` disables keep-alive.
    pub keep_alive: Duration,
    /// Time allowed to finish requests on shutdown; `Duration::ZERO` means immediately.
    pub shutdown_timeout: Duration,
    /// Where `workers` came from (for the log).
    source: WorkersSource,
}

impl ServerConfig {
    /// Assembles the configuration from the environment.
    ///
    /// Like rate limiting (and unlike the auth secrets), it is not fail-fast: an
    /// unrecognised value does not bring the service down but falls back to the
    /// default with a warning in the log.
    pub fn from_env() -> Self {
        let (workers, source) = match parse_workers(env::var("SERVER_WORKERS").ok().as_deref()) {
            Some(n) => (n, WorkersSource::Explicit),
            None => auto_workers(cpu_quota(), available_parallelism()),
        };

        Self {
            workers,
            client_request_timeout: Duration::from_millis(env_u64(
                "SERVER_CLIENT_REQUEST_TIMEOUT_MS",
                DEFAULT_CLIENT_REQUEST_TIMEOUT_MS,
            )),
            keep_alive: Duration::from_secs(env_u64(
                "SERVER_KEEP_ALIVE_SECONDS",
                DEFAULT_KEEP_ALIVE_SECONDS,
            )),
            shutdown_timeout: Duration::from_secs(env_u64(
                "SERVER_SHUTDOWN_TIMEOUT_SECONDS",
                DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
            )),
            source,
        }
    }

    /// Writes a summary to the log — so that the chosen worker count is visible
    /// in production rather than inferred by reading the code and the manifest.
    pub fn log_summary(&self) {
        let source = match self.source {
            WorkersSource::Explicit => "set by SERVER_WORKERS",
            WorkersSource::Quota => "from the cgroup CPU quota",
            WorkersSource::Fallback => "no CPU quota found, default ceiling",
        };
        info!(
            "HTTP server: {} workers ({}), client_request_timeout {} ms, keep-alive {} s, \
             shutdown_timeout {} s",
            self.workers,
            source,
            self.client_request_timeout.as_millis(),
            self.keep_alive.as_secs(),
            self.shutdown_timeout.as_secs(),
        );
    }
}

/// Reads a `u64` from an environment variable, falling back to `default`.
fn env_u64(key: &str, default: u64) -> u64 {
    parse_u64(env::var(key).ok().as_deref(), key, default)
}

/// Parses the value of an environment variable as a `u64`.
///
/// A missing variable, an empty string and garbage all mean `default` (the last
/// one with a warning): timeout configuration, like rate limiting, is not
/// fail-fast.
fn parse_u64(value: Option<&str>, key: &str, default: u64) -> u64 {
    let Some(raw) = value else {
        return default;
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return default;
    }
    match raw.parse() {
        Ok(n) => n,
        Err(_) => {
            warn!("{key}: unrecognised value '{raw}', using {default}");
            default
        }
    }
}

/// Parses `SERVER_WORKERS`.
///
/// An explicit positive number is taken as is; `auto`, `0`, an empty string and
/// a missing variable mean auto-detection (`None`). Garbage also means
/// auto-detection, but with a warning.
fn parse_workers(value: Option<&str>) -> Option<usize> {
    let raw = value?.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("auto") {
        return None;
    }
    match raw.parse::<usize>() {
        Ok(0) => None,
        Ok(n) => Some(n),
        Err(_) => {
            warn!(
                "SERVER_WORKERS: unrecognised value '{raw}', determining the worker count myself"
            );
            None
        }
    }
}

/// Chooses the worker count from the CPU quota (in cores) and the available
/// parallelism.
///
/// The quota is rounded **up**: at `500m` one worker is still needed. It is
/// capped by the parallelism from above — more threads than cores makes no
/// sense.
fn auto_workers(quota: Option<f64>, parallelism: usize) -> (usize, WorkersSource) {
    let parallelism = parallelism.max(1);
    match quota {
        Some(cores) if cores > 0.0 => {
            let by_quota = cores.ceil() as usize;
            (by_quota.clamp(1, parallelism), WorkersSource::Quota)
        }
        _ => (
            parallelism.min(DEFAULT_MAX_WORKERS),
            WorkersSource::Fallback,
        ),
    }
}

/// The number of logical cores available to the process.
///
/// `available_parallelism` accounts for the cgroup quota itself, but it cannot
/// distinguish "a quota of 4 cores" from "the host has 4 cores" — and the
/// difference is decisive here, so the quota is read separately ([`cpu_quota`]).
fn available_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// The CPU quota in cores: cgroup v2, then v1. `None` means no quota or unreadable.
fn cpu_quota() -> Option<f64> {
    if let Some(cores) = fs::read_to_string(CGROUP_V2_CPU_MAX)
        .ok()
        .and_then(|s| parse_cpu_max(&s))
    {
        return Some(cores);
    }
    let quota = fs::read_to_string(CGROUP_V1_CPU_QUOTA).ok()?;
    let period = fs::read_to_string(CGROUP_V1_CPU_PERIOD).ok()?;
    parse_cfs_quota(&quota, &period)
}

/// Parses `cpu.max` (cgroup v2): `"<quota|max> <period>"` in microseconds.
fn parse_cpu_max(content: &str) -> Option<f64> {
    let mut parts = content.split_whitespace();
    let quota = parts.next()?;
    if quota == "max" {
        return None;
    }
    let period = parts.next()?;
    parse_cfs_quota(quota, period)
}

/// Computes the quota in cores from a quota/period pair in microseconds (cgroup
/// v1 and v2).
///
/// `-1` (v1) and a non-positive period mean there is no quota.
fn parse_cfs_quota(quota: &str, period: &str) -> Option<f64> {
    let quota: i64 = quota.trim().parse().ok()?;
    let period: i64 = period.trim().parse().ok()?;
    if quota <= 0 || period <= 0 {
        return None;
    }
    Some(quota as f64 / period as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_workers_takes_explicit_value() {
        assert_eq!(parse_workers(Some("2")), Some(2));
        assert_eq!(parse_workers(Some(" 16 ")), Some(16));
    }

    #[test]
    fn parse_workers_falls_back_to_auto() {
        // A missing variable, an empty value, an explicit `auto` and `0` are all
        // a request to compute it ourselves, not a configuration error.
        assert_eq!(parse_workers(None), None);
        assert_eq!(parse_workers(Some("")), None);
        assert_eq!(parse_workers(Some("auto")), None);
        assert_eq!(parse_workers(Some("AUTO")), None);
        assert_eq!(parse_workers(Some("0")), None);
        assert_eq!(parse_workers(Some("two of them")), None);
    }

    #[test]
    fn auto_workers_uses_quota() {
        assert_eq!(auto_workers(Some(2.0), 64), (2, WorkersSource::Quota));
        // A fractional quota (500m, 1500m) rounds up: there is no such thing as less than a worker.
        assert_eq!(auto_workers(Some(0.5), 64), (1, WorkersSource::Quota));
        assert_eq!(auto_workers(Some(1.5), 64), (2, WorkersSource::Quota));
    }

    #[test]
    fn auto_workers_caps_quota_by_parallelism() {
        assert_eq!(auto_workers(Some(32.0), 4), (4, WorkersSource::Quota));
    }

    #[test]
    fn auto_workers_without_quota_ignores_host_cores() {
        // The main scenario behind this work: the CPU limit is absent and the
        // node is large. The actix default would give 64 workers here.
        assert_eq!(
            auto_workers(None, 64),
            (DEFAULT_MAX_WORKERS, WorkersSource::Fallback)
        );
        // On a machine below the ceiling its own parallelism is taken.
        assert_eq!(auto_workers(None, 2), (2, WorkersSource::Fallback));
        assert_eq!(auto_workers(None, 0), (1, WorkersSource::Fallback));
    }

    #[test]
    fn parse_u64_takes_explicit_value() {
        assert_eq!(parse_u64(Some("10"), "K", 25), 10);
        assert_eq!(parse_u64(Some(" 0 "), "K", 25), 0);
    }

    #[test]
    fn parse_u64_falls_back_to_default() {
        // Garbage and an empty value do not bring the service down — the default is taken.
        assert_eq!(parse_u64(None, "K", 25), 25);
        assert_eq!(parse_u64(Some(""), "K", 25), 25);
        assert_eq!(parse_u64(Some("   "), "K", 25), 25);
        assert_eq!(parse_u64(Some("half a minute"), "K", 25), 25);
        assert_eq!(parse_u64(Some("-1"), "K", 25), 25);
    }

    /// Extracts the value of a simple YAML key from a manifest: the first line
    /// starting with `key:` (comments are skipped).
    fn manifest_value<'a>(manifest: &'a str, key: &str) -> &'a str {
        manifest
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
            .unwrap_or_else(|| panic!("the manifest has no key {key}"))
            .trim()
            .trim_matches('"')
    }

    /// Extracts the value of an environment variable from the env list of a k8s
    /// manifest: the `value:` line right after `- name: <KEY>`.
    fn env_value<'a>(manifest: &'a str, key: &str) -> &'a str {
        let mut lines = manifest
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'));
        lines
            .find(|line| line == &format!("- name: {key}"))
            .unwrap_or_else(|| panic!("the manifest has no variable {key}"));
        lines
            .next()
            .and_then(|line| line.strip_prefix("value:"))
            .unwrap_or_else(|| panic!("the variable {key} has no value in the manifest"))
            .trim()
            .trim_matches('"')
    }

    #[test]
    fn shutdown_timeout_fits_into_grace_periods() {
        // The drain timeout and the orchestrator grace period are one setting
        // spread over two files, and the link between them is held by this test
        // rather than by attentiveness: were they equal (as with the actix
        // default of 30 s), SIGKILL would arrive exactly as the drain ran out,
        // leaving time for neither the last request nor the telemetry flushed
        // after `run()` returns.
        let k8s = include_str!("../deployments/prod/k8s/deployment.yaml");
        let compose = include_str!("../deployments/prod/docker-compose.yml");

        let grace: u64 = manifest_value(k8s, "terminationGracePeriodSeconds")
            .parse()
            .expect("terminationGracePeriodSeconds is a whole number of seconds");
        let stop_grace: u64 = manifest_value(compose, "stop_grace_period")
            .trim_end_matches('s')
            .parse()
            .expect("stop_grace_period is seconds in the '30s' form");

        assert!(
            DEFAULT_SHUTDOWN_TIMEOUT_SECONDS < grace,
            "a drain of {DEFAULT_SHUTDOWN_TIMEOUT_SECONDS} s does not fit into the k8s grace period of {grace} s"
        );
        assert!(
            DEFAULT_SHUTDOWN_TIMEOUT_SECONDS < stop_grace,
            "a drain of {DEFAULT_SHUTDOWN_TIMEOUT_SECONDS} s does not fit into the compose stop_grace_period of {stop_grace} s"
        );

        // The k8s manifest sets the variable explicitly; the value must match the
        // default, or the headroom calculation in its comments drifts from the
        // code.
        let in_k8s: u64 = env_value(k8s, "SERVER_SHUTDOWN_TIMEOUT_SECONDS")
            .parse()
            .expect("SERVER_SHUTDOWN_TIMEOUT_SECONDS in the manifest is a whole number");
        assert_eq!(in_k8s, DEFAULT_SHUTDOWN_TIMEOUT_SECONDS);
    }

    #[test]
    fn parse_cpu_max_reads_quota() {
        assert_eq!(parse_cpu_max("150000 100000\n"), Some(1.5));
        assert_eq!(parse_cpu_max("200000 100000"), Some(2.0));
    }

    #[test]
    fn parse_cpu_max_without_quota() {
        assert_eq!(parse_cpu_max("max 100000\n"), None);
        assert_eq!(parse_cpu_max(""), None);
        assert_eq!(parse_cpu_max("100000"), None);
        assert_eq!(parse_cpu_max("garbage 100000"), None);
    }

    #[test]
    fn parse_cfs_quota_v1() {
        assert_eq!(parse_cfs_quota("100000\n", "100000\n"), Some(1.0));
        // -1 in v1 means "there is no quota".
        assert_eq!(parse_cfs_quota("-1", "100000"), None);
        assert_eq!(parse_cfs_quota("100000", "0"), None);
    }
}
