//! The GlitchTip integration (a Sentry-compatible backend).
//!
//! It covers **three** observability channels, not just errors:
//!
//! | Channel | What goes there | How it is enabled |
//! |---------|-----------------|-------------------|
//! | **Issues** | panics and `ERROR`-level events | always, given a DSN |
//! | **Performance** | spans → transactions with a duration | `GLITCHTIP_TRACES_SAMPLE_RATE > 0` |
//! | **Logs** | structured logs (`INFO`/`WARN`/`DEBUG`) | `GLITCHTIP_ENABLE_LOGS=true` |
//!
//! All of it is a layer over the same `tracing` bus as the logs
//! ([`crate::logging`]) and OpenTelemetry ([`crate::tracing_otel`]): one source
//! of events, several outputs.
//!
//! ## Enabling
//!
//! Only when `GLITCHTIP_DSN` is set (`SENTRY_DSN` is accepted too — the name
//! used by Sentry-compatible tooling). Unset means the integration is off
//! entirely.
//!
//! **Not fail-fast.** An invalid DSN does not bring the service down: a warning
//! into the log and it keeps working without GlitchTip. Telemetry must never be
//! a cause of unavailability.
//!
//! ## Secrets
//!
//! The DSN is **never logged** — only the fact that the integration is on
//! appears in the messages. Event bodies must contain no tokens or secrets: see
//! the policy in [`crate::logging`] (we never write request headers or bodies).

use std::env;

use sentry::ClientInitGuard;

/// The primary name of the DSN variable.
const DSN_VAR: &str = "GLITCHTIP_DSN";

/// The compatible name (set by Sentry-compatible tooling).
const DSN_VAR_ALT: &str = "SENTRY_DSN";

/// Fraction of spans sent to performance monitoring (0.0 means off).
const TRACES_RATE_VAR: &str = "GLITCHTIP_TRACES_SAMPLE_RATE";

/// Enabling structured logs.
const ENABLE_LOGS_VAR: &str = "GLITCHTIP_ENABLE_LOGS";

/// The outcome of initialisation.
///
/// As in [`crate::tracing_otel::Status`], it exists because initialisation
/// happens **before** the `tracing` subscriber is installed: logging right there
/// would lose the message.
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    /// No DSN is set — the integration is off.
    Disabled,
    /// The integration is on.
    Enabled {
        /// Whether performance monitoring is on (sampling rate > 0).
        performance: bool,
        /// Whether structured logs are on.
        logs: bool,
    },
}

impl Status {
    /// Whether structured logs are on. Needed by [`layer`]: since 0.49 we filter
    /// the Logs channel ourselves, see the comment there.
    pub fn logs_enabled(&self) -> bool {
        matches!(self, Status::Enabled { logs: true, .. })
    }

    /// Writes the status to the log. Call it after the subscriber is installed.
    pub fn log(&self) {
        match self {
            Status::Disabled => {
                tracing::debug!("GlitchTip: integration disabled ({DSN_VAR} is not set)");
            }
            Status::Enabled { performance, logs } => {
                // The DSN is deliberately not written — it is a secret.
                tracing::info!(
                    performance,
                    logs,
                    "GlitchTip: integration enabled (errors and panics)"
                );
            }
        }
    }
}

/// Reads an `f32` from the environment, falling back to `default`.
fn env_f32(key: &str, default: f32) -> f32 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<f32>().ok())
        .filter(|v| v.is_finite())
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(default)
}

/// Reads a boolean flag from the environment (`true`/`1`/`yes`).
fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"),
        Err(_) => default,
    }
}

/// Reads the DSN: `GLITCHTIP_DSN` first, then the compatible `SENTRY_DSN`.
fn read_dsn() -> Option<String> {
    for var in [DSN_VAR, DSN_VAR_ALT] {
        if let Some(dsn) = env::var(var).ok().filter(|s| !s.trim().is_empty()) {
            return Some(dsn.trim().to_string());
        }
    }
    None
}

/// Initialises the GlitchTip client.
///
/// Returns a guard (keep it alive until the process ends — destroying it flushes
/// the accumulated events) and a status to be logged later.
///
/// Does nothing and returns [`Status::Disabled`] when no DSN is set.
pub fn init() -> (Option<ClientInitGuard>, Status) {
    let Some(dsn) = read_dsn() else {
        return (None, Status::Disabled);
    };

    // 0.0 means performance is off (the default): transactions cost money and
    // volume, so enable them deliberately.
    let traces_sample_rate = env_f32(TRACES_RATE_VAR, 0.0);
    let enable_logs = env_bool(ENABLE_LOGS_VAR, false);

    // Since 0.49 `ClientOptions` is `#[non_exhaustive]`: a struct literal does
    // not compile outside the crate, leaving only the builder.
    let mut options = sentry::ClientOptions::new()
        // The service version — so that issues are grouped by release.
        .release(env!("CARGO_PKG_VERSION"));

    if let Ok(environment) = env::var("GLITCHTIP_ENVIRONMENT") {
        options = options.environment(environment);
    }

    // The sampling strategy is set only for a non-zero rate. An absent rate is
    // `TracesSamplingStrategy::Disabled` (the default), and that differs from an
    // explicit `FixedRate(0.0)`: the latter still respects the parent decision
    // from an incoming trace context, so transactions would keep being sent.
    if traces_sample_rate > 0.0 {
        options = options.traces_sample_rate(traces_sample_rate);
    }

    let guard = sentry::init((dsn, options));

    (
        Some(guard),
        Status::Enabled {
            performance: traces_sample_rate > 0.0,
            logs: enable_logs,
        },
    )
}

/// Builds the `tracing` layer that splits events across the GlitchTip channels.
///
/// - `ERROR` → an **issue** (an entry in the Issues section);
/// - `WARN`/`INFO`/`DEBUG` → a **log** (the Logs section) when `logs` is on,
///   otherwise breadcrumbs for future errors (`DEBUG` is dropped in that case);
/// - spans → **transactions** (the Performance section) when sampling is on.
///
/// `logs` comes from the outside (see [`Status::logs_enabled`]) rather than from
/// `ClientOptions::enable_logs`: since 0.49 that field is deprecated — upstream,
/// manually captured logs are always sent and the option only affects automatic
/// capture by integrations. The recommended path is to configure what an
/// integration sends by its own means, and for `tracing` that is the event
/// filter below.
pub fn layer<S>(logs: bool) -> sentry::integrations::tracing::SentryLayer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use sentry::integrations::tracing::EventFilter;

    sentry::integrations::tracing::layer().event_filter(move |md| match *md.level() {
        // A service failure — open an issue.
        tracing::Level::ERROR => EventFilter::Event,
        // Everything else goes to Logs (and as breadcrumbs for errors).
        tracing::Level::WARN | tracing::Level::INFO => {
            if logs {
                EventFilter::Log | EventFilter::Breadcrumb
            } else {
                EventFilter::Breadcrumb
            }
        }
        tracing::Level::DEBUG => {
            if logs {
                EventFilter::Log
            } else {
                EventFilter::Ignore
            }
        }
        tracing::Level::TRACE => EventFilter::Ignore,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The tests touch global env vars — serialise them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear() {
        for v in [DSN_VAR, DSN_VAR_ALT, TRACES_RATE_VAR, ENABLE_LOGS_VAR] {
            env::remove_var(v);
        }
    }

    #[test]
    fn disabled_without_dsn() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let (client, status) = init();
        assert!(client.is_none());
        assert_eq!(status, Status::Disabled);
    }

    #[test]
    fn reads_alternative_dsn_var() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        env::set_var(DSN_VAR_ALT, "https://key@example.test/1");
        let dsn = read_dsn();
        clear();
        assert_eq!(dsn.as_deref(), Some("https://key@example.test/1"));
    }

    #[test]
    fn primary_dsn_var_wins() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        env::set_var(DSN_VAR, "https://primary@example.test/1");
        env::set_var(DSN_VAR_ALT, "https://alt@example.test/2");
        let dsn = read_dsn();
        clear();
        assert_eq!(dsn.as_deref(), Some("https://primary@example.test/1"));
    }

    #[test]
    fn blank_dsn_means_disabled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        env::set_var(DSN_VAR, "   ");
        let dsn = read_dsn();
        clear();
        assert_eq!(dsn, None);
    }

    #[test]
    fn sample_rate_is_clamped() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        env::set_var(TRACES_RATE_VAR, "2.5");
        assert_eq!(env_f32(TRACES_RATE_VAR, 0.0), 1.0);
        env::set_var(TRACES_RATE_VAR, "-1");
        assert_eq!(env_f32(TRACES_RATE_VAR, 0.0), 0.0);
        env::set_var(TRACES_RATE_VAR, "not a number");
        assert_eq!(env_f32(TRACES_RATE_VAR, 0.0), 0.0, "garbage → default");
        env::set_var(TRACES_RATE_VAR, "0.25");
        assert_eq!(env_f32(TRACES_RATE_VAR, 0.0), 0.25);
        clear();
    }

    #[test]
    fn status_reports_logs_flag() {
        assert!(Status::Enabled {
            performance: false,
            logs: true
        }
        .logs_enabled());
        assert!(!Status::Enabled {
            performance: true,
            logs: false
        }
        .logs_enabled());
        assert!(!Status::Disabled.logs_enabled());
    }

    #[test]
    fn logs_flag_parsing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        assert!(!env_bool(ENABLE_LOGS_VAR, false), "off by default");
        for truthy in ["true", "1", "yes", "TRUE"] {
            env::set_var(ENABLE_LOGS_VAR, truthy);
            assert!(env_bool(ENABLE_LOGS_VAR, false), "{truthy}");
        }
        env::set_var(ENABLE_LOGS_VAR, "false");
        assert!(!env_bool(ENABLE_LOGS_VAR, false));
        clear();
    }
}
