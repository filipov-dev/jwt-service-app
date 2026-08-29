//! Distributed tracing through OpenTelemetry (OTLP).
//!
//! A layer over the same `tracing` bus as the logs (see [`crate::logging`]): the
//! spans of requests and of calls to dependencies go over OTLP to an
//! OpenTelemetry Collector, from which Monium (or any other backend — Jaeger,
//! Tempo) picks them up.
//!
//! ## Enabling
//!
//! Only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set (the standard OpenTelemetry
//! variable, understood by agents and collectors alike). Unset means tracing is
//! off and the service works as before.
//!
//! **Not fail-fast.** Unlike the auth secrets, a misconfigured exporter does not
//! bring the service down: we write a warning and continue without tracing.
//! Telemetry must never be a cause of service unavailability.
//!
//! ## Propagation
//!
//! The incoming `traceparent` header (W3C Trace Context) is picked up in
//! [`crate::logging::RequestLog`], and outgoing requests to `jwks-service-app`
//! get their own `traceparent` — that is how a trace continues across services.
//!
//! ## Transport
//!
//! OTLP over HTTP/protobuf (usually port **4318** on the collector) rather than
//! gRPC: `reqwest` is already among the dependencies, so we do not pull in the
//! tonic/gRPC stack.

use std::env;
use std::time::Duration;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing::warn;

/// Name of the variable holding the OTLP collector address (an OpenTelemetry standard).
const ENDPOINT_VAR: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// Service name in traces; overridden by `OTEL_SERVICE_NAME`.
const DEFAULT_SERVICE_NAME: &str = "jwt-service-app";

/// Export timeout: the collector must not hang the service.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// The variable holding the full URL specifically for traces (an OpenTelemetry standard).
const TRACES_ENDPOINT_VAR: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";

/// The variable holding the full URL specifically for logs (an OpenTelemetry standard).
const LOGS_ENDPOINT_VAR: &str = "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT";

/// The flag enabling log export over OTLP.
const LOGS_ENABLED_VAR: &str = "OTEL_LOGS_ENABLED";

/// The traces signal path in OTLP/HTTP.
const TRACES_PATH: &str = "/v1/traces";

/// The logs signal path in OTLP/HTTP.
const LOGS_PATH: &str = "/v1/logs";

/// Computes the signal URL by the rules of the OpenTelemetry specification:
///
/// - the signal variable (`..._TRACES_ENDPOINT` / `..._LOGS_ENDPOINT`) is the
///   **full** URL and is used as is;
/// - `OTEL_EXPORTER_OTLP_ENDPOINT` is the **base** URL, to which the signal path
///   is appended (`/v1/traces`, `/v1/logs`).
///
/// The distinction matters: in OTLP/HTTP the request goes to an exact address,
/// and sending the base URL as is makes the collector answer `404` while the
/// data is silently lost.
fn signal_endpoint(signal: Option<String>, base: Option<String>, path: &str) -> Option<String> {
    if let Some(signal) = signal
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return Some(signal);
    }

    let base = base
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;
    Some(format!("{}{path}", base.trim_end_matches('/')))
}

/// Reads a boolean flag from the environment (`true`/`1`/`yes`).
fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"),
        Err(_) => default,
    }
}

/// The outcome of the tracing setup.
///
/// A separate type is needed because [`init_tracer_provider`] is called
/// **before** the global `tracing` subscriber is installed: logging right there
/// would lose the message (there is nowhere to write yet). So the status is
/// returned to the caller and printed through [`Status::log`] once the
/// subscriber is initialised.
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    /// `OTEL_EXPORTER_OTLP_ENDPOINT` is unset — tracing is off.
    Disabled,
    /// Export is configured.
    Enabled {
        endpoint: String,
        service_name: String,
    },
    /// The exporter could not be built; the service keeps running without tracing.
    Failed { endpoint: String, error: String },
}

impl Status {
    /// Writes the status to the log. Call it after the subscriber is installed.
    pub fn log(&self) {
        match self {
            Status::Disabled => {
                tracing::debug!("OpenTelemetry: tracing disabled ({ENDPOINT_VAR} is not set)");
            }
            Status::Enabled {
                endpoint,
                service_name,
            } => {
                tracing::info!(
                    endpoint = %endpoint,
                    service_name = %service_name,
                    "OpenTelemetry: OTLP trace export enabled"
                );
            }
            Status::Failed { endpoint, error } => {
                warn!("OTLP exporter not built ({endpoint}), tracing disabled: {error}");
            }
        }
    }
}

/// Configures OTLP trace export when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
///
/// Returns the provider (which must be kept alive until the process ends and
/// shut down properly through [`shutdown`]) — or `None` when tracing is off or
/// the exporter could not be built.
///
/// Side effect: it installs the global W3C propagator so that `traceparent`
/// headers work.
pub fn init_tracer_provider() -> (Option<SdkTracerProvider>, Status) {
    let Some(endpoint) = signal_endpoint(
        env::var(TRACES_ENDPOINT_VAR).ok(),
        env::var(ENDPOINT_VAR).ok(),
        TRACES_PATH,
    ) else {
        return (None, Status::Disabled);
    };

    let service_name =
        env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| DEFAULT_SERVICE_NAME.to_string());

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint.clone())
        .with_timeout(EXPORT_TIMEOUT)
        .build()
    {
        Ok(exporter) => exporter,
        Err(e) => {
            // Not fail-fast: telemetry is no reason to refuse to start.
            return (
                None,
                Status::Failed {
                    endpoint,
                    error: e.to_string(),
                },
            );
        }
    };

    let resource = Resource::builder()
        .with_attributes([KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_NAME,
            service_name.clone(),
        )])
        .build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    // W3C Trace Context: it understands `traceparent`/`tracestate`.
    global::set_text_map_propagator(TraceContextPropagator::new());

    (
        Some(provider),
        Status::Enabled {
            endpoint,
            service_name,
        },
    )
}

/// Builds the `tracing` layer over the provider.
pub fn layer<S>(
    provider: &SdkTracerProvider,
) -> tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::SdkTracer>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_opentelemetry::layer().with_tracer(provider.tracer(DEFAULT_SERVICE_NAME))
}

/// Configures OTLP export of **logs** when it is enabled.
///
/// Both conditions must hold:
/// - a collector address is set (`OTEL_EXPORTER_OTLP_ENDPOINT` or
///   `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`);
/// - `OTEL_LOGS_ENABLED=true` is set.
///
/// The separate flag is deliberate: logs go to stdout anyway, and where an agent
/// already collects them from the container log, sending them over OTLP would be
/// duplication (and paid-for traffic). So enabling traces does **not** enable
/// logs automatically.
pub fn init_logger_provider() -> (Option<SdkLoggerProvider>, LogsStatus) {
    if !env_bool(LOGS_ENABLED_VAR, false) {
        return (None, LogsStatus::Disabled);
    }

    let Some(endpoint) = signal_endpoint(
        env::var(LOGS_ENDPOINT_VAR).ok(),
        env::var(ENDPOINT_VAR).ok(),
        LOGS_PATH,
    ) else {
        return (None, LogsStatus::NoEndpoint);
    };

    let service_name =
        env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| DEFAULT_SERVICE_NAME.to_string());

    let exporter = match opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_endpoint(endpoint.clone())
        .with_timeout(EXPORT_TIMEOUT)
        .build()
    {
        Ok(exporter) => exporter,
        Err(e) => {
            return (
                None,
                LogsStatus::Failed {
                    endpoint,
                    error: e.to_string(),
                },
            );
        }
    };

    let resource = Resource::builder()
        .with_attributes([KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_NAME,
            service_name,
        )])
        .build();

    let provider = SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    (Some(provider), LogsStatus::Enabled { endpoint })
}

/// Builds the `tracing` layer that sends events to the OTLP logs.
pub fn logs_layer(
    provider: &SdkLoggerProvider,
) -> opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge<
    SdkLoggerProvider,
    opentelemetry_sdk::logs::SdkLogger,
> {
    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(provider)
}

/// Flushes the accumulated logs and shuts the provider down properly.
pub fn shutdown_logs(provider: SdkLoggerProvider) {
    if let Err(e) = provider.shutdown() {
        warn!("OpenTelemetry: could not shut log export down cleanly: {e}");
    }
}

/// The outcome of the OTLP log export setup.
#[derive(Debug, PartialEq, Eq)]
pub enum LogsStatus {
    /// `OTEL_LOGS_ENABLED` is unset — logs go to stdout only.
    Disabled,
    /// Logs are enabled but no collector address is set.
    NoEndpoint,
    /// Export is configured.
    Enabled { endpoint: String },
    /// The exporter could not be built; the service runs without OTLP logs.
    Failed { endpoint: String, error: String },
}

impl LogsStatus {
    /// Writes the status to the log. Call it after the subscriber is installed.
    pub fn log(&self) {
        match self {
            LogsStatus::Disabled => {
                tracing::debug!(
                    "OpenTelemetry: log export over OTLP disabled \
                     ({LOGS_ENABLED_VAR} is not set); logs go to stdout"
                );
            }
            LogsStatus::NoEndpoint => {
                warn!(
                    "{LOGS_ENABLED_VAR}=true but no collector address is set \
                     ({ENDPOINT_VAR}/{LOGS_ENDPOINT_VAR}) — logs are not sent over OTLP"
                );
            }
            LogsStatus::Enabled { endpoint } => {
                tracing::info!(endpoint = %endpoint, "OpenTelemetry: OTLP log export enabled");
            }
            LogsStatus::Failed { endpoint, error } => {
                warn!("OTLP log exporter not built ({endpoint}), OTLP logs disabled: {error}");
            }
        }
    }
}

/// An adapter of actix headers for the W3C propagator (reading `traceparent`).
struct HeaderExtractor<'a>(&'a actix_web::http::header::HeaderMap);

impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Extracts the parent trace context from the headers of an incoming request.
///
/// If the calling service sent a `traceparent`, our span becomes its child —
/// that is how a trace is stitched across service boundaries. Without the header
/// (or with tracing off) an empty context is returned and the span is a root.
pub fn extract_parent_context(
    headers: &actix_web::http::header::HeaderMap,
) -> opentelemetry::Context {
    global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(headers)))
}

/// An adapter of `reqwest` headers for writing `traceparent` into an outgoing request.
struct HeaderInjector<'a>(&'a mut reqwest::header::HeaderMap);

impl opentelemetry::propagation::Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(key.as_bytes()),
            reqwest::header::HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, value);
        }
    }
}

/// Adds the trace context headers of the current span to an outgoing request.
///
/// Thanks to this, calls to `jwks-service-app` land in the same trace as the
/// HTTP request being served. When tracing is off the default propagator writes
/// nothing — there is no overhead.
pub fn inject_context(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let context = tracing::Span::current().context();
    let mut headers = reqwest::header::HeaderMap::new();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut HeaderInjector(&mut headers))
    });

    builder.headers(headers)
}

/// Flushes the accumulated spans and shuts the provider down properly.
///
/// Call it when the service stops, or the last traces are lost.
pub fn shutdown(provider: SdkTracerProvider) {
    if let Err(e) = provider.shutdown() {
        warn!("OpenTelemetry: could not shut trace export down cleanly: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The tests touch global env vars — serialise them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn appends_signal_path_to_base_endpoint() {
        // A base URL: the signal path is mandatory, otherwise the collector
        // answers 404 and the traces are silently lost.
        assert_eq!(
            signal_endpoint(None, Some("http://collector:4318".into()), TRACES_PATH),
            Some("http://collector:4318/v1/traces".into())
        );
        // A trailing slash must not produce a double one.
        assert_eq!(
            signal_endpoint(None, Some("http://collector:4318/".into()), TRACES_PATH),
            Some("http://collector:4318/v1/traces".into())
        );
    }

    #[test]
    fn appends_logs_path_for_logs_signal() {
        // The same mechanism with a different signal path: without `/v1/logs`
        // the collector answers 404 and the logs are silently lost.
        assert_eq!(
            signal_endpoint(None, Some("http://collector:4318".into()), LOGS_PATH),
            Some("http://collector:4318/v1/logs".into())
        );
    }

    #[test]
    fn signal_endpoint_is_used_as_is() {
        // The full signal URL takes precedence and is not appended to.
        assert_eq!(
            signal_endpoint(
                Some("http://collector:4318/custom/traces".into()),
                Some("http://ignored:4318".into()),
                TRACES_PATH
            ),
            Some("http://collector:4318/custom/traces".into())
        );
    }

    #[test]
    fn no_endpoint_means_disabled() {
        assert_eq!(signal_endpoint(None, None, TRACES_PATH), None);
        assert_eq!(
            signal_endpoint(Some("  ".into()), Some("  ".into()), TRACES_PATH),
            None
        );
    }

    #[test]
    fn logs_disabled_without_flag() {
        // Enabled traces do NOT enable logs automatically — an explicit flag is
        // needed, otherwise we would duplicate stdout logs where an agent
        // collects them.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var(LOGS_ENABLED_VAR);
        env::set_var(ENDPOINT_VAR, "http://collector:4318");
        let (provider, status) = init_logger_provider();
        env::remove_var(ENDPOINT_VAR);
        assert!(provider.is_none());
        assert_eq!(status, LogsStatus::Disabled);
    }

    #[test]
    fn logs_enabled_without_endpoint_warns() {
        // The flag is there but the address is not — degrade with a warning rather than silently.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var(ENDPOINT_VAR);
        env::remove_var(LOGS_ENDPOINT_VAR);
        env::set_var(LOGS_ENABLED_VAR, "true");
        let (provider, status) = init_logger_provider();
        env::remove_var(LOGS_ENABLED_VAR);
        assert!(provider.is_none());
        assert_eq!(status, LogsStatus::NoEndpoint);
    }

    #[test]
    fn disabled_without_endpoint() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var(ENDPOINT_VAR);
        env::remove_var(TRACES_ENDPOINT_VAR);
        let (provider, status) = init_tracer_provider();
        assert!(
            provider.is_none(),
            "without {ENDPOINT_VAR} tracing must be disabled"
        );
        assert_eq!(status, Status::Disabled);
    }

    #[test]
    fn disabled_on_blank_endpoint() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var(TRACES_ENDPOINT_VAR);
        env::set_var(ENDPOINT_VAR, "   ");
        let (provider, status) = init_tracer_provider();
        env::remove_var(ENDPOINT_VAR);
        assert!(provider.is_none(), "an empty value means tracing is off");
        assert_eq!(status, Status::Disabled);
    }
}
