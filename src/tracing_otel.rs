//! Распределённый трейсинг через OpenTelemetry (OTLP).
//!
//! Слой поверх той же `tracing`-шины, что и логи (см. [`crate::logging`]): span'ы
//! запросов и обращений к зависимостям уходят по OTLP в OpenTelemetry Collector,
//! откуда их забирает Monium (или любой другой backend — Jaeger, Tempo).
//!
//! ## Включение
//!
//! Только при заданном `OTEL_EXPORTER_OTLP_ENDPOINT` (стандартная переменная
//! OpenTelemetry, её же понимают агенты и коллекторы). Не задана — трейсинг
//! выключен, сервис работает как прежде.
//!
//! **Не fail-fast.** В отличие от auth-секретов, ошибка настройки экспортёра не
//! роняет сервис: пишем предупреждение и продолжаем без трейсинга. Телеметрия не
//! должна быть причиной недоступности сервиса.
//!
//! ## Propagation
//!
//! Входящий заголовок `traceparent` (W3C Trace Context) подхватывается в
//! [`crate::logging::RequestLog`], исходящие запросы к `jwks-service-app`
//! получают свой `traceparent` — так трасса продолжается сквозь сервисы.
//!
//! ## Транспорт
//!
//! OTLP поверх HTTP/protobuf (у коллектора это обычно порт **4318**), а не gRPC:
//! `reqwest` уже есть в зависимостях, поэтому tonic/gRPC-стек не тянем.

use std::env;
use std::time::Duration;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing::warn;

/// Имя переменной с адресом OTLP-коллектора (стандарт OpenTelemetry).
const ENDPOINT_VAR: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// Имя сервиса в трейсах; переопределяется `OTEL_SERVICE_NAME`.
const DEFAULT_SERVICE_NAME: &str = "jwt-service-app";

/// Таймаут экспорта: коллектор не должен подвешивать сервис.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// Переменная с полным URL именно для трейсов (стандарт OpenTelemetry).
const TRACES_ENDPOINT_VAR: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";

/// Переменная с полным URL именно для логов (стандарт OpenTelemetry).
const LOGS_ENDPOINT_VAR: &str = "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT";

/// Флаг включения отправки логов по OTLP.
const LOGS_ENABLED_VAR: &str = "OTEL_LOGS_ENABLED";

/// Путь сигнала трейсов в OTLP/HTTP.
const TRACES_PATH: &str = "/v1/traces";

/// Путь сигнала логов в OTLP/HTTP.
const LOGS_PATH: &str = "/v1/logs";

/// Вычисляет URL сигнала по правилам спецификации OpenTelemetry:
///
/// - переменная сигнала (`..._TRACES_ENDPOINT` / `..._LOGS_ENDPOINT`) — **полный**
///   URL, используется как есть;
/// - `OTEL_EXPORTER_OTLP_ENDPOINT` — **базовый** URL, к нему добавляется путь
///   сигнала (`/v1/traces`, `/v1/logs`).
///
/// Различие принципиально: в OTLP/HTTP запрос уходит по точному адресу, и если
/// послать базовый URL как есть, коллектор ответит `404`, а данные будут молча
/// теряться.
fn signal_endpoint(signal: Option<String>, base: Option<String>, path: &str) -> Option<String> {
    if let Some(signal) = signal.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        return Some(signal);
    }

    let base = base.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())?;
    Some(format!("{}{path}", base.trim_end_matches('/')))
}

/// Читает булев флаг из окружения (`true`/`1`/`yes`).
fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"),
        Err(_) => default,
    }
}

/// Исход настройки трейсинга.
///
/// Отдельный тип нужен, потому что [`init_tracer_provider`] вызывается **до**
/// установки глобального `tracing`-subscriber'а: залогируй мы прямо там, сообщение
/// было бы потеряно (писать ещё некуда). Поэтому статус возвращается наружу и
/// печатается через [`Status::log`] уже после инициализации subscriber'а.
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    /// `OTEL_EXPORTER_OTLP_ENDPOINT` не задан — трейсинг выключен.
    Disabled,
    /// Экспорт настроен.
    Enabled { endpoint: String, service_name: String },
    /// Экспортёр не построился; сервис продолжает работу без трейсинга.
    Failed { endpoint: String, error: String },
}

impl Status {
    /// Пишет статус в лог. Вызывать после установки subscriber'а.
    pub fn log(&self) {
        match self {
            Status::Disabled => {
                tracing::debug!(
                    "OpenTelemetry: трейсинг выключен ({ENDPOINT_VAR} не задан)"
                );
            }
            Status::Enabled { endpoint, service_name } => {
                tracing::info!(
                    endpoint = %endpoint,
                    service_name = %service_name,
                    "OpenTelemetry: OTLP-экспорт трейсов включён"
                );
            }
            Status::Failed { endpoint, error } => {
                warn!("OTLP-экспортёр не построен ({endpoint}), трейсинг выключен: {error}");
            }
        }
    }
}

/// Настраивает OTLP-экспорт трейсов, если задан `OTEL_EXPORTER_OTLP_ENDPOINT`.
///
/// Возвращает провайдер (его нужно держать живым до конца работы процесса и
/// корректно завершить через [`shutdown`]) — либо `None`, если трейсинг выключен
/// или экспортёр не построился.
///
/// Побочный эффект: устанавливает глобальный W3C-propagator, чтобы работали
/// `traceparent`-заголовки.
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
            // Не fail-fast: телеметрия не повод не стартовать.
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

    // W3C Trace Context: понимает `traceparent`/`tracestate`.
    global::set_text_map_propagator(TraceContextPropagator::new());

    (
        Some(provider),
        Status::Enabled {
            endpoint,
            service_name,
        },
    )
}

/// Строит `tracing`-слой поверх провайдера.
pub fn layer<S>(provider: &SdkTracerProvider) -> tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::SdkTracer>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_opentelemetry::layer().with_tracer(provider.tracer(DEFAULT_SERVICE_NAME))
}

/// Настраивает OTLP-экспорт **логов**, если он включён.
///
/// Условия включения — оба сразу:
/// - задан адрес коллектора (`OTEL_EXPORTER_OTLP_ENDPOINT` или
///   `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`);
/// - выставлен `OTEL_LOGS_ENABLED=true`.
///
/// Отдельный флаг нужен намеренно: логи и так пишутся в stdout, и там, где их уже
/// собирает агент с контейнерного лога, отправка по OTLP была бы дублированием
/// (и оплаченным трафиком). Поэтому включение трейсов **не** включает логи
/// автоматически.
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

/// Строит `tracing`-слой, отправляющий события в OTLP-логи.
pub fn logs_layer(
    provider: &SdkLoggerProvider,
) -> opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge<SdkLoggerProvider, opentelemetry_sdk::logs::SdkLogger>
{
    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(provider)
}

/// Досылает накопленные логи и корректно завершает провайдер.
pub fn shutdown_logs(provider: SdkLoggerProvider) {
    if let Err(e) = provider.shutdown() {
        warn!("OpenTelemetry: не удалось корректно завершить экспорт логов: {e}");
    }
}

/// Исход настройки OTLP-экспорта логов.
#[derive(Debug, PartialEq, Eq)]
pub enum LogsStatus {
    /// `OTEL_LOGS_ENABLED` не выставлен — логи идут только в stdout.
    Disabled,
    /// Логи включены, но адрес коллектора не задан.
    NoEndpoint,
    /// Экспорт настроен.
    Enabled { endpoint: String },
    /// Экспортёр не построился; сервис работает без OTLP-логов.
    Failed { endpoint: String, error: String },
}

impl LogsStatus {
    /// Пишет статус в лог. Вызывать после установки subscriber'а.
    pub fn log(&self) {
        match self {
            LogsStatus::Disabled => {
                tracing::debug!(
                    "OpenTelemetry: отправка логов по OTLP выключена \
                     ({LOGS_ENABLED_VAR} не выставлен); логи идут в stdout"
                );
            }
            LogsStatus::NoEndpoint => {
                warn!(
                    "{LOGS_ENABLED_VAR}=true, но адрес коллектора не задан \
                     ({ENDPOINT_VAR}/{LOGS_ENDPOINT_VAR}) — логи по OTLP не отправляются"
                );
            }
            LogsStatus::Enabled { endpoint } => {
                tracing::info!(endpoint = %endpoint, "OpenTelemetry: OTLP-экспорт логов включён");
            }
            LogsStatus::Failed { endpoint, error } => {
                warn!("OTLP-экспортёр логов не построен ({endpoint}), логи по OTLP выключены: {error}");
            }
        }
    }
}

/// Адаптер actix-заголовков для W3C-propagator'а (чтение `traceparent`).
struct HeaderExtractor<'a>(&'a actix_web::http::header::HeaderMap);

impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Достаёт родительский трейс-контекст из заголовков входящего запроса.
///
/// Если вызывающий сервис прислал `traceparent`, наш span станет его потомком —
/// так трасса склеивается сквозь границы сервисов. Нет заголовка (или трейсинг
/// выключен) — вернётся пустой контекст, и span будет корневым.
pub fn extract_parent_context(
    headers: &actix_web::http::header::HeaderMap,
) -> opentelemetry::Context {
    global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(headers)))
}

/// Адаптер `reqwest`-заголовков для записи `traceparent` в исходящий запрос.
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

/// Добавляет к исходящему запросу заголовки трейс-контекста текущего span'а.
///
/// Благодаря этому обращения к `jwks-service-app` попадают в ту же трассу, что и
/// обслуживаемый HTTP-запрос. Если трейсинг выключен, propagator по умолчанию
/// ничего не пишет — накладных расходов нет.
pub fn inject_context(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let context = tracing::Span::current().context();
    let mut headers = reqwest::header::HeaderMap::new();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut HeaderInjector(&mut headers))
    });

    builder.headers(headers)
}

/// Досылает накопленные span'ы и корректно завершает провайдер.
///
/// Вызывать при остановке сервиса, иначе последние трейсы потеряются.
pub fn shutdown(provider: SdkTracerProvider) {
    if let Err(e) = provider.shutdown() {
        warn!("OpenTelemetry: не удалось корректно завершить экспорт трейсов: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Тесты трогают глобальные env — сериализуем.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn appends_signal_path_to_base_endpoint() {
        // Базовый URL: путь сигнала обязателен, иначе коллектор ответит 404 и
        // трейсы будут молча теряться.
        assert_eq!(
            signal_endpoint(None, Some("http://collector:4318".into()), TRACES_PATH),
            Some("http://collector:4318/v1/traces".into())
        );
        // Хвостовой слэш не должен давать двойной.
        assert_eq!(
            signal_endpoint(None, Some("http://collector:4318/".into()), TRACES_PATH),
            Some("http://collector:4318/v1/traces".into())
        );
    }

    #[test]
    fn appends_logs_path_for_logs_signal() {
        // Тот же механизм, другой путь сигнала: без `/v1/logs` коллектор ответит
        // 404 и логи будут теряться молча.
        assert_eq!(
            signal_endpoint(None, Some("http://collector:4318".into()), LOGS_PATH),
            Some("http://collector:4318/v1/logs".into())
        );
    }

    #[test]
    fn signal_endpoint_is_used_as_is() {
        // Полный URL сигнала имеет приоритет и не дополняется.
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
        assert_eq!(signal_endpoint(Some("  ".into()), Some("  ".into()), TRACES_PATH), None);
    }

    #[test]
    fn logs_disabled_without_flag() {
        // Включённые трейсы НЕ включают логи автоматически — нужен явный флаг,
        // иначе дублировали бы stdout-логи там, где их собирает агент.
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
        // Флаг есть, адреса нет — деградируем с предупреждением, а не молча.
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
        assert!(provider.is_none(), "без {ENDPOINT_VAR} трейсинг должен быть выключен");
        assert_eq!(status, Status::Disabled);
    }

    #[test]
    fn disabled_on_blank_endpoint() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var(TRACES_ENDPOINT_VAR);
        env::set_var(ENDPOINT_VAR, "   ");
        let (provider, status) = init_tracer_provider();
        env::remove_var(ENDPOINT_VAR);
        assert!(provider.is_none(), "пустое значение = трейсинг выключен");
        assert_eq!(status, Status::Disabled);
    }
}
