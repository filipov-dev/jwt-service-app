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

/// Путь сигнала трейсов в OTLP/HTTP.
const TRACES_PATH: &str = "/v1/traces";

/// Вычисляет URL, куда слать трейсы, по правилам спецификации OpenTelemetry:
///
/// - `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` — **полный** URL, используется как есть;
/// - `OTEL_EXPORTER_OTLP_ENDPOINT` — **базовый** URL, к нему добавляется
///   `/v1/traces`.
///
/// Различие принципиально: в OTLP/HTTP запрос уходит по точному адресу, и если
/// послать базовый URL как есть, коллектор ответит `404` и трейсы будут молча
/// теряться.
fn traces_endpoint(signal: Option<String>, base: Option<String>) -> Option<String> {
    if let Some(signal) = signal.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        return Some(signal);
    }

    let base = base.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())?;
    Some(format!("{}{TRACES_PATH}", base.trim_end_matches('/')))
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
    let Some(endpoint) = traces_endpoint(
        env::var(TRACES_ENDPOINT_VAR).ok(),
        env::var(ENDPOINT_VAR).ok(),
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
            traces_endpoint(None, Some("http://collector:4318".into())),
            Some("http://collector:4318/v1/traces".into())
        );
        // Хвостовой слэш не должен давать двойной.
        assert_eq!(
            traces_endpoint(None, Some("http://collector:4318/".into())),
            Some("http://collector:4318/v1/traces".into())
        );
    }

    #[test]
    fn signal_endpoint_is_used_as_is() {
        // Полный URL сигнала имеет приоритет и не дополняется.
        assert_eq!(
            traces_endpoint(
                Some("http://collector:4318/custom/traces".into()),
                Some("http://ignored:4318".into())
            ),
            Some("http://collector:4318/custom/traces".into())
        );
    }

    #[test]
    fn no_endpoint_means_disabled() {
        assert_eq!(traces_endpoint(None, None), None);
        assert_eq!(traces_endpoint(Some("  ".into()), Some("  ".into())), None);
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
