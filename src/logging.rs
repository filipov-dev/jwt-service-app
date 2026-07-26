//! Инициализация логирования и per-request middleware.
//!
//! Фундамент observability: единая настройка `tracing`-subscriber'а (формат
//! выбирается через env) и middleware [`RequestLog`], который на каждый запрос
//! заводит структурный span с `request_id` и по завершении пишет одну строку с
//! методом, путём, статусом и латентностью.
//!
//! ## Что НЕ логируется
//!
//! Осознанно **не** пишем заголовки и тело запроса/ответа — там лежат секреты
//! (`X-Proxy-Secret`, `X-TOTP-Code`) и сами токены. В лог идут только метод,
//! путь, статус, латентность, `request_id` и best-effort IP клиента.
//!
//! ## Формат
//!
//! `LOG_FORMAT=json` — построчный JSON для машинного сбора (Monium/ELK и т.п.);
//! любое другое значение (по умолчанию) — человекочитаемый `pretty` с ANSI.
//! Уровни фильтруются через `RUST_LOG` (`EnvFilter`), плюс дефолт
//! `jwt_service_app=info`.
//!
//! ## Политика уровней
//!
//! В `tracing` пять уровней: `TRACE < DEBUG < INFO < WARN < ERROR`. Отдельного
//! `CRITICAL`/`FATAL` нет — фатальные ситуации в этом сервисе фиксируются паникой
//! на старте (fail-fast при некорректной конфигурации), а не уровнем лога.
//!
//! Уровень выбирается **по виновнику и последствию**, а не по «серьёзности» текста:
//!
//! - **ERROR** — сервис не смог выполнить работу: отказ зависимости (Redis, JWKS),
//!   сбой крипты при подписи, некорректный материал ключа. Требует внимания
//!   дежурного, годится как источник алертов.
//! - **WARN** — деградация или сигнал безопасности, но запрос обработан: проблемы
//!   конфигурации (с откатом на дефолт), отказ в доступе (401), срабатывание
//!   rate-limit (429).
//! - **INFO** — жизненный цикл и бизнес-события: старт сервера, сводка конфигурации,
//!   завершение запроса (`request completed`), отзыв токена.
//! - **DEBUG** — вина клиента и детали работы: битый/протухший/подделанный токен,
//!   параметры вне границ, шаги обращения к JWKS. **Важно:** клиентские ошибки
//!   намеренно НЕ на ERROR — иначе любой кривой запрос поднимал бы ложные алерты.
//! - **TRACE** — не используется.
//!
//! Ошибку логирует тот слой, который знает **причину** (например `jwk.rs` — отказ
//! JWKS на ERROR); вышестоящие слои пишут исход на DEBUG, чтобы не плодить дубли.

use std::env;
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::time::Instant;

use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::Error;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};
use uuid::Uuid;

/// Имя заголовка сквозного идентификатора запроса (в нижнем регистре — требование
/// `HeaderName::from_static`).
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Максимальная длина принимаемого извне `X-Request-Id`.
const REQUEST_ID_MAX_LEN: usize = 128;

/// Инициализирует глобальный `tracing`-subscriber.
///
/// Собирается из слоёв поверх общего `Registry` — это и есть «единая шина»
/// телеметрии:
/// - фильтр уровней (`RUST_LOG`, дефолт `jwt_service_app=info`);
/// - вывод логов (`LOG_FORMAT`: `json` → построчный JSON, иначе `pretty`);
/// - опциональный слой OpenTelemetry, если задан `OTEL_EXPORTER_OTLP_ENDPOINT`
///   (см. [`crate::tracing_otel`]);
/// - опциональный слой GlitchTip, если задан `GLITCHTIP_DSN`
///   (см. [`crate::sentry_glitchtip`]).
///
/// Возвращает [`Telemetry`] — живые ресурсы (провайдер трейсов и guard GlitchTip),
/// которые нужно держать до конца работы процесса, иначе последние span'ы и
/// события не досылаются.
///
/// # Panics
///
/// Паникует, если глобальный subscriber уже установлен (вызывать один раз на
/// старте — fail-fast).
pub fn init_subscriber() -> Telemetry {
    // ВАЖНО: дефолт применяется, только если `RUST_LOG` не задан. Нельзя делать
    // `from_default_env().add_directive("jwt_service_app=info")` — добавленная
    // директива перекрывает одноимённый таргет из `RUST_LOG`, и уровень крейта
    // навсегда залипает на `info` (DEBUG становится недостижим).
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("jwt_service_app=info"));

    // Слои json/pretty различаются по типу — приводим к общему через `.boxed()`.
    let fmt_layer = match env::var("LOG_FORMAT").unwrap_or_default().to_lowercase().as_str() {
        "json" => tracing_subscriber::fmt::layer().json().boxed(),
        _ => tracing_subscriber::fmt::layer().pretty().with_ansi(true).boxed(),
    };

    let (provider, otel_status) = crate::tracing_otel::init_tracer_provider();
    let otel_layer = provider.as_ref().map(crate::tracing_otel::layer);

    // GlitchTip: клиент ставится до subscriber'а, слой раскладывает события по
    // каналам (issues / logs / performance) — см. `sentry_glitchtip`.
    let (sentry_guard, sentry_status) = crate::sentry_glitchtip::init();
    let sentry_layer = sentry_guard
        .as_ref()
        .map(|_| crate::sentry_glitchtip::layer());

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .with(sentry_layer)
        .init();

    // Статусы печатаем только теперь: до `.init()` писать было некуда.
    otel_status.log();
    sentry_status.log();

    Telemetry {
        tracer_provider: provider,
        sentry_guard,
    }
}

/// Живые ресурсы телеметрии, которые нужно держать до конца работы процесса.
///
/// `sentry_guard` досылает накопленные события при уничтожении, поэтому его
/// нельзя ронять сразу после инициализации; `tracer_provider` завершается явно
/// через [`crate::tracing_otel::shutdown`].
pub struct Telemetry {
    pub tracer_provider: Option<SdkTracerProvider>,
    /// Читать это поле не нужно — оно живёт ради RAII: события GlitchTip
    /// досылаются при уничтожении guard'а. Уроните его раньше времени — потеряете
    /// накопленные события.
    #[allow(dead_code)]
    pub sentry_guard: Option<sentry::ClientInitGuard>,
}

/// Проверяет, что пришедший извне `X-Request-Id` безопасен для повторного
/// использования: непустой, не длиннее [`REQUEST_ID_MAX_LEN`] и состоит только из
/// ASCII-букв/цифр и `-`/`_`. Иначе сгенерируем свой (защита от инъекций в лог и
/// «мусорных» значений).
fn is_valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= REQUEST_ID_MAX_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Middleware-фабрика per-request логирования. Вешается один раз на уровне `App`
/// (самый внешний слой), чтобы span покрывал auth/rate-limit/CORS и обработчик.
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

/// Собственно middleware: заводит span и логирует итог запроса.
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

        // Берём пришедший `X-Request-Id`, если он валиден, иначе генерируем новый.
        let request_id = req
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .filter(|s| is_valid_request_id(s))
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let method = req.method().to_string();
        let path = req.path().to_string();
        // best-effort IP клиента (с учётом realip actix); точный ключ rate-limit с
        // доверенными прокси остаётся внутри `rate_limit.rs`.
        let client_ip = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("-")
            .to_string();

        // `access_level` заполняет auth-middleware изнутри (см. `auth.rs`),
        // `status`/`latency_ms` — по завершении ниже. Объявляем их пустыми.
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

        // Если вызывающий сервис прислал `traceparent`, продолжаем его трассу —
        // иначе span станет корнем новой (см. `tracing_otel`). Неудача склейки не
        // повод отказывать в запросе: пишем в DEBUG и продолжаем без родителя.
        if let Err(e) = span.set_parent(crate::tracing_otel::extract_parent_context(req.headers()))
        {
            tracing::debug!("Не удалось связать span с входящей трассой: {e}");
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

                // Метрика запроса пишется здесь же: статус и латентность уже
                // посчитаны, второй проход middleware не нужен. В лейбл идёт
                // ШАБЛОН роута (`/tokens/{jti}`), а не фактический путь — иначе
                // каждый `jti` порождал бы свою серию (см. `metrics.rs`).
                let endpoint = res
                    .request()
                    .match_pattern()
                    .unwrap_or_else(|| "unmatched".to_string());
                crate::metrics::record_http_request(&method, &endpoint, status, elapsed);

                // Эхо-заголовок `X-Request-Id` в ответ для сквозной трассировки.
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
        let app = actix_test::init_service(
            App::new().wrap(RequestLog).route("/", web::get().to(ok)),
        )
        .await;
        let req = actix_test::TestRequest::get().uri("/").to_request();
        let res = actix_test::call_service(&app, req).await;

        let rid = res
            .headers()
            .get(REQUEST_ID_HEADER)
            .expect("X-Request-Id должен быть в ответе");
        // Сгенерированный id — валидный UUID.
        assert!(Uuid::parse_str(rid.to_str().unwrap()).is_ok());
    }

    #[actix_web::test]
    async fn propagates_valid_incoming_request_id() {
        let app = actix_test::init_service(
            App::new().wrap(RequestLog).route("/", web::get().to(ok)),
        )
        .await;
        let req = actix_test::TestRequest::get()
            .uri("/")
            .insert_header((REQUEST_ID_HEADER, "trace-42"))
            .to_request();
        let res = actix_test::call_service(&app, req).await;

        assert_eq!(
            res.headers().get(REQUEST_ID_HEADER).unwrap().to_str().unwrap(),
            "trace-42"
        );
    }

    #[actix_web::test]
    async fn replaces_invalid_incoming_request_id() {
        let app = actix_test::init_service(
            App::new().wrap(RequestLog).route("/", web::get().to(ok)),
        )
        .await;
        let req = actix_test::TestRequest::get()
            .uri("/")
            .insert_header((REQUEST_ID_HEADER, "bad value!"))
            .to_request();
        let res = actix_test::call_service(&app, req).await;

        let rid = res.headers().get(REQUEST_ID_HEADER).unwrap().to_str().unwrap();
        assert_ne!(rid, "bad value!");
        assert!(Uuid::parse_str(rid).is_ok());
    }
}
