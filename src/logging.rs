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

use std::env;
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::time::Instant;

use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::Error;
use tracing::Instrument;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

/// Имя заголовка сквозного идентификатора запроса (в нижнем регистре — требование
/// `HeaderName::from_static`).
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Максимальная длина принимаемого извне `X-Request-Id`.
const REQUEST_ID_MAX_LEN: usize = 128;

/// Инициализирует глобальный `tracing`-subscriber.
///
/// Формат выбирается по `LOG_FORMAT` (`json` → построчный JSON, иначе `pretty`).
/// Фильтр уровней — из `RUST_LOG` с дефолтом `jwt_service_app=info`.
///
/// # Panics
///
/// Паникует, если глобальный subscriber уже установлен (вызывать один раз на
/// старте — fail-fast).
pub fn init_subscriber() {
    let filter = EnvFilter::from_default_env()
        .add_directive("jwt_service_app=info".parse().unwrap());

    let builder = tracing_subscriber::fmt().with_env_filter(filter);

    match env::var("LOG_FORMAT").unwrap_or_default().to_lowercase().as_str() {
        "json" => builder.json().init(),
        _ => builder.pretty().with_ansi(true).init(),
    }
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

        let response_id = request_id;

        Box::pin(
            async move {
                let start = Instant::now();
                let mut res = service.call(req).await?;
                let status = res.status().as_u16();
                let latency_ms = start.elapsed().as_millis() as u64;

                let span = tracing::Span::current();
                span.record("status", status);
                span.record("latency_ms", latency_ms);

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
