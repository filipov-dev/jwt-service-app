//! Метрики в формате Prometheus.
//!
//! Фасад — crate `metrics`, рендерер — `metrics-exporter-prometheus`. Собственный
//! HTTP-listener экспортёра не используется: текст экспозиции отдаём через actix
//! на `GET /metrics` (см. `handlers::metrics`), чтобы не поднимать второй порт и
//! не тянуть hyper/rustls.
//!
//! ## Кто это читает
//!
//! - **Prometheus** / **Yandex Managed Prometheus** — прямой scrape `/metrics`.
//! - **Zabbix** — тем же путём через `agent2` с prometheus-плагином; отдельный
//!   экспортёр не нужен.
//! - **Monium** (Yandex Cloud) — через Prometheus-совместимость.
//!
//! ## Кардинальность
//!
//! В лейблы кладём **шаблон роута** (`/tokens/{jti}`), а не фактический путь:
//! иначе каждый `jti` порождал бы отдельную серию и Prometheus распух бы. Ничего
//! клиентского (токены, секреты, IP) в лейблы не попадает.
//!
//! ## Именование
//!
//! По соглашению Prometheus: счётчики — с суффиксом `_total`, гистограммы
//! длительностей — в секундах с суффиксом `_seconds`.

use std::time::Duration;

use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Границы бакетов гистограмм латентности (секунды): от 1 мс до 10 с.
const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Устанавливает глобальный recorder и возвращает handle для рендера экспозиции.
///
/// Handle кладётся в `app_data` и используется обработчиком `/metrics`. Вызывать
/// один раз на старте.
///
/// # Panics
///
/// Паникует, если recorder уже установлен (как и прочая конфигурация на старте —
/// fail-fast).
pub fn init_recorder() -> PrometheusHandle {
    let builder = PrometheusBuilder::new()
        .set_buckets(LATENCY_BUCKETS)
        .expect("непустой список бакетов");

    builder
        .install_recorder()
        .expect("не удалось установить Prometheus recorder")
}

/// Фиксирует завершённый HTTP-запрос: счётчик по (метод, роут, статус) и
/// гистограмма латентности.
///
/// `endpoint` — шаблон роута (например `/tokens/{jti}`), см. замечание о
/// кардинальности в описании модуля.
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

/// Выпущен токен (`POST /tokens`).
pub fn record_token_issued() {
    counter!("jwt_tokens_issued_total").increment(1);
}

/// Отозван токен (`DELETE /tokens/{jti}`).
pub fn record_token_revoked() {
    counter!("jwt_tokens_revoked_total").increment(1);
}

/// Результат проверки токена (`POST /tokens/verify`).
///
/// `success = false` — штатный исход публичной ручки (протух/подделан), а не сбой
/// сервиса; отделён лейблом, чтобы можно было строить долю отказов.
pub fn record_token_verified(success: bool) {
    counter!(
        "jwt_tokens_verified_total",
        "result" => if success { "success" } else { "failure" },
    )
    .increment(1);
}

/// Отказ в доступе (401) на указанном уровне (`open`/`proxy_secret`/`totp`).
pub fn record_auth_denied(level: &str) {
    counter!("jwt_auth_denied_total", "level" => level.to_string()).increment(1);
}

/// Сработал rate-limit (429).
pub fn record_rate_limited() {
    counter!("jwt_rate_limit_exceeded_total").increment(1);
}

/// Длительность обращения к `jwks-service-app`.
///
/// `operation` — короткое имя операции (`public_keys`, `private_key`),
/// `success` — удалось ли обращение.
pub fn record_jwks_request(operation: &str, success: bool, latency: Duration) {
    histogram!(
        "jwks_request_duration_seconds",
        "operation" => operation.to_string(),
        "success" => success.to_string(),
    )
    .record(latency.as_secs_f64());
}

/// Обращение к кешу JWKS.
///
/// `result`:
/// - `hit` — ключ отдан из памяти, в сеть не ходили;
/// - `miss` — в кеше не нашлось, пошли в `jwks-service-app`;
/// - `throttled` — `kid` неизвестен, но обновляться ещё рано (защита от флуда
///   несуществующими `kid`), запрос отклонён без похода в сеть.
///
/// Доля `hit` — главный показатель эффективности кеша; заметный поток
/// `throttled` означает, что по сервису бьют мусорными `kid`.
pub fn record_jwks_cache(result: &str) {
    counter!("jwks_cache_total", "result" => result.to_string()).increment(1);
}

/// Длительность команды к Redis (`store_jti`, `check_jti`, `delete_jti`, `ping`).
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

    /// Recorder глобален и ставится один раз на процесс; в тестах проверяем, что
    /// рендер работает и метрики попадают в экспозицию.
    #[test]
    fn renders_recorded_metrics() {
        // `install_recorder` мог уже отработать в другом тесте — используем
        // локальный recorder через `PrometheusBuilder::build_recorder`, он не
        // трогает глобальное состояние.
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
