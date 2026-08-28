//! Интеграция с GlitchTip (Sentry-совместимый бэкенд).
//!
//! Закрывает **три** канала наблюдаемости, а не только ошибки:
//!
//! | Канал | Что уходит | Как включается |
//! |-------|-----------|----------------|
//! | **Issues** | паники и события уровня `ERROR` | всегда при заданном DSN |
//! | **Performance** | span-ы → транзакции с длительностью | `GLITCHTIP_TRACES_SAMPLE_RATE > 0` |
//! | **Logs** | структурные логи (`INFO`/`WARN`/`DEBUG`) | `GLITCHTIP_ENABLE_LOGS=true` |
//!
//! Всё это — слой поверх той же `tracing`-шины, что логи ([`crate::logging`]) и
//! OpenTelemetry ([`crate::tracing_otel`]): один источник событий, разные выходы.
//!
//! ## Включение
//!
//! Только при заданном `GLITCHTIP_DSN` (принимается и `SENTRY_DSN` — имя из
//! Sentry-совместимых инструментов). Не задан — интеграция выключена целиком.
//!
//! **Не fail-fast.** Некорректный DSN не роняет сервис: предупреждение в лог и
//! работа без GlitchTip. Телеметрия не должна быть причиной недоступности.
//!
//! ## Секреты
//!
//! DSN **не логируется** — в сообщениях фигурирует только факт включения. В теле
//! событий не должно быть токенов и секретов: см. политику в [`crate::logging`]
//! (заголовки и тело запросов мы не пишем в принципе).

use std::env;

use sentry::ClientInitGuard;

/// Основное имя переменной с DSN.
const DSN_VAR: &str = "GLITCHTIP_DSN";

/// Совместимое имя (его выставляют Sentry-совместимые инструменты).
const DSN_VAR_ALT: &str = "SENTRY_DSN";

/// Доля span-ов, уходящих в performance-мониторинг (0.0 — выключено).
const TRACES_RATE_VAR: &str = "GLITCHTIP_TRACES_SAMPLE_RATE";

/// Включение структурных логов.
const ENABLE_LOGS_VAR: &str = "GLITCHTIP_ENABLE_LOGS";

/// Исход инициализации.
///
/// Как и в [`crate::tracing_otel::Status`], нужен потому, что инициализация
/// происходит **до** установки `tracing`-subscriber'а: залогируй мы прямо там,
/// сообщение было бы потеряно.
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    /// DSN не задан — интеграция выключена.
    Disabled,
    /// Интеграция включена.
    Enabled {
        /// Включён ли performance-мониторинг (доля семплирования > 0).
        performance: bool,
        /// Включены ли структурные логи.
        logs: bool,
    },
}

impl Status {
    /// Включены ли структурные логи. Нужен [`layer`]: с 0.49 канал Logs
    /// фильтруем сами, см. комментарий там.
    pub fn logs_enabled(&self) -> bool {
        matches!(self, Status::Enabled { logs: true, .. })
    }

    /// Пишет статус в лог. Вызывать после установки subscriber'а.
    pub fn log(&self) {
        match self {
            Status::Disabled => {
                tracing::debug!("GlitchTip: интеграция выключена ({DSN_VAR} не задан)");
            }
            Status::Enabled { performance, logs } => {
                // DSN намеренно не пишем — это секрет.
                tracing::info!(
                    performance,
                    logs,
                    "GlitchTip: интеграция включена (ошибки и паники)"
                );
            }
        }
    }
}

/// Читает `f32` из окружения с откатом на `default`.
fn env_f32(key: &str, default: f32) -> f32 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<f32>().ok())
        .filter(|v| v.is_finite())
        .map(|v| v.clamp(0.0, 1.0))
        .unwrap_or(default)
}

/// Читает булев флаг из окружения (`true`/`1`/`yes`).
fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"),
        Err(_) => default,
    }
}

/// Читает DSN: сначала `GLITCHTIP_DSN`, затем совместимый `SENTRY_DSN`.
fn read_dsn() -> Option<String> {
    for var in [DSN_VAR, DSN_VAR_ALT] {
        if let Some(dsn) = env::var(var).ok().filter(|s| !s.trim().is_empty()) {
            return Some(dsn.trim().to_string());
        }
    }
    None
}

/// Инициализирует клиент GlitchTip.
///
/// Возвращает guard (держать живым до конца работы процесса — при его уничтожении
/// досылаются накопленные события) и статус для последующего логирования.
///
/// Ничего не делает и возвращает [`Status::Disabled`], если DSN не задан.
pub fn init() -> (Option<ClientInitGuard>, Status) {
    let Some(dsn) = read_dsn() else {
        return (None, Status::Disabled);
    };

    // 0.0 — performance выключен (дефолт): транзакции стоят денег и объёма,
    // включать осознанно.
    let traces_sample_rate = env_f32(TRACES_RATE_VAR, 0.0);
    let enable_logs = env_bool(ENABLE_LOGS_VAR, false);

    // С 0.49 `ClientOptions` — `#[non_exhaustive]`: литерал структуры извне крейта
    // не собирается, остаётся только билдер.
    let mut options = sentry::ClientOptions::new()
        // Версия сервиса — чтобы issues группировались по релизам.
        .release(env!("CARGO_PKG_VERSION"));

    if let Ok(environment) = env::var("GLITCHTIP_ENVIRONMENT") {
        options = options.environment(environment);
    }

    // Ставим стратегию сэмплирования только при ненулевой доле. Пустая доля —
    // это `TracesSamplingStrategy::Disabled` (дефолт), и она отличается от явной
    // `FixedRate(0.0)`: последняя всё ещё уважает решение родителя из входящего
    // trace-контекста, то есть транзакции продолжали бы уходить.
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

/// Строит `tracing`-слой, раскладывающий события по каналам GlitchTip.
///
/// - `ERROR` → **issue** (событие в разделе Issues);
/// - `WARN`/`INFO`/`DEBUG` → **log** (раздел Logs), если `logs`, иначе
///   «хлебные крошки» к будущим ошибкам (`DEBUG` в этом случае отбрасывается);
/// - span-ы → **транзакции** (раздел Performance), если включено семплирование.
///
/// `logs` приходит снаружи (см. [`Status::logs_enabled`]), а не из
/// `ClientOptions::enable_logs`: с 0.49 то поле объявлено deprecated — по
/// апстриму логи, захваченные вручную, уходят всегда, а опция влияет только на
/// автоматический захват интеграциями. Рекомендованный путь — настраивать, что
/// именно шлёт интеграция, её собственными средствами; для `tracing` это и есть
/// event-фильтр ниже.
pub fn layer<S>(logs: bool) -> sentry::integrations::tracing::SentryLayer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use sentry::integrations::tracing::EventFilter;

    sentry::integrations::tracing::layer().event_filter(move |md| match *md.level() {
        // Сбой сервиса — заводим issue.
        tracing::Level::ERROR => EventFilter::Event,
        // Остальное — в Logs (и как breadcrumbs к ошибкам).
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

    /// Тесты трогают глобальные env — сериализуем.
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
        env::set_var(TRACES_RATE_VAR, "не число");
        assert_eq!(env_f32(TRACES_RATE_VAR, 0.0), 0.0, "мусор → дефолт");
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
        assert!(!env_bool(ENABLE_LOGS_VAR, false), "по умолчанию выключено");
        for truthy in ["true", "1", "yes", "TRUE"] {
            env::set_var(ENABLE_LOGS_VAR, truthy);
            assert!(env_bool(ENABLE_LOGS_VAR, false), "{truthy}");
        }
        env::set_var(ENABLE_LOGS_VAR, "false");
        assert!(!env_bool(ENABLE_LOGS_VAR, false));
        clear();
    }
}
