//! Параметры HTTP-сервера: число воркеров и таймауты соединений.
//!
//! Всё, что раньше оставалось на дефолтах actix, собрано здесь в
//! [`ServerConfig::from_env`] и применяется в `main.rs` одним местом.
//!
//! ## Почему число воркеров нельзя оставлять на дефолте
//!
//! Дефолт actix — «сколько логических ядер видит процесс», то есть ядер
//! **хоста**. В `deployments/prod/k8s/deployment.yaml` лимит CPU снят намеренно
//! (throttling бьёт по хвостам задержек на криптографии), а `requests.cpu` на
//! видимое число ядер не влияет вовсе. На 64-ядерном узле поднялось бы 64
//! воркер-потока со своими стеками и пулами соединений — и всё это должно было
//! уложиться в лимит памяти 256Mi, не считая лишних переключений контекста.
//!
//! Поэтому дефолт считается **от квоты, а не от числа ядер**:
//!
//! 1. есть квота CPU у cgroup (v2 `cpu.max`, v1 `cpu.cfs_quota_us`) — берём её,
//!    округляя вверх до целого воркера;
//! 2. квоты нет (или прочитать не удалось — не-Linux, доступ к cgroupfs закрыт)
//!    — берём не число ядер, а [`DEFAULT_MAX_WORKERS`]: предсказуемое потребление
//!    памяти важнее попытки угадать долю CPU по окружению.
//!
//! Явное значение `SERVER_WORKERS` всегда сильнее автоопределения.
//!
//! ## Почему таймауты задаются явно
//!
//! За обратным прокси медленных клиентов отсекает прокси, но образ раздаётся
//! публично и разворачивается в том числе напрямую, поэтому ограничение времени
//! на приём заголовков запроса (`client_request_timeout`) и времени простоя
//! keep-alive-соединения — не деталь тюнинга, а защита воркеров от удержания.
//!
//! ## Почему shutdown_timeout меньше grace period
//!
//! При остановке actix перестаёт принимать соединения и даёт воркерам
//! `shutdown_timeout` на дослуживание запросов в полёте. Дефолт — 30 секунд, и
//! ровно столько же стоит `terminationGracePeriodSeconds` в
//! `deployments/prod/k8s/deployment.yaml`: SIGKILL прилетает в ту же секунду,
//! когда дренаж только истекает. Запаса нет ни на добивание последнего
//! запроса, ни на досылку телеметрии — а она отправляется уже **после**
//! возврата из `run()` (OTel-провайдер и guard GlitchTip в `main.rs`).
//!
//! Поэтому дефолт здесь — [`DEFAULT_SHUTDOWN_TIMEOUT_SECONDS`], заведомо
//! меньше grace period. Значения связаны: меняете одно — пересчитайте другое,
//! иначе таймаут бесполезен (pod убьют раньше) либо дренаж заканчивается
//! мгновенным SIGKILL.

use std::env;
use std::fs;
use std::time::Duration;

use tracing::{info, warn};

/// Потолок числа воркеров, когда квоту CPU определить не удалось.
///
/// Ровно тот случай, ради которого задача и заводилась: без лимита CPU в
/// манифесте квоты нет, и дефолт actix развернулся бы по числу ядер узла.
const DEFAULT_MAX_WORKERS: usize = 4;

/// Таймаут приёма заголовков запроса по умолчанию (совпадает с дефолтом actix).
const DEFAULT_CLIENT_REQUEST_TIMEOUT_MS: u64 = 5_000;

/// Таймаут простоя keep-alive-соединения по умолчанию (дефолт actix).
const DEFAULT_KEEP_ALIVE_SECONDS: u64 = 5;

/// Время на дренаж запросов при остановке, по умолчанию.
///
/// Меньше `terminationGracePeriodSeconds: 30` из k8s-манифеста намеренно:
/// оставшиеся секунды уходят на досылку телеметрии после остановки сервера.
const DEFAULT_SHUTDOWN_TIMEOUT_SECONDS: u64 = 25;

/// Путь к квоте CPU в cgroup v2 (`<квота|max> <период>` в микросекундах).
const CGROUP_V2_CPU_MAX: &str = "/sys/fs/cgroup/cpu.max";
/// Путь к квоте CPU в cgroup v1 (микросекунды; `-1` — квоты нет).
const CGROUP_V1_CPU_QUOTA: &str = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us";
/// Путь к периоду планировщика в cgroup v1 (микросекунды).
const CGROUP_V1_CPU_PERIOD: &str = "/sys/fs/cgroup/cpu/cpu.cfs_period_us";

/// Как выбрано число воркеров — только для сообщения в лог.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkersSource {
    /// Задано явно через `SERVER_WORKERS`.
    Explicit,
    /// Посчитано по квоте CPU cgroup.
    Quota,
    /// Квоты нет — сработал потолок [`DEFAULT_MAX_WORKERS`].
    Fallback,
}

/// Параметры HTTP-сервера, применяемые к [`actix_web::HttpServer`].
#[derive(Debug, Clone, Copy)]
pub struct ServerConfig {
    /// Число воркер-потоков.
    pub workers: usize,
    /// Время на приём заголовков запроса; `Duration::ZERO` — без ограничения.
    pub client_request_timeout: Duration,
    /// Время простоя keep-alive-соединения; `Duration::ZERO` — keep-alive выключен.
    pub keep_alive: Duration,
    /// Время на дослуживание запросов при остановке; `Duration::ZERO` — сразу.
    pub shutdown_timeout: Duration,
    /// Откуда взялось `workers` (для лога).
    source: WorkersSource,
}

impl ServerConfig {
    /// Собирает конфигурацию из окружения.
    ///
    /// Как и rate limiting (и в отличие от секретов auth), не fail-fast:
    /// нераспознанное значение не роняет сервис, а откатывается к дефолту с
    /// предупреждением в лог.
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

    /// Пишет сводку в лог — чтобы выбранное число воркеров было видно в проде,
    /// а не выводилось из чтения кода и манифеста.
    pub fn log_summary(&self) {
        let source = match self.source {
            WorkersSource::Explicit => "задано SERVER_WORKERS",
            WorkersSource::Quota => "по квоте CPU cgroup",
            WorkersSource::Fallback => "квота CPU не обнаружена, потолок по умолчанию",
        };
        info!(
            "HTTP-сервер: воркеров {} ({}), client_request_timeout {} мс, keep-alive {} с, \
             shutdown_timeout {} с",
            self.workers,
            source,
            self.client_request_timeout.as_millis(),
            self.keep_alive.as_secs(),
            self.shutdown_timeout.as_secs(),
        );
    }
}

/// Читает `u64` из переменной окружения с откатом на `default`.
fn env_u64(key: &str, default: u64) -> u64 {
    parse_u64(env::var(key).ok().as_deref(), key, default)
}

/// Разбирает значение переменной окружения как `u64`.
///
/// Отсутствие переменной, пустая строка и мусор — это `default` (последнее с
/// предупреждением): конфигурация таймаутов, как и rate limiting, не fail-fast.
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
            warn!("{key}: нераспознанное значение '{raw}', использую {default}");
            default
        }
    }
}

/// Разбирает `SERVER_WORKERS`.
///
/// Явное положительное число — как есть; `auto`, `0`, пустая строка и
/// отсутствие переменной — автоопределение (`None`). Мусор — тоже
/// автоопределение, но с предупреждением.
fn parse_workers(value: Option<&str>) -> Option<usize> {
    let raw = value?.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("auto") {
        return None;
    }
    match raw.parse::<usize>() {
        Ok(0) => None,
        Ok(n) => Some(n),
        Err(_) => {
            warn!("SERVER_WORKERS: нераспознанное значение '{raw}', определяю число воркеров сам");
            None
        }
    }
}

/// Выбирает число воркеров по квоте CPU (в ядрах) и доступному параллелизму.
///
/// Квота округляется **вверх**: при `500m` один воркер всё же нужен. Сверху
/// ограничивается параллелизмом — больше потоков, чем ядер, смысла не имеет.
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

/// Число логических ядер, доступных процессу.
///
/// `available_parallelism` сам учитывает квоту cgroup, но по нему нельзя
/// отличить «квота 4 ядра» от «ядер у хоста 4» — а различие тут решающее,
/// поэтому квота читается отдельно ([`cpu_quota`]).
fn available_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Квота CPU в ядрах: cgroup v2, затем v1. `None` — квоты нет или не прочитать.
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

/// Разбирает `cpu.max` (cgroup v2): `"<квота|max> <период>"` в микросекундах.
fn parse_cpu_max(content: &str) -> Option<f64> {
    let mut parts = content.split_whitespace();
    let quota = parts.next()?;
    if quota == "max" {
        return None;
    }
    let period = parts.next()?;
    parse_cfs_quota(quota, period)
}

/// Считает квоту в ядрах по паре «квота/период» в микросекундах (cgroup v1 и v2).
///
/// `-1` (v1) и неположительный период означают отсутствие квоты.
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
        // Отсутствие переменной, пустое значение, явное `auto` и `0` — всё это
        // просьба посчитать самим, а не ошибка конфигурации.
        assert_eq!(parse_workers(None), None);
        assert_eq!(parse_workers(Some("")), None);
        assert_eq!(parse_workers(Some("auto")), None);
        assert_eq!(parse_workers(Some("AUTO")), None);
        assert_eq!(parse_workers(Some("0")), None);
        assert_eq!(parse_workers(Some("две штуки")), None);
    }

    #[test]
    fn auto_workers_uses_quota() {
        assert_eq!(auto_workers(Some(2.0), 64), (2, WorkersSource::Quota));
        // Дробная квота (500m, 1500m) округляется вверх: меньше воркера не бывает.
        assert_eq!(auto_workers(Some(0.5), 64), (1, WorkersSource::Quota));
        assert_eq!(auto_workers(Some(1.5), 64), (2, WorkersSource::Quota));
    }

    #[test]
    fn auto_workers_caps_quota_by_parallelism() {
        assert_eq!(auto_workers(Some(32.0), 4), (4, WorkersSource::Quota));
    }

    #[test]
    fn auto_workers_without_quota_ignores_host_cores() {
        // Главный сценарий задачи: лимит CPU снят, узел большой. Дефолт actix
        // дал бы здесь 64 воркера.
        assert_eq!(
            auto_workers(None, 64),
            (DEFAULT_MAX_WORKERS, WorkersSource::Fallback)
        );
        // На машине меньше потолка берётся её параллелизм.
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
        // Мусор и пустое значение не роняют сервис — берётся дефолт.
        assert_eq!(parse_u64(None, "K", 25), 25);
        assert_eq!(parse_u64(Some(""), "K", 25), 25);
        assert_eq!(parse_u64(Some("   "), "K", 25), 25);
        assert_eq!(parse_u64(Some("полминуты"), "K", 25), 25);
        assert_eq!(parse_u64(Some("-1"), "K", 25), 25);
    }

    /// Достаёт значение простого YAML-ключа из манифеста: первая строка,
    /// начинающаяся с `key:` (комментарии пропускаются).
    fn manifest_value<'a>(manifest: &'a str, key: &str) -> &'a str {
        manifest
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
            .unwrap_or_else(|| panic!("в манифесте нет ключа {key}"))
            .trim()
            .trim_matches('"')
    }

    /// Достаёт значение переменной окружения из env-списка k8s-манифеста:
    /// строка `value:` сразу за `- name: <KEY>`.
    fn env_value<'a>(manifest: &'a str, key: &str) -> &'a str {
        let mut lines = manifest
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'));
        lines
            .find(|line| line == &format!("- name: {key}"))
            .unwrap_or_else(|| panic!("в манифесте нет переменной {key}"));
        lines
            .next()
            .and_then(|line| line.strip_prefix("value:"))
            .unwrap_or_else(|| panic!("у переменной {key} в манифесте нет value"))
            .trim()
            .trim_matches('"')
    }

    #[test]
    fn shutdown_timeout_fits_into_grace_periods() {
        // Таймаут дренажа и grace period оркестратора — одна настройка на два
        // файла, и связь между ними держится этим тестом, а не внимательностью:
        // сравняйся они (как на дефолте actix в 30 с) — SIGKILL пришёл бы ровно
        // в момент истечения дренажа, не оставив времени ни на последний запрос,
        // ни на досылку телеметрии после возврата из `run()`.
        let k8s = include_str!("../deployments/prod/k8s/deployment.yaml");
        let compose = include_str!("../deployments/prod/docker-compose.yml");

        let grace: u64 = manifest_value(k8s, "terminationGracePeriodSeconds")
            .parse()
            .expect("terminationGracePeriodSeconds — целое число секунд");
        let stop_grace: u64 = manifest_value(compose, "stop_grace_period")
            .trim_end_matches('s')
            .parse()
            .expect("stop_grace_period — секунды вида '30s'");

        assert!(
            DEFAULT_SHUTDOWN_TIMEOUT_SECONDS < grace,
            "дренаж {DEFAULT_SHUTDOWN_TIMEOUT_SECONDS} с не укладывается в grace period k8s {grace} с"
        );
        assert!(
            DEFAULT_SHUTDOWN_TIMEOUT_SECONDS < stop_grace,
            "дренаж {DEFAULT_SHUTDOWN_TIMEOUT_SECONDS} с не укладывается в stop_grace_period compose {stop_grace} с"
        );

        // k8s-манифест задаёт переменную явно; значение должно совпадать с
        // дефолтом, иначе расчёт запаса в его комментариях разойдётся с кодом.
        let in_k8s: u64 = env_value(k8s, "SERVER_SHUTDOWN_TIMEOUT_SECONDS")
            .parse()
            .expect("SERVER_SHUTDOWN_TIMEOUT_SECONDS в манифесте — целое число");
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
        assert_eq!(parse_cpu_max("мусор 100000"), None);
    }

    #[test]
    fn parse_cfs_quota_v1() {
        assert_eq!(parse_cfs_quota("100000\n", "100000\n"), Some(1.0));
        // -1 в v1 означает «квоты нет».
        assert_eq!(parse_cfs_quota("-1", "100000"), None);
        assert_eq!(parse_cfs_quota("100000", "0"), None);
    }
}
