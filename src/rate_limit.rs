//! Ограничение частоты запросов (rate limiting).
//!
//! Алгоритм — token-bucket (GCRA) из crate [`governor`] (MIT); actix-обёртку
//! `actix-governor` (GPL-3.0) осознанно не тянем из-за копилефта на публично
//! раздаваемые Docker-образы — middleware реализован здесь свой, по образцу
//! [`crate::auth`]. Превышение лимита → `429 Too Many Requests` (скупое тело
//! [`ErrorResponse`], заголовок `Retry-After` в секундах).
//!
//! Модель согласована с уровнями доступа (см. `AGENTS.md`):
//!
//! - **`POST /tokens/verify` (уровень 2, публичная за прокси) — per-IP.** Ключ —
//!   IP клиента; лимит применяется к каждому адресу независимо. Middleware ставится
//!   **снаружи** auth, чтобы флуд отсекался до проверки секрета.
//! - **`POST /tokens` / `DELETE /tokens/{jti}` (уровень 3, internal) — опциональный
//!   глобальный cap.** Не per-IP (клиент один), а общий потолок на эндпоинт:
//!   defense-in-depth при утечке TOTP-секрета и backpressure для JWKS/Redis.
//!   Ставится **внутри** auth — потолок расходуют только запросы, прошедшие TOTP,
//!   иначе неаутентифицированный флуд исчерпал бы cap и заблокировал настоящего
//!   клиента.
//!
//! ## IP за обратным прокси
//!
//! Peer-адрес соединения за прокси — это всегда адрес прокси, поэтому реальный IP
//! клиента берётся из `X-Forwarded-For`. Но заголовок подделываем клиентом, поэтому
//! доверяем ему **только если peer входит в список доверенных прокси**
//! (`RATE_LIMIT_TRUSTED_PROXIES`, IP или CIDR). Разбор XFF идёт справа налево —
//! первый адрес, не являющийся доверенным прокси, и есть клиент (так корректно
//! отрабатывается цепочка прокси). Если список пуст или peer недоверенный, XFF
//! игнорируется и ключом служит peer-адрес — безопасный по умолчанию режим.

use std::env;
use std::future::{ready, Future, Ready};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use actix_web::body::EitherBody;
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderMap, RETRY_AFTER};
use actix_web::{Error, HttpResponse};
use governor::clock::{Clock, DefaultClock, QuantaInstant};
use governor::state::keyed::DefaultKeyedStateStore;
use governor::state::{InMemoryState, NotKeyed};
use governor::{NotUntil, Quota, RateLimiter};
use tracing::{info, warn};

use crate::models::ErrorResponse;

/// Keyed-лимитер (по IP) поверх дефолтного хранилища состояния и часов.
type KeyedLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;
/// Direct-лимитер (единственное ведро) для глобального потолка.
type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Период между чистками устаревших per-IP записей (`retain_recent`).
///
/// Ограничивает рост памяти на публичной ручке при большом числе разных IP.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

/// Читает `u64` из переменной окружения с откатом на `default`.
fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

/// Читает `u32` из переменной окружения с откатом на `default`.
fn env_u32(key: &str, default: u32) -> u32 {
    env::var(key).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

/// Читает булев флаг (`1/true/yes/on` — истина, `0/false/no/off/""` — ложь).
///
/// Нераспознанное значение → `default` с предупреждением в лог.
fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Err(_) => default,
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" | "" => false,
            other => {
                warn!("{key}: нераспознанное булево значение '{other}', использую {default}");
                default
            }
        },
    }
}

/// Приводит IPv4-mapped IPv6 (`::ffff:a.b.c.d`) к IPv4 — чтобы peer/XFF и записи
/// доверенных прокси сравнивались в одном семействе.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Группирует IPv6 по префиксу `/56` (как дефолтный экстрактор governor): один
/// клиент обычно получает `/56`, и лимитировать разумнее подсеть, а не адрес.
/// IPv4 возвращается без изменений.
fn group_v6(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[7..16].fill(0);
            IpAddr::V6(octets.into())
        }
        v4 => v4,
    }
}

/// Совпадают ли первые `prefix` бит двух адресов одной длины.
fn prefix_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let whole = (prefix / 8) as usize;
    if a[..whole] != b[..whole] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[whole] & mask) == (b[whole] & mask)
}

/// Диапазон адресов доверенного прокси: одиночный IP или CIDR (`10.0.0.0/8`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Разбирает `"IP"` или `"IP/prefix"`. `None` — если адрес/префикс некорректны.
    fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        let (addr_str, prefix) = match input.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (input, None),
        };
        let addr: IpAddr = canonical(addr_str.parse().ok()?);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => {
                let p: u8 = p.parse().ok()?;
                if p > max {
                    return None;
                }
                p
            }
            None => max,
        };
        Some(Self { addr, prefix })
    }

    /// Входит ли `ip` (предполагается уже канонизированным) в диапазон.
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => prefix_match(&a.octets(), &b.octets(), self.prefix),
            (IpAddr::V6(a), IpAddr::V6(b)) => prefix_match(&a.octets(), &b.octets(), self.prefix),
            _ => false,
        }
    }
}

/// Доверенный ли адрес (входит хотя бы в один диапазон списка).
fn ip_is_trusted(ip: IpAddr, trusted: &[Cidr]) -> bool {
    trusted.iter().any(|c| c.contains(ip))
}

/// Разбирает одну запись `X-Forwarded-For` (голый IP или `IP:port`) в адрес.
fn parse_forwarded_ip(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim();
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(canonical(ip));
    }
    // Возможен `IPv4:port` — отсекаем порт (для `[IPv6]:port` разбор выше уже
    // не сработал, но такие записи в XFF нетипичны).
    entry
        .rsplit_once(':')
        .and_then(|(host, _)| host.parse::<IpAddr>().ok())
        .map(canonical)
}

/// Выбирает IP клиента из `X-Forwarded-For` при доверенном peer.
///
/// Идёт справа налево и возвращает первый адрес, не являющийся доверенным прокси
/// (реальный клиент за цепочкой прокси). Если все записи доверенные — крайняя
/// левая; если заголовка нет — `None` (наверх выберут peer).
fn client_from_forwarded(headers: &HeaderMap, header: &str, trusted: &[Cidr]) -> Option<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    for value in headers.get_all(header) {
        if let Ok(text) = value.to_str() {
            for part in text.split(',') {
                if let Some(ip) = parse_forwarded_ip(part) {
                    ips.push(ip);
                }
            }
        }
    }
    ips.iter()
        .rev()
        .find(|ip| !ip_is_trusted(**ip, trusted))
        .copied()
        .or_else(|| ips.first().copied())
}

/// Итоговый ключ per-IP лимитера для запроса.
///
/// XFF учитывается **только** если peer доверенный; иначе — peer-адрес.
/// Результат группируется по `/56` для IPv6.
fn resolve_key_ip(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    header: &str,
    trusted: &[Cidr],
) -> Option<IpAddr> {
    let peer = canonical(peer?);
    let ip = if ip_is_trusted(peer, trusted) {
        client_from_forwarded(headers, header, trusted).unwrap_or(peer)
    } else {
        peer
    };
    Some(group_v6(ip))
}

/// Строит quota: `per_second` пополнений в секунду с ёмкостью всплеска `burst`.
/// Значения приводятся к минимуму 1, чтобы quota была валидной.
fn quota(per_second: u64, burst: u32) -> Quota {
    let per_second = per_second.max(1);
    let burst = NonZeroU32::new(burst.max(1)).expect("burst >= 1");
    let period = Duration::from_nanos(1_000_000_000 / per_second);
    Quota::with_period(period).expect("period > 0").allow_burst(burst)
}

/// Секунды до следующего разрешённого запроса (для заголовка `Retry-After`),
/// не меньше 1.
fn retry_after_secs(negative: NotUntil<QuantaInstant>) -> u64 {
    negative
        .wait_time_from(DefaultClock::default().now())
        .as_secs()
        .max(1)
}

/// Собранная из окружения конфигурация rate limiting.
///
/// Все параметры опциональны и имеют разумные дефолты; ошибки конфигурации
/// (например нераспознанный CIDR) не фатальны — деградируем к безопасному режиму
/// с предупреждением в лог.
pub struct RateLimitConfig {
    verify_enabled: bool,
    verify_per_second: u64,
    verify_burst: u32,
    internal_enabled: bool,
    internal_per_second: u64,
    internal_burst: u32,
    trusted: Arc<Vec<Cidr>>,
    forwarded_header: String,
}

impl RateLimitConfig {
    /// Читает конфигурацию из окружения.
    ///
    /// Переменные:
    /// - `RATE_LIMIT_VERIFY_ENABLED` (дефолт `true`) — per-IP лимит на `/tokens/verify`;
    /// - `RATE_LIMIT_VERIFY_PER_SECOND` (дефолт 10), `RATE_LIMIT_VERIFY_BURST` (дефолт 20);
    /// - `RATE_LIMIT_INTERNAL_ENABLED` (дефолт `false`) — глобальный cap на internal-ручки;
    /// - `RATE_LIMIT_INTERNAL_PER_SECOND` (дефолт 50), `RATE_LIMIT_INTERNAL_BURST` (дефолт 100);
    /// - `RATE_LIMIT_TRUSTED_PROXIES` — список доверенных прокси (IP/CIDR через запятую);
    /// - `RATE_LIMIT_FORWARDED_HEADER` (дефолт `X-Forwarded-For`) — заголовок с IP клиента.
    pub fn from_env() -> Self {
        let trusted_raw = env::var("RATE_LIMIT_TRUSTED_PROXIES").unwrap_or_default();
        let mut trusted = Vec::new();
        for entry in trusted_raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            match Cidr::parse(entry) {
                Some(cidr) => trusted.push(cidr),
                None => warn!("RATE_LIMIT_TRUSTED_PROXIES: не разобран IP/CIDR '{entry}', пропускаю"),
            }
        }

        Self {
            verify_enabled: env_bool("RATE_LIMIT_VERIFY_ENABLED", true),
            verify_per_second: env_u64("RATE_LIMIT_VERIFY_PER_SECOND", 10),
            verify_burst: env_u32("RATE_LIMIT_VERIFY_BURST", 20),
            internal_enabled: env_bool("RATE_LIMIT_INTERNAL_ENABLED", false),
            internal_per_second: env_u64("RATE_LIMIT_INTERNAL_PER_SECOND", 50),
            internal_burst: env_u32("RATE_LIMIT_INTERNAL_BURST", 100),
            trusted: Arc::new(trusted),
            forwarded_header: env::var("RATE_LIMIT_FORWARDED_HEADER")
                .unwrap_or_else(|_| "X-Forwarded-For".into()),
        }
    }

    /// Пишет в лог сводку активной конфигурации (без секретов — секретов тут нет).
    pub fn log_summary(&self) {
        if self.verify_enabled {
            info!(
                "Rate limit /tokens/verify: per-IP {}/s, burst {}, доверенных прокси: {}",
                self.verify_per_second,
                self.verify_burst,
                self.trusted.len()
            );
            if self.trusted.is_empty() {
                warn!(
                    "RATE_LIMIT_TRUSTED_PROXIES пуст: X-Forwarded-For не учитывается, ключ — peer-адрес. \
                     За обратным прокси задайте список доверенных прокси, иначе все клиенты делят один лимит."
                );
            }
        } else {
            warn!("Rate limit /tokens/verify отключён (RATE_LIMIT_VERIFY_ENABLED=false)");
        }
        if self.internal_enabled {
            info!(
                "Rate limit internal-ручек: глобальный cap {}/s, burst {}",
                self.internal_per_second, self.internal_burst
            );
        }
    }

    /// Строит per-IP лимитер для `/tokens/verify`, если он включён.
    pub fn build_verify(&self) -> Option<PerIpLimiter> {
        if !self.verify_enabled {
            return None;
        }
        Some(PerIpLimiter {
            limiter: Arc::new(RateLimiter::keyed(quota(self.verify_per_second, self.verify_burst))),
            trusted: self.trusted.clone(),
            forwarded_header: Arc::from(self.forwarded_header.as_str()),
        })
    }

    /// Строит глобальный cap для internal-ручек, если он включён.
    pub fn build_internal(&self) -> Option<GlobalLimiter> {
        if !self.internal_enabled {
            return None;
        }
        Some(GlobalLimiter {
            limiter: Arc::new(RateLimiter::direct(quota(self.internal_per_second, self.internal_burst))),
        })
    }
}

/// Per-IP лимитер (для публичной ручки). Дёшево клонируется — внутри `Arc`.
#[derive(Clone)]
pub struct PerIpLimiter {
    limiter: Arc<KeyedLimiter>,
    trusted: Arc<Vec<Cidr>>,
    forwarded_header: Arc<str>,
}

impl PerIpLimiter {
    /// Запускает фоновый поток периодической чистки устаревших per-IP записей.
    /// Вызывать один раз на старте (лимитер общий на все worker-потоки).
    pub fn spawn_cleanup(&self) {
        let limiter = self.limiter.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(CLEANUP_INTERVAL);
            limiter.retain_recent();
        });
    }
}

/// Глобальный лимитер (единое ведро на эндпоинт). Дёшево клонируется.
#[derive(Clone)]
pub struct GlobalLimiter {
    limiter: Arc<DirectLimiter>,
}

/// Стратегия проверки конкретного middleware-экземпляра.
enum Strategy {
    /// Лимит выключен — пропускаем всё.
    Disabled,
    /// Per-IP по ключу клиента.
    PerIp {
        limiter: Arc<KeyedLimiter>,
        trusted: Arc<Vec<Cidr>>,
        forwarded_header: Arc<str>,
    },
    /// Единый глобальный потолок.
    Global { limiter: Arc<DirectLimiter> },
}

impl Strategy {
    /// `Ok(())` — пропустить; `Err(secs)` — отклонить с `Retry-After: secs`.
    fn check(&self, req: &ServiceRequest) -> Result<(), u64> {
        match self {
            Strategy::Disabled => Ok(()),
            Strategy::Global { limiter } => limiter.check().map_err(retry_after_secs),
            Strategy::PerIp { limiter, trusted, forwarded_header } => {
                let peer = req.peer_addr().map(|addr| addr.ip());
                match resolve_key_ip(peer, req.headers(), forwarded_header, trusted) {
                    Some(ip) => limiter.check_key(&ip).map_err(retry_after_secs),
                    // Не смогли определить IP (нет peer-адреса) — fail-open: запрос
                    // всё равно защищён proxy-secret'ом на уровне auth.
                    None => Ok(()),
                }
            }
        }
    }
}

/// Middleware-фабрика rate limiting. Ставится через `.wrap(...)` на ресурсе.
pub struct RateLimit {
    strategy: Rc<Strategy>,
}

impl RateLimit {
    /// Per-IP лимит для публичной ручки. `None` → пропуск (лимит выключен).
    pub fn per_ip(limiter: Option<PerIpLimiter>) -> Self {
        let strategy = match limiter {
            Some(l) => Strategy::PerIp {
                limiter: l.limiter,
                trusted: l.trusted,
                forwarded_header: l.forwarded_header,
            },
            None => Strategy::Disabled,
        };
        Self { strategy: Rc::new(strategy) }
    }

    /// Глобальный cap для internal-ручки. `None` → пропуск (cap выключен).
    pub fn global(limiter: Option<GlobalLimiter>) -> Self {
        let strategy = match limiter {
            Some(l) => Strategy::Global { limiter: l.limiter },
            None => Strategy::Disabled,
        };
        Self { strategy: Rc::new(strategy) }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimit
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = RateLimitMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitMiddleware {
            service: Rc::new(service),
            strategy: self.strategy.clone(),
        }))
    }
}

/// Собственно middleware: проверяет лимит до вызова внутреннего сервиса.
pub struct RateLimitMiddleware<S> {
    service: Rc<S>,
    strategy: Rc<Strategy>,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let decision = self.strategy.check(&req);
        let service = self.service.clone();

        Box::pin(async move {
            match decision {
                Ok(()) => {
                    let res = service.call(req).await?;
                    Ok(res.map_into_left_body())
                }
                Err(retry_after) => {
                    // Срабатывание лимита — не сбой сервиса, но повод смотреть
                    // (флуд, зациклившийся клиент, заниженный лимит) → WARN.
                    warn!(retry_after, "Превышен лимит частоты запросов");
                    crate::metrics::record_rate_limited();

                    // Скупой ответ без деталей — как и на остальных ручках.
                    let (req, _payload) = req.into_parts();
                    let response = HttpResponse::TooManyRequests()
                        .insert_header((RETRY_AFTER, retry_after))
                        .json(ErrorResponse::new("Too Many Requests"))
                        .map_into_right_body();
                    Ok(ServiceResponse::new(req, response))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    //! Тесты разбора CIDR, извлечения IP из-за прокси и работы middleware поверх
    //! полного actix-стека (429 при превышении, независимость ведёр по IP,
    //! доверие XFF только за доверенным прокси).

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn cidrs(entries: &[&str]) -> Vec<Cidr> {
        entries.iter().map(|e| Cidr::parse(e).expect("valid cidr")).collect()
    }

    // --- Cidr ---

    #[test]
    fn cidr_parses_single_ip_and_range() {
        assert_eq!(Cidr::parse("10.0.0.1"), Some(Cidr { addr: "10.0.0.1".parse().unwrap(), prefix: 32 }));
        assert_eq!(Cidr::parse("10.0.0.0/8"), Some(Cidr { addr: "10.0.0.0".parse().unwrap(), prefix: 8 }));
        assert_eq!(Cidr::parse("::1"), Some(Cidr { addr: "::1".parse().unwrap(), prefix: 128 }));
        assert_eq!(Cidr::parse("2001:db8::/32").map(|c| c.prefix), Some(32));
    }

    #[test]
    fn cidr_rejects_garbage_and_overlong_prefix() {
        assert_eq!(Cidr::parse("not-an-ip"), None);
        assert_eq!(Cidr::parse("10.0.0.0/33"), None);
        assert_eq!(Cidr::parse("::/129"), None);
    }

    #[test]
    fn cidr_contains_respects_prefix() {
        let net = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(net.contains("10.255.1.2".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        // Разные семейства не пересекаются.
        assert!(!net.contains("::1".parse().unwrap()));

        let net = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(net.contains("192.168.1.200".parse().unwrap()));
        assert!(!net.contains("192.168.2.1".parse().unwrap()));

        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:abcd::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
    }

    // --- resolve_key_ip ---

    fn xff(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(
                actix_web::http::header::HeaderName::from_static("x-forwarded-for"),
                actix_web::http::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn key_uses_peer_when_no_trusted_proxies() {
        // XFF есть, но список доверенных пуст → доверять нельзя, ключ = peer.
        let key = resolve_key_ip(Some(ip("203.0.113.9")), &xff(&["1.2.3.4"]), "X-Forwarded-For", &[]);
        assert_eq!(key, Some(ip("203.0.113.9")));
    }

    #[test]
    fn key_ignores_forwarded_from_untrusted_peer() {
        // Peer не в списке доверенных — XFF мог быть подделан, берём peer.
        let trusted = cidrs(&["10.0.0.0/8"]);
        let key = resolve_key_ip(Some(ip("203.0.113.9")), &xff(&["1.2.3.4"]), "X-Forwarded-For", &trusted);
        assert_eq!(key, Some(ip("203.0.113.9")));
    }

    #[test]
    fn key_takes_client_from_forwarded_behind_trusted_proxy() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        // Peer = доверенный прокси; XFF = "клиент".
        let key = resolve_key_ip(Some(ip("10.0.0.5")), &xff(&["198.51.100.7"]), "X-Forwarded-For", &trusted);
        assert_eq!(key, Some(ip("198.51.100.7")));
    }

    #[test]
    fn key_skips_trusted_hops_in_forwarded_chain() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        // Цепочка: клиент, внешний-прокси-недоверенный? Здесь все внутренние — доверенные.
        // client, proxyA(10.x), proxyB(10.x); справа налево первый недоверенный = client.
        let headers = xff(&["198.51.100.7, 10.0.0.9, 10.0.0.5"]);
        let key = resolve_key_ip(Some(ip("10.0.0.5")), &headers, "X-Forwarded-For", &trusted);
        assert_eq!(key, Some(ip("198.51.100.7")));
    }

    #[test]
    fn key_groups_ipv6_to_56() {
        let a = resolve_key_ip(Some(ip("2001:db8:1:2:3:4:5:6")), &HeaderMap::new(), "X-Forwarded-For", &[]);
        let b = resolve_key_ip(Some(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")), &HeaderMap::new(), "X-Forwarded-For", &[]);
        // Оба адреса в одном /56 → один ключ. /56 = 7 байт: младший байт 4-го
        // хекстета (byte 7) зануляется, поэтому оба сводятся к 2001:db8:1::.
        assert_eq!(a, b);
        assert_eq!(a, Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0))));
    }

    #[test]
    fn parse_forwarded_ip_handles_bare_and_port() {
        assert_eq!(parse_forwarded_ip("1.2.3.4"), Some(ip("1.2.3.4")));
        assert_eq!(parse_forwarded_ip(" 1.2.3.4:5678 "), Some(ip("1.2.3.4")));
        assert_eq!(parse_forwarded_ip("::1"), Some(ip("::1")));
        assert_eq!(parse_forwarded_ip("garbage"), None);
    }

    #[test]
    fn canonical_unmaps_v4_mapped_v6() {
        let mapped = IpAddr::V6(Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped());
        assert_eq!(canonical(mapped), ip("1.2.3.4"));
    }

    // --- Интеграция middleware поверх actix ---

    mod middleware {
        use super::*;
        use actix_web::http::StatusCode;
        use actix_web::{test, web, App, HttpResponse};
        use std::net::SocketAddr;

        /// Приложение с ручкой `/x`, обёрнутой per-IP лимитером.
        macro_rules! per_ip_app {
            ($limiter:expr) => {
                test::init_service(
                    App::new().service(
                        web::resource("/x")
                            .wrap(RateLimit::per_ip($limiter))
                            .route(web::get().to(|| async { HttpResponse::Ok().body("ok") })),
                    ),
                )
                .await
            };
        }

        fn per_ip(per_second: u64, burst: u32, trusted: &[&str]) -> PerIpLimiter {
            PerIpLimiter {
                limiter: Arc::new(RateLimiter::keyed(quota(per_second, burst))),
                trusted: Arc::new(cidrs(trusted)),
                forwarded_header: Arc::from("X-Forwarded-For"),
            }
        }

        fn peer(ip: &str) -> SocketAddr {
            format!("{ip}:12345").parse().unwrap()
        }

        #[actix_web::test]
        async fn returns_429_after_burst_exhausted() {
            let app = per_ip_app!(Some(per_ip(1, 2, &[])));
            // burst=2: два запроса проходят, третий — 429.
            for _ in 0..2 {
                let req = test::TestRequest::get().uri("/x").peer_addr(peer("203.0.113.1")).to_request();
                assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            }
            let req = test::TestRequest::get().uri("/x").peer_addr(peer("203.0.113.1")).to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(resp.headers().contains_key(RETRY_AFTER));
        }

        #[actix_web::test]
        async fn buckets_are_independent_per_ip() {
            let app = per_ip_app!(Some(per_ip(1, 1, &[])));
            // Первый IP исчерпал ведро.
            let req = test::TestRequest::get().uri("/x").peer_addr(peer("203.0.113.1")).to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            let req = test::TestRequest::get().uri("/x").peer_addr(peer("203.0.113.1")).to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::TOO_MANY_REQUESTS);
            // Другой IP — своё ведро, проходит.
            let req = test::TestRequest::get().uri("/x").peer_addr(peer("203.0.113.2")).to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn forwarded_client_gets_own_bucket_behind_trusted_proxy() {
            let app = per_ip_app!(Some(per_ip(1, 1, &["10.0.0.0/8"])));
            // Оба запроса приходят с одного прокси-peer (10.0.0.5), но XFF — разные клиенты.
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("10.0.0.5"))
                .insert_header(("X-Forwarded-For", "198.51.100.1"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            // Тот же клиент → 429 (ведро исчерпано).
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("10.0.0.5"))
                .insert_header(("X-Forwarded-For", "198.51.100.1"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::TOO_MANY_REQUESTS);
            // Другой клиент за тем же прокси → своё ведро, проходит.
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("10.0.0.5"))
                .insert_header(("X-Forwarded-For", "198.51.100.2"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn spoofed_forwarded_from_untrusted_peer_is_ignored() {
            let app = per_ip_app!(Some(per_ip(1, 1, &["10.0.0.0/8"])));
            // Peer недоверенный, но пытается подделать XFF разными IP — ключ всё равно peer,
            // поэтому второй запрос ловит 429 несмотря на смену XFF.
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("203.0.113.9"))
                .insert_header(("X-Forwarded-For", "1.1.1.1"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            let req = test::TestRequest::get()
                .uri("/x")
                .peer_addr(peer("203.0.113.9"))
                .insert_header(("X-Forwarded-For", "2.2.2.2"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        #[actix_web::test]
        async fn disabled_limiter_passes_through() {
            let app = per_ip_app!(None);
            for _ in 0..5 {
                let req = test::TestRequest::get().uri("/x").peer_addr(peer("203.0.113.1")).to_request();
                assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            }
        }

        #[actix_web::test]
        async fn global_cap_limits_regardless_of_ip() {
            let limiter = GlobalLimiter { limiter: Arc::new(RateLimiter::direct(quota(1, 2))) };
            let app = test::init_service(
                App::new().service(
                    web::resource("/x")
                        .wrap(RateLimit::global(Some(limiter)))
                        .route(web::get().to(|| async { HttpResponse::Ok().body("ok") })),
                ),
            )
            .await;
            // burst=2 на весь эндпоинт: два любых запроса ок, третий — 429, даже с другого IP.
            let req = test::TestRequest::get().uri("/x").peer_addr(peer("203.0.113.1")).to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            let req = test::TestRequest::get().uri("/x").peer_addr(peer("203.0.113.2")).to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
            let req = test::TestRequest::get().uri("/x").peer_addr(peer("203.0.113.3")).to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }
}
