//! Многоуровневый контроль доступа к эндпоинтам.
//!
//! Реализует единый auth-middleware ([`Auth`]) с четырьмя уровнями
//! ([`AuthLevel`]); уровень задаётся при регистрации роута в `main.rs`, а разница
//! между уровнями — только в валидаторе:
//!
//! - **Уровень 1 — [`AuthLevel::Open`]**: без защиты (`/livez`, `/readyz`,
//!   OpenAPI). Всегда пропускает.
//! - **Уровень 2 — [`AuthLevel::ProxySecret`]**: статический секрет-заголовок,
//!   который ставит только обратный прокси. Сравнение constant-time
//!   ([`ProxyValidator`]).
//! - **Уровень 3 — [`AuthLevel::Totp`]**: internal app-to-app по TOTP
//!   (RFC 6238, [`TotpValidator`]).
//! - **Уровень 4 — [`AuthLevel::MetricsToken`]**: скрейп `/metrics` по статическому
//!   Bearer-токену ([`MetricsValidator`]).
//!
//! Крипта (HMAC для TOTP, constant-time сравнение) — через `openssl`, уже
//! присутствующий в зависимостях. Конфигурация целиком из окружения
//! ([`AuthConfig::from_env`]).
//!
//! **Защиты обязательны.** Секреты уровней 2, 3 и 4 (`AUTH_PROXY_SECRET`,
//! `AUTH_TOTP_SECRET`, `AUTH_METRICS_TOKEN`) — обязательны: если хотя бы один не
//! задан, [`AuthConfig::from_env`] возвращает ошибку и сервис **не стартует**
//! (fail-fast на старте, как и с прочей критичной конфигурацией). Отключить
//! уровень нельзя.
//!
//! ## Замечание о replay (уровень 3)
//!
//! TOTP-код переигрываем в пределах окна действия. Мы **осознанно не** закрываем
//! это на уровне сервиса (валидатор остаётся stateless — без обращения к Redis),
//! полагаясь на короткий шаг окна и внутренний (app-to-app) характер уровня 3.
//! При необходимости строгой защиты от повторов используйте одноразовые коды на
//! стороне клиента или добавьте учёт использованных кодов в Redis с TTL = окну.

use std::env;
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;

use actix_web::body::EitherBody;
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::HeaderMap;
use actix_web::{Error, HttpResponse};
use chrono::Utc;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

use crate::models::ErrorResponse;

/// Уровень доступа эндпоинта. Определяет, какой валидатор применяет middleware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthLevel {
    /// Уровень 1 — без защиты. Пропускает любой запрос.
    Open,
    /// Уровень 2 — статический proxy-secret заголовок.
    ProxySecret,
    /// Уровень 3 — internal app-to-app по TOTP.
    Totp,
    /// Уровень 4 — скрейп метрик по статическому Bearer-токену.
    ///
    /// Отдельный уровень, а не переиспользование уровня 2/3: TOTP системам
    /// мониторинга не по силам (они не считают одноразовые коды), а `X-Proxy-Secret`
    /// по контракту затирается прокси. Bearer же нативно поддержан и Prometheus
    /// (`authorization: {credentials_file}`), и Zabbix `agent2`, и OTel Collector
    /// (через него метрики забирает Monium).
    MetricsToken,
}

impl AuthLevel {
    /// Строковое имя уровня для логов/трейсинга (пишется в span запроса).
    fn as_str(self) -> &'static str {
        match self {
            AuthLevel::Open => "open",
            AuthLevel::ProxySecret => "proxy_secret",
            AuthLevel::Totp => "totp",
            AuthLevel::MetricsToken => "metrics_token",
        }
    }
}

/// Читает `u64` из переменной окружения с откатом на `default`.
fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Декодирует строку base32 (RFC 4648, алфавит `A–Z2–7`) в байты.
///
/// Регистронезависимо; пробелы и паддинг `=` игнорируются. Возвращает `None`,
/// если встретился символ вне алфавита. TOTP-секреты по соглашению кодируются
/// именно в base32 (совместимо с Google Authenticator и большинством библиотек).
fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();

    for ch in input.chars() {
        if ch.is_whitespace() || ch == '=' {
            continue;
        }
        let up = ch.to_ascii_uppercase() as u8;
        let value = ALPHABET.iter().position(|&a| a == up)? as u64;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }

    Some(out)
}

/// Выбирает `MessageDigest` по имени хеша для TOTP (по умолчанию SHA-1).
fn digest_by_name(name: &str) -> MessageDigest {
    match name.trim().to_ascii_uppercase().as_str() {
        "SHA256" | "SHA-256" => MessageDigest::sha256(),
        "SHA512" | "SHA-512" => MessageDigest::sha512(),
        _ => MessageDigest::sha1(),
    }
}

/// Вычисляет HOTP-код (RFC 4226) для секрета и счётчика.
///
/// Возвращает строку из `digits` десятичных знаков (с ведущими нулями). Основа
/// для TOTP: счётчик — это номер временно́го окна.
///
/// # Errors
/// Проброс `openssl::error::ErrorStack`, если не удалось построить HMAC.
fn hotp(secret: &[u8], counter: u64, digits: u32, digest: MessageDigest) -> Result<String, openssl::error::ErrorStack> {
    let key = PKey::hmac(secret)?;
    let mut signer = Signer::new(digest, &key)?;
    signer.update(&counter.to_be_bytes())?;
    let hs = signer.sign_to_vec()?;

    // Динамическое усечение по RFC 4226 §5.3.
    let offset = (hs[hs.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(hs[offset]) & 0x7f) << 24)
        | (u32::from(hs[offset + 1]) << 16)
        | (u32::from(hs[offset + 2]) << 8)
        | u32::from(hs[offset + 3]);

    let otp = bin % 10u32.pow(digits);
    Ok(format!("{otp:0width$}", width = digits as usize))
}

/// Валидатор уровня 2: статический секрет-заголовок от обратного прокси.
///
/// Секрет обязателен и гарантированно задан (см. [`AuthConfig::from_env`], которая
/// не даст сервису стартовать без него).
#[derive(Clone)]
pub struct ProxyValidator {
    /// Имя заголовка (по умолчанию `X-Proxy-Secret`).
    header: String,
    /// Ожидаемый секрет.
    secret: Vec<u8>,
}

impl ProxyValidator {
    /// Проверяет заголовок запроса. Сравнение секрета — constant-time
    /// (`openssl::memcmp::eq`, поверх предварительной проверки длины).
    pub fn validate(&self, headers: &HeaderMap) -> bool {
        match headers.get(self.header.as_str()) {
            Some(provided) => {
                let provided = provided.as_bytes();
                // `openssl::memcmp::eq` паникует на разной длине — сначала длина,
                // затем constant-time сравнение содержимого.
                provided.len() == self.secret.len() && openssl::memcmp::eq(provided, &self.secret)
            }
            None => false,
        }
    }
}

/// Валидатор уровня 4: статический Bearer-токен для скрейпа метрик.
#[derive(Clone)]
pub struct MetricsValidator {
    /// Ожидаемый токен (без префикса `Bearer `).
    token: Vec<u8>,
}

impl MetricsValidator {
    /// Проверяет заголовок `Authorization: Bearer <токен>`.
    ///
    /// Схема (`Bearer`) сравнивается регистронезависимо — так требует RFC 7235;
    /// сам токен — constant-time (`openssl::memcmp::eq` поверх проверки длины).
    pub fn validate(&self, headers: &HeaderMap) -> bool {
        let Some(value) = headers.get("Authorization") else {
            return false;
        };
        let Ok(value) = value.to_str() else {
            return false;
        };

        let Some((scheme, provided)) = value.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return false;
        }

        let provided = provided.trim().as_bytes();
        provided.len() == self.token.len() && openssl::memcmp::eq(provided, &self.token)
    }
}

/// Валидатор уровня 3: TOTP (RFC 6238).
///
/// Активные секреты обязательны и гарантированно непусты (см.
/// [`AuthConfig::from_env`], которая не даст сервису стартовать без них).
#[derive(Clone)]
pub struct TotpValidator {
    /// Имя заголовка с кодом (по умолчанию `X-TOTP-Code`).
    header: String,
    /// Активные секреты (1 или 2 — второй нужен на время ротации).
    secrets: Vec<Vec<u8>>,
    /// Шаг окна в секундах (по умолчанию 30).
    step: u64,
    /// Число знаков в коде (6–8, по умолчанию 6).
    digits: u32,
    /// Допуск по окнам в обе стороны (по умолчанию 1) — компенсирует рассинхрон часов.
    skew: u64,
    /// Хеш HMAC (SHA-1/256/512).
    digest: MessageDigest,
}

impl TotpValidator {
    /// Проверяет TOTP-код из заголовка на момент `now` (Unix-время, секунды).
    ///
    /// Код принимается, если совпал с ожидаемым хотя бы для одного активного
    /// секрета в окне `[counter - skew, counter + skew]`. Перебор окон и секретов
    /// идёт без раннего выхода — чтобы не давать таймингового сигнала о том, какое
    /// окно/секрет совпали. Сравнение кодов — constant-time.
    pub fn validate(&self, headers: &HeaderMap, now: u64) -> bool {
        let Some(provided) = headers.get(self.header.as_str()) else {
            return false;
        };
        let provided = provided.as_bytes();

        let counter = now / self.step;
        let low = counter.saturating_sub(self.skew);
        let high = counter.saturating_add(self.skew);

        let mut matched = false;
        for secret in &self.secrets {
            for c in low..=high {
                if let Ok(code) = hotp(secret, c, self.digits, self.digest) {
                    let code = code.as_bytes();
                    if provided.len() == code.len() && openssl::memcmp::eq(provided, code) {
                        matched = true;
                    }
                }
            }
        }
        matched
    }
}

/// Полная конфигурация уровней доступа, собранная из окружения.
///
/// Дёшево клонируется (короткие строки/байтовые векторы) — в `main.rs` копия
/// оборачивается в `Rc` внутри фабрики приложения на каждый worker-поток.
#[derive(Clone)]
pub struct AuthConfig {
    proxy: ProxyValidator,
    totp: TotpValidator,
    metrics: MetricsValidator,
}

impl AuthConfig {
    /// Собирает конфигурацию из переменных окружения.
    ///
    /// Секреты уровней 2 и 3 **обязательны**: если `AUTH_PROXY_SECRET` или
    /// `AUTH_TOTP_SECRET` не заданы (либо TOTP-секрет не парсится как base32),
    /// возвращается `Err` с перечнем проблем, и сервис не должен стартовать
    /// (см. вызов в `main.rs`). Отключить уровень нельзя.
    ///
    /// Переменные:
    /// - `AUTH_PROXY_SECRET` — секрет уровня 2 (обязателен; сравнивается по байтам);
    /// - `AUTH_PROXY_SECRET_HEADER` (дефолт `X-Proxy-Secret`);
    /// - `AUTH_TOTP_SECRET` — base32-секрет уровня 3 (обязателен);
    /// - `AUTH_TOTP_SECRET_NEXT` — второй base32-секрет на время ротации (опционально);
    /// - `AUTH_TOTP_HEADER` (дефолт `X-TOTP-Code`);
    /// - `AUTH_TOTP_STEP_SECONDS` (дефолт 30), `AUTH_TOTP_DIGITS` (6–8, дефолт 6),
    ///   `AUTH_TOTP_ALGORITHM` (SHA1/SHA256/SHA512, дефолт SHA1),
    ///   `AUTH_TOTP_SKEW_STEPS` (дефолт 1).
    ///
    /// # Errors
    /// Строка с перечислением всех проблем конфигурации (через `; `), если хотя бы
    /// один обязательный секрет отсутствует или некорректен.
    pub fn from_env() -> Result<Self, String> {
        let mut errors: Vec<String> = Vec::new();

        // --- Уровень 2: proxy-secret (обязателен) ---
        let proxy_header = env::var("AUTH_PROXY_SECRET_HEADER").unwrap_or_else(|_| "X-Proxy-Secret".into());
        let proxy_secret = env::var("AUTH_PROXY_SECRET").ok().filter(|s| !s.is_empty());
        if proxy_secret.is_none() {
            errors.push("AUTH_PROXY_SECRET не задан (обязателен для уровня 2 — proxy-secret)".into());
        }

        // --- Уровень 3: TOTP (хотя бы один секрет обязателен) ---
        let totp_header = env::var("AUTH_TOTP_HEADER").unwrap_or_else(|_| "X-TOTP-Code".into());
        let mut secrets = Vec::new();
        for var in ["AUTH_TOTP_SECRET", "AUTH_TOTP_SECRET_NEXT"] {
            match env::var(var) {
                Ok(raw) if !raw.trim().is_empty() => match base32_decode(&raw) {
                    Some(bytes) if !bytes.is_empty() => secrets.push(bytes),
                    _ => errors.push(format!("{var} не является корректным base32")),
                },
                _ => {}
            }
        }
        if secrets.is_empty() {
            errors.push("AUTH_TOTP_SECRET не задан (обязателен для уровня 3 — TOTP)".into());
        }

        // --- Уровень 4: токен метрик (обязателен) ---
        let metrics_token = env::var("AUTH_METRICS_TOKEN").ok().filter(|s| !s.trim().is_empty());
        if metrics_token.is_none() {
            errors.push(
                "AUTH_METRICS_TOKEN не задан (обязателен для уровня 4 — скрейп /metrics)".into(),
            );
        }

        if !errors.is_empty() {
            return Err(errors.join("; "));
        }

        let digits = env_u64("AUTH_TOTP_DIGITS", 6).clamp(6, 8) as u32;
        let step = env_u64("AUTH_TOTP_STEP_SECONDS", 30).max(1);
        let skew = env_u64("AUTH_TOTP_SKEW_STEPS", 1);
        let digest = digest_by_name(&env::var("AUTH_TOTP_ALGORITHM").unwrap_or_else(|_| "SHA1".into()));

        Ok(Self {
            proxy: ProxyValidator {
                header: proxy_header,
                // Проверено выше: при `None` мы бы уже вернули `Err`.
                secret: proxy_secret.expect("proxy secret present").into_bytes(),
            },
            totp: TotpValidator {
                header: totp_header,
                secrets,
                step,
                digits,
                skew,
                digest,
            },
            metrics: MetricsValidator {
                // Проверено выше: при `None` мы бы уже вернули `Err`.
                token: metrics_token
                    .expect("metrics token present")
                    .trim()
                    .to_string()
                    .into_bytes(),
            },
        })
    }

    /// Разрешает или отклоняет запрос для заданного уровня по его заголовкам.
    pub fn authorize(&self, level: AuthLevel, headers: &HeaderMap) -> bool {
        match level {
            AuthLevel::Open => true,
            AuthLevel::ProxySecret => self.proxy.validate(headers),
            AuthLevel::Totp => self.totp.validate(headers, Utc::now().timestamp().max(0) as u64),
            AuthLevel::MetricsToken => self.metrics.validate(headers),
        }
    }
}

/// Middleware-фабрика: оборачивает роут проверкой заданного [`AuthLevel`].
///
/// Регистрируется через `.wrap(Auth::new(level, config))` на конкретном ресурсе.
pub struct Auth {
    level: AuthLevel,
    config: Rc<AuthConfig>,
}

impl Auth {
    /// Создаёт middleware-фабрику для уровня `level` с общей конфигурацией.
    pub fn new(level: AuthLevel, config: Rc<AuthConfig>) -> Self {
        Self { level, config }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware {
            service: Rc::new(service),
            level: self.level,
            config: self.config.clone(),
        }))
    }
}

/// Собственно middleware: проверяет доступ до вызова внутреннего сервиса.
pub struct AuthMiddleware<S> {
    service: Rc<S>,
    level: AuthLevel,
    config: Rc<AuthConfig>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Пишем уровень доступа в span запроса (поле объявлено в `RequestLog`;
        // если span'а нет — no-op, безопасно в юнит-тестах).
        tracing::Span::current().record("access_level", self.level.as_str());

        let authorized = self.config.authorize(self.level, req.headers());
        let service = self.service.clone();
        let level = self.level;

        Box::pin(async move {
            if authorized {
                let res = service.call(req).await?;
                Ok(res.map_into_left_body())
            } else {
                // Отказ доступа — сигнал безопасности (подбор секрета, неверный
                // TOTP, забытый заголовок у клиента). Уровень WARN: не сбой
                // сервиса, но повод смотреть. Сам секрет/код НЕ логируем.
                tracing::warn!(access_level = level.as_str(), "Отказ в доступе");
                crate::metrics::record_auth_denied(level.as_str());

                // Единый скупой ответ без деталей — как и на остальных ручках.
                let (req, _payload) = req.into_parts();
                let response = HttpResponse::Unauthorized()
                    .json(ErrorResponse::new("Unauthorized"))
                    .map_into_right_body();
                Ok(ServiceResponse::new(req, response))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    //! Тесты валидаторов и TOTP-примитивов.
    //!
    //! `hotp` проверяется контрольными векторами RFC 4226 (секрет
    //! `"12345678901234567890"`), `base32_decode` — вектором RFC 4648, а
    //! валидаторы — на успех/отказ, границы окна TOTP и поведение без секрета.
    //! Тесты middleware-обёртки живут в `handlers.rs` (полный HTTP-стек).

    use super::*;
    use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};

    /// Секрет из контрольных векторов RFC 4226 (ASCII-строка).
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    /// Собирает `HeaderMap` с одним заголовком.
    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        h
    }

    /// Валидатор уровня 4 с известным токеном.
    fn metrics_validator() -> MetricsValidator {
        MetricsValidator {
            token: b"scrape-token".to_vec(),
        }
    }

    #[test]
    fn metrics_accepts_valid_bearer_token() {
        let v = metrics_validator();
        assert!(v.validate(&headers_with("Authorization", "Bearer scrape-token")));
    }

    #[test]
    fn metrics_scheme_is_case_insensitive() {
        // RFC 7235: имя схемы регистронезависимо.
        let v = metrics_validator();
        assert!(v.validate(&headers_with("Authorization", "bearer scrape-token")));
        assert!(v.validate(&headers_with("Authorization", "BEARER scrape-token")));
    }

    #[test]
    fn metrics_rejects_wrong_or_missing_token() {
        let v = metrics_validator();
        assert!(!v.validate(&HeaderMap::new()));
        assert!(!v.validate(&headers_with("Authorization", "Bearer wrong-token")));
        // Верный префикс токена не должен проходить (сравнение по полной длине).
        assert!(!v.validate(&headers_with("Authorization", "Bearer scrape")));
        assert!(!v.validate(&headers_with("Authorization", "Bearer ")));
    }

    #[test]
    fn metrics_rejects_other_schemes_and_raw_token() {
        let v = metrics_validator();
        // Basic-схема и «голый» токен без схемы не принимаются.
        assert!(!v.validate(&headers_with("Authorization", "Basic scrape-token")));
        assert!(!v.validate(&headers_with("Authorization", "scrape-token")));
    }

    // --- HOTP: контрольные векторы RFC 4226 (Appendix D) ---

    #[test]
    fn hotp_matches_rfc4226_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, want) in expected.iter().enumerate() {
            let got = hotp(RFC_SECRET, counter as u64, 6, MessageDigest::sha1()).unwrap();
            assert_eq!(&got, want, "HOTP расходится с RFC 4226 на counter={counter}");
        }
    }

    // --- base32 ---

    #[test]
    fn base32_decodes_rfc4648_vector() {
        // RFC 4648: "foo" => "MZXW6" (без паддинга).
        assert_eq!(base32_decode("MZXW6").unwrap(), b"foo");
        // Регистронезависимо и с игнорированием паддинга/пробелов.
        assert_eq!(base32_decode("mzxw6===").unwrap(), b"foo");
        assert_eq!(base32_decode("MZ XW6").unwrap(), b"foo");
    }

    #[test]
    fn base32_rejects_invalid_alphabet() {
        // '1', '8', '0' не входят в алфавит base32.
        assert!(base32_decode("1808").is_none());
    }

    // --- ProxyValidator ---

    fn proxy(secret: &str) -> ProxyValidator {
        ProxyValidator {
            header: "X-Proxy-Secret".into(),
            secret: secret.as_bytes().to_vec(),
        }
    }

    #[test]
    fn proxy_accepts_correct_secret() {
        let v = proxy("s3cr3t");
        assert!(v.validate(&headers_with("X-Proxy-Secret", "s3cr3t")));
    }

    #[test]
    fn proxy_rejects_wrong_and_missing_secret() {
        let v = proxy("s3cr3t");
        assert!(!v.validate(&headers_with("X-Proxy-Secret", "nope")));
        assert!(!v.validate(&HeaderMap::new()));
        // Другая длина — не должно паниковать в memcmp.
        assert!(!v.validate(&headers_with("X-Proxy-Secret", "short")));
    }

    // --- TotpValidator ---

    fn totp(secrets: Vec<&[u8]>, skew: u64) -> TotpValidator {
        TotpValidator {
            header: "X-TOTP-Code".into(),
            secrets: secrets.into_iter().map(|s| s.to_vec()).collect(),
            step: 30,
            digits: 6,
            skew,
            digest: MessageDigest::sha1(),
        }
    }

    /// Ожидаемый код для окна, в котором лежит момент `now`.
    fn code_at(secret: &[u8], now: u64, step: u64) -> String {
        hotp(secret, now / step, 6, MessageDigest::sha1()).unwrap()
    }

    #[test]
    fn totp_accepts_current_code() {
        let v = totp(vec![RFC_SECRET], 1);
        let now = 1_700_000_000;
        let code = code_at(RFC_SECRET, now, 30);
        // Валидатор берёт своё «сейчас», поэтому проверяем через прямой вызов с `now`.
        assert!(v.validate(&headers_with("X-TOTP-Code", &code), now));
    }

    #[test]
    fn totp_rejects_wrong_and_missing_code() {
        let v = totp(vec![RFC_SECRET], 1);
        let now = 1_700_000_000;
        assert!(!v.validate(&headers_with("X-TOTP-Code", "000000"), now));
        assert!(!v.validate(&HeaderMap::new(), now));
    }

    #[test]
    fn totp_accepts_within_skew_and_rejects_outside() {
        let v = totp(vec![RFC_SECRET], 1);
        let now = 1_700_000_000;
        // Код предыдущего окна принимается при skew=1.
        let prev = code_at(RFC_SECRET, now - 30, 30);
        assert!(v.validate(&headers_with("X-TOTP-Code", &prev), now));
        // Код через два окна — за пределами skew=1, отклоняется.
        let far = code_at(RFC_SECRET, now + 60, 30);
        assert!(!v.validate(&headers_with("X-TOTP-Code", &far), now));
    }

    #[test]
    fn totp_supports_secret_rotation() {
        // Два активных секрета: код от любого из них принимается.
        let old = b"old-secret-000000000".as_slice();
        let new = b"new-secret-111111111".as_slice();
        let v = totp(vec![old, new], 1);
        let now = 1_700_000_000;

        assert!(v.validate(&headers_with("X-TOTP-Code", &code_at(old, now, 30)), now));
        assert!(v.validate(&headers_with("X-TOTP-Code", &code_at(new, now, 30)), now));
    }

    // --- AuthConfig::from_env: секреты обязательны ---

    /// Сериализует тесты, трогающие процесс-глобальные `AUTH_*` переменные, и
    /// вычищает их до и после (восстановление после «отравления» лока паникой).
    fn with_clean_auth_env<T>(f: impl FnOnce() -> T) -> T {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        const VARS: &[&str] = &[
            "AUTH_PROXY_SECRET", "AUTH_PROXY_SECRET_HEADER", "AUTH_TOTP_SECRET",
            "AUTH_TOTP_SECRET_NEXT", "AUTH_TOTP_HEADER", "AUTH_TOTP_DIGITS",
            "AUTH_TOTP_STEP_SECONDS", "AUTH_TOTP_ALGORITHM", "AUTH_TOTP_SKEW_STEPS",
            "AUTH_METRICS_TOKEN",
        ];
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for v in VARS {
            env::remove_var(v);
        }
        let result = f();
        for v in VARS {
            env::remove_var(v);
        }
        result
    }

    #[test]
    fn from_env_errors_when_both_secrets_missing() {
        with_clean_auth_env(|| {
            // `let-else` вместо `unwrap_err()`, чтобы не требовать `Debug` на
            // `AuthConfig` (в нём лежат секреты — им не место в Debug-выводе).
            let Err(err) = AuthConfig::from_env() else {
                panic!("ожидалась ошибка конфигурации");
            };
            assert!(err.contains("AUTH_PROXY_SECRET"), "{err}");
            assert!(err.contains("AUTH_TOTP_SECRET"), "{err}");
        });
    }

    #[test]
    fn from_env_errors_when_only_totp_missing() {
        with_clean_auth_env(|| {
            env::set_var("AUTH_PROXY_SECRET", "s3cr3t");
            let Err(err) = AuthConfig::from_env() else {
                panic!("ожидалась ошибка конфигурации");
            };
            assert!(err.contains("AUTH_TOTP_SECRET"), "{err}");
            assert!(!err.contains("AUTH_PROXY_SECRET"), "{err}");
        });
    }

    #[test]
    fn from_env_errors_when_only_metrics_token_missing() {
        // Уровень 4 обязателен так же, как уровни 2 и 3: без токена сервис не
        // стартует (fail-fast), чтобы `/metrics` не оказалась случайно открытой.
        with_clean_auth_env(|| {
            env::set_var("AUTH_PROXY_SECRET", "s3cr3t");
            env::set_var("AUTH_TOTP_SECRET", "MZXW6");
            let Err(err) = AuthConfig::from_env() else {
                panic!("ожидалась ошибка конфигурации");
            };
            assert!(err.contains("AUTH_METRICS_TOKEN"), "{err}");
        });
    }

    #[test]
    fn from_env_ok_with_both_secrets() {
        with_clean_auth_env(|| {
            env::set_var("AUTH_PROXY_SECRET", "s3cr3t");
            env::set_var("AUTH_TOTP_SECRET", "MZXW6"); // base32("foo")
            env::set_var("AUTH_METRICS_TOKEN", "m3trics");
            let cfg = AuthConfig::from_env().expect("config должна собраться");
            assert_eq!(cfg.proxy.secret, b"s3cr3t");
            assert_eq!(cfg.totp.secrets, vec![b"foo".to_vec()]);
            assert_eq!(cfg.metrics.token, b"m3trics");
        });
    }

    #[test]
    fn from_env_errors_on_invalid_base32() {
        with_clean_auth_env(|| {
            env::set_var("AUTH_PROXY_SECRET", "s3cr3t");
            env::set_var("AUTH_TOTP_SECRET", "10108"); // 0,1,8 вне алфавита base32
            let Err(err) = AuthConfig::from_env() else {
                panic!("ожидалась ошибка конфигурации");
            };
            assert!(err.contains("base32"), "{err}");
        });
    }

    #[test]
    fn from_env_supports_two_secrets_for_rotation() {
        with_clean_auth_env(|| {
            env::set_var("AUTH_PROXY_SECRET", "s3cr3t");
            env::set_var("AUTH_TOTP_SECRET", "MZXW6");
            env::set_var("AUTH_TOTP_SECRET_NEXT", "MZXW6");
            env::set_var("AUTH_METRICS_TOKEN", "m3trics");
            let cfg = AuthConfig::from_env().expect("config должна собраться");
            assert_eq!(cfg.totp.secrets.len(), 2);
        });
    }

    // --- Интеграция: middleware поверх полного HTTP-стека actix ---

    mod middleware {
        //! Прогоняем каждый уровень через реальный actix-стек: тривиальный
        //! обработчик, обёрнутый [`Auth`], должен отдавать `200` при валидном
        //! креде и `401` — при отсутствующем/неверном. Так проверяется, что
        //! middleware действительно перехватывает запрос до обработчика.

        use super::*;
        use actix_web::http::StatusCode;
        use actix_web::{test, web, App, HttpResponse};
        use chrono::Utc;

        /// Секрет TOTP для интеграционных прогонов.
        const SECRET: &[u8] = b"12345678901234567890";

        /// Конфигурация с явными валидаторами (env не задействуется).
        fn config(proxy_secret: &str, totp_secrets: Vec<&[u8]>) -> AuthConfig {
            AuthConfig {
                proxy: ProxyValidator {
                    header: "X-Proxy-Secret".into(),
                    secret: proxy_secret.as_bytes().to_vec(),
                },
                totp: TotpValidator {
                    header: "X-TOTP-Code".into(),
                    secrets: totp_secrets.into_iter().map(|s| s.to_vec()).collect(),
                    step: 30,
                    digits: 6,
                    skew: 1,
                    digest: MessageDigest::sha1(),
                },
                metrics: MetricsValidator {
                    token: b"metrics-token".to_vec(),
                },
            }
        }

        /// Поднимает приложение с одним GET-роутом `/x`, обёрнутым уровнем `level`.
        macro_rules! guarded_app {
            ($level:expr, $config:expr) => {
                test::init_service(
                    App::new().service(
                        web::resource("/x")
                            .wrap(Auth::new($level, Rc::new($config)))
                            .route(web::get().to(|| async { HttpResponse::Ok().body("ok") })),
                    ),
                )
                .await
            };
        }

        /// TOTP-код для текущего окна и заданного секрета.
        fn current_code(secret: &[u8]) -> String {
            let now = Utc::now().timestamp().max(0) as u64;
            hotp(secret, now / 30, 6, MessageDigest::sha1()).unwrap()
        }

        #[actix_web::test]
        async fn open_level_passes_without_credentials() {
            let app = guarded_app!(AuthLevel::Open, config("s3cr3t", vec![SECRET]));
            let req = test::TestRequest::get().uri("/x").to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn proxy_level_accepts_valid_secret() {
            let app = guarded_app!(AuthLevel::ProxySecret, config("s3cr3t", vec![SECRET]));
            let req = test::TestRequest::get()
                .uri("/x")
                .insert_header(("X-Proxy-Secret", "s3cr3t"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn proxy_level_rejects_missing_and_wrong_secret() {
            let app = guarded_app!(AuthLevel::ProxySecret, config("s3cr3t", vec![SECRET]));

            let req = test::TestRequest::get().uri("/x").to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::UNAUTHORIZED
            );

            let req = test::TestRequest::get()
                .uri("/x")
                .insert_header(("X-Proxy-Secret", "wrong"))
                .to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }

        #[actix_web::test]
        async fn totp_level_accepts_valid_code() {
            let app = guarded_app!(AuthLevel::Totp, config("s3cr3t", vec![SECRET]));
            let req = test::TestRequest::get()
                .uri("/x")
                .insert_header(("X-TOTP-Code", current_code(SECRET)))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn totp_level_rejects_missing_and_wrong_code() {
            let app = guarded_app!(AuthLevel::Totp, config("s3cr3t", vec![SECRET]));

            let req = test::TestRequest::get().uri("/x").to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::UNAUTHORIZED
            );

            let req = test::TestRequest::get()
                .uri("/x")
                .insert_header(("X-TOTP-Code", "000000"))
                .to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }
}
