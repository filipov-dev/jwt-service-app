//! Многоуровневый контроль доступа к эндпоинтам.
//!
//! Реализует единый auth-middleware ([`Auth`]) с тремя уровнями
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
//!
//! Крипта (HMAC для TOTP, constant-time сравнение) — через `openssl`, уже
//! присутствующий в зависимостях. Конфигурация целиком из окружения
//! ([`AuthConfig::from_env`]); при отсутствии секретов поведение осознанно
//! определено — см. `AUTH_ENFORCE_WHEN_SECRET_MISSING`.
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
use tracing::warn;

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
}

/// Читает `u64` из переменной окружения с откатом на `default`.
fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Читает булев флаг из окружения (`true`/`1`/`yes` → `true`), иначе `default`.
fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
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
#[derive(Clone)]
pub struct ProxyValidator {
    /// Имя заголовка (по умолчанию `X-Proxy-Secret`).
    header: String,
    /// Ожидаемый секрет; `None` — секрет не сконфигурирован.
    secret: Option<Vec<u8>>,
    /// Если секрет не сконфигурирован: `true` — отклонять все запросы (fail-closed),
    /// `false` — пропускать (disabled + warn на старте).
    enforce_when_missing: bool,
}

impl ProxyValidator {
    /// Проверяет заголовок запроса. Сравнение секрета — constant-time
    /// (`openssl::memcmp::eq`, поверх предварительной проверки длины).
    pub fn validate(&self, headers: &HeaderMap) -> bool {
        let Some(secret) = &self.secret else {
            return !self.enforce_when_missing;
        };

        match headers.get(self.header.as_str()) {
            Some(provided) => {
                let provided = provided.as_bytes();
                // `openssl::memcmp::eq` паникует на разной длине — сначала длина,
                // затем constant-time сравнение содержимого.
                provided.len() == secret.len() && openssl::memcmp::eq(provided, secret)
            }
            None => false,
        }
    }
}

/// Валидатор уровня 3: TOTP (RFC 6238).
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
    /// Поведение при отсутствии секретов (см. [`ProxyValidator`]).
    enforce_when_missing: bool,
}

impl TotpValidator {
    /// Проверяет TOTP-код из заголовка на момент `now` (Unix-время, секунды).
    ///
    /// Код принимается, если совпал с ожидаемым хотя бы для одного активного
    /// секрета в окне `[counter - skew, counter + skew]`. Перебор окон и секретов
    /// идёт без раннего выхода — чтобы не давать таймингового сигнала о том, какое
    /// окно/секрет совпали. Сравнение кодов — constant-time.
    pub fn validate(&self, headers: &HeaderMap, now: u64) -> bool {
        if self.secrets.is_empty() {
            return !self.enforce_when_missing;
        }

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
}

impl AuthConfig {
    /// Собирает конфигурацию из переменных окружения и логирует предупреждения
    /// об отсутствующих секретах (единожды, на старте).
    ///
    /// Переменные:
    /// - `AUTH_PROXY_SECRET_HEADER` (дефолт `X-Proxy-Secret`);
    /// - `AUTH_PROXY_SECRET` — секрет уровня 2 (как есть, сравнивается по байтам);
    /// - `AUTH_TOTP_HEADER` (дефолт `X-TOTP-Code`);
    /// - `AUTH_TOTP_SECRET`, `AUTH_TOTP_SECRET_NEXT` — base32-секреты (второй для ротации);
    /// - `AUTH_TOTP_STEP_SECONDS` (дефолт 30), `AUTH_TOTP_DIGITS` (6–8, дефолт 6),
    ///   `AUTH_TOTP_ALGORITHM` (SHA1/SHA256/SHA512, дефолт SHA1),
    ///   `AUTH_TOTP_SKEW_STEPS` (дефолт 1);
    /// - `AUTH_ENFORCE_WHEN_SECRET_MISSING` (дефолт `false`): при `false` уровень
    ///   без секрета отключён и пропускает запросы (с предупреждением на старте);
    ///   при `true` — fail-closed, все запросы к уровню без секрета отклоняются 401.
    pub fn from_env() -> Self {
        let enforce = env_bool("AUTH_ENFORCE_WHEN_SECRET_MISSING", false);

        // --- Уровень 2: proxy-secret ---
        let proxy_header = env::var("AUTH_PROXY_SECRET_HEADER").unwrap_or_else(|_| "X-Proxy-Secret".into());
        let proxy_secret = env::var("AUTH_PROXY_SECRET").ok().and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s.into_bytes())
            }
        });
        if proxy_secret.is_none() {
            if enforce {
                warn!(
                    "AUTH_PROXY_SECRET не задан — уровень 2 (proxy-secret) в режиме enforce: все запросы будут отклонены (401)"
                );
            } else {
                warn!(
                    "AUTH_PROXY_SECRET не задан — уровень 2 (proxy-secret) ОТКЛЮЧЁН, эндпоинты уровня 2 пропускают запросы без проверки"
                );
            }
        }

        // --- Уровень 3: TOTP ---
        let totp_header = env::var("AUTH_TOTP_HEADER").unwrap_or_else(|_| "X-TOTP-Code".into());
        let mut secrets = Vec::new();
        for var in ["AUTH_TOTP_SECRET", "AUTH_TOTP_SECRET_NEXT"] {
            if let Ok(raw) = env::var(var) {
                if raw.trim().is_empty() {
                    continue;
                }
                match base32_decode(&raw) {
                    Some(bytes) if !bytes.is_empty() => secrets.push(bytes),
                    _ => warn!("{var} не является корректным base32 — секрет проигнорирован"),
                }
            }
        }
        if secrets.is_empty() {
            if enforce {
                warn!("AUTH_TOTP_SECRET не задан — уровень 3 (TOTP) в режиме enforce: все запросы будут отклонены (401)");
            } else {
                warn!("AUTH_TOTP_SECRET не задан — уровень 3 (TOTP) ОТКЛЮЧЁН, эндпоинты уровня 3 пропускают запросы без проверки");
            }
        }

        let digits = env_u64("AUTH_TOTP_DIGITS", 6).clamp(6, 8) as u32;
        let step = env_u64("AUTH_TOTP_STEP_SECONDS", 30).max(1);
        let skew = env_u64("AUTH_TOTP_SKEW_STEPS", 1);
        let digest = digest_by_name(&env::var("AUTH_TOTP_ALGORITHM").unwrap_or_else(|_| "SHA1".into()));

        Self {
            proxy: ProxyValidator {
                header: proxy_header,
                secret: proxy_secret,
                enforce_when_missing: enforce,
            },
            totp: TotpValidator {
                header: totp_header,
                secrets,
                step,
                digits,
                skew,
                digest,
                enforce_when_missing: enforce,
            },
        }
    }

    /// Разрешает или отклоняет запрос для заданного уровня по его заголовкам.
    pub fn authorize(&self, level: AuthLevel, headers: &HeaderMap) -> bool {
        match level {
            AuthLevel::Open => true,
            AuthLevel::ProxySecret => self.proxy.validate(headers),
            AuthLevel::Totp => self.totp.validate(headers, Utc::now().timestamp().max(0) as u64),
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
        let authorized = self.config.authorize(self.level, req.headers());
        let service = self.service.clone();

        Box::pin(async move {
            if authorized {
                let res = service.call(req).await?;
                Ok(res.map_into_left_body())
            } else {
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

    fn proxy(secret: Option<&str>, enforce: bool) -> ProxyValidator {
        ProxyValidator {
            header: "X-Proxy-Secret".into(),
            secret: secret.map(|s| s.as_bytes().to_vec()),
            enforce_when_missing: enforce,
        }
    }

    #[test]
    fn proxy_accepts_correct_secret() {
        let v = proxy(Some("s3cr3t"), false);
        assert!(v.validate(&headers_with("X-Proxy-Secret", "s3cr3t")));
    }

    #[test]
    fn proxy_rejects_wrong_and_missing_secret() {
        let v = proxy(Some("s3cr3t"), false);
        assert!(!v.validate(&headers_with("X-Proxy-Secret", "nope")));
        assert!(!v.validate(&HeaderMap::new()));
        // Другая длина — не должно паниковать в memcmp.
        assert!(!v.validate(&headers_with("X-Proxy-Secret", "short")));
    }

    #[test]
    fn proxy_missing_secret_respects_enforce_flag() {
        // Без секрета: enforce=false → пропускает, enforce=true → отклоняет.
        assert!(proxy(None, false).validate(&HeaderMap::new()));
        assert!(!proxy(None, true).validate(&HeaderMap::new()));
    }

    // --- TotpValidator ---

    fn totp(secrets: Vec<&[u8]>, skew: u64, enforce: bool) -> TotpValidator {
        TotpValidator {
            header: "X-TOTP-Code".into(),
            secrets: secrets.into_iter().map(|s| s.to_vec()).collect(),
            step: 30,
            digits: 6,
            skew,
            digest: MessageDigest::sha1(),
            enforce_when_missing: enforce,
        }
    }

    /// Ожидаемый код для окна, в котором лежит момент `now`.
    fn code_at(secret: &[u8], now: u64, step: u64) -> String {
        hotp(secret, now / step, 6, MessageDigest::sha1()).unwrap()
    }

    #[test]
    fn totp_accepts_current_code() {
        let v = totp(vec![RFC_SECRET], 1, false);
        let now = 1_700_000_000;
        let code = code_at(RFC_SECRET, now, 30);
        // Валидатор берёт своё «сейчас», поэтому проверяем через прямой вызов с `now`.
        assert!(v.validate(&headers_with("X-TOTP-Code", &code), now));
    }

    #[test]
    fn totp_rejects_wrong_and_missing_code() {
        let v = totp(vec![RFC_SECRET], 1, false);
        let now = 1_700_000_000;
        assert!(!v.validate(&headers_with("X-TOTP-Code", "000000"), now));
        assert!(!v.validate(&HeaderMap::new(), now));
    }

    #[test]
    fn totp_accepts_within_skew_and_rejects_outside() {
        let v = totp(vec![RFC_SECRET], 1, false);
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
        let v = totp(vec![old, new], 1, false);
        let now = 1_700_000_000;

        assert!(v.validate(&headers_with("X-TOTP-Code", &code_at(old, now, 30)), now));
        assert!(v.validate(&headers_with("X-TOTP-Code", &code_at(new, now, 30)), now));
    }

    #[test]
    fn totp_missing_secret_respects_enforce_flag() {
        let now = 1_700_000_000;
        assert!(totp(vec![], 1, false).validate(&HeaderMap::new(), now));
        assert!(!totp(vec![], 1, true).validate(&HeaderMap::new(), now));
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
        fn config(proxy_secret: Option<&str>, totp_secrets: Vec<&[u8]>, enforce: bool) -> AuthConfig {
            AuthConfig {
                proxy: ProxyValidator {
                    header: "X-Proxy-Secret".into(),
                    secret: proxy_secret.map(|s| s.as_bytes().to_vec()),
                    enforce_when_missing: enforce,
                },
                totp: TotpValidator {
                    header: "X-TOTP-Code".into(),
                    secrets: totp_secrets.into_iter().map(|s| s.to_vec()).collect(),
                    step: 30,
                    digits: 6,
                    skew: 1,
                    digest: MessageDigest::sha1(),
                    enforce_when_missing: enforce,
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
            let app = guarded_app!(AuthLevel::Open, config(None, vec![], false));
            let req = test::TestRequest::get().uri("/x").to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn proxy_level_accepts_valid_secret() {
            let app = guarded_app!(AuthLevel::ProxySecret, config(Some("s3cr3t"), vec![], false));
            let req = test::TestRequest::get()
                .uri("/x")
                .insert_header(("X-Proxy-Secret", "s3cr3t"))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn proxy_level_rejects_missing_and_wrong_secret() {
            let app = guarded_app!(AuthLevel::ProxySecret, config(Some("s3cr3t"), vec![], false));

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
            let app = guarded_app!(AuthLevel::Totp, config(None, vec![SECRET], false));
            let req = test::TestRequest::get()
                .uri("/x")
                .insert_header(("X-TOTP-Code", current_code(SECRET)))
                .to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }

        #[actix_web::test]
        async fn totp_level_rejects_missing_and_wrong_code() {
            let app = guarded_app!(AuthLevel::Totp, config(None, vec![SECRET], false));

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

        #[actix_web::test]
        async fn enforce_without_secret_rejects_all() {
            // Секрет не задан + enforce=true → fail-closed на защищённых уровнях.
            let app = guarded_app!(AuthLevel::Totp, config(None, vec![], true));
            let req = test::TestRequest::get().uri("/x").to_request();
            assert_eq!(
                test::call_service(&app, req).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }

        #[actix_web::test]
        async fn disabled_without_secret_passes() {
            // Секрет не задан + enforce=false → уровень отключён, запрос проходит.
            let app = guarded_app!(AuthLevel::ProxySecret, config(None, vec![], false));
            let req = test::TestRequest::get().uri("/x").to_request();
            assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
        }
    }
}
