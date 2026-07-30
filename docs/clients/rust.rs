//! Клиент `jwt-service-app` для эндпоинтов уровня 3 (TOTP).
//!
//! Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
//! токена и массовый отзыв токенов субъекта.
//!
//! Зависимости:
//!
//! ```toml
//! totp-rs = { version = "5", features = ["otpauth"] }
//! reqwest = { version = "0.12", features = ["json", "blocking"] }
//! serde = { version = "1", features = ["derive"] }
//! ```
//!
//! Окружение:
//! - `AUTH_TOTP_SECRET` — общий TOTP-секрет в base32 (обязательно);
//! - `JWT_SERVICE_URL` — базовый URL сервиса, по умолчанию `http://localhost:8080`.
//!
//! **Код считается заново перед каждым запросом.** При включённой на сервере
//! защите от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION`) повторное предъявление
//! того же кода вернёт `401`, хотя сам код ещё не истёк.

use std::env;

use reqwest::blocking::{Client as HttpClient, Response};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

/// Значение claim `iss`. Должно совпадать при выпуске и проверке токена.
const ISSUER_HOST: &str = "example.com";

/// Ответ на выпуск токена или обмен refresh-токена.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    /// Подписанный JWT в формате `header.payload.signature`.
    pub token: String,
    /// Refresh-токен; присутствует, только если запрашивался.
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Ответ на массовый отзыв токенов субъекта.
#[derive(Debug, Deserialize)]
pub struct RevokeGroupResponse {
    /// Сколько активных токенов отозвано; истёкшие не считаются.
    pub revoked: u64,
}

/// Тело запроса на выпуск токена.
#[derive(Debug, Serialize)]
struct IssueRequest<'a> {
    sub: &'a str,
    aud: &'a [String],
    refresh: bool,
    /// Произвольные claims; поле опускается, когда их нет.
    #[serde(skip_serializing_if = "serde_json::Map::is_empty")]
    claims: serde_json::Map<String, serde_json::Value>,
}

/// Клиент сервиса выдачи токенов.
pub struct Client {
    base_url: String,
    secret: String,
    http: HttpClient,
}

impl Client {
    /// Собирает клиент из переменных окружения.
    ///
    /// # Panics
    /// Если не задан `AUTH_TOTP_SECRET`.
    pub fn from_env() -> Self {
        Self {
            base_url: env::var("JWT_SERVICE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".into()),
            secret: env::var("AUTH_TOTP_SECRET").expect("нужен AUTH_TOTP_SECRET"),
            http: HttpClient::new(),
        }
    }

    /// Вычисляет TOTP-код на текущий момент.
    ///
    /// Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
    fn totp_code(&self) -> Result<String, Box<dyn std::error::Error>> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(self.secret.clone()).to_bytes()?,
        )?;

        Ok(totp.generate_current()?)
    }

    /// Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
    ///
    /// `body` — сериализуемое тело либо `None` для запросов без него (отзыв).
    fn request<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        // Код считается здесь, а не переиспользуется: один код — один запрос.
        let mut builder = self
            .http
            .request(method, format!("{}{path}", self.base_url))
            .header("X-TOTP-Code", self.totp_code()?)
            .header("Host", ISSUER_HOST);

        if let Some(body) = body {
            builder = builder.json(body);
        }

        Ok(builder.send()?)
    }

    /// Выпускает access-токен (`POST /tokens`).
    ///
    /// # Аргументы
    /// - `sub` — субъект, которому выдаётся токен (claim `sub`);
    /// - `aud` — список получателей (claim `aud`); не должен быть пустым;
    /// - `with_refresh` — запросить вместе с токеном refresh для продления сессии;
    /// - `claims` — произвольные claims (роли, scope, tenant), попадают в payload
    ///   рядом с зарегистрированными. Служебные имена (`iss`, `sub`, `aud`,
    ///   `exp`, `iat`, `nbf`, `jti`) переопределять нельзя — будет `422`. Число
    ///   ключей и объём ограничены на сервере.
    ///
    /// # Errors
    /// `401` — неверный TOTP-код, `422` — некорректные параметры или запрещённый
    /// claim, `500` — недоступны JWKS или Redis.
    pub fn issue_token(
        &self,
        sub: &str,
        aud: &[String],
        with_refresh: bool,
        claims: serde_json::Map<String, serde_json::Value>,
    ) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        let payload = IssueRequest {
            sub,
            aud,
            refresh: with_refresh,
            claims,
        };

        let response = self.request(Method::POST, "/tokens", Some(&payload))?;
        if !response.status().is_success() {
            return Err(format!("выпуск не удался: {}", response.status()).into());
        }

        Ok(response.json()?)
    }

    /// Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).
    ///
    /// Старый токен после обмена недействителен: сохраните новый и выбросьте
    /// предыдущий.
    ///
    /// # Внимание
    /// Не повторяйте обмен старым токеном при потере ответа. Повторное
    /// предъявление трактуется как кража и гасит **всю семью** — и refresh-токены,
    /// и выданные по ним access-токены. Надёжнее выпустить пару заново.
    ///
    /// # Errors
    /// `401` — токен неизвестен, истёк или уже использован.
    pub fn refresh_tokens(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        let payload = serde_json::json!({ "refresh_token": refresh_token });

        let response = self.request(Method::POST, "/tokens/refresh", Some(&payload))?;
        if !response.status().is_success() {
            return Err(format!("обмен не удался: {}", response.status()).into());
        }

        Ok(response.json()?)
    }

    /// Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).
    ///
    /// Идемпотентно: отзыв несуществующего `jti` — тоже успех, желаемое состояние
    /// достигнуто.
    ///
    /// # Errors
    /// `500` — хранилище недоступно, отзыв **не выполнен**: повторите попытку.
    pub fn revoke_token(&self, jti: &str) -> Result<(), Box<dyn std::error::Error>> {
        let response =
            self.request::<()>(Method::DELETE, &format!("/tokens/{jti}"), None)?;

        if !response.status().is_success() {
            return Err(format!("отзыв не удался: {}", response.status()).into());
        }

        Ok(())
    }

    /// Отзывает все активные токены субъекта.
    ///
    /// Ручка `DELETE /subjects/{sub}/tokens`. Нужна при компрометации: гасить
    /// токены по одному нельзя, их `jti` вызывающему неизвестны.
    ///
    /// Возвращает число отозванных токенов; уже истёкшие не считаются.
    ///
    /// # Errors
    /// `500` — хранилище недоступно, отзыв не выполнен.
    pub fn revoke_subject(&self, sub: &str) -> Result<u64, Box<dyn std::error::Error>> {
        let response =
            self.request::<()>(Method::DELETE, &format!("/subjects/{sub}/tokens"), None)?;

        if !response.status().is_success() {
            return Err(format!("массовый отзыв не удался: {}", response.status()).into());
        }

        let body: RevokeGroupResponse = response.json()?;
        Ok(body.revoked)
    }
}

/// Демонстрирует полный жизненный цикл токена.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::from_env();

    let mut claims = serde_json::Map::new();
    claims.insert("role".into(), serde_json::json!("admin"));

    let issued = client.issue_token("svc-a", &["svc-b".to_string()], true, claims)?;
    println!("выпущен: {}...", &issued.token[..32]);

    let refresh = issued.refresh_token.expect("запрашивали refresh");
    let refreshed = client.refresh_tokens(&refresh)?;
    println!("обновлён: {}...", &refreshed.token[..32]);

    println!("отозвано токенов: {}", client.revoke_subject("svc-a")?);

    Ok(())
}
