//! Низкоуровневое представление JWT: claims, заголовки, сборка и разбор токена.
//!
//! Ключевые типы:
//! - [`TokenClaims`] — полезная нагрузка (`iss`, `sub`, `aud`, `exp`, ...);
//! - [`TokenHeaders`] — заголовок JOSE (`alg`, `kid`, `typ`, опциональный `jku`);
//! - [`JsonWebToken`] — обёртка над заголовком, claims и ключом; параметризована
//!   типом ключа: `JsonWebToken<Private>` умеет подписывать
//!   ([`JsonWebToken::to_string`]), `JsonWebToken<Public>` — разбирать и
//!   проверять ([`JsonWebToken::from_string`]);
//! - [`JtiStore`] — трейт хранилища идентификаторов токенов (реализуется
//!   [`crate::redis::RedisClient`]).
//!
//! Кодирование сегментов — base64url без паддинга, как того требует JWS.

use std::env;
use actix_web::web::Data;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, info};
use uuid::Uuid;
use crate::key::{KeyManager, SUPPORTED_ALGORITHMS};

#[derive(Error, Debug)]
pub enum JtiError {
    #[error("Bad connection")]
    BadConnection,
    #[error("Wrong operation")]
    WrongOperation,
    #[error("Internal")]
    Internal,
}

/// Хранилище идентификаторов токенов (`jti`).
///
/// Абстрагирует бэкенд (в проекте — Redis) от доменной логики. Наличие `jti` в
/// хранилище означает, что токен «активен»: при выпуске `jti` записывается с
/// TTL, при отзыве — удаляется, при проверке — проверяется на существование.
pub trait JtiStore where Self: Sized {
    /// Сохраняет `jti` со временем жизни `ttl` (в секундах).
    async fn store_jti(&self, jti: &str, ttl: u64) -> Result<(), JtiError>;
    /// Возвращает `true`, если `jti` присутствует (токен не отозван и не истёк).
    async fn check_jti(&self, jti: &str) -> Result<bool, JtiError>;
    /// Удаляет `jti` (отзыв токена). Идемпотентна.
    async fn delete_jti(&self, jti: &str) -> Result<(), JtiError>;
}

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("Unprocessable entity")]
    UnprocessableEntity,
    #[error("Store error")]
    StoreError,
    #[error("Bad signature")]
    BadSignature,
    #[error("Not valid")]
    NotValid,
    #[error("Broken")]
    Broken,
}

/// Полезная нагрузка токена (registered claims по RFC 7519).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Issuer — издатель токена (из заголовка `Host`).
    pub iss: String,
    /// Subject — субъект, о котором выдан токен.
    pub sub: String,
    /// Audience — список получателей.
    pub aud: Vec<String>,
    /// Expiration — момент истечения (Unix-время, секунды).
    pub exp: usize,
    /// Issued At — момент выпуска.
    pub iat: usize,
    /// Not Before — момент, с которого токен действителен.
    pub nbf: usize,
    /// JWT ID — уникальный идентификатор (UUID v4), ключ в [`JtiStore`].
    pub jti: String,
}

impl TokenClaims {
    /// Формирует новый набор claims и регистрирует `jti` в хранилище.
    ///
    /// Время жизни берётся из `TOKEN_EXPIRATION_SECONDS` (по умолчанию `3600`);
    /// на его основе вычисляются `exp` и TTL записи в хранилище. `jti`
    /// генерируется как UUID v4.
    ///
    /// # Errors
    /// - [`JwtError::UnprocessableEntity`] — пустой `audience` или невалидное
    ///   значение `TOKEN_EXPIRATION_SECONDS`;
    /// - [`JwtError::StoreError`] — сформированные claims не прошли
    ///   самопроверку [`TokenClaims::is_verify`].
    ///
    /// # Замечание
    /// Ошибка записи `jti` в хранилище логируется, но **не** прерывает выпуск —
    /// это осознанное поведение текущей реализации.
    pub async fn create_new<T: JtiStore>(
        issuer: &str,
        subject: &str,
        audience: &[String],
        store: Data<T>,
    ) -> Result<Self, JwtError> {
        let expiration_seconds = match env::var("TOKEN_EXPIRATION_SECONDS")
            .unwrap_or("3600".into())
            .parse::<u64>() {
                Ok(v) => { v }
                Err(e) => {
                    error!("{}", e);
                    return Err(JwtError::UnprocessableEntity)
                }
            };

        if audience.is_empty() {
            return Err(JwtError::UnprocessableEntity);
        }

        let now = Utc::now();
        let exp = now + Duration::seconds(expiration_seconds as i64);

        let jti = Uuid::new_v4().to_string();

        match store.store_jti(&jti, expiration_seconds).await {
            Ok(_) => {}
            Err(e) => {
                error!("JTI Store: {}", e);
            }
        };

        let jwt = Self {
            iss: issuer.to_string(),
            sub: subject.to_string(),
            aud: audience.to_vec(),
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
            nbf: now.timestamp() as usize,
            jti,
        };

        if !jwt.is_verify(issuer, audience.first().unwrap(), store).await {
            return Err(JwtError::StoreError);
        }

        Ok(jwt)
    }

    /// Декодирует claims из base64url-сегмента токена.
    ///
    /// # Errors
    /// [`JwtError::Broken`] — сегмент не является корректным base64url, не
    /// декодируется в UTF-8 или не парсится как JSON claims.
    pub fn from_base64(str: String) -> Result<Self, JwtError> {
        let bytes = match BASE64_URL_SAFE_NO_PAD.decode(str) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("{}", e);
                return Err(JwtError::Broken)
            },
        };

        let json = match String::from_utf8(bytes) {
            Ok(string) => string,
            Err(e) => {
                error!("{}", e);
                return Err(JwtError::Broken)
            },
        };

        match serde_json::from_str(&json) {
            Ok(jwt) => Ok(jwt),
            Err(e) => {
                error!("{}", e);
                Err(JwtError::Broken)
            },
        }
    }

    /// Проверяет claims относительно ожидаемых `issuer`/`audience` и текущего
    /// времени, а также наличие `jti` в хранилище.
    ///
    /// Возвращает `true`, только если совпал `iss`, `audience` входит в `aud`,
    /// выполнены временные границы (`nbf <= now`, `iat <= now`, `exp > now`) и
    /// `jti` найден в [`JtiStore`].
    ///
    /// # Panics
    /// Паникует, если обращение к хранилищу вернуло ошибку (используется
    /// `.unwrap()` на результате `check_jti`).
    pub async fn is_verify<T: JtiStore>(
        &self,
        issuer: &str,
        audience: &str,
        store: Data<T>,
    ) -> bool {
        let now = Utc::now().timestamp() as usize;

        self.iss == issuer &&
            self.aud.contains(&audience.to_owned()) &&
            self.nbf <= now &&
            self.iat <= now &&
            self.exp > now &&
            store.check_jti(&self.jti).await.unwrap()
    }

    /// Сериализует claims в JSON-строку.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    /// Кодирует claims в base64url-сегмент (JSON → base64url без паддинга).
    pub fn to_base64(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.to_json())
    }
}

/// Заголовок токена (JOSE header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenHeaders {
    /// Алгоритм подписи (`RS256`, `ES256`, `EdDSA`, ...).
    alg: String,
    /// Идентификатор ключа, которым подписан токен.
    kid: String,
    /// Тип токена; всегда `"JWT"`.
    typ: String,
    /// JWK Set URL — не сериализуется, если не задан (`TOKEN_JKU`).
    #[serde(skip_serializing_if = "Option::is_none")]
    jku: Option<String>,
}

impl TokenHeaders {
    /// Создаёт заголовок для нового токена.
    ///
    /// `alg` берётся из `TOKEN_ALGORITHM` (по умолчанию `RS256`), `jku` —
    /// из необязательной `TOKEN_JKU`, `kid` передаётся из менеджера ключей.
    pub fn create_new(kid: String) -> Self {
        let jku = match env::var("TOKEN_JKU") {
            Ok(v) => { Some(v) }
            Err(_) => { None }
        };

        let alg = env::var("TOKEN_ALGORITHM")
            .unwrap_or("RS256".into());

        Self {
            alg,
            kid,
            typ: "JWT".to_string(),
            jku,
        }
    }

    /// Декодирует заголовок из base64url-сегмента токена.
    ///
    /// # Panics
    /// Паникует на некорректном base64url/UTF-8/JSON (используется `.unwrap()`).
    pub fn from_base64(str: String) -> Self {
        let json = BASE64_URL_SAFE_NO_PAD.decode(str).unwrap();

        serde_json::from_str(&*String::from_utf8(json).unwrap()).unwrap()
    }

    /// Проверяет корректность заголовка при верификации токена.
    ///
    /// Требует, чтобы `alg` был из [`SUPPORTED_ALGORITHMS`], `typ` был `"JWT"`,
    /// а `jku` совпадал с текущей конфигурацией (`TOKEN_JKU`).
    pub fn is_verify(&self) -> bool {
        let jku = match env::var("TOKEN_JKU") {
            Ok(v) => { Some(v) }
            Err(_) => { None }
        };

        SUPPORTED_ALGORITHMS.contains(&self.alg.as_str()) &&
            self.jku == jku &&
            self.typ == "JWT"
    }

    /// Сериализует заголовок в JSON-строку.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    /// Кодирует заголовок в base64url-сегмент.
    pub fn to_base64(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.to_json())
    }
}

/// Токен целиком: заголовок, claims и ключ.
///
/// Параметр `T` — тип ключа OpenSSL: [`Private`] для выпуска (подпись),
/// [`Public`] для проверки. Соответствующие операции реализованы в отдельных
/// `impl`-блоках.
#[derive(Debug, Clone)]
pub struct JsonWebToken<T> {
    pub headers: TokenHeaders,
    pub claims: TokenClaims,
    key: PKey<T>,
}

impl JsonWebToken<Private> {
    /// Собирает токен из готовых заголовка, claims и приватного ключа.
    pub fn create_new(headers: TokenHeaders, claims: TokenClaims, key: PKey<Private>) -> Self {
        Self {
            headers,
            claims,
            key,
        }
    }

    /// Сериализует и подписывает токен в форму `header.payload.signature`.
    ///
    /// Заголовок и claims кодируются в base64url, подпись считается по строке
    /// `header.payload` приватным ключом (без явного дайджеста — алгоритм задан
    /// самим ключом) и также кодируется в base64url.
    ///
    /// # Panics
    /// Паникует при ошибке инициализации `Signer` или вычисления подписи.
    pub fn to_string(&self) -> String {
        let headers = self.headers.to_base64();
        let claims= self.claims.to_base64();

        let mut signer = Signer::new_without_digest(&self.key).unwrap();
        let signature_bytes = signer.sign_oneshot_to_vec(format!("{}.{}", headers, claims).as_bytes()).unwrap();

        let signature = URL_SAFE_NO_PAD.encode(signature_bytes);

        format!("{}.{}.{}", headers, claims, signature)
    }
}

impl JsonWebToken<Public> {
    /// Разбирает строковый токен и полностью его проверяет.
    ///
    /// Шаги:
    /// 1. Разбивает токен на сегменты `header.payload.signature`.
    /// 2. По `kid` из заголовка получает публичный ключ через
    ///    [`KeyManager::get_public_key`].
    /// 3. Выбирает дайджест по `alg` и проверяет подпись над `header.payload`.
    /// 4. Валидирует заголовок ([`TokenHeaders::is_verify`]) и claims
    ///    ([`TokenClaims::is_verify`]) относительно `issuer`/`audience`.
    ///
    /// # Errors
    /// - [`JwtError::Broken`] — некорректная подпись в base64url;
    /// - [`JwtError::BadSignature`] — подпись не сошлась или не построился verifier;
    /// - [`JwtError::NotValid`] — заголовок или claims не прошли проверку.
    ///
    /// # Panics
    /// Текущая реализация паникует на токене неверной структуры (меньше трёх
    /// сегментов) и при ошибке получения публичного ключа (`.unwrap()`).
    pub async fn from_string<T: JtiStore>(
        token: &str,
        issuer: &str,
        audience: &str,
        store: Data<T>,
    ) -> Result<Self, JwtError> {
        let mut parts = token.split(".");
        let headers = parts.next().unwrap();
        let claims = parts.next().unwrap();
        let signature = parts.next().unwrap();

        let key = {
            let headers = TokenHeaders::from_base64(headers.to_string());

            KeyManager::get_public_key(headers.kid.as_str()).await.unwrap()
        };

        let mut verifier = {
            let headers = TokenHeaders::from_base64(headers.to_string());

            let verifier = match headers.alg.as_str() {
                "RS256" | "ES256" => Verifier::new(MessageDigest::sha256(), &key),
                "RS384" | "ES384" => Verifier::new(MessageDigest::sha384(), &key),
                "RS512" | "ES512" => Verifier::new(MessageDigest::sha512(), &key),
                _ => Verifier::new_without_digest(&key),
            };

            match verifier {
                Ok(verifier) => verifier,
                Err(e) => {
                    error!("{}", e);
                    return Err(JwtError::BadSignature);
                }
            }
        };

        let signature_decoded = match URL_SAFE_NO_PAD.decode(signature) {
            Ok(decoded) => decoded,
            Err(e) => {
                error!("{}", e);
                return Err(JwtError::Broken);
            }
        };

        let is_success = match verifier
            .verify_oneshot(
                &signature_decoded,
                format!("{}.{}", headers, claims).as_bytes(),
            ) {
            Ok(is_success) => is_success,
            Err(e) => {
                error!("{}", e);
                return Err(JwtError::BadSignature);
            }
        };

        if !is_success {
            return Err(JwtError::BadSignature);
        }

        let headers = TokenHeaders::from_base64(headers.to_string());
        let claims = TokenClaims::from_base64(claims.to_string()).unwrap();

        if !headers.is_verify() || !claims.is_verify(issuer, audience, store).await {
            return Err(JwtError::NotValid);
        }

        Ok(Self {
            headers,
            claims,
            key: key.clone(),
        })
    }
}