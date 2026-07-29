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

use crate::key::{KeyManager, SUPPORTED_ALGORITHMS};
use actix_web::web::Data;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::env;
use thiserror::Error;
use tracing::{debug, error, warn};
use uuid::Uuid;

/// Читает `u64` из переменной окружения, откатываясь на `default` при её
/// отсутствии или неразборчивом значении.
fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

#[derive(Error, Debug)]
pub enum JtiError {
    #[error("Bad connection")]
    BadConnection,
    #[error("Wrong operation")]
    WrongOperation,
}

/// Хранилище идентификаторов токенов (`jti`).
///
/// Абстрагирует бэкенд (в проекте — Redis) от доменной логики. Наличие `jti` в
/// хранилище означает, что токен «активен»: при выпуске `jti` записывается с
/// TTL, при отзыве — удаляется, при проверке — проверяется на существование.
pub trait JtiStore
where
    Self: Sized,
{
    /// Сохраняет `jti` со временем жизни `ttl` (в секундах).
    async fn store_jti(&self, jti: &str, ttl: u64) -> Result<(), JtiError>;
    /// Возвращает `true`, если `jti` присутствует (токен не отозван и не истёк).
    async fn check_jti(&self, jti: &str) -> Result<bool, JtiError>;
    /// Удаляет `jti` (отзыв токена). Идемпотентна.
    async fn delete_jti(&self, jti: &str) -> Result<(), JtiError>;
    /// Привязывает `jti` к группе; `expires_at` — unix-время истечения токена.
    ///
    /// Группа нужна, чтобы гасить токены пачкой. Ключ группы формирует
    /// вызывающий (см. [`subject_group`]) — само хранилище о его смысле не знает.
    async fn add_to_group(&self, group: &str, jti: &str, expires_at: i64) -> Result<(), JtiError>;
    /// Отзывает все токены группы и саму группу. Возвращает число отозванных.
    ///
    /// Идемпотентна: для несуществующей группы возвращает `0`.
    async fn revoke_group(&self, group: &str) -> Result<u64, JtiError>;
    /// Сохраняет запись refresh-токена со временем жизни `ttl` (в секундах).
    async fn store_refresh(
        &self,
        id: &str,
        record: &RefreshRecord,
        ttl: u64,
    ) -> Result<(), JtiError>;
    /// Читает запись refresh-токена. `None` — записи нет (истекла или отозвана).
    async fn get_refresh(&self, id: &str) -> Result<Option<RefreshRecord>, JtiError>;
    /// Помечает refresh-токен использованным.
    ///
    /// Возвращает `true`, если пометка проставлена именно этим вызовом, и
    /// `false`, если токен уже был использован раньше. Операция обязана быть
    /// **атомарной**: на ней держится и детектор повторного использования, и
    /// защита от гонки двух одновременных обменов одним токеном.
    async fn mark_refresh_used(&self, id: &str) -> Result<bool, JtiError>;
    /// Резервирует одноразовый TOTP-код на время `ttl` (в секундах).
    ///
    /// Возвращает `true`, если код зарезервирован именно этим вызовом, и
    /// `false`, если он уже предъявлялся — то есть это повтор.
    ///
    /// Как и [`JtiStore::mark_refresh_used`], операция обязана быть **атомарной**
    /// (`SET NX`): на ней держится защита от переигрывания кода.
    async fn claim_totp_code(&self, hash: &str, ttl: u64) -> Result<bool, JtiError>;
}

/// Ключ зарезервированного TOTP-кода в хранилище.
pub fn totp_code_key(hash: &str) -> String {
    format!("totp:used:{hash}")
}

/// Ключ группы токенов, выпущенных на субъект.
///
/// Вынесено в функцию не ради красоты: тот же механизм групп переиспользует
/// отзыв семьи refresh-токенов ([`family_group`]), поэтому хранилище оперирует
/// абстрактным ключом, а смысл группы задаёт вызывающий. Префикс отделяет группы
/// от плоских ключей-`jti`.
pub fn subject_group(subject: &str) -> String {
    format!("group:sub:{subject}")
}

/// Ключ группы одной семьи refresh-токенов.
///
/// В группу попадают и `jti` выданных access-токенов, и ключи самих
/// refresh-записей — поэтому один `revoke_group` гасит всю цепочку целиком.
pub fn family_group(family: &str) -> String {
    format!("group:family:{family}")
}

/// Ключ записи refresh-токена в хранилище.
pub fn refresh_key(id: &str) -> String {
    format!("refresh:{id}")
}

/// Запись refresh-токена: всё, что нужно, чтобы выпустить по нему новый access.
///
/// Сам refresh-токен — непрозрачная случайная строка, а не JWT: его никто не
/// разбирает и не проверяет по подписи, он лишь ключ к этой записи. Значит и
/// утёкший токен бесполезен без хранилища, а отзыв мгновенен.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRecord {
    /// Субъект, которому выдан токен.
    pub subject: String,
    /// Аудитория, с которой выпускаются access-токены цепочки.
    pub audience: Vec<String>,
    /// Идентификатор семьи — общий для всей цепочки ротации.
    pub family: String,
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
    #[error("Key error")]
    KeyError,
    #[error("Serialization failed")]
    Serialization,
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
    /// Время жизни определяется аргументом `ttl` (секунды): если он задан,
    /// используется он (после проверки границ), иначе — `TOKEN_EXPIRATION_SECONDS`
    /// (по умолчанию `3600`). На его основе вычисляются `exp` и TTL записи в
    /// хранилище — они всегда совпадают. `jti` генерируется как UUID v4.
    ///
    /// Границы кастомного `ttl` задаются `TOKEN_TTL_MIN_SECONDS` (по умолчанию
    /// `1`) и `TOKEN_TTL_MAX_SECONDS` (по умолчанию `86400`).
    ///
    /// # Errors
    /// - [`JwtError::UnprocessableEntity`] — пустой `audience`, невалидное
    ///   значение `TOKEN_EXPIRATION_SECONDS` или кастомный `ttl` вне границ
    ///   `[TOKEN_TTL_MIN_SECONDS, TOKEN_TTL_MAX_SECONDS]`;
    /// - [`JwtError::StoreError`] — не удалось записать `jti` в хранилище либо
    ///   сформированные claims не прошли самопроверку [`TokenClaims::is_verify`].
    ///
    /// # Замечание
    /// Выпуск устроен по принципу fail-fast: если `jti` не удалось сохранить в
    /// хранилище, токен **не** отдаётся ([`JwtError::StoreError`]) — это гарантирует
    /// консистентность с последующей проверкой (`is_verify` требует наличия `jti`).
    pub async fn create_new<T: JtiStore>(
        issuer: &str,
        subject: &str,
        audience: &[String],
        ttl: Option<u64>,
        store: Data<T>,
    ) -> Result<Self, JwtError> {
        let expiration_seconds = match ttl {
            Some(requested) => {
                let min = env_u64("TOKEN_TTL_MIN_SECONDS", 1);
                let max = env_u64("TOKEN_TTL_MAX_SECONDS", 86400);

                if requested < min || requested > max {
                    // Вина клиента (отдаём 422) — не повод для ERROR в проде.
                    debug!(
                        "Requested ttl {} out of bounds [{}, {}]",
                        requested, min, max
                    );
                    return Err(JwtError::UnprocessableEntity);
                }

                requested
            }
            None => match env::var("TOKEN_EXPIRATION_SECONDS")
                .unwrap_or("3600".into())
                .parse::<u64>()
            {
                Ok(v) => v,
                Err(e) => {
                    // Некорректная конфигурация сервиса — деградация, не отказ
                    // зависимости.
                    warn!("TOKEN_EXPIRATION_SECONDS: {}", e);
                    return Err(JwtError::UnprocessableEntity);
                }
            },
        };

        let Some(first_audience) = audience.first() else {
            return Err(JwtError::UnprocessableEntity);
        };

        let now = Utc::now();
        let exp = now + Duration::seconds(expiration_seconds as i64);

        let jti = Uuid::new_v4().to_string();

        // Fail-fast: если `jti` не записался в хранилище, токен выпускать нельзя —
        // иначе его последующая проверка провалится (jti отсутствует → считается
        // отозванным). Пробрасываем ошибку наверх, обработчик вернёт 500.
        store
            .store_jti(&jti, expiration_seconds)
            .await
            .map_err(|e| {
                error!("JTI Store: {}", e);
                JwtError::StoreError
            })?;

        // Индекс для массового отзыва — тоже fail-fast, и по той же причине, что
        // и сам `jti`: токен, не попавший в индекс, переживёт отзыв всех токенов
        // субъекта. Тихо выпустить такой токен опаснее, чем не выпустить вовсе.
        store
            .add_to_group(&subject_group(subject), &jti, exp.timestamp())
            .await
            .map_err(|e| {
                error!("JTI Store (индекс субъекта): {}", e);
                JwtError::StoreError
            })?;

        let jwt = Self {
            iss: issuer.to_string(),
            sub: subject.to_string(),
            aud: audience.to_vec(),
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
            nbf: now.timestamp() as usize,
            jti,
        };

        if !jwt.is_verify(issuer, first_audience, store).await {
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
        // Битый токен присылает клиент — это DEBUG, а не ERROR: в проде такие
        // события нормальны и не должны поднимать алерты.
        let bytes = match BASE64_URL_SAFE_NO_PAD.decode(str) {
            Ok(bytes) => bytes,
            Err(e) => {
                debug!("Claims: base64url не декодируется: {}", e);
                return Err(JwtError::Broken);
            }
        };

        let json = match String::from_utf8(bytes) {
            Ok(string) => string,
            Err(e) => {
                debug!("Claims: не UTF-8: {}", e);
                return Err(JwtError::Broken);
            }
        };

        match serde_json::from_str(&json) {
            Ok(jwt) => Ok(jwt),
            Err(e) => {
                debug!("Claims: не разбирается как JSON: {}", e);
                Err(JwtError::Broken)
            }
        }
    }

    /// Проверяет claims относительно ожидаемых `issuer`/`audience` и текущего
    /// времени, а также наличие `jti` в хранилище.
    ///
    /// Возвращает `true`, только если совпал `iss`, `audience` входит в `aud`,
    /// выполнены временные границы (`nbf <= now`, `iat <= now`, `exp > now`) и
    /// `jti` найден в [`JtiStore`].
    ///
    /// Ошибка обращения к хранилищу логируется и трактуется как «не валиден»
    /// (возвращается `false`).
    pub async fn is_verify<T: JtiStore>(
        &self,
        issuer: &str,
        audience: &str,
        store: Data<T>,
    ) -> bool {
        let now = Utc::now().timestamp() as usize;

        let claims_valid = self.iss == issuer
            && self.aud.contains(&audience.to_owned())
            && self.nbf <= now
            && self.iat <= now
            && self.exp > now;

        if !claims_valid {
            return false;
        }

        match store.check_jti(&self.jti).await {
            Ok(exists) => exists,
            Err(e) => {
                error!("JTI check: {}", e);
                false
            }
        }
    }

    /// Сериализует claims в JSON-строку.
    ///
    /// # Errors
    /// [`JwtError::Serialization`] — сериализация не удалась (практически
    /// недостижимо для этого типа).
    pub fn to_json(&self) -> Result<String, JwtError> {
        serde_json::to_string(self).map_err(|e| {
            error!("{}", e);
            JwtError::Serialization
        })
    }

    /// Кодирует claims в base64url-сегмент (JSON → base64url без паддинга).
    ///
    /// # Errors
    /// [`JwtError::Serialization`] — не удалось сериализовать claims в JSON.
    pub fn to_base64(&self) -> Result<String, JwtError> {
        Ok(BASE64_URL_SAFE_NO_PAD.encode(self.to_json()?))
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
        let jku = env::var("TOKEN_JKU").ok();

        let alg = env::var("TOKEN_ALGORITHM").unwrap_or("RS256".into());

        Self {
            alg,
            kid,
            typ: "JWT".to_string(),
            jku,
        }
    }

    /// Декодирует заголовок из base64url-сегмента токена.
    ///
    /// # Errors
    /// [`JwtError::Broken`] — сегмент не является корректным base64url, не
    /// декодируется в UTF-8 или не парсится как JSON-заголовок.
    pub fn from_base64(str: String) -> Result<Self, JwtError> {
        // Как и у claims: битый заголовок — вина клиента, уровень DEBUG.
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(str).map_err(|e| {
            debug!("Header: base64url не декодируется: {}", e);
            JwtError::Broken
        })?;

        let json = String::from_utf8(bytes).map_err(|e| {
            debug!("Header: не UTF-8: {}", e);
            JwtError::Broken
        })?;

        serde_json::from_str(&json).map_err(|e| {
            debug!("Header: не разбирается как JSON: {}", e);
            JwtError::Broken
        })
    }

    /// Проверяет корректность заголовка при верификации токена.
    ///
    /// Требует, чтобы `alg` был из [`SUPPORTED_ALGORITHMS`], `typ` был `"JWT"`,
    /// а `jku` совпадал с текущей конфигурацией (`TOKEN_JKU`).
    pub fn is_verify(&self) -> bool {
        let jku = env::var("TOKEN_JKU").ok();

        SUPPORTED_ALGORITHMS.contains(&self.alg.as_str()) && self.jku == jku && self.typ == "JWT"
    }

    /// Сериализует заголовок в JSON-строку.
    ///
    /// # Errors
    /// [`JwtError::Serialization`] — сериализация не удалась (практически
    /// недостижимо для этого типа).
    pub fn to_json(&self) -> Result<String, JwtError> {
        serde_json::to_string(self).map_err(|e| {
            error!("{}", e);
            JwtError::Serialization
        })
    }

    /// Кодирует заголовок в base64url-сегмент.
    ///
    /// # Errors
    /// [`JwtError::Serialization`] — не удалось сериализовать заголовок в JSON.
    pub fn to_base64(&self) -> Result<String, JwtError> {
        Ok(BASE64_URL_SAFE_NO_PAD.encode(self.to_json()?))
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
    /// `header.payload` приватным ключом и также кодируется в base64url.
    ///
    /// Дайджест выбирается по `alg` **тем же образом, что и при проверке**
    /// ([`JsonWebToken::from_string`]): `RS*`/`ES*` подписываются поверх
    /// соответствующего SHA-2 (256/384/512), `EdDSA` — без явного дайджеста
    /// (алгоритм задан самим ключом). Схемы подписи и проверки обязаны совпадать,
    /// иначе выпущенный токен не пройдёт собственную верификацию.
    ///
    /// # Errors
    /// - [`JwtError::Serialization`] — не удалось сериализовать заголовок/claims;
    /// - [`JwtError::BadSignature`] — не удалось инициализировать `Signer` или
    ///   вычислить подпись.
    pub fn to_string(&self) -> Result<String, JwtError> {
        let headers = self.headers.to_base64()?;
        let claims = self.claims.to_base64()?;

        let mut signer = match self.headers.alg.as_str() {
            "RS256" | "ES256" => Signer::new(MessageDigest::sha256(), &self.key),
            "RS384" | "ES384" => Signer::new(MessageDigest::sha384(), &self.key),
            "RS512" | "ES512" => Signer::new(MessageDigest::sha512(), &self.key),
            _ => Signer::new_without_digest(&self.key),
        }
        .map_err(|e| {
            error!("{}", e);
            JwtError::BadSignature
        })?;
        let signature_bytes = signer
            .sign_oneshot_to_vec(format!("{}.{}", headers, claims).as_bytes())
            .map_err(|e| {
                error!("{}", e);
                JwtError::BadSignature
            })?;

        let signature = URL_SAFE_NO_PAD.encode(signature_bytes);

        Ok(format!("{}.{}.{}", headers, claims, signature))
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
    pub async fn from_string<T: JtiStore>(
        token: &str,
        issuer: &str,
        audience: &str,
        key_manager: &KeyManager,
        store: Data<T>,
    ) -> Result<Self, JwtError> {
        let mut parts = token.split('.');
        let (headers_segment, claims_segment, signature_segment) =
            match (parts.next(), parts.next(), parts.next()) {
                (Some(h), Some(c), Some(s)) => (h, c, s),
                _ => return Err(JwtError::Broken),
            };

        let headers = TokenHeaders::from_base64(headers_segment.to_string())?;

        let key = match key_manager.get_public_key(headers.kid.as_str()).await {
            Ok(key) => key,
            Err(e) => {
                // Причину (недоступность JWKS и т.п.) уже залогировал `key.rs` на
                // своём уровне — здесь только исход проверки, без дубля ERROR.
                debug!("Публичный ключ по kid не получен: {}", e);
                return Err(JwtError::BadSignature);
            }
        };

        let signature_decoded = match URL_SAFE_NO_PAD.decode(signature_segment) {
            Ok(decoded) => decoded,
            Err(e) => {
                debug!("Подпись: base64url не декодируется: {}", e);
                return Err(JwtError::Broken);
            }
        };

        // Verifier заимствует `key`, поэтому держим его в отдельной области —
        // иначе `key` нельзя было бы переместить в возвращаемый токен.
        let is_success = {
            let mut verifier = match headers.alg.as_str() {
                "RS256" | "ES256" => Verifier::new(MessageDigest::sha256(), &key),
                "RS384" | "ES384" => Verifier::new(MessageDigest::sha384(), &key),
                "RS512" | "ES512" => Verifier::new(MessageDigest::sha512(), &key),
                _ => Verifier::new_without_digest(&key),
            }
            .map_err(|e| {
                error!("{}", e);
                JwtError::BadSignature
            })?;

            verifier
                .verify_oneshot(
                    &signature_decoded,
                    format!("{}.{}", headers_segment, claims_segment).as_bytes(),
                )
                .map_err(|e| {
                    // Чаще всего — некорректные байты подписи от клиента.
                    debug!("Проверка подписи не выполнена: {}", e);
                    JwtError::BadSignature
                })?
        };

        if !is_success {
            return Err(JwtError::BadSignature);
        }

        let claims = TokenClaims::from_base64(claims_segment.to_string())?;

        if !headers.is_verify() || !claims.is_verify(issuer, audience, store).await {
            return Err(JwtError::NotValid);
        }

        Ok(Self {
            headers,
            claims,
            key,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Тесты сборки/разбора JWT и проверки claims.
    //!
    //! Хранилище `jti` подменяется in-memory моком [`MockStore`] — Redis и сеть
    //! не нужны. Полный round-trip проверки токена (`from_string`) требует
    //! публичного ключа из `jwks-service-app`, поэтому здесь проверяется всё, что
    //! от сети не зависит: жизненный цикл claims, кодирование сегментов и
    //! корректность подписи, которую ставит [`JsonWebToken::to_string`].

    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::Id;
    use openssl::rsa::Rsa;
    use parking_lot::Mutex;
    use std::collections::{HashMap, HashSet};

    /// In-memory реализация [`JtiStore`] для тестов.
    struct MockStore {
        jtis: Mutex<HashSet<String>>,
        groups: Mutex<HashMap<String, HashSet<String>>>,
        refreshes: Mutex<HashMap<String, (RefreshRecord, bool)>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                jtis: Mutex::new(HashSet::new()),
                groups: Mutex::new(HashMap::new()),
                refreshes: Mutex::new(HashMap::new()),
            }
        }

        fn insert(&self, jti: &str) {
            self.jtis.lock().insert(jti.to_string());
        }
    }

    impl JtiStore for MockStore {
        async fn store_jti(&self, jti: &str, _ttl: u64) -> Result<(), JtiError> {
            self.jtis.lock().insert(jti.to_string());
            Ok(())
        }

        async fn check_jti(&self, jti: &str) -> Result<bool, JtiError> {
            Ok(self.jtis.lock().contains(jti))
        }

        async fn delete_jti(&self, jti: &str) -> Result<(), JtiError> {
            self.jtis.lock().remove(jti);
            Ok(())
        }

        async fn add_to_group(
            &self,
            group: &str,
            jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            self.groups
                .lock()
                .entry(group.to_string())
                .or_default()
                .insert(jti.to_string());
            Ok(())
        }

        async fn revoke_group(&self, group: &str) -> Result<u64, JtiError> {
            let members = self.groups.lock().remove(group).unwrap_or_default();

            let mut jtis = self.jtis.lock();
            let revoked = members.iter().filter(|jti| jtis.remove(*jti)).count();

            Ok(revoked as u64)
        }

        async fn store_refresh(
            &self,
            id: &str,
            record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            self.refreshes
                .lock()
                .insert(id.to_string(), (record.clone(), false));
            Ok(())
        }

        async fn get_refresh(&self, id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Ok(self
                .refreshes
                .lock()
                .get(id)
                .map(|(record, _)| record.clone()))
        }

        async fn mark_refresh_used(&self, id: &str) -> Result<bool, JtiError> {
            let mut refreshes = self.refreshes.lock();

            match refreshes.get_mut(id) {
                Some((_, true)) => Ok(false),
                Some((_, used)) => {
                    *used = true;
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        async fn claim_totp_code(&self, _hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            Ok(true)
        }
    }

    /// [`JtiStore`], у которого запись `jti` всегда падает — имитирует
    /// недоступный Redis для проверки fail-fast при выпуске.
    struct FailingStore;

    impl JtiStore for FailingStore {
        async fn store_jti(&self, _jti: &str, _ttl: u64) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn check_jti(&self, _jti: &str) -> Result<bool, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn delete_jti(&self, _jti: &str) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn add_to_group(
            &self,
            _group: &str,
            _jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn revoke_group(&self, _group: &str) -> Result<u64, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn store_refresh(
            &self,
            _id: &str,
            _record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn get_refresh(&self, _id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn mark_refresh_used(&self, _id: &str) -> Result<bool, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn claim_totp_code(&self, _hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            Err(JtiError::BadConnection)
        }
    }

    /// [`JtiStore`], у которого падает ТОЛЬКО запись в индекс группы.
    ///
    /// Нужен, чтобы проверить fail-fast отдельно: сам `jti` записался, а индекс
    /// для массового отзыва — нет. Такой токен пережил бы отзыв всех токенов
    /// субъекта, поэтому выпускать его нельзя.
    struct FailingGroupStore {
        jtis: Mutex<HashSet<String>>,
    }

    impl FailingGroupStore {
        fn new() -> Self {
            Self {
                jtis: Mutex::new(HashSet::new()),
            }
        }
    }

    impl JtiStore for FailingGroupStore {
        async fn store_jti(&self, jti: &str, _ttl: u64) -> Result<(), JtiError> {
            self.jtis.lock().insert(jti.to_string());
            Ok(())
        }

        async fn check_jti(&self, jti: &str) -> Result<bool, JtiError> {
            Ok(self.jtis.lock().contains(jti))
        }

        async fn delete_jti(&self, jti: &str) -> Result<(), JtiError> {
            self.jtis.lock().remove(jti);
            Ok(())
        }

        async fn add_to_group(
            &self,
            _group: &str,
            _jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            Err(JtiError::WrongOperation)
        }

        async fn revoke_group(&self, _group: &str) -> Result<u64, JtiError> {
            Err(JtiError::WrongOperation)
        }

        async fn store_refresh(
            &self,
            _id: &str,
            _record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            Err(JtiError::WrongOperation)
        }

        async fn get_refresh(&self, _id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Err(JtiError::WrongOperation)
        }

        async fn mark_refresh_used(&self, _id: &str) -> Result<bool, JtiError> {
            Err(JtiError::WrongOperation)
        }

        async fn claim_totp_code(&self, _hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            Err(JtiError::WrongOperation)
        }
    }

    /// Заведомо валидные claims: выпущены «сейчас», живут ещё час.
    fn sample_claims() -> TokenClaims {
        let now = Utc::now().timestamp() as usize;
        TokenClaims {
            iss: "issuer".to_string(),
            sub: "subject".to_string(),
            aud: vec!["api1".to_string(), "api2".to_string()],
            exp: now + 3600,
            iat: now,
            nbf: now,
            jti: "jti-1".to_string(),
        }
    }

    // --- Кодирование/декодирование сегментов ---

    #[test]
    fn claims_base64_roundtrip() {
        let claims = sample_claims();
        let decoded = TokenClaims::from_base64(claims.to_base64().unwrap()).unwrap();

        assert_eq!(decoded.iss, claims.iss);
        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.aud, claims.aud);
        assert_eq!(decoded.exp, claims.exp);
        assert_eq!(decoded.iat, claims.iat);
        assert_eq!(decoded.nbf, claims.nbf);
        assert_eq!(decoded.jti, claims.jti);
    }

    #[test]
    fn claims_from_base64_rejects_invalid_base64() {
        // '!' не входит в алфавит base64url — ошибка декодирования.
        assert!(matches!(
            TokenClaims::from_base64("!!!not-base64!!!".to_string()),
            Err(JwtError::Broken)
        ));
    }

    #[test]
    fn claims_from_base64_rejects_non_json() {
        // Валидный base64url, но за ним не JSON claims.
        let payload = BASE64_URL_SAFE_NO_PAD.encode("just a string");
        assert!(matches!(
            TokenClaims::from_base64(payload),
            Err(JwtError::Broken)
        ));
    }

    #[test]
    fn header_from_base64_rejects_invalid() {
        // Битый base64url — раньше был бы panic, теперь Err(Broken).
        assert!(matches!(
            TokenHeaders::from_base64("!!!not-base64!!!".to_string()),
            Err(JwtError::Broken)
        ));
    }

    #[actix_web::test]
    async fn from_string_rejects_malformed_token() {
        // Меньше трёх сегментов — раньше был бы panic на `parts.next().unwrap()`.
        // Токен отбрасывается на разборе, до обращения к ключам, поэтому
        // менеджер здесь нужен только для сигнатуры — в сеть он не ходит.
        let store = Data::new(MockStore::new());
        let keys = KeyManager::new("RS256".to_string());
        let result =
            JsonWebToken::<Public>::from_string("not-a-jwt", "issuer", "api1", &keys, store).await;
        assert!(matches!(result, Err(JwtError::Broken)));
    }

    #[test]
    fn header_roundtrip_and_verify() {
        let header = TokenHeaders::create_new("kid-1".to_string());
        let decoded = TokenHeaders::from_base64(header.to_base64().unwrap()).unwrap();

        assert_eq!(decoded.kid, "kid-1");
        assert_eq!(decoded.typ, "JWT");
        // alg по умолчанию RS256 (входит в SUPPORTED_ALGORITHMS), jku не задан.
        assert!(decoded.is_verify());
    }

    // --- Проверка claims (iss/aud/nbf/iat/exp, jti) ---

    #[actix_web::test]
    async fn is_verify_accepts_valid_claims() {
        let store = Data::new(MockStore::new());
        store.insert("jti-1");

        let claims = sample_claims();
        assert!(claims.is_verify("issuer", "api2", store).await);
    }

    #[actix_web::test]
    async fn is_verify_rejects_wrong_issuer() {
        let store = Data::new(MockStore::new());
        store.insert("jti-1");

        let claims = sample_claims();
        assert!(!claims.is_verify("other-issuer", "api1", store).await);
    }

    #[actix_web::test]
    async fn is_verify_rejects_wrong_audience() {
        let store = Data::new(MockStore::new());
        store.insert("jti-1");

        let claims = sample_claims();
        assert!(!claims.is_verify("issuer", "unknown-aud", store).await);
    }

    #[actix_web::test]
    async fn is_verify_rejects_expired_token() {
        let store = Data::new(MockStore::new());
        store.insert("jti-1");

        let now = Utc::now().timestamp() as usize;
        let mut claims = sample_claims();
        claims.iat = now - 7200;
        claims.nbf = now - 7200;
        claims.exp = now - 3600; // истёк час назад

        assert!(!claims.is_verify("issuer", "api1", store).await);
    }

    #[actix_web::test]
    async fn is_verify_rejects_not_yet_valid_token() {
        let store = Data::new(MockStore::new());
        store.insert("jti-1");

        let now = Utc::now().timestamp() as usize;
        let mut claims = sample_claims();
        claims.nbf = now + 3600; // станет валиден только через час

        assert!(!claims.is_verify("issuer", "api1", store).await);
    }

    #[actix_web::test]
    async fn is_verify_rejects_missing_jti() {
        // Хранилище пустое: `jti` отозван/протух.
        let store = Data::new(MockStore::new());

        let claims = sample_claims();
        assert!(!claims.is_verify("issuer", "api1", store).await);
    }

    // --- Выпуск claims (create_new) ---

    #[actix_web::test]
    async fn create_new_builds_valid_claims_and_stores_jti() {
        let store = Data::new(MockStore::new());
        let audience = vec!["api1".to_string()];

        let claims = TokenClaims::create_new("issuer", "subject", &audience, None, store.clone())
            .await
            .unwrap();

        assert_eq!(claims.iss, "issuer");
        assert_eq!(claims.sub, "subject");
        assert_eq!(claims.aud, audience);
        assert_eq!(claims.iat, claims.nbf);
        assert!(claims.exp > claims.iat);
        assert!(Uuid::parse_str(&claims.jti).is_ok());
        // jti должен быть зарегистрирован в хранилище.
        assert!(store.check_jti(&claims.jti).await.unwrap());
    }

    #[actix_web::test]
    async fn create_new_rejects_empty_audience() {
        let store = Data::new(MockStore::new());
        let result = TokenClaims::create_new("issuer", "subject", &[], None, store).await;
        assert!(matches!(result, Err(JwtError::UnprocessableEntity)));
    }

    #[actix_web::test]
    async fn create_new_honors_custom_ttl() {
        let store = Data::new(MockStore::new());
        let audience = vec!["api1".to_string()];

        let before = Utc::now().timestamp() as usize;
        let claims =
            TokenClaims::create_new("issuer", "subject", &audience, Some(120), store.clone())
                .await
                .unwrap();
        let after = Utc::now().timestamp() as usize;

        // exp = iat + ttl, с поправкой на возможный сдвиг секунды при замере.
        assert!(claims.exp >= before + 120 && claims.exp <= after + 120);
        assert_eq!(claims.exp, claims.iat + 120);
    }

    #[actix_web::test]
    async fn create_new_rejects_ttl_below_min() {
        // Дефолтная нижняя граница — 1 секунда, значит 0 недопустим.
        let store = Data::new(MockStore::new());
        let audience = vec!["api1".to_string()];

        let result = TokenClaims::create_new("issuer", "subject", &audience, Some(0), store).await;
        assert!(matches!(result, Err(JwtError::UnprocessableEntity)));
    }

    #[actix_web::test]
    async fn create_new_rejects_ttl_above_max() {
        // Дефолтная верхняя граница — 86400 секунд.
        let store = Data::new(MockStore::new());
        let audience = vec!["api1".to_string()];

        let result =
            TokenClaims::create_new("issuer", "subject", &audience, Some(86401), store).await;
        assert!(matches!(result, Err(JwtError::UnprocessableEntity)));
    }

    #[actix_web::test]
    async fn create_new_fails_when_store_unavailable() {
        // Redis недоступен: запись `jti` падает, токен выпускать нельзя (fail-fast).
        let store = Data::new(FailingStore);
        let audience = vec!["api1".to_string()];

        let result = TokenClaims::create_new("issuer", "subject", &audience, None, store).await;
        assert!(matches!(result, Err(JwtError::StoreError)));
    }

    #[actix_web::test]
    async fn create_new_fails_when_group_index_unavailable() {
        // Сам `jti` записался, а индекс субъекта — нет. Такой токен пережил бы
        // массовый отзыв, поэтому выпускать его нельзя: fail-fast, как и при
        // недоступной записи `jti`.
        let store = Data::new(FailingGroupStore::new());
        let audience = vec!["api1".to_string()];

        let result = TokenClaims::create_new("issuer", "subject", &audience, None, store).await;
        assert!(matches!(result, Err(JwtError::StoreError)));
    }

    #[test]
    fn subject_group_is_namespaced() {
        // Префикс отделяет группы от плоских ключей-`jti`, иначе субъект с
        // именем-UUID мог бы совпасть с чужим идентификатором токена.
        assert_eq!(subject_group("user1"), "group:sub:user1");
    }

    // --- Подпись токена (JsonWebToken::to_string) ---

    #[test]
    fn to_string_produces_verifiable_signature() {
        // Ключ Ed25519: подпись/проверка без явного дайджеста — как в `to_string`.
        let private = PKey::generate_ed25519().unwrap();
        let public =
            PKey::public_key_from_raw_bytes(&private.raw_public_key().unwrap(), Id::ED25519)
                .unwrap();

        // `alg` задаётся явно, а не через `TokenHeaders::create_new`: тот читает
        // `TOKEN_ALGORITHM` из окружения, и тест проходил лишь потому, что
        // соседи успевали выставить там `EdDSA`. В одиночку он падал — ключ
        // Ed25519 подписывался с дайджестом от дефолтного `RS256`.
        let headers = headers_with_alg("EdDSA");
        let claims = sample_claims();
        let jwt = JsonWebToken::create_new(headers, claims, private);

        let token = jwt.to_string().unwrap();

        // Ровно три сегмента header.payload.signature.
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Подпись действительно покрывает "header.payload".
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let mut verifier = Verifier::new_without_digest(&public).unwrap();
        let signed_data = format!("{}.{}", parts[0], parts[1]);
        assert!(verifier
            .verify_oneshot(&signature, signed_data.as_bytes())
            .unwrap());

        // Сегмент claims декодируется обратно без потерь.
        let decoded_claims = TokenClaims::from_base64(parts[1].to_string()).unwrap();
        assert_eq!(decoded_claims.jti, "jti-1");
        assert_eq!(decoded_claims.iss, "issuer");
    }

    // --- Согласованность подписи и проверки для всех алгоритмов (JWT-13) ---

    /// Генерирует пару (приватный, публичный) ключ, подходящую под `alg`.
    fn keypair_for(alg: &str) -> (PKey<Private>, PKey<Public>) {
        match alg {
            "RS256" | "RS384" | "RS512" => {
                let rsa = Rsa::generate(2048).unwrap();
                let public = PKey::from_rsa(
                    Rsa::from_public_components(
                        rsa.n().to_owned().unwrap(),
                        rsa.e().to_owned().unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap();
                (PKey::from_rsa(rsa).unwrap(), public)
            }
            "ES256" | "ES384" | "ES512" => {
                let nid = match alg {
                    "ES256" => Nid::X9_62_PRIME256V1,
                    "ES384" => Nid::SECP384R1,
                    _ => Nid::SECP521R1,
                };
                let group = EcGroup::from_curve_name(nid).unwrap();
                let ec = EcKey::generate(&group).unwrap();
                let public =
                    PKey::from_ec_key(EcKey::from_public_key(&group, ec.public_key()).unwrap())
                        .unwrap();
                (PKey::from_ec_key(ec).unwrap(), public)
            }
            "EdDSA" => {
                let private = PKey::generate_ed25519().unwrap();
                let public = PKey::public_key_from_raw_bytes(
                    &private.raw_public_key().unwrap(),
                    Id::ED25519,
                )
                .unwrap();
                (private, public)
            }
            other => panic!("нет генератора ключа для alg {other} в тесте"),
        }
    }

    /// Заголовок с явным `alg` — минует зависимость `create_new` от env
    /// `TOKEN_ALGORITHM` (важно для параллельного прогона тестов).
    fn headers_with_alg(alg: &str) -> TokenHeaders {
        TokenHeaders {
            alg: alg.to_string(),
            kid: "kid-1".to_string(),
            typ: "JWT".to_string(),
            jku: None,
        }
    }

    /// Проверяет подпись токена ровно так же, как это делает
    /// [`JsonWebToken::from_string`]: дайджест выбирается по `alg`. Это тот же
    /// путь верификации, что и на боевом `POST /tokens/verify`, поэтому успешная
    /// проверка здесь эквивалентна прохождению round-trip выпуск→проверка.
    fn verify_signature(token: &str, alg: &str, public: &PKey<Public>) -> bool {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "токен должен состоять из трёх сегментов");

        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let signed = format!("{}.{}", parts[0], parts[1]);

        let mut verifier = match alg {
            "RS256" | "ES256" => Verifier::new(MessageDigest::sha256(), public),
            "RS384" | "ES384" => Verifier::new(MessageDigest::sha384(), public),
            "RS512" | "ES512" => Verifier::new(MessageDigest::sha512(), public),
            _ => Verifier::new_without_digest(public),
        }
        .unwrap();

        verifier
            .verify_oneshot(&signature, signed.as_bytes())
            .unwrap()
    }

    /// Round-trip выпуск→проверка для дефолтного `RS256` (регресс на JWT-13:
    /// раньше подпись ставилась без дайджеста и не проходила собственную проверку).
    #[test]
    fn sign_verify_roundtrip_rs256() {
        let (private, public) = keypair_for("RS256");
        let jwt = JsonWebToken::create_new(headers_with_alg("RS256"), sample_claims(), private);
        let token = jwt.to_string().unwrap();

        assert!(verify_signature(&token, "RS256", &public));
    }

    /// Round-trip выпуск→проверка для `ES256` (представитель семейства `ES*`).
    #[test]
    fn sign_verify_roundtrip_es256() {
        let (private, public) = keypair_for("ES256");
        let jwt = JsonWebToken::create_new(headers_with_alg("ES256"), sample_claims(), private);
        let token = jwt.to_string().unwrap();

        assert!(verify_signature(&token, "ES256", &public));
    }

    /// Round-trip для **всех** алгоритмов из [`SUPPORTED_ALGORITHMS`]: подпись,
    /// поставленная `to_string`, обязана сходиться с проверкой из `from_string`.
    /// Именно рассогласование дайджестов было багом JWT-13.
    #[test]
    fn sign_verify_roundtrip_all_supported_algorithms() {
        for &alg in SUPPORTED_ALGORITHMS {
            let (private, public) = keypair_for(alg);
            let jwt = JsonWebToken::create_new(headers_with_alg(alg), sample_claims(), private);
            let token = jwt.to_string().unwrap();

            assert!(
                verify_signature(&token, alg, &public),
                "подпись {alg} не прошла проверку тем же дайджестом (рассогласование sign/verify)"
            );
        }
    }
}
