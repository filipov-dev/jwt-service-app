//! Управление криптографическими ключами.
//!
//! [`KeyManager`] — тонкая обёртка над [`crate::jwk::JwkService`], которая:
//! - получает приватный ключ для подписи (создавая новый через сервис, если
//!   текущего нет) и декодирует его из PKCS#8;
//! - реконструирует публичный ключ OpenSSL из компонентов JWK для проверки
//!   подписи, поддерживая RSA, EC (P-256/384/521) и EdDSA (Ed25519/Ed448).
//!
//! Менеджер кэширует идентификатор текущего ключа (`current_key_id`) под
//! `RwLock`, чтобы переиспользовать один ключ между запросами.

use parking_lot::RwLock;
use serde_json::json;
use std::sync::Arc;
use base64::{Engine};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::rsa::Rsa;
use thiserror::Error;
use tracing::{error, info};

use crate::jwk::JwkService;
use crate::models::{Jwk, JwkData};

/// Алгоритмы подписи, поддерживаемые сервисом.
///
/// Используется при проверке заголовка токена ([`crate::models::jwt::TokenHeaders::is_verify`]).
pub const SUPPORTED_ALGORITHMS: &[&str] = &["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"];

/// Ошибки работы с ключами.
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Key not found")]
    NotFound,
    #[error("Key generation failed")]
    GenerationFailed,
    #[error("Key is invalid")]
    InvalidKey,
    #[error("Key is unsupported")]
    Unsupported,
}

/// Менеджер ключей: источник приватного ключа для подписи и фабрика публичных
/// ключей для проверки. Дёшево клонируется (общий `current_key_id` через `Arc`).
#[derive(Clone)]
pub struct KeyManager {
    /// Идентификатор текущего активного ключа; пуст до первого обращения.
    current_key_id: Arc<RwLock<String>>,
    /// Клиент сервиса ключей.
    service: JwkService,
    /// Алгоритм подписи (из `TOKEN_ALGORITHM`), с которым создаются новые ключи.
    algorithm: String,
}

impl KeyManager {
    /// Создаёт менеджер для указанного алгоритма подписи. Ключ ещё не запрошен.
    pub fn new(algorithm: String) -> Self {
        Self {
            current_key_id: Arc::new(RwLock::new(String::new())),
            service: JwkService::new(),
            algorithm,
        }
    }

    /// Получает данные текущего ключа (с приватной частью), при необходимости
    /// создавая новый через сервис, и обновляет кэш `current_key_id`.
    async fn get_jwk_data(&self) -> Result<JwkData, KeyError> {
        let key_id = self.current_key_id.read().clone();

        let jwk = match self.service.private_key(
            key_id.as_str(),
            self.algorithm.as_str()
        ).await {
            Ok(v) => { v }
            Err(e) => {
                error!("{}", e);
                return Err(KeyError::NotFound)
            }
        };

        *self.current_key_id.write() = jwk.id.clone();

        Ok(jwk)
    }

    /// Получает публичный JWK по `kid` из сервиса ключей.
    async fn get_jwk(kid: &str) -> Result<Jwk, KeyError> {
        let service = JwkService::new();

        let jwk = match service.public_key(kid).await {
            Ok(v) => { v }
            Err(e) => {
                error!("{}", e);
                return Err(KeyError::NotFound)
            }
        };

        Ok(jwk)
    }

    /// Возвращает текущий приватный ключ вместе с его метаданными JWK.
    ///
    /// Приватный ключ хранится в сервисе как base64url(PKCS#8) и здесь
    /// декодируется в [`PKey<Private>`].
    ///
    /// # Errors
    /// - [`KeyError::NotFound`] — не удалось получить/создать ключ;
    /// - [`KeyError::InvalidKey`] — приватный ключ не декодируется из base64url
    ///   или не парсится как PKCS#8.
    pub async fn get_private_key(&self) -> Result<(JwkData, PKey<Private>), KeyError> {
        let jwk = self.get_jwk_data().await?;

        let new_private_key = match URL_SAFE_NO_PAD.decode(jwk.private_key.clone()) {
            Ok(v) => { v }
            Err(e) => {
                error!("{}", e);
                return Err(KeyError::InvalidKey)
            }
        };

        let private_key = match PKey::private_key_from_pkcs8(&*new_private_key) {
            Ok(v) => { v }
            Err(e) => {
                error!("{}", e);
                return Err(KeyError::InvalidKey)
            }
        };

        Ok((jwk, private_key))
    }

    /// Получает и реконструирует публичный ключ по `kid`.
    ///
    /// По полю `alg` из JWK выбирается способ сборки ключа: RSA — из `n`/`e`,
    /// EC — из `crv`/`x`/`y`, EdDSA — из сырых байт `x`.
    ///
    /// # Errors
    /// - [`KeyError::NotFound`] — ключ с таким `kid` не найден;
    /// - [`KeyError::Unsupported`] — алгоритм/кривая не поддерживается;
    /// - [`KeyError::InvalidKey`] — компоненты ключа некорректны.
    pub async fn get_public_key(kid: &str) -> Result<PKey<Public>, KeyError> {
        let jwk = Self::get_jwk(kid).await?;

        match jwk.alg.as_str() {
            "RS256" | "RS384" | "RS512" => Self::get_public_key_from_rs(jwk),
            "ES256" | "ES384" | "ES512" => Self::get_public_key_from_es(jwk),
            "EdDSA" => Self::get_public_key_from_dsa(jwk),
            _ => Err(KeyError::Unsupported)
        }
    }

    /// Собирает RSA-публичный ключ из компонентов `n` (модуль) и `e` (экспонента).
    fn get_public_key_from_rs(jwk: Jwk) -> Result<PKey<Public>, KeyError> {
        let jwk_n = Self::get_big_num_from_option_string(jwk.n)?;
        let jwk_e = Self::get_big_num_from_option_string(jwk.e)?;

        let rsa_public_key = match Rsa::from_public_components(jwk_n, jwk_e) {
            Ok(v) => { v }
            Err(e) => {
                error!("{}", e);
                return Err(KeyError::InvalidKey)
            }
        };

        match PKey::from_rsa(rsa_public_key) {
            Ok(v) => { Ok(v) }
            Err(e) => {
                error!("{}", e);
                Err(KeyError::InvalidKey)
            }
        }
    }

    /// Собирает EC-публичный ключ из аффинных координат `x`/`y` на кривой,
    /// выбранной по `alg` (P-256/P-384/P-521).
    ///
    /// # Panics
    /// Текущая реализация паникует при ошибках OpenSSL (создание группы/точки,
    /// установка координат) — используются `.unwrap()`.
    fn get_public_key_from_es(jwk: Jwk) -> Result<PKey<Public>, KeyError> {
        let curve = match jwk.alg.as_str() {
            "ES256" => { Nid::X9_62_PRIME256V1 }
            "ES384" => { Nid::SECP384R1 }
            "ES512" => { Nid::SECP521R1 }
            _ => { return Err(KeyError::Unsupported) }
        };

        let group = EcGroup::from_curve_name(curve).unwrap();

        let jwk_x = Self::get_big_num_from_option_string(jwk.x)?;
        let jwk_y = Self::get_big_num_from_option_string(jwk.y)?;

        let mut ctx = BigNumContext::new().unwrap();
        let mut point = EcPoint::new(&group).unwrap();
        point.set_affine_coordinates_gfp(&group, &jwk_x, &jwk_y, &mut ctx).unwrap();

        let ec_key_public = EcKey::from_public_key(&group, &point).unwrap();

        match PKey::from_ec_key(ec_key_public) {
            Ok(v) => { Ok(v) }
            Err(e) => {
                error!("{}", e);
                Err(KeyError::InvalidKey)
            }
        }
    }

    /// Собирает EdDSA-публичный ключ (Ed25519/Ed448) из сырых байт `x`.
    ///
    /// Кривая определяется полем `crv`.
    ///
    /// # Panics
    /// Паникует, если `x` отсутствует или некорректен как base64url (`.unwrap()`).
    fn get_public_key_from_dsa(jwk: Jwk) -> Result<PKey<Public>, KeyError> {
        let jwk_x = &*URL_SAFE_NO_PAD.decode(jwk.x.unwrap()).unwrap();

        let id = match jwk.crv {
            None => { return Err(KeyError::InvalidKey) }
            Some(crv) => {
                match crv.as_str() {
                    "Ed25519" => Id::ED25519,
                    "Ed448" => Id::ED448,
                    _ => return Err(KeyError::Unsupported)
                }
            }
        };

        match PKey::public_key_from_raw_bytes(&jwk_x, id) {
            Ok(v) => { Ok(v) }
            Err(e) => {
                error!("{}", e);
                Err(KeyError::InvalidKey)
            }
        }
    }

    /// Декодирует base64url-строку в [`BigNum`] (для компонентов RSA/EC).
    ///
    /// # Panics
    /// Паникует, если `str` — `None` или не является корректным base64url.
    fn get_big_num_from_option_string(str: Option<String>) -> Result<BigNum, KeyError> {
        match BigNum::from_slice(
            &*URL_SAFE_NO_PAD.decode(str.unwrap()).unwrap()
        ) {
            Ok(v) => { Ok(v) }
            Err(e) => {
                error!("{}", e);
                Err(KeyError::InvalidKey)
            }
        }
    }
}
