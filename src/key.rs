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
    /// # Errors
    /// - [`KeyError::Unsupported`] — `alg` не соответствует поддерживаемой кривой;
    /// - [`KeyError::InvalidKey`] — компоненты `x`/`y` некорректны или OpenSSL не
    ///   смог собрать ключ из них.
    fn get_public_key_from_es(jwk: Jwk) -> Result<PKey<Public>, KeyError> {
        let curve = match jwk.alg.as_str() {
            "ES256" => { Nid::X9_62_PRIME256V1 }
            "ES384" => { Nid::SECP384R1 }
            "ES512" => { Nid::SECP521R1 }
            _ => { return Err(KeyError::Unsupported) }
        };

        let group = EcGroup::from_curve_name(curve).map_err(|e| {
            error!("{}", e);
            KeyError::InvalidKey
        })?;

        let jwk_x = Self::get_big_num_from_option_string(jwk.x)?;
        let jwk_y = Self::get_big_num_from_option_string(jwk.y)?;

        let mut ctx = BigNumContext::new().map_err(|e| {
            error!("{}", e);
            KeyError::InvalidKey
        })?;
        let mut point = EcPoint::new(&group).map_err(|e| {
            error!("{}", e);
            KeyError::InvalidKey
        })?;
        point.set_affine_coordinates_gfp(&group, &jwk_x, &jwk_y, &mut ctx)
            .map_err(|e| {
                error!("{}", e);
                KeyError::InvalidKey
            })?;

        let ec_key_public = EcKey::from_public_key(&group, &point).map_err(|e| {
            error!("{}", e);
            KeyError::InvalidKey
        })?;

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
    /// # Errors
    /// - [`KeyError::InvalidKey`] — `x` отсутствует или не декодируется как
    ///   base64url;
    /// - [`KeyError::Unsupported`] — `crv` не является Ed25519/Ed448.
    fn get_public_key_from_dsa(jwk: Jwk) -> Result<PKey<Public>, KeyError> {
        let encoded_x = jwk.x.ok_or(KeyError::InvalidKey)?;
        let jwk_x = URL_SAFE_NO_PAD.decode(encoded_x).map_err(|e| {
            error!("{}", e);
            KeyError::InvalidKey
        })?;

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
    /// # Errors
    /// [`KeyError::InvalidKey`] — `str` равен `None`, не является корректным
    /// base64url или не парсится как [`BigNum`].
    fn get_big_num_from_option_string(str: Option<String>) -> Result<BigNum, KeyError> {
        let encoded = str.ok_or(KeyError::InvalidKey)?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
            error!("{}", e);
            KeyError::InvalidKey
        })?;

        match BigNum::from_slice(&bytes) {
            Ok(v) => { Ok(v) }
            Err(e) => {
                error!("{}", e);
                Err(KeyError::InvalidKey)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Тесты реконструкции публичных ключей из компонентов JWK.
    //!
    //! Стратегия: генерируем настоящий ключ через OpenSSL, раскладываем его на
    //! компоненты JWK (base64url), скармливаем реконструктору и убеждаемся, что
    //! получившийся публичный ключ совпадает с исходным (`public_eq`). Сеть и
    //! `jwks-service-app` не задействуются — проверяется только чистая крипто-логика.

    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    /// base64url без паддинга — формат, в котором компоненты приходят в JWK.
    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Пустой JWK с заданным алгоритмом; поля-компоненты заполняются в тесте.
    fn jwk(alg: &str) -> Jwk {
        Jwk {
            kty: String::new(),
            alg: alg.to_string(),
            kid: "test-kid".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
        }
    }

    #[test]
    fn reconstructs_rsa_public_key() {
        let rsa = Rsa::generate(2048).unwrap();
        let n = b64(&rsa.n().to_vec());
        let e = b64(&rsa.e().to_vec());
        let original = PKey::from_rsa(rsa).unwrap();

        let mut jwk = jwk("RS256");
        jwk.kty = "RSA".to_string();
        jwk.n = Some(n);
        jwk.e = Some(e);

        let reconstructed = KeyManager::get_public_key_from_rs(jwk).unwrap();
        assert!(reconstructed.public_eq(&original));
    }

    #[test]
    fn reconstructs_ec_public_key_es256() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();

        let mut ctx = BigNumContext::new().unwrap();
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
        ec.public_key()
            .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
            .unwrap();

        let original = PKey::from_ec_key(ec).unwrap();

        let mut jwk = jwk("ES256");
        jwk.kty = "EC".to_string();
        jwk.crv = Some("P-256".to_string());
        jwk.x = Some(b64(&x.to_vec()));
        jwk.y = Some(b64(&y.to_vec()));

        let reconstructed = KeyManager::get_public_key_from_es(jwk).unwrap();
        assert!(reconstructed.public_eq(&original));
    }

    #[test]
    fn reconstructs_eddsa_public_key_ed25519() {
        let original = PKey::generate_ed25519().unwrap();
        let raw = original.raw_public_key().unwrap();

        let mut jwk = jwk("EdDSA");
        jwk.kty = "OKP".to_string();
        jwk.crv = Some("Ed25519".to_string());
        jwk.x = Some(b64(&raw));

        let reconstructed = KeyManager::get_public_key_from_dsa(jwk).unwrap();
        assert!(reconstructed.public_eq(&original));
    }

    #[test]
    fn es_rejects_unsupported_curve() {
        // Неизвестный `alg` для EC — кривая не выбирается, ждём `Unsupported`.
        let jwk = jwk("ES999");
        let result = KeyManager::get_public_key_from_es(jwk);
        assert!(matches!(result, Err(KeyError::Unsupported)));
    }

    #[test]
    fn es_rejects_missing_coordinates() {
        // `x`/`y` отсутствуют — раньше был бы panic на `.unwrap()`, теперь InvalidKey.
        let jwk = jwk("ES256");
        let result = KeyManager::get_public_key_from_es(jwk);
        assert!(matches!(result, Err(KeyError::InvalidKey)));
    }

    #[test]
    fn es_rejects_invalid_base64_coordinate() {
        // `x` невалиден как base64url — ждём InvalidKey вместо паники.
        let mut jwk = jwk("ES256");
        jwk.x = Some("!!!not-base64!!!".to_string());
        jwk.y = Some(b64(&[1, 2, 3]));

        let result = KeyManager::get_public_key_from_es(jwk);
        assert!(matches!(result, Err(KeyError::InvalidKey)));
    }

    #[test]
    fn dsa_rejects_missing_x() {
        // `x` отсутствует — раньше был бы panic на `jwk.x.unwrap()`, теперь InvalidKey.
        let mut jwk = jwk("EdDSA");
        jwk.crv = Some("Ed25519".to_string());
        jwk.x = None;

        let result = KeyManager::get_public_key_from_dsa(jwk);
        assert!(matches!(result, Err(KeyError::InvalidKey)));
    }

    #[test]
    fn dsa_rejects_missing_crv() {
        // `x` присутствует и валиден, но `crv` не задан — ждём `InvalidKey`.
        let raw = PKey::generate_ed25519().unwrap().raw_public_key().unwrap();
        let mut jwk = jwk("EdDSA");
        jwk.x = Some(b64(&raw));
        jwk.crv = None;

        let result = KeyManager::get_public_key_from_dsa(jwk);
        assert!(matches!(result, Err(KeyError::InvalidKey)));
    }

    #[test]
    fn dsa_rejects_unsupported_crv() {
        let raw = PKey::generate_ed25519().unwrap().raw_public_key().unwrap();
        let mut jwk = jwk("EdDSA");
        jwk.x = Some(b64(&raw));
        jwk.crv = Some("Ed99999".to_string());

        let result = KeyManager::get_public_key_from_dsa(jwk);
        assert!(matches!(result, Err(KeyError::Unsupported)));
    }

    #[test]
    fn ed448_id_is_recognised() {
        // Проверяем ветку Ed448 в маппинге `crv` -> `Id` (реконструкция ключа).
        let original = PKey::generate_ed448().unwrap();
        let raw = original.raw_public_key().unwrap();

        let mut jwk = jwk("EdDSA");
        jwk.crv = Some("Ed448".to_string());
        jwk.x = Some(b64(&raw));

        let reconstructed = KeyManager::get_public_key_from_dsa(jwk).unwrap();
        assert!(reconstructed.public_eq(&original));
    }
}
