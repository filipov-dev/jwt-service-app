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

pub const SUPPORTED_ALGORITHMS: &[&str] = &["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"];

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

#[derive(Clone)]
pub struct KeyManager {
    current_key_id: Arc<RwLock<String>>,
    service: JwkService,
    algorithm: String,
}

impl KeyManager {
    pub fn new(algorithm: String) -> Self {
        Self {
            current_key_id: Arc::new(RwLock::new(String::new())),
            service: JwkService::new(),
            algorithm,
        }
    }

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

    pub async fn get_public_key(kid: &str) -> Result<PKey<Public>, KeyError> {
        let jwk = Self::get_jwk(kid).await?;

        match jwk.alg.as_str() {
            "RS256" | "RS384" | "RS512" => Self::get_public_key_from_rs(jwk),
            "ES256" | "ES384" | "ES512" => Self::get_public_key_from_es(jwk),
            "EdDSA" => Self::get_public_key_from_dsa(jwk),
            _ => Err(KeyError::Unsupported)
        }
    }

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
