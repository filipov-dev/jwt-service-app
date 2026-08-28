//! Cryptographic key management.
//!
//! [`KeyManager`] is a thin wrapper over [`crate::jwk::JwkService`] that:
//! - obtains the private key for signing (creating a new one through the service
//!   when there is none) and decodes it from PKCS#8;
//! - reconstructs an OpenSSL public key from the JWK components for signature
//!   verification, supporting RSA, EC (P-256/384/521) and EdDSA
//!   (Ed25519/Ed448).
//!
//! The manager caches the identifier of the current key (`current_key_id`)
//! behind an `RwLock` so that one key is reused across requests.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::rsa::Rsa;
use parking_lot::RwLock;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error};

use crate::jwk::JwkService;
use crate::models::{Jwk, JwkData};

/// Signature algorithms supported by the service.
///
/// Used when checking the token header ([`crate::models::jwt::TokenHeaders::is_verify`]).
pub const SUPPORTED_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA",
];

/// Errors of key handling.
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Key not found")]
    NotFound,
    #[error("Key is invalid")]
    InvalidKey,
    #[error("Key is unsupported")]
    Unsupported,
}

/// The key manager: the source of the private signing key and a factory of
/// public keys for verification. Cheap to clone (a shared `current_key_id`
/// through an `Arc`).
#[derive(Clone)]
pub struct KeyManager {
    /// Identifier of the currently active key; empty until the first call.
    current_key_id: Arc<RwLock<String>>,
    /// The key service client.
    service: JwkService,
    /// Signature algorithm (from `TOKEN_ALGORITHM`) used when creating new keys.
    algorithm: String,
}

impl KeyManager {
    /// Creates a manager for the given signature algorithm. No key is requested yet.
    pub fn new(algorithm: String) -> Self {
        Self {
            current_key_id: Arc::new(RwLock::new(String::new())),
            service: JwkService::new(),
            algorithm,
        }
    }

    /// Checks that the key service is available, for the readiness probe
    /// (`GET /readyz`).
    ///
    /// Delegates to [`JwkService::health_check`] — it requests the public keys.
    ///
    /// # Errors
    /// [`KeyError::NotFound`] — the key service is unavailable or returned an
    /// invalid response.
    pub async fn check_jwks(&self) -> Result<(), KeyError> {
        // The cause was already logged by `jwk.rs` at ERROR level — no duplicate here.
        self.service.health_check().await.map_err(|e| {
            debug!("JWKS check failed: {}", e);
            KeyError::NotFound
        })
    }

    /// Whether memory holds a JWKS snapshot still usable for verification.
    ///
    /// This answers the readiness probe's question "can we verify a token right
    /// now" when a live request to the key service failed: while the snapshot is
    /// usable, `POST /tokens/verify` works and there is no reason to take the
    /// pod out of the load balancer.
    pub fn has_servable_jwks_snapshot(&self) -> bool {
        self.service.has_servable_snapshot()
    }

    /// Obtains the data of the current key (with its private part), creating a
    /// new one through the service when needed, and updates the
    /// `current_key_id` cache.
    async fn get_jwk_data(&self) -> Result<JwkData, KeyError> {
        let key_id = self.current_key_id.read().clone();

        let jwk = match self
            .service
            .private_key(key_id.as_str(), self.algorithm.as_str())
            .await
        {
            Ok(v) => v,
            Err(e) => {
                // No duplicate: the cause was already logged by `jwk.rs` (ERROR).
                debug!("Private key not obtained: {}", e);
                return Err(KeyError::NotFound);
            }
        };

        *self.current_key_id.write() = jwk.id.clone();

        Ok(jwk)
    }

    /// Fetches a public JWK by `kid` from the key service.
    ///
    /// A method rather than an associated function: the client and the JWKS
    /// cache live in this manager's [`JwkService`]. This used to create a new
    /// `JwkService` on every call — that is, a new HTTP client with its own
    /// connection pool and a trip to the JWKS on every token verification.
    async fn get_jwk(&self, kid: &str) -> Result<Jwk, KeyError> {
        let jwk = match self.service.public_key(kid).await {
            Ok(v) => v,
            Err(e) => {
                // No duplicate: the cause was already logged by `jwk.rs` (ERROR).
                debug!("Public key by kid not obtained: {}", e);
                return Err(KeyError::NotFound);
            }
        };

        Ok(jwk)
    }

    /// Returns the current private key together with its JWK metadata.
    ///
    /// The private key is stored in the service as base64url(PKCS#8) and is
    /// decoded here into a [`PKey<Private>`].
    ///
    /// # Errors
    /// - [`KeyError::NotFound`] — the key could not be obtained or created;
    /// - [`KeyError::InvalidKey`] — the private key does not decode from
    ///   base64url or does not parse as PKCS#8.
    pub async fn get_private_key(&self) -> Result<(JwkData, PKey<Private>), KeyError> {
        let jwk = self.get_jwk_data().await?;

        let new_private_key = match URL_SAFE_NO_PAD.decode(jwk.private_key.clone()) {
            Ok(v) => v,
            Err(e) => {
                error!("{}", e);
                return Err(KeyError::InvalidKey);
            }
        };

        let private_key = match PKey::private_key_from_pkcs8(&new_private_key) {
            Ok(v) => v,
            Err(e) => {
                error!("{}", e);
                return Err(KeyError::InvalidKey);
            }
        };

        Ok((jwk, private_key))
    }

    /// Fetches and reconstructs the public key for a `kid`.
    ///
    /// The `alg` field of the JWK selects how the key is assembled: RSA from
    /// `n`/`e`, EC from `crv`/`x`/`y`, EdDSA from the raw bytes of `x`.
    ///
    /// # Errors
    /// - [`KeyError::NotFound`] — no key with that `kid` was found;
    /// - [`KeyError::Unsupported`] — the algorithm or curve is not supported;
    /// - [`KeyError::InvalidKey`] — the key components are invalid.
    pub async fn get_public_key(&self, kid: &str) -> Result<PKey<Public>, KeyError> {
        let jwk = self.get_jwk(kid).await?;

        match jwk.alg.as_str() {
            "RS256" | "RS384" | "RS512" => Self::get_public_key_from_rs(jwk),
            "ES256" | "ES384" | "ES512" => Self::get_public_key_from_es(jwk),
            "EdDSA" => Self::get_public_key_from_dsa(jwk),
            _ => Err(KeyError::Unsupported),
        }
    }

    /// Assembles an RSA public key from the components `n` (modulus) and `e` (exponent).
    fn get_public_key_from_rs(jwk: Jwk) -> Result<PKey<Public>, KeyError> {
        let jwk_n = Self::get_big_num_from_option_string(jwk.n)?;
        let jwk_e = Self::get_big_num_from_option_string(jwk.e)?;

        let rsa_public_key = match Rsa::from_public_components(jwk_n, jwk_e) {
            Ok(v) => v,
            Err(e) => {
                error!("{}", e);
                return Err(KeyError::InvalidKey);
            }
        };

        match PKey::from_rsa(rsa_public_key) {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("{}", e);
                Err(KeyError::InvalidKey)
            }
        }
    }

    /// Assembles an EC public key from the affine coordinates `x`/`y` on the
    /// curve selected by `alg` (P-256/P-384/P-521).
    ///
    /// # Errors
    /// - [`KeyError::Unsupported`] — `alg` does not map to a supported curve;
    /// - [`KeyError::InvalidKey`] — the `x`/`y` components are invalid or
    ///   OpenSSL could not assemble a key from them.
    fn get_public_key_from_es(jwk: Jwk) -> Result<PKey<Public>, KeyError> {
        let curve = match jwk.alg.as_str() {
            "ES256" => Nid::X9_62_PRIME256V1,
            "ES384" => Nid::SECP384R1,
            "ES512" => Nid::SECP521R1,
            _ => return Err(KeyError::Unsupported),
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
        point
            .set_affine_coordinates_gfp(&group, &jwk_x, &jwk_y, &mut ctx)
            .map_err(|e| {
                error!("{}", e);
                KeyError::InvalidKey
            })?;

        let ec_key_public = EcKey::from_public_key(&group, &point).map_err(|e| {
            error!("{}", e);
            KeyError::InvalidKey
        })?;

        match PKey::from_ec_key(ec_key_public) {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("{}", e);
                Err(KeyError::InvalidKey)
            }
        }
    }

    /// Assembles an EdDSA public key (Ed25519/Ed448) from the raw bytes of `x`.
    ///
    /// The curve is determined by the `crv` field.
    ///
    /// # Errors
    /// - [`KeyError::InvalidKey`] — `x` is missing or does not decode as
    ///   base64url;
    /// - [`KeyError::Unsupported`] — `crv` is neither Ed25519 nor Ed448.
    fn get_public_key_from_dsa(jwk: Jwk) -> Result<PKey<Public>, KeyError> {
        let encoded_x = jwk.x.ok_or(KeyError::InvalidKey)?;
        let jwk_x = URL_SAFE_NO_PAD.decode(encoded_x).map_err(|e| {
            error!("{}", e);
            KeyError::InvalidKey
        })?;

        let id = match jwk.crv {
            None => return Err(KeyError::InvalidKey),
            Some(crv) => match crv.as_str() {
                "Ed25519" => Id::ED25519,
                "Ed448" => Id::ED448,
                _ => return Err(KeyError::Unsupported),
            },
        };

        match PKey::public_key_from_raw_bytes(&jwk_x, id) {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("{}", e);
                Err(KeyError::InvalidKey)
            }
        }
    }

    /// Decodes a base64url string into a [`BigNum`] (for the RSA/EC components).
    ///
    /// # Errors
    /// [`KeyError::InvalidKey`] — `str` is `None`, is not valid base64url or
    /// does not parse as a [`BigNum`].
    fn get_big_num_from_option_string(str: Option<String>) -> Result<BigNum, KeyError> {
        let encoded = str.ok_or(KeyError::InvalidKey)?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
            error!("{}", e);
            KeyError::InvalidKey
        })?;

        match BigNum::from_slice(&bytes) {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("{}", e);
                Err(KeyError::InvalidKey)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests for reconstructing public keys from JWK components.
    //!
    //! The strategy: generate a real key through OpenSSL, decompose it into JWK
    //! components (base64url), feed it to the reconstructor and check that the
    //! resulting public key matches the original (`public_eq`). Neither the
    //! network nor `jwks-service-app` is involved — only the pure crypto logic
    //! is exercised.

    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    /// base64url without padding — the form the components arrive in inside a JWK.
    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// An empty JWK with the given algorithm; the component fields are filled in by the test.
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
        // An unknown `alg` for EC — no curve is selected, we expect `Unsupported`.
        let jwk = jwk("ES999");
        let result = KeyManager::get_public_key_from_es(jwk);
        assert!(matches!(result, Err(KeyError::Unsupported)));
    }

    #[test]
    fn es_rejects_missing_coordinates() {
        // `x`/`y` are missing — this used to panic on `.unwrap()`, now InvalidKey.
        let jwk = jwk("ES256");
        let result = KeyManager::get_public_key_from_es(jwk);
        assert!(matches!(result, Err(KeyError::InvalidKey)));
    }

    #[test]
    fn es_rejects_invalid_base64_coordinate() {
        // `x` is not valid base64url — we expect InvalidKey rather than a panic.
        let mut jwk = jwk("ES256");
        jwk.x = Some("!!!not-base64!!!".to_string());
        jwk.y = Some(b64(&[1, 2, 3]));

        let result = KeyManager::get_public_key_from_es(jwk);
        assert!(matches!(result, Err(KeyError::InvalidKey)));
    }

    #[test]
    fn dsa_rejects_missing_x() {
        // `x` is missing — this used to panic on `jwk.x.unwrap()`, now InvalidKey.
        let mut jwk = jwk("EdDSA");
        jwk.crv = Some("Ed25519".to_string());
        jwk.x = None;

        let result = KeyManager::get_public_key_from_dsa(jwk);
        assert!(matches!(result, Err(KeyError::InvalidKey)));
    }

    #[test]
    fn dsa_rejects_missing_crv() {
        // `x` is present and valid but `crv` is unset — we expect `InvalidKey`.
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
        // We exercise the Ed448 branch of the `crv` -> `Id` mapping (key reconstruction).
        let original = PKey::generate_ed448().unwrap();
        let raw = original.raw_public_key().unwrap();

        let mut jwk = jwk("EdDSA");
        jwk.crv = Some("Ed448".to_string());
        jwk.x = Some(b64(&raw));

        let reconstructed = KeyManager::get_public_key_from_dsa(jwk).unwrap();
        assert!(reconstructed.public_eq(&original));
    }
}
