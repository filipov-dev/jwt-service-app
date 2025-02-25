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

pub trait JtiStore where Self: Sized {
    async fn store_jti(&self, jti: &str, ttl: u64) -> Result<(), JtiError>;
    async fn check_jti(&self, jti: &str) -> Result<bool, JtiError>;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    pub nbf: usize,
    pub jti: String,
}

impl TokenClaims {
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

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn to_base64(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.to_json())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenHeaders {
    alg: String,
    kid: String,
    typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jku: Option<String>,
}

impl TokenHeaders {
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

    pub fn from_base64(str: String) -> Self {
        let json = BASE64_URL_SAFE_NO_PAD.decode(str).unwrap();

        serde_json::from_str(&*String::from_utf8(json).unwrap()).unwrap()
    }

    pub fn is_verify(&self) -> bool {
        let jku = match env::var("TOKEN_JKU") {
            Ok(v) => { Some(v) }
            Err(_) => { None }
        };

        SUPPORTED_ALGORITHMS.contains(&self.alg.as_str()) &&
            self.jku == jku &&
            self.typ == "JWT"
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn to_base64(&self) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(self.to_json())
    }
}

#[derive(Debug, Clone)]
pub struct JsonWebToken<T> {
    pub headers: TokenHeaders,
    pub claims: TokenClaims,
    key: PKey<T>,
}

impl JsonWebToken<Private> {
    pub fn create_new(headers: TokenHeaders, claims: TokenClaims, key: PKey<Private>) -> Self {
        Self {
            headers,
            claims,
            key,
        }
    }

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