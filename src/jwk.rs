//! Реализация методов работы с JWK сервисом

use std::env;
use reqwest::Client;
use serde_json::json;
use thiserror::Error;
use tracing::{error, debug, info};
use crate::models::{Jwk, JwkData, Jwks};

#[derive(Error, Debug)]
pub enum JwkError {
    #[error("Bad connection")]
    BadConnection,
    #[error("Bad response")]
    BadResponse,
    #[error("NotFound")]
    NotFound,
}

#[derive(Clone)]
pub struct JwkService {
    client: Client,
    url: String,
}

impl JwkService {
    pub fn new() -> Self {
        let url = env::var("JWKS_SERVICE_URL")
            .unwrap_or("http://jwks-service-app:8080".into());

        Self {
            client: Client::new(),
            url,
        }
    }

    /// Получаем все ключи
    async fn public_keys(&self) -> Result<Jwks, JwkError> {
        let url = format!("{}/.well-known/jwks.json", self.url);
        let response = match self.client.get(&url)
            .send()
            .await {
            Ok(v) => v,
            Err(e) => {
                error!("{}", e);
                return Err(JwkError::BadConnection);
            }
        };

        match response.json().await {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("{}", e);
                Err(JwkError::BadResponse)
            }
        }
    }

    /// Получаем ключ
    pub async fn public_key(&self, kid: &str) -> Result<Jwk, JwkError> {
        let jwks = self.public_keys().await?;

        for jwk in jwks.keys.iter() {
            if jwk.kid == kid {
                return Ok(Jwk {
                    kty: jwk.kty.clone(),
                    alg: jwk.alg.clone(),
                    kid: jwk.kid.clone(),
                    crv: jwk.crv.clone(),
                    x: jwk.x.clone(),
                    y: jwk.y.clone(),
                    n: jwk.n.clone(),
                    e: jwk.e.clone(),
                });
            }
        }

        Err(JwkError::NotFound)
    }

    /// Получаем, либо создаем ключ
    pub async fn private_key(&self, id: &str, alg: &str) -> Result<JwkData, JwkError> {
        match self.get_key(id).await {
            Ok(v) => { Ok(v) }
            _ => { self.create_key(alg).await }
        }
    }

    /// Создаем новый ключ в сервисе
    async fn create_key(&self, alg: &str) -> Result<JwkData, JwkError> {
        let url = format!("{}/jwks", self.url);

        let alg = if alg == "EdDSA" {  "Ed25519" } else { alg };

        let response = match self.client.post(&url)
            .json(&json!({
                "alg": alg
            }))
            .send()
            .await {
            Ok(v) => v,
            Err(e) => {
                error!("{}", e);
                return Err(JwkError::BadConnection);
            }
        };

        match response.json().await {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("{}", e);
                Err(JwkError::BadResponse)
            }
        }
    }

    /// Получаем ключ из сервиса
    async fn get_key(&self, id: &str) -> Result<JwkData, JwkError> {
        let url = format!("{}/jwks/{}", self.url, id);

        let response = match self.client.get(&url).send().await {
            Ok(v) => v,
            Err(e) => {
                error!("{}", e);
                return Err(JwkError::BadConnection);
            }
        };

        if !response.status().is_success() {
            return Err(JwkError::NotFound);
        }

        match response.json().await {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("{}", e);
                Err(JwkError::BadResponse)
            }
        }
    }
}