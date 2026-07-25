//! HTTP-клиент к внешнему сервису ключей `jwks-service-app`.
//!
//! [`JwkService`] инкапсулирует все обращения к сервису ключей:
//! - `GET /.well-known/jwks.json` — список публичных ключей;
//! - `GET /jwks/{id}` — конкретный ключ (с приватной частью);
//! - `POST /jwks` — создание нового ключа под заданный алгоритм.
//!
//! Базовый URL берётся из `JWKS_SERVICE_URL`.

use std::env;
use reqwest::Client;
use serde_json::json;
use thiserror::Error;
use tracing::{error, debug, info};
use crate::models::{Jwk, JwkData, Jwks};

/// Ошибки взаимодействия с сервисом ключей.
#[derive(Error, Debug)]
pub enum JwkError {
    #[error("Bad connection")]
    BadConnection,
    #[error("Bad response")]
    BadResponse,
    #[error("NotFound")]
    NotFound,
}

/// Клиент сервиса ключей на базе `reqwest`.
#[derive(Clone)]
pub struct JwkService {
    client: Client,
    /// Базовый URL сервиса (`JWKS_SERVICE_URL`).
    url: String,
}

impl JwkService {
    /// Создаёт клиент; базовый URL берётся из `JWKS_SERVICE_URL`
    /// (по умолчанию `http://jwks-service-app:8080`).
    pub fn new() -> Self {
        let url = env::var("JWKS_SERVICE_URL")
            .unwrap_or("http://jwks-service-app:8080".into());

        Self {
            client: Client::new(),
            url,
        }
    }

    /// Проверяет доступность сервиса ключей (`GET /.well-known/jwks.json`).
    ///
    /// Используется в readiness-проверке (`GET /readyz`): достаточно, что список
    /// публичных ключей успешно запросился и распарсился.
    ///
    /// # Errors
    /// - [`JwkError::BadConnection`] — сервис недоступен;
    /// - [`JwkError::BadResponse`] — некорректный ответ.
    pub async fn health_check(&self) -> Result<(), JwkError> {
        self.public_keys().await.map(|_| ())
    }

    /// Получаем все ключи
    async fn public_keys(&self) -> Result<Jwks, JwkError> {
        let url = format!("{}/.well-known/jwks.json", self.url);
        debug!("JWKS: запрашиваю публичные ключи ({})", url);

        let response = match self.client.get(&url)
            .send()
            .await {
            Ok(v) => v,
            Err(e) => {
                // Отказ внешней зависимости — ERROR.
                error!("JWKS недоступен ({}): {}", url, e);
                return Err(JwkError::BadConnection);
            }
        };

        match response.json().await {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("JWKS вернул некорректный ответ ({}): {}", url, e);
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

    /// Возвращает приватный ключ по `id`, создавая новый под алгоритм `alg`,
    /// если ключа с таким `id` нет (или `id` пуст).
    pub async fn private_key(&self, id: &str, alg: &str) -> Result<JwkData, JwkError> {
        match self.get_key(id).await {
            Ok(v) => { Ok(v) }
            _ => { self.create_key(alg).await }
        }
    }

    /// Создаёт новый ключ в сервисе под указанный алгоритм.
    ///
    /// Для `EdDSA` сервису передаётся конкретная кривая `Ed25519` (сервис ключей
    /// оперирует именем кривой, а не общим именем алгоритма).
    async fn create_key(&self, alg: &str) -> Result<JwkData, JwkError> {
        let url = format!("{}/jwks", self.url);

        let alg = if alg == "EdDSA" {  "Ed25519" } else { alg };

        debug!("JWKS: запрашиваю приватный ключ (alg={})", alg);

        let response = match self.client.post(&url)
            .json(&json!({
                "alg": alg
            }))
            .send()
            .await {
            Ok(v) => v,
            Err(e) => {
                error!("JWKS недоступен при запросе приватного ключа: {}", e);
                return Err(JwkError::BadConnection);
            }
        };

        match response.json().await {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("JWKS вернул некорректный приватный ключ: {}", e);
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