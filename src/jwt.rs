//! Фасад доменной логики работы с токенами.
//!
//! [`JwtManager`] связывает воедино менеджер ключей ([`KeyManager`]), хранилище
//! `jti` ([`JtiStore`]) и низкоуровневые типы токена из [`crate::models::jwt`],
//! предоставляя обработчикам два высокоуровневых метода: генерацию и проверку.

use actix_web::web::Data;
use tracing::error;
use crate::models::jwt::{JsonWebToken, JtiStore, JwtError, TokenClaims, TokenHeaders};
use crate::key::KeyManager;

/// Без состояния: набор ассоциированных операций над токенами.
pub struct JwtManager;

impl JwtManager {
    /// Генерирует и подписывает новый JWT.
    ///
    /// # Аргументы
    /// - `issuer` — значение claim `iss` (берётся из заголовка `Host`);
    /// - `subject` — значение claim `sub`;
    /// - `audience` — список получателей (`aud`); не должен быть пустым;
    /// - `ttl` — необязательное кастомное время жизни токена (секунды); при
    ///   `None` берётся `TOKEN_EXPIRATION_SECONDS`;
    /// - `key_manager` — источник приватного ключа и его `kid`;
    /// - `store` — хранилище `jti` (Redis), куда пишется идентификатор токена.
    ///
    /// Возвращает сериализованный токен в формате `header.payload.signature`.
    ///
    /// # Errors
    /// Возвращает [`JwtError`], если не удалось получить приватный ключ
    /// ([`JwtError::KeyError`]), сформировать claims (например, пустой `audience`)
    /// или сохранить/проверить состояние в хранилище.
    pub async fn generate_token<T: JtiStore>(
        issuer: &str,
        subject: &str,
        audience: &[String],
        ttl: Option<u64>,
        key_manager: &KeyManager,
        store: Data<T>,
    ) -> Result<String, JwtError> {
        let (jwk, private_key) = key_manager.get_private_key().await.map_err(|e| {
            error!("{}", e);
            JwtError::KeyError
        })?;

        let claims = TokenClaims::create_new(
            issuer,
            subject,
            audience,
            ttl,
            store,
        ).await?;

        let headers = TokenHeaders::create_new(jwk.kid);

        let token = JsonWebToken::create_new(
            headers,
            claims,
            private_key,
        );

        token.to_string()
    }

    /// Проверяет токен и возвращает его claims при успехе.
    ///
    /// Делегирует разбор и валидацию [`JsonWebToken::from_string`]: проверяются
    /// подпись, `iss`, вхождение `audience` в `aud`, временные границы и наличие
    /// `jti` в хранилище.
    ///
    /// # Errors
    /// Возвращает [`JwtError`] при любой неуспешной проверке (плохая подпись,
    /// истёкший/отозванный токен, несовпадение issuer/audience и т.п.).
    pub async fn verify_token<T: JtiStore>(
        token: &str,
        issuer: &str,
        audience: &str,
        store: Data<T>,
    ) -> Result<TokenClaims, JwtError> {
        match JsonWebToken::from_string(token, issuer, audience, store).await {
            Ok(jwt) => Ok(jwt.claims),
            Err(e) => Err(e),
        }
    }
}