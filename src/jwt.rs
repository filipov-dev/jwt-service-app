//! Фасад доменной логики работы с токенами.
//!
//! [`JwtManager`] связывает воедино менеджер ключей ([`KeyManager`]), хранилище
//! `jti` ([`JtiStore`]) и низкоуровневые типы токена из [`crate::models::jwt`],
//! предоставляя обработчикам два высокоуровневых метода: генерацию и проверку.

use crate::key::KeyManager;
use crate::models::jwt::{
    family_group, refresh_key, JsonWebToken, JtiStore, JwtError, RefreshRecord, TokenClaims,
    TokenHeaders,
};
use actix_web::web::Data;
use chrono::Utc;
use std::env;
use tracing::{debug, error, warn};
use uuid::Uuid;

/// Время жизни refresh-токена по умолчанию (`REFRESH_TOKEN_TTL_SECONDS`).
///
/// Тридцать суток — обычный горизонт «не просить вход заново». Ротация при
/// каждом обмене делает длинный срок безопаснее, чем он выглядит: украденный
/// токен работает лишь до первого обмена настоящим клиентом, после чего семья
/// гасится детектором.
const DEFAULT_REFRESH_TTL_SECONDS: u64 = 2_592_000;

/// Читает `u64` из переменной окружения, откатываясь на `default`.
fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

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

        let claims = TokenClaims::create_new(issuer, subject, audience, ttl, store).await?;

        let headers = TokenHeaders::create_new(jwk.kid);

        let token = JsonWebToken::create_new(headers, claims, private_key);

        token.to_string()
    }

    /// Выпускает access-токен вместе с refresh-токеном новой семьи.
    ///
    /// Возвращает пару `(access, refresh)`. `refresh` — непрозрачная случайная
    /// строка; всё, что нужно для обмена, лежит в хранилище.
    pub async fn generate_token_pair<T: JtiStore>(
        issuer: &str,
        subject: &str,
        audience: &[String],
        ttl: Option<u64>,
        key_manager: &KeyManager,
        store: Data<T>,
    ) -> Result<(String, String), JwtError> {
        let family = Uuid::new_v4().to_string();

        let access =
            Self::generate_token(issuer, subject, audience, ttl, key_manager, store.clone())
                .await?;
        Self::register_access_in_family(&access, &family, store.clone()).await?;

        let refresh = Self::issue_refresh(subject, audience, &family, store).await?;

        Ok((access, refresh))
    }

    /// Обменивает refresh-токен на новую пару access + refresh.
    ///
    /// Ротация: старый refresh помечается использованным и больше не сработает,
    /// на его место выдаётся новый — из той же семьи.
    ///
    /// **Детектор повторного использования.** Предъявление уже использованного
    /// refresh означает, что токен утёк: настоящий клиент свой экземпляр уже
    /// обменял. Отличить вора от жертвы невозможно, поэтому гасим всю семью —
    /// и выданные по ней access-токены, и остальные refresh. Расплата за ложное
    /// срабатывание (клиент потерял ответ и повторил запрос) — повторный вход,
    /// что дешевле, чем оставить вору рабочую цепочку.
    ///
    /// # Errors
    /// - [`JwtError::NotValid`] — токен неизвестен, истёк или уже использован;
    /// - [`JwtError::StoreError`] — сбой хранилища.
    pub async fn refresh_token_pair<T: JtiStore>(
        refresh_token: &str,
        issuer: &str,
        key_manager: &KeyManager,
        store: Data<T>,
    ) -> Result<(String, String), JwtError> {
        let Some(record) = store.get_refresh(refresh_token).await.map_err(|e| {
            error!("Refresh Store: {}", e);
            JwtError::StoreError
        })?
        else {
            // Вина клиента: токен неизвестен или уже истёк.
            debug!("Refresh: токен неизвестен");
            return Err(JwtError::NotValid);
        };

        let marked = store.mark_refresh_used(refresh_token).await.map_err(|e| {
            error!("Refresh Store: {}", e);
            JwtError::StoreError
        })?;

        if !marked {
            // Повторное использование — сигнал кражи, а не ошибка клиента.
            warn!("Refresh: повторное использование токена, гашу семью");
            store
                .revoke_group(&family_group(&record.family))
                .await
                .map_err(|e| {
                    error!("Refresh Store: {}", e);
                    JwtError::StoreError
                })?;
            return Err(JwtError::NotValid);
        }

        let access = Self::generate_token(
            issuer,
            &record.subject,
            &record.audience,
            None,
            key_manager,
            store.clone(),
        )
        .await?;
        Self::register_access_in_family(&access, &record.family, store.clone()).await?;

        let refresh =
            Self::issue_refresh(&record.subject, &record.audience, &record.family, store).await?;

        Ok((access, refresh))
    }

    /// Регистрирует выпущенный access-токен в группе семьи.
    ///
    /// Без этого детектор повторного использования погасил бы только
    /// refresh-цепочку, а уже выданные access-токены продолжали бы работать до
    /// своего `exp` — то есть у вора оставалось бы рабочее окно.
    async fn register_access_in_family<T: JtiStore>(
        access: &str,
        family: &str,
        store: Data<T>,
    ) -> Result<(), JwtError> {
        let claims_segment = access
            .split('.')
            .nth(1)
            .ok_or(JwtError::Broken)?
            .to_string();
        let claims = TokenClaims::from_base64(claims_segment)?;

        store
            .add_to_group(&family_group(family), &claims.jti, claims.exp as i64)
            .await
            .map_err(|e| {
                error!("Refresh Store (индекс семьи): {}", e);
                JwtError::StoreError
            })
    }

    /// Выпускает refresh-токен и регистрирует его в семье.
    ///
    /// Регистрация в группе семьи — то, благодаря чему один `revoke_group`
    /// гасит всю цепочку: там лежат и `jti` access-токенов, и ключи
    /// refresh-записей.
    async fn issue_refresh<T: JtiStore>(
        subject: &str,
        audience: &[String],
        family: &str,
        store: Data<T>,
    ) -> Result<String, JwtError> {
        let ttl = env_u64("REFRESH_TOKEN_TTL_SECONDS", DEFAULT_REFRESH_TTL_SECONDS);
        let id = Uuid::new_v4().to_string();

        let record = RefreshRecord {
            subject: subject.to_string(),
            audience: audience.to_vec(),
            family: family.to_string(),
        };

        store.store_refresh(&id, &record, ttl).await.map_err(|e| {
            error!("Refresh Store: {}", e);
            JwtError::StoreError
        })?;

        let expires_at = Utc::now().timestamp() + ttl as i64;

        store
            .add_to_group(&family_group(family), &refresh_key(&id), expires_at)
            .await
            .map_err(|e| {
                error!("Refresh Store (индекс семьи): {}", e);
                JwtError::StoreError
            })?;

        Ok(id)
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
        key_manager: &KeyManager,
        store: Data<T>,
    ) -> Result<TokenClaims, JwtError> {
        match JsonWebToken::from_string(token, issuer, audience, key_manager, store).await {
            Ok(jwt) => Ok(jwt.claims),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Тесты фасада, дополняющие интеграционные тесты HTTP-слоя.
    //!
    //! Здесь проверяются ветки, до которых через HTTP не дотянуться: сбой
    //! хранилища на конкретном шаге обмена. Ключи не нужны — все эти ветки
    //! отрабатывают до обращения к JWKS.

    use super::*;
    use crate::models::jwt::JtiError;
    use actix_web::web::Data;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    /// Хранилище, у которого известен один refresh-токен, а всё остальное падает.
    ///
    /// Позволяет довести обмен до нужного шага и уронить именно его.
    struct StoreWithRefresh {
        records: Mutex<HashMap<String, RefreshRecord>>,
        used: Mutex<Vec<String>>,
        /// Ронять ли `mark_refresh_used` (имитация сбоя хранилища на пометке).
        fail_mark: bool,
    }

    impl StoreWithRefresh {
        fn new(id: &str, fail_mark: bool) -> Self {
            let mut records = HashMap::new();
            records.insert(
                id.to_string(),
                RefreshRecord {
                    subject: "user1".to_string(),
                    audience: vec!["api1".to_string()],
                    family: "family-1".to_string(),
                },
            );

            Self {
                records: Mutex::new(records),
                used: Mutex::new(Vec::new()),
                fail_mark,
            }
        }
    }

    impl JtiStore for StoreWithRefresh {
        async fn store_jti(&self, _jti: &str, _ttl: u64) -> Result<(), JtiError> {
            Ok(())
        }

        async fn check_jti(&self, _jti: &str) -> Result<bool, JtiError> {
            Ok(true)
        }

        async fn delete_jti(&self, _jti: &str) -> Result<(), JtiError> {
            Ok(())
        }

        async fn add_to_group(
            &self,
            _group: &str,
            _jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            Ok(())
        }

        async fn revoke_group(&self, _group: &str) -> Result<u64, JtiError> {
            Ok(0)
        }

        async fn store_refresh(
            &self,
            _id: &str,
            _record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            Ok(())
        }

        async fn get_refresh(&self, id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Ok(self.records.lock().get(id).cloned())
        }

        async fn mark_refresh_used(&self, id: &str) -> Result<bool, JtiError> {
            if self.fail_mark {
                return Err(JtiError::BadConnection);
            }

            let mut used = self.used.lock();
            if used.iter().any(|u| u == id) {
                return Ok(false);
            }

            used.push(id.to_string());
            Ok(true)
        }

        async fn claim_totp_code(&self, _hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            Ok(true)
        }
    }

    #[actix_web::test]
    async fn refresh_rejects_unknown_token() {
        let store = Data::new(StoreWithRefresh::new("known", false));
        let keys = KeyManager::new("EdDSA".to_string());

        let result = JwtManager::refresh_token_pair("unknown", "issuer", &keys, store).await;

        // Именно NotValid, а не StoreError: это вина клиента, и наружу уйдёт 401.
        assert!(matches!(result, Err(JwtError::NotValid)));
    }

    #[actix_web::test]
    async fn refresh_reports_store_failure_separately() {
        // Токен найден, но пометка использования не прошла — это сбой хранилища,
        // а не невалидный токен. Разница видна снаружи: 500 против 401.
        let store = Data::new(StoreWithRefresh::new("known", true));
        let keys = KeyManager::new("EdDSA".to_string());

        let result = JwtManager::refresh_token_pair("known", "issuer", &keys, store).await;

        assert!(matches!(result, Err(JwtError::StoreError)));
    }

    #[test]
    fn refresh_ttl_falls_back_to_default() {
        // Значение по умолчанию берётся, когда переменная не задана; кривое
        // значение тоже откатывается на дефолт, а не роняет выпуск.
        std::env::remove_var("JWT_TEST_TTL");
        assert_eq!(env_u64("JWT_TEST_TTL", 42), 42);

        std::env::set_var("JWT_TEST_TTL", "не-число");
        assert_eq!(env_u64("JWT_TEST_TTL", 42), 42);

        std::env::set_var("JWT_TEST_TTL", "100");
        assert_eq!(env_u64("JWT_TEST_TTL", 42), 100);

        std::env::remove_var("JWT_TEST_TTL");
    }
}
