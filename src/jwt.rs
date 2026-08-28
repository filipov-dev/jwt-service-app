//! The facade of the token domain logic.
//!
//! [`JwtManager`] ties together the key manager ([`KeyManager`]), the `jti`
//! store ([`JtiStore`]) and the low-level token types from
//! [`crate::models::jwt`], giving the handlers two high-level methods:
//! generation and verification.

use crate::key::KeyManager;
use crate::models::jwt::{
    family_group, refresh_key, JsonWebToken, JtiStore, JwtError, RefreshRecord, TokenClaims,
    TokenHeaders,
};
use actix_web::web::Data;
use chrono::Utc;
use serde_json::{Map, Value};
use std::env;
use tracing::{debug, error, warn};
use uuid::Uuid;

/// Default lifetime of a refresh token (`REFRESH_TOKEN_TTL_SECONDS`).
///
/// Thirty days is the usual horizon for "do not ask me to sign in again".
/// Rotation on every exchange makes such a long window safer than it looks: a
/// stolen token works only until the real client next exchanges it, after which
/// the detector kills the family.
const DEFAULT_REFRESH_TTL_SECONDS: u64 = 2_592_000;

/// Reads a `u64` from an environment variable, falling back to `default`.
fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Stateless: a set of associated operations on tokens.
pub struct JwtManager;

impl JwtManager {
    /// Generates and signs a new JWT.
    ///
    /// # Arguments
    /// - `issuer` — the value of the `iss` claim (taken from the `Host` header);
    /// - `subject` — the value of the `sub` claim;
    /// - `audience` — the list of recipients (`aud`); must not be empty;
    /// - `ttl` — an optional custom token lifetime (seconds); `None` means
    ///   `TOKEN_EXPIRATION_SECONDS`;
    /// - `key_manager` — the source of the private key and its `kid`;
    /// - `store` — the `jti` store (Redis) the token identifier is written to.
    ///
    /// Returns the serialised token in the `header.payload.signature` form.
    ///
    /// # Errors
    /// Returns a [`JwtError`] when the private key could not be obtained
    /// ([`JwtError::KeyError`]), the claims could not be built (an empty
    /// `audience`, for example) or the state could not be stored or checked.
    pub async fn generate_token<T: JtiStore>(
        issuer: &str,
        subject: &str,
        audience: &[String],
        ttl: Option<u64>,
        extra: Map<String, Value>,
        key_manager: &KeyManager,
        store: Data<T>,
    ) -> Result<String, JwtError> {
        let (jwk, private_key) = key_manager.get_private_key().await.map_err(|e| {
            error!("{}", e);
            JwtError::KeyError
        })?;

        let claims = TokenClaims::create_new(issuer, subject, audience, ttl, extra, store).await?;

        let headers = TokenHeaders::create_new(jwk.kid);

        let token = JsonWebToken::create_new(headers, claims, private_key);

        token.to_string()
    }

    /// Issues an access token together with a refresh token of a new family.
    ///
    /// Returns the `(access, refresh)` pair. `refresh` is an opaque random
    /// string; everything needed for an exchange lives in the store.
    pub async fn generate_token_pair<T: JtiStore>(
        issuer: &str,
        subject: &str,
        audience: &[String],
        ttl: Option<u64>,
        extra: Map<String, Value>,
        key_manager: &KeyManager,
        store: Data<T>,
    ) -> Result<(String, String), JwtError> {
        let family = Uuid::new_v4().to_string();

        let access = Self::generate_token(
            issuer,
            subject,
            audience,
            ttl,
            extra,
            key_manager,
            store.clone(),
        )
        .await?;
        Self::register_access_in_family(&access, &family, store.clone()).await?;

        let refresh = Self::issue_refresh(subject, audience, &family, store).await?;

        Ok((access, refresh))
    }

    /// Exchanges a refresh token for a new access + refresh pair.
    ///
    /// Rotation: the old refresh token is marked used and never works again, and
    /// a new one from the same family takes its place.
    ///
    /// **Reuse detector.** Presenting an already-used refresh token means the
    /// token has leaked: the real client has exchanged its copy already. There
    /// is no way to tell the thief from the victim, so we kill the whole
    /// family — the access tokens issued through it and the remaining refresh
    /// tokens. The price of a false positive (a client lost the response and
    /// retried) is one more sign-in, which is cheaper than leaving the thief a
    /// working chain.
    ///
    /// # Errors
    /// - [`JwtError::NotValid`] — the token is unknown, expired or already used;
    /// - [`JwtError::StoreError`] — a store failure.
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
            // The client's fault: the token is unknown or has already expired.
            debug!("Refresh: unknown token");
            return Err(JwtError::NotValid);
        };

        let marked = store.mark_refresh_used(refresh_token).await.map_err(|e| {
            error!("Refresh Store: {}", e);
            JwtError::StoreError
        })?;

        if !marked {
            // Reuse is a sign of theft, not a client error.
            warn!("Refresh: token reused, killing the family");
            store
                .revoke_group(&family_group(&record.family))
                .await
                .map_err(|e| {
                    error!("Refresh Store: {}", e);
                    JwtError::StoreError
                })?;
            return Err(JwtError::NotValid);
        }

        // Custom claims are NOT carried over on an exchange: we do not store
        // them in the refresh record. Keeping them would extend roles and scopes
        // granted long ago without a fresh decision about permissions. A client
        // that needs claims in the renewed token should issue a new pair through
        // `POST /tokens`.
        let access = Self::generate_token(
            issuer,
            &record.subject,
            &record.audience,
            None,
            Map::new(),
            key_manager,
            store.clone(),
        )
        .await?;
        Self::register_access_in_family(&access, &record.family, store.clone()).await?;

        let refresh =
            Self::issue_refresh(&record.subject, &record.audience, &record.family, store).await?;

        Ok((access, refresh))
    }

    /// Registers an issued access token in the family group.
    ///
    /// Without this the reuse detector would kill only the refresh chain, while
    /// the access tokens already issued would keep working until their `exp` —
    /// that is, the thief would retain a working window.
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
                error!("Refresh Store (family index): {}", e);
                JwtError::StoreError
            })
    }

    /// Issues a refresh token and registers it in the family.
    ///
    /// Registration in the family group is what lets a single `revoke_group`
    /// kill the whole chain: it holds both the `jti` values of the access tokens
    /// and the keys of the refresh records.
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
                error!("Refresh Store (family index): {}", e);
                JwtError::StoreError
            })?;

        Ok(id)
    }

    /// Verifies a token and returns its claims on success.
    ///
    /// Parsing and validation are delegated to [`JsonWebToken::from_string`]:
    /// the signature, `iss`, the presence of `audience` in `aud`, the time
    /// bounds and the presence of the `jti` in the store are all checked.
    ///
    /// # Errors
    /// Returns a [`JwtError`] for any failed check (a bad signature, an expired
    /// or revoked token, an issuer/audience mismatch and so on).
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
    //! Facade tests complementing the integration tests of the HTTP layer.
    //!
    //! What is checked here are the branches unreachable over HTTP: a store
    //! failure at a particular step of an exchange. No keys are needed — all
    //! these branches run before the JWKS is contacted.

    use super::*;
    use crate::models::jwt::JtiError;
    use actix_web::web::Data;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    /// A store that knows one refresh token and fails at everything else.
    ///
    /// It lets an exchange reach the desired step and fail exactly there.
    struct StoreWithRefresh {
        records: Mutex<HashMap<String, RefreshRecord>>,
        used: Mutex<Vec<String>>,
        /// Whether to fail `mark_refresh_used` (simulating a store failure on the mark).
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
        async fn ping(&self) -> Result<(), JtiError> {
            Ok(())
        }

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

        // NotValid rather than StoreError: this is the client's fault and 401 goes out.
        assert!(matches!(result, Err(JwtError::NotValid)));
    }

    #[actix_web::test]
    async fn refresh_reports_store_failure_separately() {
        // The token was found but the used mark did not go through — that is a
        // store failure, not an invalid token. The difference shows from the
        // outside: 500 against 401.
        let store = Data::new(StoreWithRefresh::new("known", true));
        let keys = KeyManager::new("EdDSA".to_string());

        let result = JwtManager::refresh_token_pair("known", "issuer", &keys, store).await;

        assert!(matches!(result, Err(JwtError::StoreError)));
    }

    #[test]
    fn refresh_ttl_falls_back_to_default() {
        // The default is taken when the variable is unset; a malformed value
        // also falls back to the default rather than breaking issuing.
        std::env::remove_var("JWT_TEST_TTL");
        assert_eq!(env_u64("JWT_TEST_TTL", 42), 42);

        std::env::set_var("JWT_TEST_TTL", "not-a-number");
        assert_eq!(env_u64("JWT_TEST_TTL", 42), 42);

        std::env::set_var("JWT_TEST_TTL", "100");
        assert_eq!(env_u64("JWT_TEST_TTL", 42), 100);

        std::env::remove_var("JWT_TEST_TTL");
    }
}
