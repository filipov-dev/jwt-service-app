//! The `jti` store implemented on top of Redis.
//!
//! [`RedisClient`] implements the [`JtiStore`] trait: every active token is
//! represented by a `jti` key with a placeholder value and a TTL equal to the
//! token lifetime. The presence of the key means the token is active, deleting
//! it means revocation, and the TTL expiring is the natural way a token goes
//! stale.

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{AsyncCommands, ExistenceCheck, RedisError, SetExpiry, SetOptions};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::OnceCell;

use tracing::error;

use crate::metrics::record_redis_command;
use crate::models::jwt::{refresh_key, totp_code_key, JtiError, JtiStore, RefreshRecord};

/// Timeout waiting for a command response (`REDIS_RESPONSE_TIMEOUT_MS`).
///
/// Redis answers in fractions of a millisecond, so a whole second is already a
/// clear anomaly. Without a timeout a hung (not crashed) Redis would hold a
/// handler indefinitely.
const DEFAULT_RESPONSE_TIMEOUT_MS: u64 = 1000;

/// Connection timeout (`REDIS_CONNECT_TIMEOUT_MS`).
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 500;

/// Upper bound on the pause between reconnection attempts.
const REFRESH_MAX_DELAY_MS: u64 = 200;

/// Reads milliseconds from an environment variable, falling back to `default`.
///
/// Not fail-fast: a malformed value gives a warning and the default — a typo in
/// a timeout must not bring the service down.
fn env_millis(name: &str, default: u64) -> u64 {
    match env::var(name) {
        Err(_) => default,
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!("{name}: invalid value {raw:?}, using the default {default}");
                default
            }
        },
    }
}

/// Distinguishes a connection failure from other command errors.
///
/// This distinction used to come from a separate connection-opening stage; the
/// connection is now permanent and the kind of failure is only visible from the
/// error itself. The split is kept: [`JtiError::BadConnection`] means "the store
/// is unavailable", and it makes clear that the command itself is not at fault.
fn classify(error: &RedisError) -> JtiError {
    if error.is_timeout() || error.is_connection_dropped() || error.is_connection_refusal() {
        JtiError::BadConnection
    } else {
        JtiError::WrongOperation
    }
}

/// The Redis client on top of a [`ConnectionManager`].
///
/// The manager holds **one** multiplexed connection per process and restores it
/// itself after a drop. Cloning is cheap (an `Arc` inside) — every copy works
/// through that connection.
///
/// This used to open a new connection per command: under load that exhausted the
/// ephemeral ports (`os error 49`), and valid tokens got a `401` because
/// `check_jti` could not reach the store.
#[derive(Clone)]
pub struct RedisClient {
    client: redis::Client,
    config: ConnectionManagerConfig,
    /// The connection manager, created on first use.
    manager: Arc<OnceCell<ConnectionManager>>,
}

impl RedisClient {
    /// Creates a client from the connection string in `REDIS_URL`
    /// (`redis://redis:6379` by default).
    ///
    /// # Errors
    /// A [`RedisError`] when the URL is invalid. No connection is opened here —
    /// see [`RedisClient::connection`].
    pub fn new() -> Result<Self, RedisError> {
        let url = env::var("REDIS_URL").unwrap_or("redis://redis:6379".into());

        let client = redis::Client::open(url)?;

        // The timeouts became `Option` in redis 1.0: `None` means "no timeout",
        // and since that is now expressed explicitly the value became optional.
        // We always have a timeout, so both are `Some`.
        let config = ConnectionManagerConfig::new()
            .set_response_timeout(Some(Duration::from_millis(env_millis(
                "REDIS_RESPONSE_TIMEOUT_MS",
                DEFAULT_RESPONSE_TIMEOUT_MS,
            ))))
            .set_connection_timeout(Some(Duration::from_millis(env_millis(
                "REDIS_CONNECT_TIMEOUT_MS",
                DEFAULT_CONNECT_TIMEOUT_MS,
            ))))
            // The default is 6 attempts with exponential backoff, more than six
            // seconds in total. That is unacceptable for us: while the retries
            // run, a request handler is blocked (`/readyz` included, which must
            // answer quickly). One retry is enough to survive an instantaneous
            // drop, and a longer outage is better shown in readiness than hidden
            // behind waiting.
            .set_number_of_retries(1)
            .set_max_delay(Duration::from_millis(REFRESH_MAX_DELAY_MS));

        Ok(Self {
            client,
            config,
            manager: Arc::new(OnceCell::new()),
        })
    }

    /// Returns a connection for running a command, creating it on first use.
    ///
    /// The manager is initialised **lazily and once per process**: from then on
    /// every command goes over one multiplexed connection, which it restores
    /// itself after a drop.
    ///
    /// The laziness here is a principle rather than an inheritance: a Redis that
    /// is unavailable at startup must not bring the process down. The service
    /// comes up, `GET /readyz` honestly answers `503`, no traffic is routed to
    /// the pod — and once the store appears the connection establishes itself
    /// without a restart. A failed attempt leaves the cell empty, so the next
    /// request tries again.
    ///
    /// # Errors
    /// [`JtiError::BadConnection`] when the connection could not be established.
    async fn connection(&self) -> Result<ConnectionManager, JtiError> {
        self.manager
            .get_or_try_init(|| {
                ConnectionManager::new_with_config(self.client.clone(), self.config.clone())
            })
            .await
            .cloned()
            .map_err(|e| {
                // A store failure — ERROR.
                error!("Redis: could not open a connection: {}", e);
                JtiError::BadConnection
            })
    }
}

impl JtiStore for RedisClient {
    /// Checks that Redis is available with a `PING` command.
    ///
    /// Used by the readiness check (`GET /readyz`): it opens a connection and
    /// runs `PING`, expecting a `PONG` back.
    ///
    /// # Errors
    /// - [`JtiError::BadConnection`] — the connection could not be opened;
    /// - [`JtiError::WrongOperation`] — the `PING` command failed.
    #[tracing::instrument(name = "redis.ping", skip_all, err(level = "debug"))]
    async fn ping(&self) -> Result<(), JtiError> {
        let mut conn = self.connection().await?;

        let started = Instant::now();

        match redis::cmd("PING").query_async::<String>(&mut conn).await {
            Ok(_) => {
                record_redis_command("ping", true, started.elapsed());
                Ok(())
            }
            Err(e) => {
                error!("Redis: PING failed: {}", e);
                record_redis_command("ping", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Writes the `jti` with the placeholder value `1` and a TTL of `ttl` seconds (`SETEX`).
    #[tracing::instrument(name = "redis.store_jti", skip_all, err(level = "debug"))]
    async fn store_jti(&self, jti: &str, ttl: u64) -> Result<(), JtiError> {
        let mut conn = self.connection().await?;
        let started = Instant::now();

        match conn.set_ex::<&str, u8, ()>(jti, 1, ttl).await {
            Ok(_) => {
                record_redis_command("store_jti", true, started.elapsed());
                Ok(())
            }
            Err(e) => {
                error!("Redis: SETEX failed: {}", e);
                record_redis_command("store_jti", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Checks whether the `jti` key exists (`EXISTS`).
    #[tracing::instrument(name = "redis.check_jti", skip_all, err(level = "debug"))]
    async fn check_jti(&self, jti: &str) -> Result<bool, JtiError> {
        let mut conn = self.connection().await?;
        let started = Instant::now();

        match conn.exists(jti).await {
            Ok(v) => {
                record_redis_command("check_jti", true, started.elapsed());
                Ok(v)
            }
            Err(e) => {
                error!("Redis: EXISTS failed: {}", e);
                record_redis_command("check_jti", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Adds the `jti` to the group's ZSET with the expiry time as the score
    /// (`ZADD`).
    ///
    /// A ZSET rather than a SET: elements of a set have no TTL of their own, and
    /// expired `jti` values would pile up in the index as dead weight. With the
    /// expiry moment as the score they can be cut off by a single command (see
    /// [`RedisClient::revoke_group`]).
    ///
    /// The TTL of the group itself is extended to the lifetime of its
    /// longest-lived token: otherwise the index would outlive all of its tokens
    /// and hang around in memory.
    #[tracing::instrument(name = "redis.add_to_group", skip_all, err(level = "debug"))]
    async fn add_to_group(&self, group: &str, jti: &str, expires_at: i64) -> Result<(), JtiError> {
        let mut conn = self.connection().await?;
        let started = Instant::now();

        let result: Result<(), RedisError> = async {
            conn.zadd::<&str, i64, &str, ()>(group, jti, expires_at)
                .await?;
            conn.expire_at::<&str, ()>(group, expires_at).await?;
            Ok(())
        }
        .await;

        match result {
            Ok(()) => {
                record_redis_command("add_to_group", true, started.elapsed());
                Ok(())
            }
            Err(e) => {
                error!("Redis: ZADD into the group failed: {}", e);
                record_redis_command("add_to_group", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Revokes every token of a group.
    ///
    /// The order: cut off the expired entries by score, take the remaining `jti`
    /// values, delete them in one batch and then the group itself.
    ///
    /// There is deliberately no atomicity here: a token issued concurrently with
    /// a revocation may add its `jti` after the `ZRANGE`, and such a token
    /// survives. The window is a fraction of a millisecond, and the cost of
    /// atomicity (a Lua script or WATCH) outweighs the benefit: bulk revocation
    /// happens on compromise, and the subject's credentials are usually rotated
    /// right after.
    #[tracing::instrument(name = "redis.revoke_group", skip_all, err(level = "debug"))]
    async fn revoke_group(&self, group: &str) -> Result<u64, JtiError> {
        let mut conn = self.connection().await?;
        let started = Instant::now();

        let now = chrono::Utc::now().timestamp();

        let result: Result<u64, RedisError> = async {
            // There is no point revoking expired tokens — they are invalid anyway.
            conn.zrembyscore::<&str, &str, i64, ()>(group, "-inf", now)
                .await?;

            let jtis: Vec<String> = conn.zrange(group, 0, -1).await?;

            if !jtis.is_empty() {
                conn.del::<&Vec<String>, ()>(&jtis).await?;
            }
            conn.del::<&str, ()>(group).await?;

            Ok(jtis.len() as u64)
        }
        .await;

        match result {
            Ok(count) => {
                record_redis_command("revoke_group", true, started.elapsed());
                Ok(count)
            }
            Err(e) => {
                error!("Redis: group revocation failed: {}", e);
                record_redis_command("revoke_group", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Stores a refresh token record as a HASH with a TTL.
    #[tracing::instrument(name = "redis.store_refresh", skip_all, err(level = "debug"))]
    async fn store_refresh(
        &self,
        id: &str,
        record: &RefreshRecord,
        ttl: u64,
    ) -> Result<(), JtiError> {
        let mut conn = self.connection().await?;
        let started = Instant::now();
        let key = refresh_key(id);

        // The audience is a list while HASH values are flat; we store it as a JSON array.
        let audience = match serde_json::to_string(&record.audience) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "Redis: the refresh token audience does not serialise: {}",
                    e
                );
                return Err(JtiError::WrongOperation);
            }
        };

        let result: Result<(), RedisError> = async {
            conn.hset_multiple::<&str, &str, String, ()>(
                &key,
                &[
                    ("sub", record.subject.clone()),
                    ("aud", audience),
                    ("family", record.family.clone()),
                ],
            )
            .await?;
            conn.expire::<&str, ()>(&key, ttl as i64).await?;
            Ok(())
        }
        .await;

        match result {
            Ok(()) => {
                record_redis_command("store_refresh", true, started.elapsed());
                Ok(())
            }
            Err(e) => {
                error!("Redis: writing the refresh token failed: {}", e);
                record_redis_command("store_refresh", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Reads a refresh token record (`HGETALL`).
    #[tracing::instrument(name = "redis.get_refresh", skip_all, err(level = "debug"))]
    async fn get_refresh(&self, id: &str) -> Result<Option<RefreshRecord>, JtiError> {
        let mut conn = self.connection().await?;
        let started = Instant::now();

        let fields: Result<HashMap<String, String>, RedisError> =
            conn.hgetall(refresh_key(id)).await;

        let fields = match fields {
            Ok(v) => {
                record_redis_command("get_refresh", true, started.elapsed());
                v
            }
            Err(e) => {
                error!("Redis: reading the refresh token failed: {}", e);
                record_redis_command("get_refresh", false, started.elapsed());
                return Err(classify(&e));
            }
        };

        // An empty HASH means there is no key: it expired or was revoked.
        if fields.is_empty() {
            return Ok(None);
        }

        let (Some(subject), Some(audience), Some(family)) =
            (fields.get("sub"), fields.get("aud"), fields.get("family"))
        else {
            // The record exists but is incomplete — that should not happen; we
            // treat it as absent so as not to issue a token on junk data.
            error!("Redis: the refresh token record is incomplete");
            return Ok(None);
        };

        let audience: Vec<String> = match serde_json::from_str(audience) {
            Ok(v) => v,
            Err(e) => {
                error!("Redis: the refresh token audience does not parse: {}", e);
                return Ok(None);
            }
        };

        Ok(Some(RefreshRecord {
            subject: subject.clone(),
            audience,
            family: family.clone(),
        }))
    }

    /// Marks a refresh token as used (`HSETNX`).
    ///
    /// `HSETNX` returns `1` only when the field was not there yet — that is, the
    /// operation is atomic and there is exactly one winner. The reuse detector
    /// rests on that: a second exchange of the same token gets `false`.
    #[tracing::instrument(name = "redis.mark_refresh_used", skip_all, err(level = "debug"))]
    async fn mark_refresh_used(&self, id: &str) -> Result<bool, JtiError> {
        let mut conn = self.connection().await?;
        let started = Instant::now();

        match conn
            .hset_nx::<String, &str, u8, bool>(refresh_key(id), "used", 1)
            .await
        {
            Ok(marked) => {
                record_redis_command("mark_refresh_used", true, started.elapsed());
                Ok(marked)
            }
            Err(e) => {
                error!("Redis: marking the refresh token failed: {}", e);
                record_redis_command("mark_refresh_used", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Reserves a TOTP code through `SET NX EX`.
    ///
    /// `SET NX` returns `nil` when the key already exists — that is, the
    /// operation is atomic and there is exactly one winner. Replay protection
    /// rests on that: a second presentation of the same code gets `false`.
    ///
    /// The placeholder value is `1`: what matters is the presence of the key,
    /// and the TTL removes the record together with the code's validity window.
    #[tracing::instrument(name = "redis.claim_totp_code", skip_all, err(level = "debug"))]
    async fn claim_totp_code(&self, hash: &str, ttl: u64) -> Result<bool, JtiError> {
        let mut conn = self.connection().await?;
        let started = Instant::now();

        let options = SetOptions::default()
            .conditional_set(ExistenceCheck::NX)
            .with_expiration(SetExpiry::EX(ttl));

        match conn
            .set_options::<String, u8, Option<String>>(totp_code_key(hash), 1, options)
            .await
        {
            Ok(result) => {
                record_redis_command("claim_totp_code", true, started.elapsed());
                // `Some("OK")` means we created the key, `None` that it already existed.
                Ok(result.is_some())
            }
            Err(e) => {
                error!("Redis: reserving the TOTP code failed: {}", e);
                record_redis_command("claim_totp_code", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Deletes the `jti` key (`DEL`); a token revocation. Idempotent.
    #[tracing::instrument(name = "redis.delete_jti", skip_all, err(level = "debug"))]
    async fn delete_jti(&self, jti: &str) -> Result<(), JtiError> {
        let mut conn = self.connection().await?;
        let started = Instant::now();

        match conn.del::<&str, ()>(jti).await {
            Ok(_) => {
                record_redis_command("delete_jti", true, started.elapsed());
                Ok(())
            }
            Err(e) => {
                error!("Redis: DEL failed: {}", e);
                record_redis_command("delete_jti", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests of configuration parsing and error classification.
    //!
    //! A live Redis is not needed here: what is checked is what used to be
    //! implied by a separate connection-opening stage and is now derived from the
    //! error itself.

    use super::*;
    use std::io;

    #[test]
    fn timeout_and_refusal_mean_bad_connection() {
        let timeout = RedisError::from(io::Error::new(io::ErrorKind::TimedOut, "timed out"));
        assert!(matches!(classify(&timeout), JtiError::BadConnection));

        let refused = RedisError::from(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "connection refused",
        ));
        assert!(matches!(classify(&refused), JtiError::BadConnection));
    }

    #[test]
    fn other_errors_mean_wrong_operation() {
        // A response of the wrong type — the command failed, not the connection.
        // `UnexpectedReturnType` is what redis 1.0 renamed `TypeError` to.
        let type_error =
            RedisError::from((redis::ErrorKind::UnexpectedReturnType, "unexpected type"));
        assert!(matches!(classify(&type_error), JtiError::WrongOperation));
    }

    #[test]
    fn client_is_created_without_touching_the_network() {
        // The connection is lazy, so a client is created even for a deliberately
        // unreachable address — and that is exactly the behaviour `/readyz`
        // relies on (the service comes up and honestly reports unavailability).
        let client = RedisClient::new();
        assert!(client.is_ok());
        assert!(client.unwrap().manager.get().is_none());
    }
}
