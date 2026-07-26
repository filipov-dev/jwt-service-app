//! Реализация хранилища `jti` поверх Redis.
//!
//! [`RedisClient`] реализует трейт [`JtiStore`]: каждый активный токен
//! представлен ключом-`jti` со значением-заглушкой и TTL, равным времени жизни
//! токена. Наличие ключа = токен активен, удаление = отзыв, истечение TTL =
//! естественное «протухание».

use redis::aio::MultiplexedConnection;
use redis::{AsyncCommands, RedisError};
use std::env;
use std::time::Instant;

use tracing::error;

use crate::metrics::record_redis_command;
use crate::models::jwt::{JtiError, JtiStore};

/// Клиент Redis. Дёшево клонируется; соединения берутся по требованию
/// (multiplexed async connection).
#[derive(Clone)]
pub struct RedisClient {
    client: redis::Client,
}

impl RedisClient {
    /// Создаёт клиент по строке подключения из `REDIS_URL`
    /// (по умолчанию `redis://redis:6379`).
    ///
    /// # Errors
    /// [`RedisError`], если URL некорректен. Само TCP-соединение открывается
    /// лениво — при первой операции.
    pub fn new() -> Result<Self, RedisError> {
        let url = env::var("REDIS_URL").unwrap_or("redis://redis:6379".into());

        let client = redis::Client::open(url)?;
        Ok(Self { client })
    }

    /// Открывает мультиплексированное async-соединение.
    ///
    /// # Errors
    /// [`JtiError::BadConnection`], если подключиться не удалось.
    async fn get_connection(&self) -> Result<MultiplexedConnection, JtiError> {
        match self.client.get_multiplexed_async_connection().await {
            Ok(c) => Ok(c),
            Err(e) => {
                // Отказ хранилища — ERROR.
                error!("Redis: не удалось открыть соединение: {}", e);
                Err(JtiError::BadConnection)
            }
        }
    }

    /// Проверяет доступность Redis командой `PING`.
    ///
    /// Используется в readiness-проверке (`GET /readyz`): открывает соединение и
    /// выполняет `PING`, ожидая ответ `PONG`.
    ///
    /// # Errors
    /// - [`JtiError::BadConnection`] — не удалось открыть соединение;
    /// - [`JtiError::WrongOperation`] — команда `PING` не выполнилась.
    #[tracing::instrument(name = "redis.ping", skip_all, err(level = "debug"))]
    pub async fn ping(&self) -> Result<(), JtiError> {
        let mut conn = self.get_connection().await?;

        let started = Instant::now();

        match redis::cmd("PING").query_async::<String>(&mut conn).await {
            Ok(_) => {
                record_redis_command("ping", true, started.elapsed());
                Ok(())
            }
            Err(e) => {
                error!("Redis: PING не выполнился: {}", e);
                record_redis_command("ping", false, started.elapsed());
                Err(JtiError::WrongOperation)
            }
        }
    }
}

impl JtiStore for RedisClient {
    /// Записывает `jti` со значением-заглушкой `1` и TTL `ttl` секунд (`SETEX`).
    #[tracing::instrument(name = "redis.store_jti", skip_all, err(level = "debug"))]
    async fn store_jti(&self, jti: &str, ttl: u64) -> Result<(), JtiError> {
        let mut conn = self.get_connection().await?;
        let started = Instant::now();

        match conn.set_ex::<&str, u8, ()>(jti, 1, ttl).await {
            Ok(_) => {
                record_redis_command("store_jti", true, started.elapsed());
                Ok(())
            }
            Err(e) => {
                error!("Redis: SETEX не выполнился: {}", e);
                record_redis_command("store_jti", false, started.elapsed());
                Err(JtiError::WrongOperation)
            }
        }
    }

    /// Проверяет существование ключа `jti` (`EXISTS`).
    #[tracing::instrument(name = "redis.check_jti", skip_all, err(level = "debug"))]
    async fn check_jti(&self, jti: &str) -> Result<bool, JtiError> {
        let mut conn = self.get_connection().await?;
        let started = Instant::now();

        match conn.exists(jti).await {
            Ok(v) => {
                record_redis_command("check_jti", true, started.elapsed());
                Ok(v)
            }
            Err(e) => {
                error!("Redis: EXISTS не выполнился: {}", e);
                record_redis_command("check_jti", false, started.elapsed());
                Err(JtiError::WrongOperation)
            }
        }
    }

    /// Удаляет ключ `jti` (`DEL`); отзыв токена. Идемпотентна.
    #[tracing::instrument(name = "redis.delete_jti", skip_all, err(level = "debug"))]
    async fn delete_jti(&self, jti: &str) -> Result<(), JtiError> {
        let mut conn = self.get_connection().await?;
        let started = Instant::now();

        match conn.del::<&str, ()>(jti).await {
            Ok(_) => {
                record_redis_command("delete_jti", true, started.elapsed());
                Ok(())
            }
            Err(e) => {
                error!("Redis: DEL не выполнился: {}", e);
                record_redis_command("delete_jti", false, started.elapsed());
                Err(JtiError::WrongOperation)
            }
        }
    }
}
