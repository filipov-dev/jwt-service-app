//! Реализация хранилища `jti` поверх Redis.
//!
//! [`RedisClient`] реализует трейт [`JtiStore`]: каждый активный токен
//! представлен ключом-`jti` со значением-заглушкой и TTL, равным времени жизни
//! токена. Наличие ключа = токен активен, удаление = отзыв, истечение TTL =
//! естественное «протухание».

use std::env;
use redis::{AsyncCommands, RedisError};
use redis::aio::MultiplexedConnection;
use tracing::error;
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
            Ok(c) => { Ok(c) }
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
    pub async fn ping(&self) -> Result<(), JtiError> {
        let mut conn = self.get_connection().await?;

        match redis::cmd("PING").query_async::<String>(&mut conn).await {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Redis: PING не выполнился: {}", e);
                Err(JtiError::WrongOperation)
            }
        }
    }
}

impl JtiStore for RedisClient {
    /// Записывает `jti` со значением-заглушкой `1` и TTL `ttl` секунд (`SETEX`).
    async fn store_jti(&self, jti: &str, ttl: u64) -> Result<(), JtiError> {
        let mut conn = self.get_connection().await?;

        match conn.set_ex::<&str, u8, ()>(jti, 1, ttl).await {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("{}", e);
                Err(JtiError::WrongOperation)
            },
        }
    }

    /// Проверяет существование ключа `jti` (`EXISTS`).
    async fn check_jti(&self, jti: &str) -> Result<bool, JtiError> {
        let mut conn = self.get_connection().await?;

        match conn.exists(jti).await {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("{}", e);
                Err(JtiError::WrongOperation)
            },
        }
    }

    /// Удаляет ключ `jti` (`DEL`); отзыв токена. Идемпотентна.
    async fn delete_jti(&self, jti: &str) -> Result<(), JtiError> {
        let mut conn = self.get_connection().await?;

        match conn.del::<&str, ()>(jti).await {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("{}", e);
                Err(JtiError::WrongOperation)
            },
        }
    }
}