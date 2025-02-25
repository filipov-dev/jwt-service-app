use std::env;
use redis::{AsyncCommands, RedisError};
use redis::aio::MultiplexedConnection;
use tracing::log::error;
use crate::models::jwt::{JtiError, JtiStore};

#[derive(Clone)]
pub struct RedisClient {
    client: redis::Client,
}

impl RedisClient {
    pub fn new() -> Result<Self, RedisError> {
        let url = env::var("REDIS_URL").unwrap_or("redis://redis:6379".into());

        let client = redis::Client::open(url)?;
        Ok(Self { client })
    }

    async fn get_connection(&self) -> Result<MultiplexedConnection, JtiError> {
        match self.client.get_multiplexed_async_connection().await {
            Ok(c) => { Ok(c) }
            Err(e) => {
                error!("{}", e);
                Err(JtiError::BadConnection)
            }
        }
    }
}

impl JtiStore for RedisClient {
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