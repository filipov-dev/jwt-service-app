//! Реализация хранилища `jti` поверх Redis.
//!
//! [`RedisClient`] реализует трейт [`JtiStore`]: каждый активный токен
//! представлен ключом-`jti` со значением-заглушкой и TTL, равным времени жизни
//! токена. Наличие ключа = токен активен, удаление = отзыв, истечение TTL =
//! естественное «протухание».

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{AsyncCommands, RedisError};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::OnceCell;

use tracing::error;

use crate::metrics::record_redis_command;
use crate::models::jwt::{refresh_key, JtiError, JtiStore, RefreshRecord};

/// Таймаут ожидания ответа на команду (`REDIS_RESPONSE_TIMEOUT_MS`).
///
/// Redis отвечает за доли миллисекунды, так что секунда — это уже явная
/// аномалия. Без таймаута зависший (не упавший) Redis удерживал бы обработчик
/// неограниченно долго.
const DEFAULT_RESPONSE_TIMEOUT_MS: u64 = 1000;

/// Таймаут установки соединения (`REDIS_CONNECT_TIMEOUT_MS`).
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 500;

/// Потолок паузы между попытками переподключения.
const REFRESH_MAX_DELAY_MS: u64 = 200;

/// Читает миллисекунды из переменной окружения, откатываясь на `default`.
///
/// Не fail-fast: кривое значение даёт предупреждение и дефолт — опечатка в
/// таймауте не должна ронять сервис.
fn env_millis(name: &str, default: u64) -> u64 {
    match env::var(name) {
        Err(_) => default,
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!("{name}: некорректное значение {raw:?}, беру дефолт {default}");
                default
            }
        },
    }
}

/// Различает отказ соединения и прочие ошибки команды.
///
/// Прежде это различие давала отдельная стадия открытия соединения; теперь
/// соединение постоянное, и тип сбоя виден только по самой ошибке. Деление
/// сохраняем: [`JtiError::BadConnection`] означает «хранилище недоступно», и по
/// нему видно, что дело не в самой команде.
fn classify(error: &RedisError) -> JtiError {
    if error.is_timeout() || error.is_connection_dropped() || error.is_connection_refusal() {
        JtiError::BadConnection
    } else {
        JtiError::WrongOperation
    }
}

/// Клиент Redis поверх [`ConnectionManager`].
///
/// Менеджер держит **одно** мультиплексированное соединение на процесс и сам
/// восстанавливает его после обрыва. Клонирование дёшево (внутри `Arc`) — все
/// копии работают через это соединение.
///
/// Раньше здесь на каждую команду открывалось новое соединение: под нагрузкой
/// это исчерпывало эфемерные порты (`os error 49`), и валидные токены получали
/// `401`, потому что `check_jti` не мог достучаться до хранилища.
#[derive(Clone)]
pub struct RedisClient {
    client: redis::Client,
    config: ConnectionManagerConfig,
    /// Менеджер соединения, создаваемый при первом обращении.
    manager: Arc<OnceCell<ConnectionManager>>,
}

impl RedisClient {
    /// Создаёт клиент по строке подключения из `REDIS_URL`
    /// (по умолчанию `redis://redis:6379`).
    ///
    /// # Errors
    /// [`RedisError`], если URL некорректен. Соединение здесь не открывается —
    /// см. [`RedisClient::connection`].
    pub fn new() -> Result<Self, RedisError> {
        let url = env::var("REDIS_URL").unwrap_or("redis://redis:6379".into());

        let client = redis::Client::open(url)?;

        let config = ConnectionManagerConfig::new()
            .set_response_timeout(Duration::from_millis(env_millis(
                "REDIS_RESPONSE_TIMEOUT_MS",
                DEFAULT_RESPONSE_TIMEOUT_MS,
            )))
            .set_connection_timeout(Duration::from_millis(env_millis(
                "REDIS_CONNECT_TIMEOUT_MS",
                DEFAULT_CONNECT_TIMEOUT_MS,
            )))
            // Дефолт — 6 попыток с экспоненциальной задержкой, суммарно больше
            // шести секунд. Для нас это неприемлемо: пока идут ретраи, висит
            // обработчик запроса (в том числе `/readyz`, который обязан отвечать
            // быстро). Одной повторной попытки достаточно, чтобы пережить
            // мгновенный обрыв, а более долгую недоступность правильнее показать
            // в readiness, чем прятать за ожиданием.
            .set_number_of_retries(1)
            .set_max_delay(REFRESH_MAX_DELAY_MS);

        Ok(Self {
            client,
            config,
            manager: Arc::new(OnceCell::new()),
        })
    }

    /// Возвращает соединение для выполнения команды, создавая его при первом
    /// обращении.
    ///
    /// Менеджер инициализируется **лениво и один раз на процесс**: дальше все
    /// команды идут по одному мультиплексированному соединению, которое он сам
    /// восстанавливает после обрыва.
    ///
    /// Ленивость здесь принципиальна, а не унаследована: недоступный на старте
    /// Redis не должен ронять процесс. Сервис поднимается, `GET /readyz` честно
    /// отвечает `503`, трафик на под не идёт — а когда хранилище появится,
    /// соединение установится само, без рестарта. При неудачной попытке ячейка
    /// остаётся пустой, поэтому следующий запрос попробует снова.
    ///
    /// # Errors
    /// [`JtiError::BadConnection`], если подключиться не удалось.
    async fn connection(&self) -> Result<ConnectionManager, JtiError> {
        self.manager
            .get_or_try_init(|| {
                ConnectionManager::new_with_config(self.client.clone(), self.config.clone())
            })
            .await
            .cloned()
            .map_err(|e| {
                // Отказ хранилища — ERROR.
                error!("Redis: не удалось открыть соединение: {}", e);
                JtiError::BadConnection
            })
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
        let mut conn = self.connection().await?;

        let started = Instant::now();

        match redis::cmd("PING").query_async::<String>(&mut conn).await {
            Ok(_) => {
                record_redis_command("ping", true, started.elapsed());
                Ok(())
            }
            Err(e) => {
                error!("Redis: PING не выполнился: {}", e);
                record_redis_command("ping", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }
}

impl JtiStore for RedisClient {
    /// Записывает `jti` со значением-заглушкой `1` и TTL `ttl` секунд (`SETEX`).
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
                error!("Redis: SETEX не выполнился: {}", e);
                record_redis_command("store_jti", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Проверяет существование ключа `jti` (`EXISTS`).
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
                error!("Redis: EXISTS не выполнился: {}", e);
                record_redis_command("check_jti", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Добавляет `jti` в ZSET группы со score, равным времени истечения
    /// (`ZADD`).
    ///
    /// ZSET, а не SET: у элементов множества нет собственного TTL, и истёкшие
    /// `jti` копились бы в индексе мёртвым грузом. Score = момент истечения
    /// позволяет отрезать их одной командой (см. [`RedisClient::revoke_group`]).
    ///
    /// TTL самой группы продлевается до времени жизни самого долгого токена в
    /// ней: иначе индекс пережил бы все свои токены и остался висеть в памяти.
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
                error!("Redis: ZADD в группу не выполнился: {}", e);
                record_redis_command("add_to_group", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Отзывает все токены группы.
    ///
    /// Порядок: отрезаем протухшие записи по score, забираем оставшиеся `jti`,
    /// удаляем их пачкой и саму группу.
    ///
    /// Атомарности здесь намеренно нет: параллельный выпуск токена во время
    /// отзыва может добавить `jti` уже после `ZRANGE`, и такой токен уцелеет.
    /// Окно — доли миллисекунды, а цена атомарности (Lua-скрипт или WATCH) выше
    /// пользы: массовый отзыв делают при компрометации, и следом за ним обычно
    /// меняют учётные данные субъекта.
    #[tracing::instrument(name = "redis.revoke_group", skip_all, err(level = "debug"))]
    async fn revoke_group(&self, group: &str) -> Result<u64, JtiError> {
        let mut conn = self.connection().await?;
        let started = Instant::now();

        let now = chrono::Utc::now().timestamp();

        let result: Result<u64, RedisError> = async {
            // Протухшие токены отзывать незачем — они и так невалидны.
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
                error!("Redis: отзыв группы не выполнился: {}", e);
                record_redis_command("revoke_group", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Сохраняет запись refresh-токена как HASH с TTL.
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

        // Аудитория — список, а в HASH значения плоские; кладём JSON-массивом.
        let audience = match serde_json::to_string(&record.audience) {
            Ok(v) => v,
            Err(e) => {
                error!("Redis: не сериализуется audience refresh-токена: {}", e);
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
                error!("Redis: запись refresh-токена не выполнилась: {}", e);
                record_redis_command("store_refresh", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Читает запись refresh-токена (`HGETALL`).
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
                error!("Redis: чтение refresh-токена не выполнилось: {}", e);
                record_redis_command("get_refresh", false, started.elapsed());
                return Err(classify(&e));
            }
        };

        // Пустой HASH — ключа нет: истёк или отозван.
        if fields.is_empty() {
            return Ok(None);
        }

        let (Some(subject), Some(audience), Some(family)) =
            (fields.get("sub"), fields.get("aud"), fields.get("family"))
        else {
            // Запись есть, но неполная — так быть не должно; трактуем как
            // отсутствие, чтобы не выпустить токен на мусорных данных.
            error!("Redis: запись refresh-токена неполная");
            return Ok(None);
        };

        let audience: Vec<String> = match serde_json::from_str(audience) {
            Ok(v) => v,
            Err(e) => {
                error!("Redis: audience refresh-токена не разбирается: {}", e);
                return Ok(None);
            }
        };

        Ok(Some(RefreshRecord {
            subject: subject.clone(),
            audience,
            family: family.clone(),
        }))
    }

    /// Помечает refresh-токен использованным (`HSETNX`).
    ///
    /// `HSETNX` возвращает `1`, только если поля ещё не было, — то есть операция
    /// атомарна и «победитель» ровно один. На этом держится детектор повторного
    /// использования: второй обмен тем же токеном получит `false`.
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
                error!("Redis: пометка refresh-токена не выполнилась: {}", e);
                record_redis_command("mark_refresh_used", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }

    /// Удаляет ключ `jti` (`DEL`); отзыв токена. Идемпотентна.
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
                error!("Redis: DEL не выполнился: {}", e);
                record_redis_command("delete_jti", false, started.elapsed());
                Err(classify(&e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Тесты разбора конфигурации и классификации ошибок.
    //!
    //! Живой Redis здесь не нужен: проверяется то, что раньше подразумевалось
    //! отдельной стадией открытия соединения, а теперь выводится из самой ошибки.

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
        // Ответ не того типа — сбой не связи, а самой команды.
        let type_error = RedisError::from((redis::ErrorKind::TypeError, "unexpected type"));
        assert!(matches!(classify(&type_error), JtiError::WrongOperation));
    }

    #[test]
    fn client_is_created_without_touching_the_network() {
        // Соединение ленивое, поэтому клиент создаётся даже под заведомо
        // недоступный адрес — и это именно то поведение, на которое опирается
        // `/readyz` (сервис поднимается и честно сообщает о недоступности).
        let client = RedisClient::new();
        assert!(client.is_ok());
        assert!(client.unwrap().manager.get().is_none());
    }
}
