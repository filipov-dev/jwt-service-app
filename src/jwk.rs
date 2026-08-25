//! HTTP-клиент к внешнему сервису ключей `jwks-service-app`.
//!
//! [`JwkService`] инкапсулирует все обращения к сервису ключей:
//! - `GET /.well-known/jwks.json` — список публичных ключей;
//! - `GET /jwks/{id}` — конкретный ключ (с приватной частью);
//! - `POST /jwks` — создание нового ключа под заданный алгоритм.
//!
//! Базовый URL берётся из `JWKS_SERVICE_URL`.

use parking_lot::RwLock;
use reqwest::Client;
use serde_json::json;
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

use tracing::{debug, error};

use crate::metrics::{record_jwks_cache, record_jwks_request};
use crate::models::{Jwk, JwkData, Jwks};
use crate::tracing_otel::inject_context;

/// Сколько кеш JWKS считается свежим (`JWKS_CACHE_TTL_SECONDS`).
///
/// Пять минут — компромисс: ключи в `jwks-service-app` живут сутками
/// (`KEY_EXPIRATION_SECONDS`), поэтому запаздывание на минуты безопасно, а
/// держать отозванный ключ в памяти дольше не хочется. `0` полностью отключает
/// кеш и возвращает прежнее поведение — полезно при отладке.
const DEFAULT_CACHE_TTL_SECONDS: u64 = 300;

/// Общий таймаут запроса к сервису ключей (`JWKS_REQUEST_TIMEOUT_MS`).
///
/// Две секунды с запасом покрывают самую долгую операцию — генерацию ключа — и
/// заметно меньше типичного клиентского таймаута в 5–10 с: клиент успевает
/// получить осмысленную ошибку вместо обрыва по своему таймауту.
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 2000;

/// Таймаут установки соединения с сервисом ключей (`JWKS_CONNECT_TIMEOUT_MS`).
///
/// JWKS живёт в той же сети, поэтому полсекунды на установку соединения — уже
/// аномалия.
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 500;

/// Сколько простаивающее соединение держится в пуле.
///
/// Пул нужен, чтобы не платить за TCP-хендшейк на каждом обновлении кеша;
/// удерживать соединение дольше минуты смысла нет — обновления реже.
const POOL_IDLE_TIMEOUT_SECONDS: u64 = 60;

/// Минимальный интервал между внеплановыми обновлениями кеша по неизвестному
/// `kid` (`JWKS_CACHE_MISS_REFRESH_SECONDS`).
///
/// Без него кеш не закрывал бы главный сценарий перегрузки: поток токенов со
/// случайными `kid` промахивался бы мимо кеша и транслировался в JWKS один к
/// одному — ровно то, от чего мы уходим.
const DEFAULT_MISS_REFRESH_SECONDS: u64 = 10;

/// Предельный возраст снимка, который ещё разрешено отдавать при недоступном
/// сервисе ключей (`JWKS_CACHE_STALE_MAX_SECONDS`).
///
/// Час — компромисс между доступностью и безопасностью: он с запасом
/// перекрывает типичную аварию `jwks-service-app`, но не даёт отозванному ключу
/// считаться валидным бесконечно. `0` выключает отдачу устаревших снимков
/// совсем — прежнее поведение, когда лежащий JWKS означал отказ верификации.
const DEFAULT_STALE_MAX_SECONDS: u64 = 3600;

/// Собирает HTTP-клиент к сервису ключей с таймаутами.
///
/// Без них `reqwest` ждёт ответа неограниченно, и зависший — не упавший, а
/// именно висящий — JWKS удерживал бы воркеры actix до TCP-таймаута ОС, то есть
/// десятки минут. Кеш (JWT-25) частоту обращений сократил, но от одного
/// зависшего запроса не защищает.
///
/// Не fail-fast: если клиент почему-то не собрался, берём дефолтный — без
/// таймаутов, но рабочий. Телеметрия и настройки такого рода не должны быть
/// причиной недоступности сервиса.
fn build_client() -> Client {
    let request_timeout = env_millis("JWKS_REQUEST_TIMEOUT_MS", DEFAULT_REQUEST_TIMEOUT_MS);
    let connect_timeout = env_millis("JWKS_CONNECT_TIMEOUT_MS", DEFAULT_CONNECT_TIMEOUT_MS);

    Client::builder()
        .timeout(Duration::from_millis(request_timeout))
        .connect_timeout(Duration::from_millis(connect_timeout))
        .pool_idle_timeout(Duration::from_secs(POOL_IDLE_TIMEOUT_SECONDS))
        .build()
        .unwrap_or_else(|e| {
            tracing::warn!(
                "JWKS: не удалось собрать HTTP-клиент с таймаутами ({e}), беру дефолтный"
            );
            Client::new()
        })
}

/// Читает миллисекунды из переменной окружения, откатываясь на `default`.
fn env_millis(name: &str, default: u64) -> u64 {
    env_u64(name, default)
}

/// Читает секунды из переменной окружения, откатываясь на `default`.
fn env_seconds(name: &str, default: u64) -> u64 {
    env_u64(name, default)
}

/// Общий разбор `u64` из переменной окружения.
///
/// Не fail-fast: как и прочая настройка кеша и телеметрии, кривое значение даёт
/// предупреждение и дефолт, а не падение сервиса.
fn env_u64(name: &str, default: u64) -> u64 {
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

/// Состояние кеша публичных ключей.
struct CacheState {
    /// Последний успешно полученный набор ключей и момент получения.
    entry: Option<(Jwks, Instant)>,
    /// Момент последнего похода в JWKS (успешного или нет) — для троттлинга
    /// обновлений по промаху.
    last_attempt: Option<Instant>,
    /// Момент последнего **неудачного** похода; сбрасывается успешным. Отличает
    /// «обновляться ещё рано» от «сервис ключей лежит»: отдавать устаревший
    /// снимок можно только во втором случае.
    last_failure: Option<Instant>,
}

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
///
/// Экземпляр создаётся **один раз на процесс** и дальше клонируется: `client`
/// несёт пул соединений, а `cache` и `refresh_lock` спрятаны за `Arc`, поэтому
/// все копии разделяют один кеш и один пул. Создавать `JwkService` на каждый
/// запрос нельзя — именно так и появлялся поход в JWKS на каждую верификацию.
#[derive(Clone)]
pub struct JwkService {
    client: Client,
    /// Базовый URL сервиса (`JWKS_SERVICE_URL`).
    url: String,
    /// Кеш публичных ключей, общий для всех клонов.
    cache: Arc<RwLock<CacheState>>,
    /// Замок на обновление кеша: под нагрузкой в JWKS уходит один запрос, а не
    /// столько, сколько запросов промахнулось одновременно. Асинхронный —
    /// удерживается через `await` на время HTTP-запроса, где `parking_lot`
    /// использовать нельзя.
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
    /// Время жизни снимка кеша.
    cache_ttl: Duration,
    /// Минимальный интервал между обновлениями по промаху.
    miss_refresh_interval: Duration,
    /// Предельный возраст снимка, отдаваемого при недоступном сервисе ключей.
    stale_max_age: Duration,
}

impl JwkService {
    /// Создаёт клиент; базовый URL берётся из `JWKS_SERVICE_URL`
    /// (по умолчанию `http://jwks-service-app:8080`).
    pub fn new() -> Self {
        let url = env::var("JWKS_SERVICE_URL").unwrap_or("http://jwks-service-app:8080".into());

        let cache_ttl = Duration::from_secs(env_seconds(
            "JWKS_CACHE_TTL_SECONDS",
            DEFAULT_CACHE_TTL_SECONDS,
        ));
        let stale_max_age = Duration::from_secs(env_seconds(
            "JWKS_CACHE_STALE_MAX_SECONDS",
            DEFAULT_STALE_MAX_SECONDS,
        ));

        // Окно отдачи устаревшего снимка — это промежуток между TTL и пределом
        // возраста. Предел не больше TTL сервис не роняет, но и смысла не имеет:
        // свежий снимок отдаётся и так, а устаревший не будет отдан никогда.
        if !stale_max_age.is_zero() && stale_max_age <= cache_ttl {
            tracing::warn!(
                "JWKS_CACHE_STALE_MAX_SECONDS ({} с) не больше JWKS_CACHE_TTL_SECONDS ({} с): \
                 при недоступном сервисе ключей устаревший снимок отдаваться не будет",
                stale_max_age.as_secs(),
                cache_ttl.as_secs()
            );
        }

        Self {
            client: build_client(),
            url,
            cache: Arc::new(RwLock::new(CacheState {
                entry: None,
                last_attempt: None,
                last_failure: None,
            })),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            cache_ttl,
            miss_refresh_interval: Duration::from_secs(env_seconds(
                "JWKS_CACHE_MISS_REFRESH_SECONDS",
                DEFAULT_MISS_REFRESH_SECONDS,
            )),
            stale_max_age,
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
    #[tracing::instrument(name = "jwks.public_keys", skip(self), err(level = "debug"))]
    async fn public_keys(&self) -> Result<Jwks, JwkError> {
        let url = format!("{}/.well-known/jwks.json", self.url);
        debug!("JWKS: запрашиваю публичные ключи ({})", url);
        let started = Instant::now();

        // Пробрасываем трейс-контекст: обращение к JWKS попадёт в ту же трассу.
        let response = match inject_context(self.client.get(&url)).send().await {
            Ok(v) => v,
            Err(e) => {
                // Отказ внешней зависимости — ERROR.
                error!("JWKS недоступен ({}): {}", url, e);
                record_jwks_request("public_keys", false, started.elapsed());
                return Err(JwkError::BadConnection);
            }
        };

        match response.json().await {
            Ok(v) => {
                record_jwks_request("public_keys", true, started.elapsed());
                Ok(v)
            }
            Err(e) => {
                error!("JWKS вернул некорректный ответ ({}): {}", url, e);
                record_jwks_request("public_keys", false, started.elapsed());
                Err(JwkError::BadResponse)
            }
        }
    }

    /// Возвращает публичный ключ по `kid`, по возможности из кеша.
    ///
    /// Порядок:
    /// 1. **Попадание** — свежий кеш содержит `kid`, в сеть не идём.
    /// 2. **Промах** — берём замок обновления и проверяем кеш ещё раз: пока мы
    ///    ждали, его мог наполнить другой запрос.
    /// 3. Если обновляться ещё рано (`JWKS_CACHE_MISS_REFRESH_SECONDS`), пробуем
    ///    отдать устаревший снимок; при свежем кеше без нужного `kid` — отказываем,
    ///    не трогая сеть, иначе поток случайных `kid` снова транслировался бы в
    ///    JWKS один к одному.
    /// 4. Иначе идём в JWKS, обновляем кеш и ищем в нём.
    /// 5. Если поход не удался — отдаём последний известный снимок
    ///    (stale-while-revalidate), пока его возраст не превысил
    ///    `JWKS_CACHE_STALE_MAX_SECONDS`.
    ///
    /// # Errors
    /// - [`JwkError::NotFound`] — ключа нет ни в кеше, ни в свежем ответе JWKS,
    ///   либо обновление сейчас троттлится;
    /// - [`JwkError::BadConnection`] / [`JwkError::BadResponse`] — от запроса к JWKS,
    ///   когда пригодного устаревшего снимка нет.
    pub async fn public_key(&self, kid: &str) -> Result<Jwk, JwkError> {
        if let Some(jwk) = self.lookup_fresh(kid) {
            record_jwks_cache("hit");
            return Ok(jwk);
        }

        // Single-flight: под нагрузкой в JWKS уходит один запрос на весь всплеск
        // промахов, остальные ждут здесь и забирают уже готовый кеш.
        let _guard = self.refresh_lock.lock().await;

        if let Some(jwk) = self.lookup_fresh(kid) {
            record_jwks_cache("hit");
            return Ok(jwk);
        }

        if !self.allow_refresh_on_miss() {
            // Обновляться ещё рано. Если прошлый поход провалился, повторный
            // сейчас ничего не даст — отдаём устаревший снимок, не трогая сеть.
            // Это не только лучше отказа: иначе запросы выстроились бы в
            // очередь, каждый со своим таймаутом к лежащему JWKS, и верификация
            // всё равно лежала бы — уже по латентности.
            if self.refresh_recently_failed() {
                if let Some(jwk) = self.serve_stale(kid) {
                    return Ok(jwk);
                }
            }

            if self.cache_is_fresh() {
                // Кеш свежий, ключа в нём нет — отказываем, не трогая сеть. Для
                // клиента это неотличимо от «ключ не найден».
                record_jwks_cache("throttled");
                debug!("JWKS: kid {} неизвестен, обновление кеша троттлится", kid);
                return Err(JwkError::NotFound);
            }

            // Пригодного снимка нет вовсе — беречь тут нечего, идём в сеть.
        }

        let jwks = match self.fetch_and_store().await {
            Ok(jwks) => jwks,
            Err(e) => {
                // Сервис ключей не ответил, но рабочий снимок лежит в памяти —
                // отдаём его, вместо того чтобы класть верификацию целиком.
                return match self.serve_stale(kid) {
                    Some(jwk) => Ok(jwk),
                    None => {
                        record_jwks_cache("miss");
                        Err(e)
                    }
                };
            }
        };

        record_jwks_cache("miss");

        jwks.keys
            .iter()
            .find(|jwk| jwk.kid == kid)
            .cloned()
            .ok_or(JwkError::NotFound)
    }

    /// Отдаёт `kid` из устаревшего снимка, если тот ещё пригоден.
    ///
    /// Осознанный размен: недоступный `jwks-service-app` не должен класть
    /// верификацию на всё время аварии, пока рабочий снимок ключей лежит в
    /// памяти. Расплата — отозванный ключ какое-то время продолжает считаться
    /// валидным, поэтому возраст снимка ограничен `JWKS_CACHE_STALE_MAX_SECONDS`,
    /// а сама деградация видна в логе (WARN) и в метрике
    /// `jwks_cache_total{result="stale"}`.
    fn serve_stale(&self, kid: &str) -> Option<Jwk> {
        let (jwk, age) = self.lookup_stale(kid)?;

        record_jwks_cache("stale");
        // WARN, а не INFO: это деградация, и она должна быть заметна в логах.
        tracing::warn!(
            "JWKS недоступен: ключ {} отдан из устаревшего снимка (возраст {} с, предел {} с)",
            kid,
            age.as_secs(),
            self.stale_max_age.as_secs()
        );

        Some(jwk)
    }

    /// Провалился ли последний поход в JWKS настолько недавно, что повторять его
    /// сейчас бессмысленно.
    ///
    /// Отметка снимается успешным обновлением, поэтому «свежий провал» — это
    /// именно недоступный сервис ключей, а не троттлинг мусорных `kid`.
    fn refresh_recently_failed(&self) -> bool {
        self.cache
            .read()
            .last_failure
            .is_some_and(|at| at.elapsed() < self.miss_refresh_interval)
    }

    /// Ищет `kid` в последнем снимке, даже протухшем, но не старше
    /// `stale_max_age`. Возвращает ключ вместе с возрастом снимка.
    fn lookup_stale(&self, kid: &str) -> Option<(Jwk, Duration)> {
        // Нулевой TTL — кеш выключен целиком, и устаревшему снимку взяться
        // неоткуда; нулевой предел — отдача устаревших снимков выключена явно.
        if self.cache_ttl.is_zero() || self.stale_max_age.is_zero() {
            return None;
        }

        let state = self.cache.read();
        let (jwks, fetched_at) = state.entry.as_ref()?;
        let age = fetched_at.elapsed();

        if age >= self.stale_max_age {
            return None;
        }

        jwks.keys
            .iter()
            .find(|jwk| jwk.kid == kid)
            .cloned()
            .map(|jwk| (jwk, age))
    }

    /// Ищет `kid` в кеше, если тот ещё свеж. `None` — промах или протухший кеш.
    fn lookup_fresh(&self, kid: &str) -> Option<Jwk> {
        let state = self.cache.read();
        let (jwks, fetched_at) = state.entry.as_ref()?;

        if fetched_at.elapsed() >= self.cache_ttl {
            return None;
        }

        jwks.keys.iter().find(|jwk| jwk.kid == kid).cloned()
    }

    /// Есть ли в кеше непротухший снимок (независимо от конкретного `kid`).
    fn cache_is_fresh(&self) -> bool {
        self.cache
            .read()
            .entry
            .as_ref()
            .is_some_and(|(_, fetched_at)| fetched_at.elapsed() < self.cache_ttl)
    }

    /// Разрешено ли сейчас обновление по промаху; отмечает попытку.
    ///
    /// Троттлит не только флуд неизвестными `kid`, но и повторные походы в
    /// недоступный JWKS: успешный поход делает кеш свежим, поэтому «попытка была
    /// только что, а кеш не свеж» означает, что она провалилась.
    fn allow_refresh_on_miss(&self) -> bool {
        let mut state = self.cache.write();

        match state.last_attempt {
            Some(at) if at.elapsed() < self.miss_refresh_interval => false,
            _ => {
                state.last_attempt = Some(Instant::now());
                true
            }
        }
    }

    /// Запрашивает JWKS и кладёт результат в кеш.
    async fn fetch_and_store(&self) -> Result<Jwks, JwkError> {
        {
            // Отмечаем попытку до запроса: если JWKS лежит, троттлинг не даст
            // долбить его в цикле.
            let mut state = self.cache.write();
            state.last_attempt = Some(Instant::now());
        }

        let jwks = match self.public_keys().await {
            Ok(jwks) => jwks,
            Err(e) => {
                // Помечаем провал: пока он свеж, повторные походы троттлятся, а
                // запросы обслуживаются устаревшим снимком.
                self.cache.write().last_failure = Some(Instant::now());
                return Err(e);
            }
        };

        let mut state = self.cache.write();
        state.entry = Some((jwks.clone(), Instant::now()));
        state.last_failure = None;

        Ok(jwks)
    }

    /// Возвращает приватный ключ по `id`, создавая новый под алгоритм `alg`,
    /// если ключа с таким `id` нет (или `id` пуст).
    pub async fn private_key(&self, id: &str, alg: &str) -> Result<JwkData, JwkError> {
        // Идентификатора ещё нет — первый ключ за время жизни процесса.
        if id.is_empty() {
            return self.create_key(alg).await;
        }

        match self.get_key(id).await {
            Ok(v) => Ok(v),
            // Ключа действительно нет — создаём новый.
            Err(JwkError::NotFound) => self.create_key(alg).await,
            // А вот недоступность или сбой сервиса ключей — НЕ повод плодить
            // ключи: раньше сюда попадали и `BadConnection`, и `BadResponse`,
            // поэтому кратковременный сбой сети приводил к созданию нового
            // ключа, мусору в хранилище и смене активного `kid` на ровном месте.
            Err(e) => Err(e),
        }
    }

    /// Создаёт новый ключ в сервисе под указанный алгоритм.
    ///
    /// Для `EdDSA` сервису передаётся конкретная кривая `Ed25519` (сервис ключей
    /// оперирует именем кривой, а не общим именем алгоритма).
    async fn create_key(&self, alg: &str) -> Result<JwkData, JwkError> {
        let url = format!("{}/jwks", self.url);

        let alg = if alg == "EdDSA" { "Ed25519" } else { alg };

        debug!("JWKS: запрашиваю приватный ключ (alg={})", alg);
        let started = Instant::now();

        let response = match inject_context(self.client.post(&url))
            .json(&json!({
                "alg": alg
            }))
            .send()
            .await
        {
            Ok(v) => v,
            Err(e) => {
                error!("JWKS недоступен при запросе приватного ключа: {}", e);
                record_jwks_request("private_key", false, started.elapsed());
                return Err(JwkError::BadConnection);
            }
        };

        match response.json().await {
            Ok(v) => {
                record_jwks_request("private_key", true, started.elapsed());
                Ok(v)
            }
            Err(e) => {
                error!("JWKS вернул некорректный приватный ключ: {}", e);
                record_jwks_request("private_key", false, started.elapsed());
                Err(JwkError::BadResponse)
            }
        }
    }

    /// Получаем ключ из сервиса
    /// Получает ключ из сервиса по его `id`.
    ///
    /// # Errors
    /// - [`JwkError::NotFound`] — **только** ответ `404`, то есть ключа
    ///   действительно нет;
    /// - [`JwkError::BadResponse`] — любой другой неуспешный статус (`5xx` и
    ///   прочее) либо нечитаемое тело;
    /// - [`JwkError::BadConnection`] — сервис недоступен.
    ///
    /// Различие принципиально: вызывающий ([`JwkService::private_key`]) создаёт
    /// новый ключ по `NotFound`, поэтому «сервис ответил 500» ни в коем случае не
    /// должно выглядеть как «ключа нет».
    async fn get_key(&self, id: &str) -> Result<JwkData, JwkError> {
        let url = format!("{}/jwks/{}", self.url, id);
        let started = Instant::now();

        let response = match inject_context(self.client.get(&url)).send().await {
            Ok(v) => v,
            Err(e) => {
                error!("JWKS недоступен при запросе ключа {}: {}", id, e);
                record_jwks_request("get_key", false, started.elapsed());
                return Err(JwkError::BadConnection);
            }
        };

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            debug!("JWKS: ключ {} не найден", id);
            record_jwks_request("get_key", true, started.elapsed());
            return Err(JwkError::NotFound);
        }

        if !response.status().is_success() {
            error!("JWKS вернул {} на запрос ключа {}", response.status(), id);
            record_jwks_request("get_key", false, started.elapsed());
            return Err(JwkError::BadResponse);
        }

        match response.json().await {
            Ok(v) => {
                record_jwks_request("get_key", true, started.elapsed());
                Ok(v)
            }
            Err(e) => {
                error!("JWKS вернул некорректный ключ {}: {}", id, e);
                record_jwks_request("get_key", false, started.elapsed());
                Err(JwkError::BadResponse)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Тесты кеша публичных ключей.
    //!
    //! `jwks-service-app` поднимается как HTTP-мок ([`wiremock`]), а число
    //! реально ушедших запросов сверяется через `received_requests` — именно оно
    //! и есть предмет проверки: до кеша каждая верификация давала свой запрос.

    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    impl JwkService {
        /// Конструктор для тестов: URL и тайминги задаются явно, минуя окружение.
        ///
        /// Через env это делать нельзя — переменные процесса общие, а тесты
        /// бегут параллельно.
        fn for_test(url: String, cache_ttl: Duration, miss_refresh_interval: Duration) -> Self {
            Self::for_test_with_client(Client::new(), url, cache_ttl, miss_refresh_interval)
        }

        /// То же, но с заранее собранным клиентом — нужен тестам таймаутов.
        fn for_test_with_client(
            client: Client,
            url: String,
            cache_ttl: Duration,
            miss_refresh_interval: Duration,
        ) -> Self {
            Self {
                client,
                url,
                cache: Arc::new(RwLock::new(CacheState {
                    entry: None,
                    last_attempt: None,
                    last_failure: None,
                })),
                refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
                cache_ttl,
                miss_refresh_interval,
                stale_max_age: Duration::from_secs(DEFAULT_STALE_MAX_SECONDS),
            }
        }

        /// Задаёт предел возраста устаревшего снимка (по умолчанию в тестах —
        /// боевой час).
        fn with_stale_max_age(mut self, stale_max_age: Duration) -> Self {
            self.stale_max_age = stale_max_age;
            self
        }

        /// Состаривает содержимое кеша на `age`.
        ///
        /// Иначе тесту протухания пришлось бы ждать TTL вживую. Вместе со
        /// снимком сдвигается и отметка последней попытки обновления: без этого
        /// троттлинг не пустил бы обновление в сеть и тест проверял бы не то,
        /// что собирался.
        fn backdate_cache(&self, age: Duration) {
            let mut state = self.cache.write();

            if let Some((_, fetched_at)) = state.entry.as_mut() {
                *fetched_at = fetched_at
                    .checked_sub(age)
                    .expect("тестовый сдвиг времени должен быть в пределах монотонных часов");
            }

            state.last_attempt = state.last_attempt.and_then(|at| at.checked_sub(age));
            state.last_failure = state.last_failure.and_then(|at| at.checked_sub(age));
        }
    }

    /// Поднимает мок JWKS с единственным ключом `kid-1`.
    async fn start_jwks_mock() -> MockServer {
        let server = MockServer::start().await;

        let jwks = json!({ "keys": [ {
            "kty": "OKP", "alg": "EdDSA", "kid": "kid-1", "crv": "Ed25519",
            "x": "AAAA", "y": null, "n": null, "e": null,
        } ] });

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;

        server
    }

    async fn requests_to(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    #[actix_web::test]
    async fn repeated_lookups_hit_cache_and_do_not_refetch() {
        let server = start_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        for _ in 0..10 {
            assert!(service.public_key("kid-1").await.is_ok());
        }

        // Главное число задачи: десять верификаций — один поход в JWKS.
        assert_eq!(requests_to(&server).await, 1);
    }

    #[actix_web::test]
    async fn unknown_kid_refreshes_when_interval_passed() {
        let server = start_jwks_mock().await;
        // Нулевой интервал — обновление по промаху разрешено всегда.
        let service = JwkService::for_test(server.uri(), Duration::from_secs(300), Duration::ZERO);

        // Прогреваем кеш известным ключом.
        assert!(service.public_key("kid-1").await.is_ok());
        assert_eq!(requests_to(&server).await, 1);

        // Неизвестный `kid` — повод обновиться: так подхватывается ключ,
        // появившийся после последнего обновления (ротация).
        assert!(matches!(
            service.public_key("kid-unknown").await,
            Err(JwkError::NotFound)
        ));
        assert_eq!(requests_to(&server).await, 2);
    }

    #[actix_web::test]
    async fn unknown_kid_is_throttled_right_after_refresh() {
        let server = start_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(300),
        );

        assert!(service.public_key("kid-1").await.is_ok());
        assert_eq!(requests_to(&server).await, 1);

        // Кеш только что обновлён, ключа в нём нет — значит его нет и в JWKS,
        // повторный поход ничего не даст. Поток случайных `kid` упирается сюда
        // и в сеть не проходит.
        for _ in 0..5 {
            assert!(matches!(
                service.public_key("kid-unknown").await,
                Err(JwkError::NotFound)
            ));
        }
        assert_eq!(requests_to(&server).await, 1);
    }

    #[actix_web::test]
    async fn expired_cache_is_refreshed() {
        let server = start_jwks_mock().await;
        // Нулевой TTL — кеш выключен: каждый запрос идёт в сеть (прежнее
        // поведение, оставлено для отладки).
        let service = JwkService::for_test(server.uri(), Duration::ZERO, Duration::from_secs(300));

        for _ in 0..3 {
            assert!(service.public_key("kid-1").await.is_ok());
        }

        assert_eq!(requests_to(&server).await, 3);
    }

    #[actix_web::test]
    async fn concurrent_misses_share_a_single_refresh() {
        let server = start_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        // Двадцать одновременных промахов по холодному кешу должны сойтись в
        // один запрос: замок обновления пропускает первого, остальные забирают
        // уже готовый результат.
        let mut handles = Vec::new();
        for _ in 0..20 {
            let service = service.clone();
            handles.push(actix_web::rt::spawn(async move {
                service.public_key("kid-1").await.is_ok()
            }));
        }

        for handle in handles {
            assert!(handle.await.unwrap());
        }

        assert_eq!(requests_to(&server).await, 1);
    }

    #[actix_web::test]
    async fn hanging_jwks_is_cut_off_by_timeout() {
        let server = MockServer::start().await;

        // Мок отвечает с задержкой, заведомо большей таймаута клиента: именно
        // так выглядит зависший (а не упавший) сервис ключей — самый неприятный
        // случай, потому что без таймаута воркер ждал бы до таймаута ОС.
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "keys": [] }))
                    .set_delay(Duration::from_secs(5)),
            )
            .mount(&server)
            .await;

        let client = Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let service = JwkService::for_test_with_client(
            client,
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        let started = Instant::now();
        let result = service.public_key("kid-1").await;
        let elapsed = started.elapsed();

        assert!(matches!(result, Err(JwkError::BadConnection)));
        // Уложились в таймаут, а не ждали ответа мока пять секунд.
        assert!(
            elapsed < Duration::from_secs(2),
            "запрос должен был прерваться по таймауту, а занял {elapsed:?}"
        );
    }

    /// Мок JWKS, который отвечает ровно один раз, а дальше падает с `500`:
    /// так выглядит сервис ключей, легший уже после того, как кеш прогрелся.
    async fn start_dying_jwks_mock() -> MockServer {
        let server = MockServer::start().await;

        let jwks = json!({ "keys": [ {
            "kty": "OKP", "alg": "EdDSA", "kid": "kid-1", "crv": "Ed25519",
            "x": "AAAA", "y": null, "n": null, "e": null,
        } ] });

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        server
    }

    #[actix_web::test]
    async fn stale_snapshot_is_served_when_jwks_is_down() {
        let server = start_dying_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        assert!(service.public_key("kid-1").await.is_ok());

        // Снимок протух, а сервис ключей к этому моменту лёг.
        service.backdate_cache(Duration::from_secs(600));

        // Главное требование задачи: лежащий JWKS не кладёт верификацию, пока
        // рабочий снимок ключей лежит в памяти.
        assert!(service.public_key("kid-1").await.is_ok());
        // Попытка обновиться всё же была — отдача устаревшего снимка её не
        // заменяет, а страхует.
        assert_eq!(requests_to(&server).await, 2);
    }

    #[actix_web::test]
    async fn too_old_snapshot_is_refused() {
        let server = start_dying_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        )
        .with_stale_max_age(Duration::from_secs(3600));

        assert!(service.public_key("kid-1").await.is_ok());

        // За пределом возраста отказываем: иначе отозванный ключ считался бы
        // валидным сколь угодно долго.
        service.backdate_cache(Duration::from_secs(7200));

        assert!(matches!(
            service.public_key("kid-1").await,
            Err(JwkError::BadResponse)
        ));
    }

    #[actix_web::test]
    async fn stale_serving_can_be_disabled() {
        let server = start_dying_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        )
        .with_stale_max_age(Duration::ZERO);

        assert!(service.public_key("kid-1").await.is_ok());
        service.backdate_cache(Duration::from_secs(600));

        // Нулевой предел — прежнее поведение: недоступный JWKS означает отказ.
        assert!(matches!(
            service.public_key("kid-1").await,
            Err(JwkError::BadResponse)
        ));
    }

    #[actix_web::test]
    async fn down_jwks_is_not_hammered_while_stale_snapshot_serves() {
        let server = start_dying_jwks_mock().await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        assert!(service.public_key("kid-1").await.is_ok());
        service.backdate_cache(Duration::from_secs(600));

        for _ in 0..5 {
            assert!(service.public_key("kid-1").await.is_ok());
        }

        // Один неудачный поход на весь интервал троттлинга: без этого каждый
        // запрос ждал бы таймаута лежащего JWKS, и verify всё равно лежал бы —
        // теперь уже по латентности.
        assert_eq!(requests_to(&server).await, 2);
    }

    #[actix_web::test]
    async fn live_jwks_is_refreshed_even_when_refresh_is_throttled() {
        let server = start_jwks_mock().await;
        // TTL короче интервала троттлинга: протухший снимок есть, обновление
        // формально «ещё рано».
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(1),
            Duration::from_secs(300),
        );

        assert!(service.public_key("kid-1").await.is_ok());
        service.backdate_cache(Duration::from_secs(2));

        assert!(service.public_key("kid-1").await.is_ok());

        // Устаревший снимок — страховка на время аварии, а не замена живому
        // сервису: пока JWKS отвечает, кеш обновляется.
        assert_eq!(requests_to(&server).await, 2);
    }

    /// Мок сервиса ключей для сценариев выпуска: `GET /jwks/{id}` отвечает
    /// заданным статусом, `POST /jwks` всегда успешен.
    async fn start_key_mock(get_status: u16) -> MockServer {
        let server = MockServer::start().await;

        let key = json!({
            "id": "kid-new", "kty": "OKP", "alg": "EdDSA", "kid": "kid-new",
            "crv": "Ed25519", "x": "AAAA", "y": null, "n": null, "e": null,
            "private_key": "AAAA",
        });

        Mock::given(method("GET"))
            .and(path("/jwks/kid-1"))
            .respond_with(ResponseTemplate::new(get_status))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(key))
            .mount(&server)
            .await;

        server
    }

    async fn post_requests(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == wiremock::http::Method::POST)
            .count()
    }

    #[actix_web::test]
    async fn missing_key_is_created() {
        // 404 — ключа действительно нет, новый выпустить можно и нужно.
        let server = start_key_mock(404).await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        let key = service.private_key("kid-1", "EdDSA").await;

        assert!(key.is_ok());
        assert_eq!(post_requests(&server).await, 1);
    }

    #[actix_web::test]
    async fn server_error_does_not_create_a_key() {
        // 500 — сбой сервиса ключей. Раньше он был неотличим от «ключа нет»,
        // и на каждом таком ответе выпускался новый ключ.
        let server = start_key_mock(500).await;
        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        let key = service.private_key("kid-1", "EdDSA").await;

        assert!(matches!(key, Err(JwkError::BadResponse)));
        assert_eq!(post_requests(&server).await, 0);
    }

    #[actix_web::test]
    async fn unreachable_service_does_not_create_a_key() {
        // Сеть недоступна: порт 1 гарантированно никем не слушается.
        let service = JwkService::for_test(
            "http://127.0.0.1:1".to_string(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        let key = service.private_key("kid-1", "EdDSA").await;

        assert!(matches!(key, Err(JwkError::BadConnection)));
    }

    #[actix_web::test]
    async fn existing_key_is_reused() {
        let server = MockServer::start().await;
        let key = json!({
            "id": "kid-1", "kty": "OKP", "alg": "EdDSA", "kid": "kid-1",
            "crv": "Ed25519", "x": "AAAA", "y": null, "n": null, "e": null,
            "private_key": "AAAA",
        });
        Mock::given(method("GET"))
            .and(path("/jwks/kid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(key))
            .mount(&server)
            .await;

        let service = JwkService::for_test(
            server.uri(),
            Duration::from_secs(300),
            Duration::from_secs(10),
        );

        assert!(service.private_key("kid-1", "EdDSA").await.is_ok());
        // Ключ нашёлся — выпускать новый незачем.
        assert_eq!(post_requests(&server).await, 0);
    }
}
