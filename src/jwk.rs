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
}

impl JwkService {
    /// Создаёт клиент; базовый URL берётся из `JWKS_SERVICE_URL`
    /// (по умолчанию `http://jwks-service-app:8080`).
    pub fn new() -> Self {
        let url = env::var("JWKS_SERVICE_URL").unwrap_or("http://jwks-service-app:8080".into());

        Self {
            client: build_client(),
            url,
            cache: Arc::new(RwLock::new(CacheState {
                entry: None,
                last_attempt: None,
            })),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            cache_ttl: Duration::from_secs(env_seconds(
                "JWKS_CACHE_TTL_SECONDS",
                DEFAULT_CACHE_TTL_SECONDS,
            )),
            miss_refresh_interval: Duration::from_secs(env_seconds(
                "JWKS_CACHE_MISS_REFRESH_SECONDS",
                DEFAULT_MISS_REFRESH_SECONDS,
            )),
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
    /// 3. Если кеш свежий, но `kid` в нём нет, это либо новый ключ, либо мусор.
    ///    Обновляемся, но не чаще `JWKS_CACHE_MISS_REFRESH_SECONDS` — иначе поток
    ///    случайных `kid` снова транслировался бы в JWKS один к одному.
    /// 4. Иначе идём в JWKS, обновляем кеш и ищем в нём.
    ///
    /// # Errors
    /// - [`JwkError::NotFound`] — ключа нет ни в кеше, ни в свежем ответе JWKS,
    ///   либо обновление сейчас троттлится;
    /// - [`JwkError::BadConnection`] / [`JwkError::BadResponse`] — от запроса к JWKS.
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

        if self.cache_is_fresh() && !self.allow_refresh_on_miss() {
            // Кеш свежий, ключа в нём нет, обновляться ещё рано — отказываем, не
            // трогая сеть. Для клиента это неотличимо от «ключ не найден».
            record_jwks_cache("throttled");
            debug!("JWKS: kid {} неизвестен, обновление кеша троттлится", kid);
            return Err(JwkError::NotFound);
        }

        record_jwks_cache("miss");
        let jwks = self.fetch_and_store().await?;

        jwks.keys
            .iter()
            .find(|jwk| jwk.kid == kid)
            .cloned()
            .ok_or(JwkError::NotFound)
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

    /// Разрешено ли сейчас внеплановое обновление по промаху; отмечает попытку.
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

        let jwks = self.public_keys().await?;

        let mut state = self.cache.write();
        state.entry = Some((jwks.clone(), Instant::now()));

        Ok(jwks)
    }

    /// Возвращает приватный ключ по `id`, создавая новый под алгоритм `alg`,
    /// если ключа с таким `id` нет (или `id` пуст).
    pub async fn private_key(&self, id: &str, alg: &str) -> Result<JwkData, JwkError> {
        match self.get_key(id).await {
            Ok(v) => Ok(v),
            _ => self.create_key(alg).await,
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
                })),
                refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
                cache_ttl,
                miss_refresh_interval,
            }
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
}
