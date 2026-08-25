//! HTTP-обработчики публичного API.
//!
//! Модуль содержит эндпоинты:
//! - `POST /tokens` — выпуск токена ([`create_token`]);
//! - `POST /tokens/verify` — проверка токена ([`verify_token`]);
//! - `DELETE /tokens/{jti}` — отзыв токена ([`revoke_token`]);
//! - `POST /tokens/refresh` — обмен refresh-токена ([`refresh_token`]);
//! - `DELETE /subjects/{sub}/tokens` — массовый отзыв токенов субъекта
//!   ([`revoke_subject_tokens`]);
//! - `GET /livez`, `GET /readyz` — пробы ([`livez`], [`readyz`]);
//! - `GET /metrics` — метрики Prometheus ([`metrics`]).
//!
//! Обработчики намеренно тонкие: вся доменная логика вынесена в
//! [`crate::jwt::JwtManager`] и модели. Значение claim `iss` (issuer) берётся
//! из HTTP-заголовка `Host` входящего запроса, а не из конфигурации; список
//! допустимых значений при этом ограничивается аллоулистом (см.
//! [`crate::issuer`]).

use actix_web::{delete, get, post, web, HttpResponse};
use metrics_exporter_prometheus::PrometheusHandle;
use tracing::{debug, error, info, warn};

use crate::error::*;
use crate::jwt::JwtManager;
use crate::key::KeyManager;
use crate::models::jwt::{subject_group, JtiStore, JwtError};
use crate::models::{
    ErrorResponse, ReadinessResponse, RefreshRequest, RevokeGroupResponse, TokenRequest,
    TokenResponse, TokenVerifyRequest,
};
use crate::redis::RedisClient;

/// Достаёт заголовок `Host` — значение будущего claim `iss`.
///
/// Общая часть всех ручек, работающих с issuer: выпуск, обмен refresh и
/// проверка. Отсутствующий или не-ASCII заголовок — ошибка клиента (`400`).
fn host_header(req: &actix_web::HttpRequest) -> Result<&str, Error> {
    req.headers()
        .get("Host")
        .ok_or(Error::Validation("Missing Host header".into()))?
        .to_str()
        .map_err(|_| Error::Validation("Invalid Host header".into()))
}

/// Достаёт `Host` для ручек **выпуска** токена и сверяет его с аллоулистом
/// issuer'ов (`TOKEN_ISSUER_ALLOWLIST`, см. [`crate::issuer`]).
///
/// Отказ явный (`403`): выпуск дёргает доверенный internal-клиент, от которого
/// конфигурацию инстанса скрывать незачем, а неотличимый отказ отлаживали бы
/// вслепую. Пустой аллоулист ничего не запрещает — поведение прежнее.
fn issuer_for_issuance(req: &actix_web::HttpRequest) -> Result<&str, Error> {
    let host = host_header(req)?;
    if !crate::issuer::is_allowed(host) {
        warn!(
            "Отказ в выпуске: issuer '{}' отсутствует в {}",
            host,
            crate::issuer::ALLOWLIST_VAR
        );
        return Err(Error::Forbidden("Issuer not allowed".into()));
    }
    Ok(host)
}

#[utoipa::path(
    post,
    path = "/tokens",
    request_body = TokenRequest,
    security(("totp" = [])),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse, description = "Уровень 3: отсутствует/некорректен TOTP-код"),
        (status = 403, body = ErrorResponse, description = "`Host` вне `TOKEN_ISSUER_ALLOWLIST` (если задан)"),
        (status = 422, body = ErrorResponse),
        (status = 429, body = ErrorResponse, description = "Превышен глобальный cap эндпоинта (если включён)"),
        (status = 500, body = ErrorResponse)
    )
)]
/// Выпускает новый JWT.
///
/// Тело запроса — [`TokenRequest`] с `sub` (subject), `aud` (audience) и
/// необязательным `ttl` (кастомное время жизни в секундах). Issuer (`iss`)
/// подставляется из заголовка `Host`. При выпуске генерируется `jti` и
/// сохраняется в Redis с TTL, равным времени жизни токена.
///
/// # Ответы
/// - `200 OK` — [`TokenResponse`] с подписанным токеном;
/// - `422 Unprocessable Entity` — некорректные входные данные (например, пустой
///   `aud`, невалидный `TOKEN_EXPIRATION_SECONDS` или `ttl` вне допустимых
///   границ);
/// - `400 Bad Request` — отсутствует/некорректен заголовок `Host`;
/// - `403 Forbidden` — `Host` не входит в `TOKEN_ISSUER_ALLOWLIST` (если задан);
/// - `500 Internal Server Error` — прочие ошибки (недоступность JWKS и т.п.).
#[post("/tokens")]
pub async fn create_token(
    req: web::Json<TokenRequest>,
    redis: web::Data<RedisClient>,
    keys: web::Data<KeyManager>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    create_token_impl(req, redis, keys, host).await
}

/// Реализация [`create_token`], обобщённая по хранилищу `jti` ([`JtiStore`]).
///
/// Вынесена отдельно, чтобы в интеграционных тестах подставлять in-memory-хранилище
/// вместо [`RedisClient`] (для которого в CI нет реального Redis). Продакшн-обработчик
/// [`create_token`] вызывает её с [`RedisClient`], поведение при этом не меняется.
pub async fn create_token_impl<S: JtiStore + 'static>(
    req: web::Json<TokenRequest>,
    store: web::Data<S>,
    keys: web::Data<KeyManager>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let host_header = issuer_for_issuance(&host)?;

    let issued = if req.refresh {
        JwtManager::generate_token_pair(
            host_header,
            &req.sub,
            &req.aud,
            req.ttl,
            req.claims.clone(),
            &keys,
            store,
        )
        .await
        .map(|(token, refresh)| (token, Some(refresh)))
    } else {
        JwtManager::generate_token(
            host_header,
            &req.sub,
            &req.aud,
            req.ttl,
            req.claims.clone(),
            &keys,
            store,
        )
        .await
        .map(|token| (token, None))
    };

    match issued {
        // Имя `refresh` намеренно не совпадает с полем: обработчик обмена ниже
        // называется `refresh_token`, и одноимённая переменная затеняла бы его.
        Ok((token, refresh)) => {
            crate::metrics::record_token_issued();
            Ok(HttpResponse::Ok().json(TokenResponse {
                token,
                refresh_token: refresh,
            }))
        }
        Err(e) => {
            // Уровень по вине: некорректный запрос клиента (422) — DEBUG,
            // отказ зависимости/внутренний сбой (500) — ERROR.
            match e {
                JwtError::UnprocessableEntity => {
                    debug!("Некорректные параметры запроса токена: {}", e);
                    Err(Error::Unprocessable(
                        "Invalid token request parameters".into(),
                    ))
                }
                _ => {
                    error!("Не удалось выпустить токен: {}", e);
                    Err(Error::Internal(e.to_string()))
                }
            }
        }
    }
}

#[utoipa::path(
    post,
    path = "/tokens/verify",
    request_body = TokenVerifyRequest,
    security(("proxy_secret" = [])),
    responses(
        (status = 200),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse, description = "Уровень 2: нет proxy-secret, либо токен невалиден/истёк"),
        (status = 429, body = ErrorResponse, description = "Превышен per-IP лимит запросов")
    )
)]
/// Проверяет валидность JWT.
///
/// Тело запроса — [`TokenVerifyRequest`] с самим `token` и ожидаемым
/// `audience`. Проверяются подпись (по публичному ключу из JWKS, найденному по
/// `kid`), совпадение `iss` с заголовком `Host` (и его допустимость по
/// аллоулисту issuer'ов), вхождение `audience` в `aud`,
/// временные границы (`nbf`/`iat`/`exp`) и наличие `jti` в Redis (не отозван).
///
/// # Ответы
/// - `200 OK` — токен валиден, в теле возвращаются его claims;
/// - `401 Unauthorized` — любая ошибка проверки (намеренно без деталей), в том
///   числе `Host` вне `TOKEN_ISSUER_ALLOWLIST`;
/// - `400 Bad Request` — отсутствует/некорректен заголовок `Host`.
#[post("/tokens/verify")]
pub async fn verify_token(
    request: web::Json<TokenVerifyRequest>,
    redis: web::Data<RedisClient>,
    keys: web::Data<KeyManager>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    verify_token_impl(request, redis, keys, host).await
}

/// Реализация [`verify_token`], обобщённая по хранилищу `jti` ([`JtiStore`]).
///
/// Как и [`create_token_impl`], вынесена для подмены хранилища в тестах.
pub async fn verify_token_impl<S: JtiStore + 'static>(
    request: web::Json<TokenVerifyRequest>,
    store: web::Data<S>,
    keys: web::Data<KeyManager>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let host_header = host_header(&host)?;

    // Проверка — публичная ручка: причину отказа наружу не раскрываем, ответ
    // тот же, что и на протухший токен. Issuer вне аллоулиста означает, что
    // токен выпущен не этим контуром, даже если подпись сделана общим ключом.
    if !crate::issuer::is_allowed(host_header) {
        debug!(
            "Проверка токена отклонена: issuer '{}' отсутствует в {}",
            host_header,
            crate::issuer::ALLOWLIST_VAR
        );
        return Err(Error::Unauthorized("Invalid or expired token".into()));
    }

    match JwtManager::verify_token(&request.token, host_header, &request.audience, &keys, store)
        .await
    {
        Ok(v) => {
            crate::metrics::record_token_verified(true);
            Ok(HttpResponse::Ok().json(v))
        }
        Err(e) => {
            crate::metrics::record_token_verified(false);
            // Детали проверки наружу намеренно не раскрываем, чтобы не давать
            // подсказок атакующему — единый ответ на любую причину.
            //
            // Уровень DEBUG: протухший/отозванный/подделанный токен — штатное
            // событие публичной ручки, а не сбой сервиса. Иначе любой такой
            // запрос поднимал бы ERROR-алерты в проде.
            debug!("Проверка токена не удалась: {}", e);
            Err(Error::Unauthorized("Invalid or expired token".into()))
        }
    }
}

#[utoipa::path(
    delete,
    path = "/tokens/{jti}",
    security(("totp" = [])),
    responses(
        (status = 204, description = "Токен отозван. Идемпотентно: несуществующий `jti` — тоже 204"),
        (status = 401, body = ErrorResponse, description = "Уровень 3: отсутствует/некорректен TOTP-код"),
        (status = 429, body = ErrorResponse, description = "Превышен глобальный cap эндпоинта (если включён)"),
        (status = 500, body = ErrorResponse, description = "Хранилище недоступно — отзыв НЕ выполнен")
    )
)]
/// Отзывает токен по его идентификатору `jti`.
///
/// Удаляет запись `jti` из Redis; после этого проверка соответствующего токена
/// в [`verify_token`] будет неуспешной.
///
/// # Ответы
/// - `204 No Content` — токен отозван. **Идемпотентно**: несуществующий `jti`
///   тоже даёт `204`, потому что желаемое состояние достигнуто — такого токена
///   нет;
/// - `500 Internal Server Error` — хранилище недоступно, отзыв **не выполнен**.
///   Отличать этот случай от успеха обязательно: вызывающий отзывает
///   скомпрометированный токен и должен узнать, что попытка не удалась.
#[delete("/tokens/{jti}")]
pub async fn revoke_token(
    jti: web::Path<String>,
    redis: web::Data<RedisClient>,
) -> Result<HttpResponse, Error> {
    revoke_token_impl(jti, redis).await
}

/// Реализация [`revoke_token`], обобщённая по хранилищу `jti` ([`JtiStore`]).
///
/// Как и [`create_token_impl`], вынесена для подмены хранилища в тестах.
pub async fn revoke_token_impl<S: JtiStore + 'static>(
    jti: web::Path<String>,
    store: web::Data<S>,
) -> Result<HttpResponse, Error> {
    match store.delete_jti(&jti).await {
        Ok(_) => {
            crate::metrics::record_token_revoked();
            info!("Токен отозван");
            Ok(HttpResponse::NoContent().finish())
        }
        Err(e) => {
            // Отказ хранилища — наша вина, ERROR.
            //
            // Раньше ошибка проглатывалась и наружу всё равно уходил `204`:
            // вызывающий считал скомпрометированный токен отозванным и не
            // повторял попытку, хотя токен оставался активным. Молчаливый
            // «успех» здесь опаснее честной ошибки.
            error!("Не удалось отозвать токен: {}", e);
            Err(Error::Internal("Failed to revoke token".into()))
        }
    }
}

#[utoipa::path(
    delete,
    path = "/subjects/{sub}/tokens",
    params(("sub" = String, Path, description = "Субъект (claim `sub`), чьи токены отзываются")),
    security(("totp" = [])),
    responses(
        (status = 200, body = RevokeGroupResponse),
        (status = 401, body = ErrorResponse, description = "Уровень 3: отсутствует/некорректен TOTP-код"),
        (status = 429, body = ErrorResponse, description = "Превышен глобальный cap эндпоинта (если включён)"),
        (status = 500, body = ErrorResponse, description = "Хранилище недоступно — отзыв НЕ выполнен")
    )
)]
/// Отзывает все активные токены субъекта.
///
/// Нужно при компрометации: гасить токены по одному через
/// `DELETE /tokens/{jti}` вызывающий не может — он не знает их `jti`.
///
/// # Ответы
/// - `200 OK` — [`RevokeGroupResponse`] с числом отозванных токенов (уже
///   истёкшие не считаются, они и так невалидны);
/// - `500 Internal Server Error` — хранилище недоступно. В отличие от
///   `DELETE /tokens/{jti}`, ошибка **не** проглатывается: молчаливый «успех»
///   при неудавшемся отзыве скомпрометированных токенов опаснее честной ошибки.
#[delete("/subjects/{sub}/tokens")]
pub async fn revoke_subject_tokens(
    sub: web::Path<String>,
    redis: web::Data<RedisClient>,
) -> Result<HttpResponse, Error> {
    revoke_subject_tokens_impl(sub, redis).await
}

/// Реализация [`revoke_subject_tokens`], обобщённая по хранилищу.
pub async fn revoke_subject_tokens_impl<S: JtiStore + 'static>(
    sub: web::Path<String>,
    store: web::Data<S>,
) -> Result<HttpResponse, Error> {
    match store.revoke_group(&subject_group(&sub)).await {
        Ok(revoked) => {
            for _ in 0..revoked {
                crate::metrics::record_token_revoked();
            }
            info!(revoked, "Отозваны все токены субъекта");
            Ok(HttpResponse::Ok().json(RevokeGroupResponse { revoked }))
        }
        Err(e) => {
            // Отказ хранилища — наша вина, ERROR.
            error!("Не удалось отозвать токены субъекта: {}", e);
            Err(Error::Internal("Failed to revoke subject tokens".into()))
        }
    }
}

#[utoipa::path(
    post,
    path = "/tokens/refresh",
    request_body = RefreshRequest,
    security(("totp" = [])),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse, description = "Уровень 3: нет TOTP-кода, либо refresh-токен неизвестен/использован"),
        (status = 429, body = ErrorResponse, description = "Превышен глобальный cap эндпоинта (если включён)"),
        (status = 500, body = ErrorResponse)
    )
)]
/// Обменивает refresh-токен на новую пару access + refresh.
///
/// Старый refresh после обмена не работает: выдаётся новый, из той же семьи.
/// Предъявление уже использованного токена означает утечку — тогда гасится вся
/// семья, включая выданные по ней access-токены (см.
/// [`JwtManager::refresh_token_pair`]).
///
/// Уровень доступа 3 (TOTP), как и у `POST /tokens`: обмен — это выпуск токена,
/// просто основанием служит предъявленный refresh, а не запрос доверенного
/// бэкенда. Ручку дёргает тот же internal-клиент, что выпускает токены; конечное
/// приложение с сервисом напрямую не общается.
///
/// # Ответы
/// - `200 OK` — [`TokenResponse`] с новыми `token` и `refresh_token`;
/// - `401 Unauthorized` — токен неизвестен, истёк или уже использован (детали
///   наружу не раскрываются, как и при проверке токена);
/// - `403 Forbidden` — `Host` не входит в `TOKEN_ISSUER_ALLOWLIST` (если задан);
/// - `400 Bad Request` — отсутствует/некорректен заголовок `Host`.
#[post("/tokens/refresh")]
pub async fn refresh_token(
    request: web::Json<RefreshRequest>,
    redis: web::Data<RedisClient>,
    keys: web::Data<KeyManager>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    refresh_token_impl(request, redis, keys, host).await
}

/// Реализация [`refresh_token`], обобщённая по хранилищу.
pub async fn refresh_token_impl<S: JtiStore + 'static>(
    request: web::Json<RefreshRequest>,
    store: web::Data<S>,
    keys: web::Data<KeyManager>,
    host: actix_web::HttpRequest,
) -> Result<HttpResponse, Error> {
    let host_header = issuer_for_issuance(&host)?;

    match JwtManager::refresh_token_pair(&request.refresh_token, host_header, &keys, store).await {
        Ok((token, refresh)) => {
            crate::metrics::record_token_issued();
            Ok(HttpResponse::Ok().json(TokenResponse {
                token,
                refresh_token: Some(refresh),
            }))
        }
        Err(JwtError::NotValid) => {
            // Причину не раскрываем: неизвестный, истёкший и переигранный токен
            // снаружи неразличимы — как и при проверке access-токена.
            debug!("Обмен refresh-токена не удался");
            Err(Error::Unauthorized("Invalid refresh token".into()))
        }
        Err(e) => {
            error!("Не удалось обменять refresh-токен: {}", e);
            Err(Error::Internal(e.to_string()))
        }
    }
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "Метрики в текстовом формате Prometheus", content_type = "text/plain")
    )
)]
/// Отдаёт метрики в формате экспозиции Prometheus.
///
/// Уровень доступа 4: статический Bearer-токен (`AUTH_METRICS_TOKEN`) — его
/// нативно умеют слать Prometheus (`authorization: {credentials_file}`), Zabbix
/// `agent2` и OTel Collector, через который метрики забирает Monium.
///
/// Токен — не замена сетевой изоляции: ручку всё равно не стоит публиковать
/// наружу, метрики раскрывают операционную картину (объём трафика, доли отказов,
/// латентности зависимостей).
///
/// Роут регистрируется в `main.rs` (не через атрибут-макрос), потому что ручка
/// оборачивается auth-middleware уровня 4 и публикуется **условно**: без
/// `AUTH_METRICS_TOKEN` её нет вовсе и путь отдаёт `404`.
pub async fn metrics(handle: web::Data<PrometheusHandle>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(handle.render())
}

#[utoipa::path(
    get,
    path = "/livez",
    responses(
        (status = 200, description = "Процесс жив")
    )
)]
/// Liveness-проба: подтверждает, что процесс жив.
///
/// Всегда возвращает `200 OK` без тела. Зависимости не проверяются — для этого
/// служит [`readyz`]. Предназначен для liveness-проверки оркестратора.
#[get("/livez")]
pub async fn livez() -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[utoipa::path(
    get,
    path = "/readyz",
    responses(
        (status = 200, body = ReadinessResponse, description = "Все зависимости доступны"),
        (status = 503, body = ReadinessResponse, description = "Одна из зависимостей недоступна")
    )
)]
/// Readiness-проба: проверяет доступность зависимостей.
///
/// Пингует Redis и запрашивает JWKS у `jwks-service-app`
/// (`GET /.well-known/jwks.json`). Возвращает `200 OK`, если обе зависимости
/// доступны, иначе `503 Service Unavailable`. В обоих случаях тело —
/// [`ReadinessResponse`] с детализацией по каждой зависимости.
#[get("/readyz")]
pub async fn readyz(redis: web::Data<RedisClient>, keys: web::Data<KeyManager>) -> HttpResponse {
    let redis_ok = redis.ping().await.is_ok();
    let jwks_ok = keys.check_jwks().await.is_ok();

    let body = ReadinessResponse {
        status: if redis_ok && jwks_ok {
            "ok"
        } else {
            "unavailable"
        }
        .into(),
        redis: redis_ok,
        jwks: jwks_ok,
    };

    if redis_ok && jwks_ok {
        HttpResponse::Ok().json(body)
    } else {
        HttpResponse::ServiceUnavailable().json(body)
    }
}

#[cfg(test)]
mod tests {
    //! Тесты HTTP-слоя: health/readiness и полный жизненный цикл токенов.
    //!
    //! `livez` не зависит от окружения. Для `readyz` зависимости (Redis и
    //! `jwks-service-app`) направляются на заведомо недоступные адреса, чтобы
    //! детерминированно проверить ветку `503` без реальной инфраструктуры.
    //!
    //! Эндпоинты токенов проверяются через `actix_web::test`: хранилище `jti`
    //! подменяется in-memory-моком [`MockStore`] (Redis не нужен), а сервис ключей
    //! `jwks-service-app` поднимается как HTTP-мок ([`wiremock`]) — так тесты
    //! проходят в CI без реальной инфраструктуры. Часть проверок конструирует токены
    //! напрямую (истёкший, с чужой подписью), чего нельзя добиться через публичный API.
    //!
    //! Обработчики регистрируются через обобщённые `*_impl`-реализации
    //! ([`create_token_impl`] и др.) с подстановкой [`MockStore`]; продакшн-обёртки
    //! (`create_token` и т.п.) идентичны им, но жёстко завязаны на [`RedisClient`].

    // `env_guard` намеренно держит std-`MutexGuard` через `.await`: `#[actix_web::test]`
    // запускает каждый тест на отдельном однопоточном рантайме, задача с потока не
    // мигрирует и одна на рантайм — так лок сериализует тесты по общим переменным
    // окружения без риска дедлока. Async-Mutex здесь избыточен.
    #![allow(clippy::await_holding_lock)]

    use super::*;
    use crate::models::jwt::{JsonWebToken, JtiError, RefreshRecord, TokenClaims, TokenHeaders};
    use crate::models::TokenResponse;
    use actix_web::http::header::HeaderValue;
    use actix_web::http::StatusCode;
    use actix_web::{test, App};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use chrono::Utc;
    use openssl::pkey::{PKey, Private};
    use parking_lot::Mutex as PlMutex;
    use serde_json::json;
    use std::collections::{HashMap, HashSet};
    use std::env;
    use std::sync::Mutex;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Тесты токенов правят процесс-глобальные переменные окружения
    /// (`JWKS_SERVICE_URL`, `TOKEN_ALGORITHM`, ...) и адрес JWKS-мока, поэтому
    /// выполняются строго последовательно. `readyz` тоже трогает `JWKS_SERVICE_URL`,
    /// так что берёт тот же лок. Восстанавливаемся после «отравления» (`into_inner`),
    /// чтобы паника одного теста не роняла остальные.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// In-memory реализация [`JtiStore`] для тестов HTTP-слоя.
    ///
    /// Группы ведутся по-настоящему (`group -> набор jti`), иначе тесты
    /// массового отзыва проверяли бы только код ответа, но не сам отзыв.
    struct MockStore {
        jtis: PlMutex<HashSet<String>>,
        groups: PlMutex<HashMap<String, HashSet<String>>>,
        /// Записи refresh-токенов и признак использования.
        refreshes: PlMutex<HashMap<String, (RefreshRecord, bool)>>,
        /// Отпечатки уже предъявленных TOTP-кодов.
        used_codes: PlMutex<HashSet<String>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                jtis: PlMutex::new(HashSet::new()),
                groups: PlMutex::new(HashMap::new()),
                refreshes: PlMutex::new(HashMap::new()),
                used_codes: PlMutex::new(HashSet::new()),
            }
        }
    }

    impl JtiStore for MockStore {
        async fn store_jti(&self, jti: &str, _ttl: u64) -> Result<(), JtiError> {
            self.jtis.lock().insert(jti.to_string());
            Ok(())
        }

        async fn check_jti(&self, jti: &str) -> Result<bool, JtiError> {
            Ok(self.jtis.lock().contains(jti))
        }

        async fn delete_jti(&self, jti: &str) -> Result<(), JtiError> {
            self.jtis.lock().remove(jti);
            Ok(())
        }

        async fn add_to_group(
            &self,
            group: &str,
            jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            self.groups
                .lock()
                .entry(group.to_string())
                .or_default()
                .insert(jti.to_string());
            Ok(())
        }

        async fn revoke_group(&self, group: &str) -> Result<u64, JtiError> {
            let members = self.groups.lock().remove(group).unwrap_or_default();

            let mut refreshes = self.refreshes.lock();
            let mut jtis = self.jtis.lock();

            // В группе семьи лежат и `jti`, и ключи refresh-записей — гасим и то,
            // и другое, как это делает `DEL` в Redis.
            let revoked = members
                .iter()
                .filter(|member| {
                    let refresh_removed = member
                        .strip_prefix("refresh:")
                        .is_some_and(|id| refreshes.remove(id).is_some());
                    jtis.remove(*member) || refresh_removed
                })
                .count();

            Ok(revoked as u64)
        }

        async fn store_refresh(
            &self,
            id: &str,
            record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            self.refreshes
                .lock()
                .insert(id.to_string(), (record.clone(), false));
            Ok(())
        }

        async fn get_refresh(&self, id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Ok(self
                .refreshes
                .lock()
                .get(id)
                .map(|(record, _)| record.clone()))
        }

        async fn mark_refresh_used(&self, id: &str) -> Result<bool, JtiError> {
            let mut refreshes = self.refreshes.lock();

            match refreshes.get_mut(id) {
                // Уже использован — повторное предъявление.
                Some((_, true)) => Ok(false),
                Some((_, used)) => {
                    *used = true;
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        async fn claim_totp_code(&self, hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            // `insert` возвращает false, если элемент уже был — это и есть повтор.
            Ok(self.used_codes.lock().insert(hash.to_string()))
        }
    }

    /// [`JtiStore`], у которого любая операция падает: имитирует недоступное
    /// хранилище.
    ///
    /// Нужен там, где проверяется не результат операции, а честность ответа при
    /// сбое: `MockStore` всегда успешен и такую ветку не покрывает.
    struct UnavailableStore;

    impl JtiStore for UnavailableStore {
        async fn store_jti(&self, _jti: &str, _ttl: u64) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn check_jti(&self, _jti: &str) -> Result<bool, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn delete_jti(&self, _jti: &str) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn add_to_group(
            &self,
            _group: &str,
            _jti: &str,
            _expires_at: i64,
        ) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn revoke_group(&self, _group: &str) -> Result<u64, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn store_refresh(
            &self,
            _id: &str,
            _record: &RefreshRecord,
            _ttl: u64,
        ) -> Result<(), JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn get_refresh(&self, _id: &str) -> Result<Option<RefreshRecord>, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn mark_refresh_used(&self, _id: &str) -> Result<bool, JtiError> {
            Err(JtiError::BadConnection)
        }

        async fn claim_totp_code(&self, _hash: &str, _ttl: u64) -> Result<bool, JtiError> {
            Err(JtiError::BadConnection)
        }
    }

    /// Тестовый ключ Ed25519 и его JWK-представление.
    ///
    /// `EdDSA` выбран потому, что подпись/проверка идут без явного дайджеста —
    /// ровно как в [`JsonWebToken::to_string`] / `from_string`, что гарантирует
    /// round-trip (см. также юнит-тесты в `models/jwt.rs`).
    struct TestKey {
        pkey: PKey<Private>,
        kid: String,
        /// Приватный ключ в base64url(PKCS#8 DER) — формат поля `private_key` JWK.
        private_b64: String,
        /// Сырой публичный ключ в base64url — компонент `x` JWK для OKP.
        x_b64: String,
    }

    fn make_key(kid: &str) -> TestKey {
        let pkey = PKey::generate_ed25519().unwrap();
        let pkcs8 = pkey.private_key_to_pkcs8().unwrap();
        let raw_public = pkey.raw_public_key().unwrap();
        TestKey {
            kid: kid.to_string(),
            private_b64: URL_SAFE_NO_PAD.encode(&pkcs8),
            x_b64: URL_SAFE_NO_PAD.encode(&raw_public),
            pkey,
        }
    }

    /// Поднимает HTTP-мок `jwks-service-app`, отдающий приватный ключ при выпуске
    /// (`POST /jwks`) и публичный — при проверке (`GET /.well-known/jwks.json`).
    async fn start_jwks_mock(key: &TestKey) -> MockServer {
        let server = MockServer::start().await;

        let jwk_data = json!({
            "id": key.kid, "kty": "OKP", "alg": "EdDSA", "kid": key.kid,
            "crv": "Ed25519", "x": key.x_b64, "y": null, "n": null, "e": null,
            "private_key": key.private_b64,
        });
        Mock::given(method("POST"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwk_data))
            .mount(&server)
            .await;

        let jwks = json!({ "keys": [ {
            "kty": "OKP", "alg": "EdDSA", "kid": key.kid, "crv": "Ed25519",
            "x": key.x_b64, "y": null, "n": null, "e": null,
        } ] });
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;

        server
    }

    /// Настраивает окружение под тестовый JWKS-мок с алгоритмом `EdDSA` и
    /// дефолтными границами TTL. Требует удержания [`env_guard`].
    fn set_jwks_env(server: &MockServer) {
        env::set_var("JWKS_SERVICE_URL", server.uri());
        env::set_var("TOKEN_ALGORITHM", "EdDSA");
        env::remove_var("TOKEN_JKU");
        env::remove_var("TOKEN_EXPIRATION_SECONDS");
        env::remove_var("TOKEN_TTL_MIN_SECONDS");
        env::remove_var("TOKEN_TTL_MAX_SECONDS");
        env::remove_var(crate::issuer::ALLOWLIST_VAR);
    }

    /// Собирает тестовое приложение с эндпоинтами токенов поверх [`MockStore`].
    ///
    /// Оформлено макросом, чтобы не выписывать громоздкий тип
    /// `App<impl ServiceFactory<...>>`. `KeyManager` конструируется здесь и читает
    /// `JWKS_SERVICE_URL` — вызывать после [`set_jwks_env`].
    macro_rules! token_app {
        ($store:expr) => {{
            let keys = web::Data::new(KeyManager::new("EdDSA".to_string()));
            App::new()
                .app_data($store)
                .app_data(keys)
                .route("/tokens", web::post().to(create_token_impl::<MockStore>))
                .route(
                    "/tokens/verify",
                    web::post().to(verify_token_impl::<MockStore>),
                )
                .route(
                    "/tokens/{jti}",
                    web::delete().to(revoke_token_impl::<MockStore>),
                )
                .route(
                    "/subjects/{sub}/tokens",
                    web::delete().to(revoke_subject_tokens_impl::<MockStore>),
                )
                .route(
                    "/tokens/refresh",
                    web::post().to(refresh_token_impl::<MockStore>),
                )
        }};
    }

    /// Выпускает токен на субъект `$sub` через тестовое приложение.
    ///
    /// Макрос, а не функция: тип приложения из `init_service` не выписывается
    /// без вороха дженериков (та же причина, что у `token_app!`).
    macro_rules! issue_token {
        ($app:expr, $sub:expr) => {{
            let req = test::TestRequest::post()
                .uri("/tokens")
                .insert_header(("Host", "example.com"))
                .set_json(json!({ "sub": $sub, "aud": ["api1"] }))
                .to_request();
            let resp = test::call_service($app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let issued: TokenResponse = test::read_body_json(resp).await;
            issued.token
        }};
    }

    /// Достаёт `jti` из сегмента claims сериализованного токена.
    fn jti_of(token: &str) -> String {
        let claims_segment = token.split('.').nth(1).expect("нет сегмента claims");
        TokenClaims::from_base64(claims_segment.to_string())
            .expect("claims не декодируются")
            .jti
    }

    #[actix_web::test]
    async fn livez_returns_200() {
        let app = test::init_service(App::new().service(livez)).await;
        let req = test::TestRequest::get().uri("/livez").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn metrics_route_absent_gives_404() {
        // Без токена роут не регистрируется (см. `main.rs`) — путь должен вести
        // себя как любой несуществующий: 404, а не 401. Так наружу не виден даже
        // факт существования ручки.
        let app = test::init_service(App::new().service(livez)).await;

        for req in [
            test::TestRequest::get().uri("/metrics").to_request(),
            test::TestRequest::get()
                .uri("/metrics")
                .insert_header(("Authorization", "Bearer anything"))
                .to_request(),
        ] {
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
    }

    #[actix_web::test]
    async fn metrics_returns_prometheus_exposition() {
        // Локальный recorder: глобальный ставится один раз на процесс и в тестах
        // недоступен (см. `metrics.rs`).
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        ::metrics::with_local_recorder(&recorder, || {
            crate::metrics::record_token_issued();
        });

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(handle))
                .route("/metrics", web::get().to(super::metrics)),
        )
        .await;
        let req = test::TestRequest::get().uri("/metrics").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(content_type.starts_with("text/plain"));

        let body = test::read_body(resp).await;
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("jwt_tokens_issued_total"));
    }

    #[actix_web::test]
    async fn readyz_reports_503_when_dependencies_unavailable() {
        let _guard = env_guard();

        // Порт 1 гарантированно недоступен — и Redis, и JWKS быстро падают с
        // «connection refused» независимо от окружения.
        env::set_var("REDIS_URL", "redis://127.0.0.1:1");
        env::set_var("JWKS_SERVICE_URL", "http://127.0.0.1:1");

        let redis = RedisClient::new().unwrap();
        let keys = KeyManager::new("RS256".to_string());

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(redis))
                .app_data(web::Data::new(keys))
                .service(readyz),
        )
        .await;

        let req = test::TestRequest::get().uri("/readyz").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body: ReadinessResponse = test::read_body_json(resp).await;
        assert_eq!(body.status, "unavailable");
        assert!(!body.redis);
        assert!(!body.jwks);
    }

    // --- Эндпоинты токенов ---

    /// Сквозной сценарий: выпуск → verify(ok) → revoke → verify(fail).
    #[actix_web::test]
    async fn token_lifecycle_issue_verify_revoke_verify() {
        let _guard = env_guard();
        let key = make_key("test-key-1");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store.clone())).await;

        // Выпуск.
        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "user1", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let issued: TokenResponse = test::read_body_json(resp).await;
        let jti = jti_of(&issued.token);

        // Проверка выпущенного токена — успех.
        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": issued.token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Отзыв.
        let req = test::TestRequest::delete()
            .uri(&format!("/tokens/{}", jti))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Повторная проверка того же токена — теперь отказ (jti отозван).
        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": issued.token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// `ttl` ниже нижней границы (дефолт — 1 секунда) → 422.
    #[actix_web::test]
    async fn create_token_rejects_ttl_below_min() {
        let _guard = env_guard();
        let key = make_key("k");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "u", "aud": ["api1"], "ttl": 0 }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// `ttl` выше верхней границы (дефолт — 86400 секунд) → 422.
    #[actix_web::test]
    async fn create_token_rejects_ttl_above_max() {
        let _guard = env_guard();
        let key = make_key("k");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "u", "aud": ["api1"], "ttl": 100_000 }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Пустой `aud` → 422.
    #[actix_web::test]
    async fn create_token_rejects_empty_audience() {
        let _guard = env_guard();
        let key = make_key("k");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "u", "aud": [] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Отсутствует заголовок `Host` → 400 (проверяется до обращения к JWKS).
    #[actix_web::test]
    async fn create_token_missing_host_returns_400() {
        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .set_json(json!({ "sub": "u", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Невалидный (не-ASCII) заголовок `Host` → 400.
    #[actix_web::test]
    async fn create_token_invalid_host_returns_400() {
        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            // 0xFF — не декодируется в ASCII, `to_str()` вернёт ошибку.
            .insert_header(("Host", HeaderValue::from_bytes(&[0xFF, 0xFE]).unwrap()))
            .set_json(json!({ "sub": "u", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Аллоулист issuer'ов: `Host` вне списка не выпускает токен (403), а
    /// перечисленный — выпускает.
    ///
    /// Это и есть закрываемая дыра: инстанс `a.example.com`, разделяющий ключи
    /// с `b.example.com`, не должен подписывать токены с чужим `iss`.
    #[actix_web::test]
    async fn create_token_rejects_issuer_outside_allowlist() {
        let _guard = env_guard();
        let key = make_key("kid-allowlist");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);
        env::set_var(crate::issuer::ALLOWLIST_VAR, "a.example.com");

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "b.example.com"))
            .set_json(json!({ "sub": "u", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "a.example.com"))
            .set_json(json!({ "sub": "u", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        env::remove_var(crate::issuer::ALLOWLIST_VAR);
    }

    /// Пустой аллоулист — прежнее поведение: любой `Host` выпускает токен.
    #[actix_web::test]
    async fn create_token_allows_any_issuer_without_allowlist() {
        let _guard = env_guard();
        let key = make_key("kid-no-allowlist");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "whatever.example.net"))
            .set_json(json!({ "sub": "u", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Проверка токена с `Host` вне аллоулиста → 401, как и любой другой отказ
    /// верификации: причину публичная ручка наружу не раскрывает.
    #[actix_web::test]
    async fn verify_rejects_issuer_outside_allowlist() {
        let _guard = env_guard();
        let key = make_key("kid-allowlist-verify");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        // Токен выпущен, пока ограничений не было...
        let token = issue_token!(&app, "user1");

        // ...а после включения аллоулиста его issuer стал чужим.
        env::set_var(crate::issuer::ALLOWLIST_VAR, "other.example.com");
        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        env::remove_var(crate::issuer::ALLOWLIST_VAR);
    }

    /// Проверка истёкшего токена → 401. `jti` в хранилище присутствует, чтобы
    /// единственной причиной отказа был `exp` в прошлом.
    #[actix_web::test]
    async fn verify_rejects_expired_token() {
        let _guard = env_guard();
        let key = make_key("test-key-1");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        store.store_jti("expired-jti", 3600).await.unwrap();
        let app = test::init_service(token_app!(store.clone())).await;

        let now = Utc::now().timestamp() as usize;
        let headers = TokenHeaders::create_new(key.kid.clone());
        let claims = TokenClaims {
            iss: "example.com".into(),
            sub: "u".into(),
            aud: vec!["api1".into()],
            exp: now - 10,
            iat: now - 3600,
            nbf: now - 3600,
            jti: "expired-jti".into(),
            extra: Default::default(),
        };
        let token = JsonWebToken::create_new(headers, claims, key.pkey.clone())
            .to_string()
            .unwrap();

        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Проверка токена с чужой подписью → 401. Токен подписан ключом атакующего,
    /// но с тем же `kid`; публичный ключ из JWKS его не подтверждает.
    #[actix_web::test]
    async fn verify_rejects_forged_signature() {
        let _guard = env_guard();
        let key = make_key("test-key-1");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        store.store_jti("forged-jti", 3600).await.unwrap();
        let app = test::init_service(token_app!(store.clone())).await;

        let attacker = make_key("test-key-1");
        let now = Utc::now().timestamp() as usize;
        let headers = TokenHeaders::create_new(key.kid.clone());
        let claims = TokenClaims {
            iss: "example.com".into(),
            sub: "u".into(),
            aud: vec!["api1".into()],
            exp: now + 3600,
            iat: now,
            nbf: now,
            jti: "forged-jti".into(),
            extra: Default::default(),
        };
        let token = JsonWebToken::create_new(headers, claims, attacker.pkey.clone())
            .to_string()
            .unwrap();

        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": token, "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Проверка синтаксически битого токена → 401 (без обращения к JWKS).
    #[actix_web::test]
    async fn verify_rejects_malformed_token() {
        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": "not-a-jwt", "audience": "api1" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Отзыв несуществующего `jti` идемпотентен → всегда 204.
    #[actix_web::test]
    async fn revoke_unknown_jti_returns_204() {
        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::delete()
            .uri("/tokens/does-not-exist")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[actix_web::test]
    async fn revoke_reports_store_failure_instead_of_204() {
        // Хранилище недоступно — отзыв не выполнен, и клиент обязан это узнать.
        // Прежнее поведение (всегда `204`) означало, что вызывающий считал
        // скомпрометированный токен погашенным и не повторял попытку.
        let store = web::Data::new(UnavailableStore);
        let app = test::init_service(App::new().app_data(store).route(
            "/tokens/{jti}",
            web::delete().to(revoke_token_impl::<UnavailableStore>),
        ))
        .await;

        let req = test::TestRequest::delete()
            .uri("/tokens/some-jti")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[actix_web::test]
    async fn revoking_subject_kills_all_its_tokens() {
        let _guard = env_guard();
        let key = make_key("kid-bulk");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store.clone())).await;

        // Три токена на одного субъекта и один — на другого.
        let mut tokens = Vec::new();
        for _ in 0..3 {
            tokens.push(issue_token!(&app, "victim"));
        }
        let bystander = issue_token!(&app, "bystander");

        let req = test::TestRequest::delete()
            .uri("/subjects/victim/tokens")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: RevokeGroupResponse = test::read_body_json(resp).await;
        assert_eq!(body.revoked, 3);

        // Токены субъекта больше не проходят проверку...
        for token in &tokens {
            assert!(!store.check_jti(&jti_of(token)).await.unwrap());
        }
        // ...а чужой не задет.
        assert!(store.check_jti(&jti_of(&bystander)).await.unwrap());
    }

    #[actix_web::test]
    async fn revoking_unknown_subject_is_idempotent() {
        let _guard = env_guard();
        let key = make_key("kid-none");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::delete()
            .uri("/subjects/nobody/tokens")
            .to_request();
        let resp = test::call_service(&app, req).await;

        // Нечего отзывать — это не ошибка.
        assert_eq!(resp.status(), StatusCode::OK);
        let body: RevokeGroupResponse = test::read_body_json(resp).await;
        assert_eq!(body.revoked, 0);
    }

    /// Выпускает пару access + refresh через тестовое приложение.
    macro_rules! issue_pair {
        ($app:expr, $sub:expr) => {{
            let req = test::TestRequest::post()
                .uri("/tokens")
                .insert_header(("Host", "example.com"))
                .set_json(json!({ "sub": $sub, "aud": ["api1"], "refresh": true }))
                .to_request();
            let resp = test::call_service($app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let issued: TokenResponse = test::read_body_json(resp).await;
            let refresh = issued.refresh_token.clone().expect("нет refresh-токена");
            (issued.token, refresh)
        }};
    }

    /// Обменивает refresh-токен, возвращая ответ целиком.
    macro_rules! exchange {
        ($app:expr, $refresh:expr) => {{
            let req = test::TestRequest::post()
                .uri("/tokens/refresh")
                .insert_header(("Host", "example.com"))
                .set_json(json!({ "refresh_token": $refresh }))
                .to_request();
            test::call_service($app, req).await
        }};
    }

    #[actix_web::test]
    async fn refresh_is_absent_unless_requested() {
        let _guard = env_guard();
        let key = make_key("kid-norefresh");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "sub": "user1", "aud": ["api1"] }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Контракт прежних клиентов не изменился: поля в ответе нет.
        let issued: TokenResponse = test::read_body_json(resp).await;
        assert!(issued.refresh_token.is_none());
    }

    #[actix_web::test]
    async fn refresh_rotates_and_old_token_stops_working() {
        let _guard = env_guard();
        let key = make_key("kid-rotate");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store.clone())).await;

        let (_access, refresh) = issue_pair!(&app, "user1");

        // Обмен выдаёт новую пару...
        let resp = exchange!(&app, &refresh);
        assert_eq!(resp.status(), StatusCode::OK);
        let refreshed: TokenResponse = test::read_body_json(resp).await;
        let new_refresh = refreshed.refresh_token.expect("нет нового refresh-токена");
        assert_ne!(new_refresh, refresh);

        // ...а новый access-токен валиден.
        let req = test::TestRequest::post()
            .uri("/tokens/verify")
            .insert_header(("Host", "example.com"))
            .set_json(json!({ "token": refreshed.token, "audience": "api1" }))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn reused_refresh_kills_the_whole_family() {
        let _guard = env_guard();
        let key = make_key("kid-reuse");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store.clone())).await;

        let (first_access, refresh) = issue_pair!(&app, "user1");

        // Законный обмен.
        let resp = exchange!(&app, &refresh);
        assert_eq!(resp.status(), StatusCode::OK);
        let refreshed: TokenResponse = test::read_body_json(resp).await;
        let new_refresh = refreshed.refresh_token.expect("нет нового refresh-токена");

        // Повторное предъявление старого токена — сигнал кражи.
        let resp = exchange!(&app, &refresh);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Гасится вся семья: и выданные access-токены...
        assert!(!store.check_jti(&jti_of(&first_access)).await.unwrap());
        assert!(!store.check_jti(&jti_of(&refreshed.token)).await.unwrap());

        // ...и refresh, выданный в законном обмене.
        let resp = exchange!(&app, &new_refresh);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn unknown_refresh_is_rejected() {
        let _guard = env_guard();
        let key = make_key("kid-unknown-refresh");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let resp = exchange!(&app, "no-such-token");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Обмен refresh-токена — тот же выпуск, поэтому `Host` вне аллоулиста
    /// отвергается так же явно (403), как и `POST /tokens`.
    #[actix_web::test]
    async fn refresh_rejects_issuer_outside_allowlist() {
        let _guard = env_guard();
        let key = make_key("kid-allowlist-refresh");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let (_access, refresh) = issue_pair!(&app, "user1");

        // Макрос обмена ходит с `Host: example.com` — теперь он вне списка.
        env::set_var(crate::issuer::ALLOWLIST_VAR, "other.example.com");
        let resp = exchange!(&app, &refresh);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        env::remove_var(crate::issuer::ALLOWLIST_VAR);
    }

    #[actix_web::test]
    async fn custom_claims_land_in_issued_token() {
        let _guard = env_guard();
        let key = make_key("kid-claims");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({
                "sub": "user1",
                "aud": ["api1"],
                "claims": { "role": "admin", "tenant": 42 }
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let issued: TokenResponse = test::read_body_json(resp).await;

        // Разбираем payload и проверяем, что claims лежат рядом с
        // зарегистрированными — потребитель токена ищет `role`, не `extra.role`.
        let payload = issued.token.split('.').nth(1).expect("нет сегмента claims");
        let decoded = URL_SAFE_NO_PAD.decode(payload).expect("base64url");
        let value: serde_json::Value = serde_json::from_slice(&decoded).expect("JSON");

        assert_eq!(value["role"], "admin");
        assert_eq!(value["tenant"], 42);
        assert_eq!(value["sub"], "user1");
    }

    #[actix_web::test]
    async fn reserved_custom_claim_gives_422() {
        let _guard = env_guard();
        let key = make_key("kid-reserved");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        // Подмена `exp` позволила бы обойти границы TTL — ручка обязана отказать.
        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(("Host", "example.com"))
            .set_json(json!({
                "sub": "user1",
                "aud": ["api1"],
                "claims": { "exp": 9999999999u64 }
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[actix_web::test]
    async fn token_without_claims_is_unchanged() {
        let _guard = env_guard();
        let key = make_key("kid-noclaims");
        let server = start_jwks_mock(&key).await;
        set_jwks_env(&server);

        let store = web::Data::new(MockStore::new());
        let app = test::init_service(token_app!(store)).await;

        // Контракт прежних клиентов: без поля `claims` payload остаётся ровно
        // таким, каким был до появления этой возможности.
        let token = issue_token!(&app, "user1");
        let payload = token.split('.').nth(1).expect("нет сегмента claims");
        let decoded = URL_SAFE_NO_PAD.decode(payload).expect("base64url");
        let value: serde_json::Value = serde_json::from_slice(&decoded).expect("JSON");

        let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 7, "лишние поля в payload: {keys:?}");
    }
}
