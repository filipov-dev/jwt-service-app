//! Описание OpenAPI-спецификации и её выгрузка в файл.
//!
//! Здесь живёт корневой описатель [`ApiDoc`], из которого `utoipa` собирает
//! спеку, и код, который выгружает её в `docs/openapi.json`. Спека **лежит в
//! репозитории** (JWT-59): в рантайме она доступна на
//! `GET /api-docs/openapi.json`, но пока её не было в git, изменение контракта
//! API не оставляло следа в диффе — ломающую правку нельзя было заметить на
//! ревью.
//!
//! Выгрузка живёт под `#[cfg(test)]` и делается тестом
//! `spec_file_is_up_to_date`: `UPDATE_OPENAPI=1 cargo test openapi` переписывает
//! файл, обычный прогон сверяет его с кодом. Отдельный бинарь-генератор
//! пришлось бы ещё и не забывать запускать, а тест уже гоняет CI на каждый PR —
//! разойтись со спекой файл не может.

use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

// Импортируется модулем, а не пофункционально: `utoipa` берёт **текст** пути из
// `paths(...)` как имя тега, под которым ручки группируются в Swagger UI. С
// `crate::handlers::create_token` тег стал бы `crate::handlers`.
use crate::handlers;
use crate::models::{
    ErrorResponse, ReadinessResponse, RefreshRequest, RevokeGroupResponse, TokenRequest,
    TokenResponse,
};

/// Путь к выгруженной спеке относительно корня репозитория.
///
/// Вместе с хелперами выгрузки — только для тестов: в рантайме сервис отдаёт
/// спеку из памяти и файл ему не нужен.
#[cfg(test)]
const SPEC_PATH: &str = "docs/openapi.json";

/// Корневой описатель OpenAPI-документации.
///
/// Перечисляет пути (эндпоинты) и компоненты-схемы, из которых `utoipa`
/// генерирует OpenAPI-спецификацию. При добавлении нового эндпоинта его нужно
/// зарегистрировать здесь в `paths(...)`, а новые DTO — в `components(schemas(...))`,
/// иначе они не попадут в спеку. После правки перегенерируйте файл спеки:
/// `UPDATE_OPENAPI=1 cargo test openapi`.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::create_token,
        handlers::verify_token,
        handlers::refresh_token,
        handlers::revoke_token,
        handlers::revoke_subject_tokens,
        handlers::livez,
        handlers::readyz,
        handlers::metrics
    ),
    components(schemas(
        TokenRequest,
        TokenResponse,
        ErrorResponse,
        ReadinessResponse,
        RefreshRequest,
        RevokeGroupResponse
    )),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

/// Регистрирует security-схемы для уровней доступа 2 и 3.
///
/// Уровень 2 (`proxy_secret`) и уровень 3 (`totp`) требуют заголовка-`apiKey`.
/// Имена заголовков — дефолтные (`X-Proxy-Secret` / `X-TOTP-Code`); при их
/// переопределении через env обновите и описание в OpenAPI. Уровень 1 (health,
/// OpenAPI) защиты не требует и схем не имеет.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        // `components` уже создан, т.к. в схеме есть зарегистрированные DTO.
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "proxy_secret",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "X-Proxy-Secret",
                    "Уровень 2: статический секрет, проставляемый обратным прокси. \
                     Прокси ОБЯЗАН затирать клиентскую версию заголовка.",
                ))),
            );
            components.add_security_scheme(
                "totp",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "X-TOTP-Code",
                    "Уровень 3: текущий TOTP-код (RFC 6238) на общем секрете.",
                ))),
            );
            components.add_security_scheme(
                "metrics_token",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some(
                            "Уровень 4: статический Bearer-токен для скрейпа /metrics \
                             (AUTH_METRICS_TOKEN).",
                        ))
                        .build(),
                ),
            );
        }
    }
}

/// Абсолютный путь к [`SPEC_PATH`] в дереве исходников.
///
/// Корень берётся из `CARGO_MANIFEST_DIR` — переменной времени компиляции, а не
/// из текущего каталога процесса: тесты cargo запускает из корня, но полагаться
/// на это не стоит.
#[cfg(test)]
fn spec_file() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SPEC_PATH)
}

/// Спека в том виде, в каком она лежит в файле.
///
/// Формат — pretty-JSON с переводом строки на конце: так дифф в PR читается
/// построчно, а не одной длинной строкой, и файл не «безымянный» для утилит,
/// ожидающих текст.
#[cfg(test)]
fn spec_json() -> String {
    let mut json = ApiDoc::openapi()
        .to_pretty_json()
        .expect("OpenAPI-спека не сериализуется в JSON");
    json.push('\n');
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Спека перечисляет все опубликованные пути.
    ///
    /// Аннотации `#[utoipa::path]` живут на **обобщённых** обработчиках (JWT-60):
    /// потеряться при рефакторинге они могут молча — компилятор на это не ругается,
    /// а Swagger UI просто недосчитается ручки.
    #[test]
    fn openapi_spec_lists_all_endpoints() {
        let spec = ApiDoc::openapi();
        for expected in [
            "/tokens",
            "/tokens/verify",
            "/tokens/refresh",
            "/tokens/{jti}",
            "/subjects/{sub}/tokens",
            "/livez",
            "/readyz",
            "/metrics",
        ] {
            assert!(
                spec.paths.paths.contains_key(expected),
                "{expected} отсутствует в OpenAPI-спеке"
            );
        }
    }

    /// Файл спеки в репозитории совпадает с тем, что генерирует код.
    ///
    /// Этот же тест и **выгружает** спеку: с `UPDATE_OPENAPI=1` он переписывает
    /// файл вместо сравнения. Одна точка входа вместо пары «генератор + чекер»,
    /// которые расходятся между собой; регенерация вызывается ровно тем же
    /// кодом, который в CI сторожит актуальность.
    ///
    /// Без такой проверки выгрузка мертва по построению: файл разошёлся бы со
    /// спекой при первой же правке контракта, и дифф в PR перестал бы что-либо
    /// значить.
    ///
    /// Учтите: `info.version` в спеке — это версия из `Cargo.toml`, поэтому
    /// подъём версии тоже требует регенерации. Специально исключать это поле не
    /// стали: файл в репозитории должен быть ровно тем, что отдаёт сервис,
    /// иначе это уже не снимок контракта, а его пересказ.
    #[test]
    fn spec_file_is_up_to_date() {
        let path = spec_file();
        let generated = spec_json();

        if std::env::var_os("UPDATE_OPENAPI").is_some() {
            std::fs::write(&path, &generated)
                .unwrap_or_else(|e| panic!("не удалось записать {}: {e}", path.display()));
            return;
        }

        let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{} не читается ({e}). Выгрузите спеку: UPDATE_OPENAPI=1 cargo test openapi",
                path.display()
            )
        });

        // Не `assert_eq!`: он вывалил бы в отчёт обе спеки целиком (сотни строк),
        // и настоящая разница в них утонула бы. Что именно поменялось, видно в
        // `git diff` после регенерации.
        assert!(
            committed == generated,
            "{SPEC_PATH} разошёлся с кодом. Если контракт API менялся осознанно \
             (или поднята версия в Cargo.toml — она попадает в info.version), \
             перегенерируйте файл: UPDATE_OPENAPI=1 cargo test openapi"
        );
    }
}
