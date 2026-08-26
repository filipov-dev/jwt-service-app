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
    use std::collections::BTreeSet;

    /// Пути, которые зарегистрированы, но в спеке отсутствуют осознанно.
    ///
    /// Спека не описывает саму себя: ручка выдачи документа — это транспорт, а
    /// не часть контракта API. Список именно списком-исключением, а не «молча
    /// не проверяем»: любая другая незадокументированная ручка обязана уронить
    /// тест.
    const ROUTES_OUTSIDE_SPEC: &[&str] = &["/api-docs/openapi.json"];

    /// Пути, зарегистрированные в приложении, вычитанные из исходника.
    ///
    /// Способ грубый, но честный: перечислить роуты у собранного actix-приложения
    /// нельзя — `ResourceMap` наружу не отдаётся, а обход «дёрнем путь и
    /// посмотрим, не 404 ли» требует заранее знать, что дёргать, то есть ровно
    /// того списка, который мы и ищем. Поэтому читаем текст: роуты в этом сервисе
    /// регистрируются вручную строковыми литералами в одном месте
    /// (`configure_api`), см. «Соглашения и подводные камни» в `AGENTS.md`.
    ///
    /// Сканируется только тело `configure_api` и не-тестовая часть `handlers.rs`
    /// — иначе в список попали бы роуты из тестовых приложений соседних модулей.
    fn registered_routes() -> BTreeSet<&'static str> {
        // Тело `configure_api`: от сигнатуры до закрывающей скобки в нулевой
        // колонке. Внутри функции такой скобки нет — вложенные блоки отбиты.
        let main_rs = include_str!("main.rs");
        let body_start = main_rs
            .find("fn configure_api")
            .expect("configure_api не найдена в main.rs — тест отстал от кода");
        let body = &main_rs[body_start..];
        let body = &body[..body.find("\n}\n").expect("не найден конец configure_api") + 1];

        // `handlers.rs` — ради ручек на атрибут-макросах actix (`#[get("/livez")]`).
        // Тестовый модуль отрезаем: там свои приложения со своими роутами.
        let handlers_rs = include_str!("handlers.rs");
        let handlers_rs = &handlers_rs[..handlers_rs
            .find("#[cfg(test)]")
            .unwrap_or(handlers_rs.len())];

        // Вложенный scope с непустым префиксом сломал бы плоский разбор: путь
        // ручки собирался бы из префикса и литерала. Сейчас scope ровно один и
        // пустой; появится другой — тест упадёт, а не соврёт.
        for prefix in literals_after(body, "web::scope(\"") {
            assert!(
                prefix.is_empty(),
                "web::scope(\"{prefix}\") — непустой префиксный scope. Разбор роутов \
                 в этом тесте плоский и такой путь потеряет префикс; научите его \
                 склейке или перепишите регистрацию"
            );
        }

        let mut routes = BTreeSet::new();
        for (source, marker) in [
            (body, "web::resource(\""),
            (body, ".route(\""),
            (handlers_rs, "#[get(\""),
            (handlers_rs, "#[post(\""),
            (handlers_rs, "#[put(\""),
            (handlers_rs, "#[patch(\""),
            (handlers_rs, "#[delete(\""),
        ] {
            routes.extend(literals_after(source, marker).filter(|path| !path.is_empty()));
        }

        // Страховка на случай, если разбор сломается о новый способ регистрации:
        // пустой (или подозрительно короткий) список сделал бы тест зелёным
        // всегда. Число — заведомо ниже текущего, чтобы не править его на каждую
        // новую ручку.
        assert!(
            routes.len() >= 8,
            "разбор роутов нашёл всего {} путей ({routes:?}) — похоже, роуты стали \
             регистрировать иначе и тест ослеп",
            routes.len()
        );

        routes
    }

    /// Строковые литералы, идущие сразу за каждым вхождением `marker`.
    fn literals_after<'a>(
        source: &'a str,
        marker: &'a str,
    ) -> impl Iterator<Item = &'a str> + use<'a> {
        source
            .match_indices(marker)
            .map(move |(at, _)| &source[at + marker.len()..])
            .filter_map(|rest| rest.split_once('"').map(|(literal, _)| literal))
    }

    /// Спека перечисляет все опубликованные пути — и ровно их.
    ///
    /// Аннотации `#[utoipa::path]` живут на **обобщённых** обработчиках (JWT-60):
    /// потеряться при рефакторинге они могут молча — компилятор на это не ругается,
    /// а Swagger UI просто недосчитается ручки.
    ///
    /// Список ожидаемых путей **не захардкожен**, а вычитан из исходника, где
    /// роуты регистрируются. С ручным списком тест сторожил бы сам себя: новую
    /// ручку забыли бы и в `ApiDoc`, и в списке — оба теста остались бы
    /// зелёными, а файл спеки «актуальным» ровно в том смысле, что совпадает с
    /// неполным `ApiDoc`. Сверка с файлом ловит правки спеки, эта — расхождение
    /// спеки с приложением.
    #[test]
    fn openapi_spec_lists_all_endpoints() {
        let spec = ApiDoc::openapi();
        let documented: BTreeSet<&str> = spec.paths.paths.keys().map(String::as_str).collect();
        let registered = registered_routes();

        let missing: Vec<&&str> = registered
            .iter()
            .filter(|path| !documented.contains(*path) && !ROUTES_OUTSIDE_SPEC.contains(*path))
            .collect();
        assert!(
            missing.is_empty(),
            "ручки зарегистрированы, но не попали в OpenAPI-спеку: {missing:?}. \
             Нужна аннотация #[utoipa::path] на обработчике и регистрация в paths(...) выше"
        );

        let stale: Vec<&&str> = documented
            .iter()
            .filter(|path| !registered.contains(*path))
            .collect();
        assert!(
            stale.is_empty(),
            "в спеке есть пути, которых нет в приложении: {stale:?}. \
             Ручку убрали или переименовали — уберите её и из paths(...) выше"
        );
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
