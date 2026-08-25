//! Аллоулист issuer'ов (`TOKEN_ISSUER_ALLOWLIST`).
//!
//! Значение claim `iss` берётся из заголовка `Host` запроса, а не из конфига
//! (см. [`crate::handlers`]). Это удобно — один образ обслуживает несколько
//! доменов, — но без ограничений клиент выбирает `iss` сам. Когда два инстанса
//! делят один `jwks-service-app`, у инстанса `A` можно выпустить токен с
//! `Host: b.example.com`: подпись сделана общим ключом, и инстанс `B` такой
//! токен примет как свой.
//!
//! Аллоулист закрывает это: если список задан, `Host` вне него отвергается.
//! Пустой/незаданный список — прежнее поведение (любой `Host`), чтобы
//! обновление не ломало текущие деплои.
//!
//! Сравнение регистронезависимое (имена хостов регистронезависимы), но в
//! остальном точное: порт — часть значения (`example.com` и `example.com:8443`
//! различны), так как именно строка `Host` целиком уезжает в `iss` и с ней же
//! сверяется при проверке токена.

use std::env;

use tracing::{info, warn};

/// Имя переменной окружения со списком разрешённых `iss`.
pub const ALLOWLIST_VAR: &str = "TOKEN_ISSUER_ALLOWLIST";

/// Разбирает аллоулист из окружения: значения через запятую, пустые элементы
/// пропускаются, регистр нормализуется к нижнему.
///
/// Читается на каждый запрос, как и остальная конфигурация токенов
/// (`TOKEN_EXPIRATION_SECONDS` и соседи): список короткий, а лишнего состояния
/// в обработчиках не заводим.
fn allowlist() -> Vec<String> {
    parse(&env::var(ALLOWLIST_VAR).unwrap_or_default())
}

/// Разбирает сырое значение аллоулиста (вынесено из [`allowlist`], чтобы тесты
/// не трогали процесс-глобальное окружение).
fn parse(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Разрешён ли `host` в качестве `iss`.
///
/// Пустой или незаданный аллоулист разрешает любой `Host`.
pub fn is_allowed(host: &str) -> bool {
    allowed_by(&allowlist(), host)
}

/// Проверка по уже разобранному списку.
fn allowed_by(allowed: &[String], host: &str) -> bool {
    allowed.is_empty() || allowed.iter().any(|a| a == &host.to_ascii_lowercase())
}

/// Пишет в лог сводку конфигурации на старте.
///
/// Незаданный список — не ошибка, но о нём предупреждаем: в конфигурации с
/// общим `jwks-service-app` это открытый выпуск токенов от чужого имени.
pub fn log_summary() {
    let allowed = allowlist();
    if allowed.is_empty() {
        warn!(
            "{ALLOWLIST_VAR} не задан: claim iss берётся из заголовка Host без проверки. \
             Если инстансы делят один jwks-service-app, задайте список разрешённых issuer'ов."
        );
    } else {
        info!("Разрешённые issuer (iss): {}", allowed.join(", "));
    }
}

#[cfg(test)]
mod tests {
    //! Разбор и сверка проверяются на чистых функциях: процесс-глобальную
    //! переменную окружения тесты не трогают, иначе они конфликтовали бы с
    //! тестами HTTP-слоя, бегущими параллельно.

    use super::*;

    #[test]
    fn empty_allowlist_allows_any_host() {
        assert!(allowed_by(&parse(""), "example.com"));
        assert!(allowed_by(&parse(""), "evil.example.net"));

        // Заданный, но пустой по содержанию список — тоже «без ограничений»:
        // иначе лишняя запятая в конфиге молча закрывала бы выпуск целиком.
        assert!(allowed_by(&parse(" , ,"), "example.com"));
    }

    #[test]
    fn allowlist_accepts_listed_and_rejects_others() {
        let allowed = parse("a.example.com, b.example.com");
        assert!(allowed_by(&allowed, "a.example.com"));
        assert!(allowed_by(&allowed, "b.example.com"));
        assert!(!allowed_by(&allowed, "c.example.com"));
    }

    #[test]
    fn matching_is_case_insensitive_but_port_sensitive() {
        let allowed = parse("A.Example.COM, b.example.com:8443");
        assert!(allowed_by(&allowed, "a.example.com"));
        assert!(allowed_by(&allowed, "A.EXAMPLE.COM"));
        assert!(allowed_by(&allowed, "b.example.com:8443"));
        // Порт — часть значения `Host`, а значит и `iss`.
        assert!(!allowed_by(&allowed, "a.example.com:8443"));
        assert!(!allowed_by(&allowed, "b.example.com"));
    }
}
