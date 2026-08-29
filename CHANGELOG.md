# Changelog

All notable changes to this project. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the versions follow
[semantic versioning](https://semver.org/).

The file is assembled from the commit history and regenerated with
`scripts/changelog.sh --all`; the body of every GitHub release is built by the
same script. The entries are commit subjects verbatim, with the task key in
parentheses — `JWT-NNN` is an identifier in the maintainer's own issue tracker,
which is not public, so it records where a change came from rather than linking
anywhere.

**One section per release, not per version bump.** The version is bumped by
every commit while a tag is created only for the last of them, so the numbers
here have gaps (1.11.0, 1.12.0, 1.12.1). Nothing is lost: those commits belong
to the section of the tag that followed them.

Two sections are added to the six of Keep a Changelog: "Documentation" (client
examples and operating instructions — changes for the consumer of the service)
and "Internal" (CI, tests, formatting).

Entries before 1.17.13 are in Russian: the repository switched to English in
JWT-114 and the commit history was deliberately left as it was.

## [1.17.17] - 2026-08-29

### Documentation

- refresh the secret audit verdict and rebuild the changelog before publication (JWT-72)

## [1.17.16] - 2026-08-29

### Fixed

- rebuild CHANGELOG.md from the history and gate it in CI (JWT-115)

## [1.17.15] - 2026-08-29

### Documentation

- remove internal references from AGENTS.md and docs before publication (JWT-64)
- split the pre-publication settings checklist by what a private repository allows (JWT-64)

## [1.17.13] - 2026-08-29

### Documentation

- switch the repository to English, with a CI language gate (JWT-114)

## [1.17.12] - 2026-08-28

### Documentation

- CONTRIBUTING, кодекс поведения, шаблоны issue/PR и README для внешнего читателя (JWT-58)

## [1.17.11] - 2026-08-28

### Internal

- bump parking_lot from 0.12.3 to 0.12.5
- bump serde_json from 1.0.138 to 1.0.151
- bump uuid from 1.24.0 to 1.25.0
- bump redis from 1.2.4 to 1.6.0
- bump thiserror from 2.0.19 to 2.0.20
- bump actions/upload-artifact from 4 to 7
- bump docker/login-action from 4.5.2 to 4.6.0
- bump actions/download-artifact from 4 to 8
- bump actix-web from 4.9.0 to 4.14.0
- релиз 1.17.11 (JWT-113)

### Other

- JWT-113: миграция на sentry 0.49

## [1.17.10] - 2026-08-27

### Documentation

- SECURITY.md — приватный канал для сообщений об уязвимостях, сроки и поддерживаемые версии (JWT-57)

## [1.17.9] - 2026-08-27

### Documentation

- Apache-2.0 — LICENSE, поле license в Cargo.toml и метки образа (JWT-56)

## [1.17.8] - 2026-08-27

### Security

- аудит workflow на PR с форков (JWT-54)

## [1.17.7] - 2026-08-26

### Internal

- релизный профиль — fat LTO, один codegen-unit, strip символов (JWT-47)

## [1.17.6] - 2026-08-26

### Internal

- единственный TLS-стек в бинаре — native-tls вместо rustls (JWT-46)

## [1.17.5] - 2026-08-26

### Documentation

- английские комментарии в клиентских примерах (JWT-63)
- вернуть содержательность английским комментариям (JWT-63)

### Internal

- выгрузка OpenAPI-спеки в docs/openapi.json (JWT-59)
- сверка путей спеки с реально зарегистрированными роутами (JWT-59)

## [1.17.3] - 2026-08-25

### Internal

- расшить шов JtiStore от Redis (JWT-60)

## [1.17.2] - 2026-08-25

### Security

- аудит истории на секреты и гейт gitleaks/trufflehog в CI (JWT-52)

## [1.17.1] - 2026-08-25

### Added

- явный shutdown_timeout HTTP-сервера, согласованный с grace period (JWT-48)

### Internal

- .DS_Store в .gitignore (JWT-48)

## [1.16.1] - 2026-08-25

### Added

- stale-while-revalidate для кеша JWKS (JWT-50)

### Fixed

- короткая отсрочка stale-снимка JWKS и readiness по снимку (JWT-50)

## [1.15.2] - 2026-08-25

### Added

- аллоулист issuer'ов TOKEN_ISSUER_ALLOWLIST (JWT-55)

### Fixed

- обновление h2 до 0.4.19 и ignore RUSTSEC-2026-0258 (JWT-55)
- выключена фича http2 у actix-web, ignore RUSTSEC-2026-0258 снят (JWT-55)

## [1.14.1] - 2026-08-25

### Documentation

- PodDisruptionBudget, разнос реплик и NetworkPolicy в k8s-манифестах (JWT-49)

## [1.14.0] - 2026-07-31

### Added

- воркеры actix по квоте CPU и явные таймауты соединений (JWT-37)

## [1.13.5] - 2026-07-31

### Internal

- rust-toolchain.toml — единый тулчейн с CI (JWT-45)

## [1.13.4] - 2026-07-31

### Documentation

- prod-манифесты для Docker Compose и Kubernetes (JWT-32)

## [1.13.3] - 2026-07-31

### Internal

- bump redis from 0.29.0 to 1.2.4
- клиент Redis под API redis 1.x
- версия 1.13.3

## [1.13.2] - 2026-07-31

### Internal

- bump peter-evans/dockerhub-description from 3 to 5
- bump docker/build-push-action from 6 to 7
- bump docker/setup-buildx-action from 3 to 4
- bump chrono from 0.4.39 to 0.4.45
- bump utoipa from 5.3.1 to 5.5.0
- bump uuid from 1.13.2 to 1.24.0
- bump reqwest from 0.12.12 to 0.13.4
- bump actions/checkout from 4 to 7
- bump actix-cors from 0.7.0 to 0.7.1
- bump docker/login-action from 3 to 4.5.2
- версия 1.13.2, deps-коммиты в разделе «Внутреннее» changelog'а

## [1.13.1] - 2026-07-31

### Documentation

- CHANGELOG и генерация описания релиза из коммитов (JWT-33)

## [1.13.0] - 2026-07-30

### Added

- пользовательские claims в POST /tokens (JWT-30)

### Documentation

- claims в демо-вызове perl-примера (JWT-30)

## [1.12.3] - 2026-07-30

### Documentation

- примеры всех четырёх ручек уровня 3 на 30 языках (JWT-36)

## [1.12.2] - 2026-07-29

### Added

- защита от переигрывания TOTP-кода (JWT-31)

### Fixed

- clippy 1.97 — manual_option_zip в auth-middleware (JWT-31)

### Documentation

- правило «один код — один запрос» для клиентов (JWT-31)

## [1.11.3] - 2026-07-29

### Fixed

- DELETE /tokens/{jti} сообщает о недоступности хранилища (JWT-35)

## [1.11.2] - 2026-07-29

### Internal

- покрыть уровни доступа, фасад JwtManager и DTO (JWT-27)

## [1.11.1] - 2026-07-29

### Added

- refresh-токены с ротацией и детектором повторного использования (JWT-28)

### Fixed

- обмен refresh-токена закрыт уровнем 3 (TOTP), а не proxy-secret (JWT-28)

## [1.10.0] - 2026-07-29

### Added

- массовый отзыв токенов субъекта (JWT-29)

## [1.9.3] - 2026-07-29

### Fixed

- новый ключ создаётся только на 404 от сервиса ключей (JWT-22)

## [1.9.2] - 2026-07-29

### Fixed

- таймауты HTTP-клиента к сервису ключей (JWT-23)

## [1.9.1] - 2026-07-29

### Fixed

- переиспользование соединения Redis вместо коннекта на каждую команду (JWT-24)

## [1.9.0] - 2026-07-28

### Added

- кеш JWKS и общий HTTP-клиент на верификации (JWT-25)

## [1.8.5] - 2026-07-27

### Internal

- нагрузочный тест /tokens/verify и baseline до оптимизаций (JWT-34)

## [1.8.4] - 2026-07-26

### Internal

- устранить замечания clippy перед включением строгого режима (JWT-26)
- применить cargo fmt ко всему проекту (JWT-26)
- строгий clippy, проверка форматирования и запуск на push в master (JWT-26)

## [1.8.1] - 2026-07-26

### Documentation

- итоговая инструкция по observability (JWT-15)

## [1.8.0] - 2026-07-26

### Added

- отправка логов по OTLP — сигнал logs рядом с трейсами (JWT-20)

## [1.7.0] - 2026-07-26

### Added

- без AUTH_METRICS_TOKEN сервис не падает — ручка /metrics просто не публикуется (JWT-21)

## [1.6.0] - 2026-07-26

### Added

- GlitchTip — ошибки, performance и логи (JWT-19)

## [1.5.0] - 2026-07-25

### Added

- распределённый трейсинг OpenTelemetry — OTLP-экспорт в коллектор (JWT-18)

## [1.4.0] - 2026-07-25

### Added

- метрики Prometheus на /metrics (JWT-17)
- /metrics закрыт Bearer-токеном — уровень доступа 4 (JWT-17)

## [1.3.0] - 2026-07-25

### Added

- структурное логирование — JSON-формат, request-id, span на запрос (JWT-16)
- осмысленные уровни логирования debug/info/warn/error (JWT-16)

## [1.2.0] - 2026-07-25

### Added

- CORS только на /tokens/verify через CORS_ALLOWED_ORIGINS + доки и dependabot (JWT-14)
- запрещающий CORS (deny_cors) на всех ручках кроме /tokens/verify (JWT-14)

## [1.1.1] - 2026-07-25

### Changed

- кеширование зависимостей в Docker-сборке через cargo-chef + GHA cache (JWT-6)

## [1.1.0] - 2026-07-25

### Added

- rate limiting — per-IP на /tokens/verify и опц. глобальный cap на internal (JWT-11)

## [1.0.0] - 2026-07-24

### Fixed

- сделать защиты уровней 2/3 обязательными и починить Docker-сборку (JWT-12)

## [0.3.0] - 2026-07-24

### Added

- многоуровневый доступ (proxy-secret + TOTP) и клиентские примеры (JWT-12)

## [0.2.3] - 2026-07-24

### Internal

- добавить cargo audit в CI и починить уязвимости зависимостей (JWT-10)

## [0.2.2] - 2026-07-24

### Fixed

- согласовать дайджест подписи и проверки для RS*/ES* (JWT-13)

## [0.2.1] - 2026-07-24

### Internal

- интеграционные тесты HTTP-слоя токенов (JWT-9)

## [0.2.0] - 2026-07-24

### Added

- добавить health/readiness эндпоинты /livez и /readyz (JWT-8)

### Fixed

- fail-fast при ошибке записи jti в Redis при выпуске токена (JWT-7)

### Documentation

- уточнить правила выбора разряда версии по semver

## [0.1.10] - 2026-07-24

### Internal

- отключить provenance-аттестации в multi-arch сборке (JWT-5)

## [0.1.9] - 2026-07-24

### Internal

- собирать arm64-образ нативно вместо эмуляции QEMU (JWT-5)

## [0.1.8] - 2026-07-24

### Added

- возвращать структурированные тела ошибок в ответах (JWT-3)

## [0.1.7] - 2026-07-24

### Internal

- убрать unwrap() из доменного кода, вернуть Result (JWT-2)

## [0.1.6] - 2026-07-24

### Added

- кастомный TTL токена при выпуске (JWT-4)

### Internal

- unit-тесты на JWT, claims и реконструкцию ключей (JWT-1)
- прогонять clippy, build и test на каждый PR
- запускать только на pull_request, без дубля на push

## [0.1.5] - 2026-07-24

### Documentation

- add AGENTS.md and inline code documentation
- ссылка на приватный AGENTS_INTERNAL.md, добавлен в .gitignore
- правило поднимать версию с каждым коммитом; bump 0.1.5

## [0.1.4] - 2025-08-10

### Other

- Update Dockerfile
- Update Cargo.toml

## [0.1.3] - 2025-02-26

### Other

- Clean

## [0.1.2] - 2025-02-26

### Other

- Init
- Init
- Build

## [0.1.0] - 2025-02-26

### Other

- Init

[Unreleased]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.17...HEAD
[1.17.17]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.16...v1.17.17
[1.17.16]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.15...v1.17.16
[1.17.15]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.13...v1.17.15
[1.17.13]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.12...v1.17.13
[1.17.12]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.11...v1.17.12
[1.17.11]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.10...v1.17.11
[1.17.10]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.9...v1.17.10
[1.17.9]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.8...v1.17.9
[1.17.8]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.7...v1.17.8
[1.17.7]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.6...v1.17.7
[1.17.6]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.5...v1.17.6
[1.17.5]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.3...v1.17.5
[1.17.3]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.2...v1.17.3
[1.17.2]: https://github.com/filipov-dev/jwt-service-app/compare/v1.17.1...v1.17.2
[1.17.1]: https://github.com/filipov-dev/jwt-service-app/compare/v1.16.1...v1.17.1
[1.16.1]: https://github.com/filipov-dev/jwt-service-app/compare/v1.15.2...v1.16.1
[1.15.2]: https://github.com/filipov-dev/jwt-service-app/compare/v1.14.1...v1.15.2
[1.14.1]: https://github.com/filipov-dev/jwt-service-app/compare/v1.14.0...v1.14.1
[1.14.0]: https://github.com/filipov-dev/jwt-service-app/compare/v1.13.5...v1.14.0
[1.13.5]: https://github.com/filipov-dev/jwt-service-app/compare/v1.13.4...v1.13.5
[1.13.4]: https://github.com/filipov-dev/jwt-service-app/compare/v1.13.3...v1.13.4
[1.13.3]: https://github.com/filipov-dev/jwt-service-app/compare/v1.13.2...v1.13.3
[1.13.2]: https://github.com/filipov-dev/jwt-service-app/compare/v1.13.1...v1.13.2
[1.13.1]: https://github.com/filipov-dev/jwt-service-app/compare/v1.13.0...v1.13.1
[1.13.0]: https://github.com/filipov-dev/jwt-service-app/compare/v1.12.3...v1.13.0
[1.12.3]: https://github.com/filipov-dev/jwt-service-app/compare/v1.12.2...v1.12.3
[1.12.2]: https://github.com/filipov-dev/jwt-service-app/compare/v1.11.3...v1.12.2
[1.11.3]: https://github.com/filipov-dev/jwt-service-app/compare/v1.11.2...v1.11.3
[1.11.2]: https://github.com/filipov-dev/jwt-service-app/compare/v1.11.1...v1.11.2
[1.11.1]: https://github.com/filipov-dev/jwt-service-app/compare/v1.10.0...v1.11.1
[1.10.0]: https://github.com/filipov-dev/jwt-service-app/compare/v1.9.3...v1.10.0
[1.9.3]: https://github.com/filipov-dev/jwt-service-app/compare/v1.9.2...v1.9.3
[1.9.2]: https://github.com/filipov-dev/jwt-service-app/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/filipov-dev/jwt-service-app/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/filipov-dev/jwt-service-app/compare/v1.8.5...v1.9.0
[1.8.5]: https://github.com/filipov-dev/jwt-service-app/compare/v1.8.4...v1.8.5
[1.8.4]: https://github.com/filipov-dev/jwt-service-app/compare/v1.8.1...v1.8.4
[1.8.1]: https://github.com/filipov-dev/jwt-service-app/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/filipov-dev/jwt-service-app/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/filipov-dev/jwt-service-app/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/filipov-dev/jwt-service-app/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/filipov-dev/jwt-service-app/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/filipov-dev/jwt-service-app/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/filipov-dev/jwt-service-app/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/filipov-dev/jwt-service-app/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/filipov-dev/jwt-service-app/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/filipov-dev/jwt-service-app/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/filipov-dev/jwt-service-app/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/filipov-dev/jwt-service-app/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/filipov-dev/jwt-service-app/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/filipov-dev/jwt-service-app/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/filipov-dev/jwt-service-app/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/filipov-dev/jwt-service-app/compare/v0.1.10...v0.2.0
[0.1.10]: https://github.com/filipov-dev/jwt-service-app/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/filipov-dev/jwt-service-app/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/filipov-dev/jwt-service-app/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/filipov-dev/jwt-service-app/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/filipov-dev/jwt-service-app/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/filipov-dev/jwt-service-app/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/filipov-dev/jwt-service-app/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/filipov-dev/jwt-service-app/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/filipov-dev/jwt-service-app/compare/v0.1.0...v0.1.2
[0.1.0]: https://github.com/filipov-dev/jwt-service-app/releases/tag/v0.1.0
