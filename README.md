# jwt-service-app

[![CI](https://github.com/filipov-dev/jwt-service-app/actions/workflows/ci.yml/badge.svg)](https://github.com/filipov-dev/jwt-service-app/actions/workflows/ci.yml)
[![Audit](https://github.com/filipov-dev/jwt-service-app/actions/workflows/audit.yml/badge.svg)](https://github.com/filipov-dev/jwt-service-app/actions/workflows/audit.yml)
[![Docker Hub](https://img.shields.io/docker/v/filipov/jwt-service-app?sort=semver&label=docker%20hub)](https://hub.docker.com/r/filipov/jwt-service-app)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

HTTP-сервис на Rust (actix-web), который **выпускает, проверяет и отзывает
JWT** — и делает только это.

Если у вас несколько сервисов и им нужен общий формат аутентификации, обычный
путь — вкомпилировать библиотеку JWT в каждый и раздать всем приватный ключ.
`jwt-service-app` — альтернатива: ключ не покидает инфраструктуру ключей,
выпуск и проверка живут за HTTP-ручками, а отозвать конкретный токен можно, не
дожидаясь истечения его срока.

## Что он делает и чего не делает

**Делает:**

- выпускает JWT с произвольными claims и заданным TTL (`POST /tokens`);
- проверяет подпись, срок и `iss`/`aud`, а заодно — не отозван ли токен
  (`POST /tokens/verify`);
- выдаёт refresh-токен и меняет его на новую пару с ротацией
  (`POST /tokens/refresh`);
- отзывает токен по `jti` или все токены субъекта сразу
  (`DELETE /tokens/{jti}`, `DELETE /subjects/{sub}/tokens`);
- подписывает через RS256/384/512, ES256/384/512 и EdDSA;
- отдаёт метрики Prometheus, структурные логи, трейсы OpenTelemetry и ошибки в
  GlitchTip/Sentry.

**Не делает:**

- **не хранит и не генерирует ключи** — за это отвечает отдельный сервис
  `jwks-service-app`, к которому этот ходит по HTTP;
- **не терминирует TLS** — снаружи стоит обратный прокси, он же ставит секрет
  уровня 2 (см. ниже);
- **не заводит пользователей и не проверяет пароли** — это не сервис
  идентификации, он только оформляет уже принятое кем-то решение «этому
  субъекту токен выдать можно».

## Как он стоит в системе

```
              ┌──────────────────┐        Host → iss
   клиенты ──▶│ обратный   прокси│───────────────────┐
              │ (TLS, X-Proxy-…) │                   │
              └──────────────────┘                   ▼
                                            ┌──────────────────┐
   ваши бэкенды ─── X-TOTP-Code ───────────▶│ jwt-service-app  │
                                            └────────┬─────────┘
                                       приватный ключ│  │ jti, refresh
                                          и JWKS     ▼  ▼
                                 ┌──────────────────┐ ┌───────┐
                                 │ jwks-service-app │ │ Redis │
                                 └──────────────────┘ └───────┘
```

Без Redis и `jwks-service-app` сервис стартует, но `GET /readyz` отдаёт `503`:
слать на него трафик рано.

## Быстрый старт

```bash
docker run --rm -p 8080:8080 \
  -e HOST=0.0.0.0 \
  -e REDIS_URL=redis://redis:6379 \
  -e JWKS_SERVICE_URL=http://jwks-service-app:8080 \
  -e AUTH_PROXY_SECRET=... \
  -e AUTH_TOTP_SECRET=... \
  filipov/jwt-service-app:latest
```

`HOST=0.0.0.0` обязателен — дефолт `127.0.0.1` слушает только петлю внутри
контейнера. `AUTH_PROXY_SECRET` и `AUTH_TOTP_SECRET` тоже обязательны: без них
сервис **не стартует**, чтобы защиту нельзя было «забыть» включить. Образ
multi-arch (`linux/amd64`, `linux/arm64`), публикуется в Docker Hub и
`ghcr.io/filipov-dev/jwt-service-app`; для боевого стенда пинуйте версию, а не
`latest`.

Готовые манифесты Docker Compose и Kubernetes — в
[`deployments/prod/`](deployments/prod/README.md). Стенд для разработки (сервис,
Redis, Redis Commander, Postgres, `jwks-service-app`, Swagger UI) поднимается
из [`deployments/dev/docker-compose.yml`](deployments/dev/docker-compose.yml):

```bash
docker compose -p jwt-dev -f deployments/dev/docker-compose.yml up -d
```

Собрать и запустить без Docker (нужны Rust stable, Redis и `jwks-service-app`):

```bash
cargo run
```

## Ручки и уровни доступа

Доступ к эндпоинтам разграничен единым auth-middleware по четырём уровням;
уровень задаётся при регистрации роута, разница — только в валидаторе.

| Уровень | Эндпоинты | Защита |
|--------:|-----------|--------|
| **1 — открыт** | `GET /livez`, `GET /readyz`, `GET /api-docs/openapi.json` | нет |
| **2 — proxy-secret** | `POST /tokens/verify` | статический секрет-заголовок от обратного прокси (constant-time) |
| **3 — TOTP** | `POST /tokens`, `POST /tokens/refresh`, `DELETE /tokens/{jti}`, `DELETE /subjects/{sub}/tokens` | TOTP (RFC 6238), internal app-to-app |
| **4 — Bearer-токен** | `GET /metrics` (только если задан токен) | статический токен в `Authorization: Bearer` (constant-time) |

Невалидный или отсутствующий кред → `401`. Защиты основных ручек
**обязательны**: секреты уровней 2 и 3 (`AUTH_PROXY_SECRET`,
`AUTH_TOTP_SECRET`) должны быть заданы, иначе сервис **не стартует**. Уровень 4
— исключение: без `AUTH_METRICS_TOKEN` сервис стартует, а ручка `/metrics`
просто не публикуется (`404`).

**Уровень 2 держится на обратном прокси**: он ставит `X-Proxy-Secret` и
**обязан затирать клиентскую версию заголовка**, иначе секрет подставят снаружи
и уровень будет обойдён. Отсюда же следует, что порт контейнера не надо
публиковать наружу напрямую.

Полный контракт — OpenAPI-спека: `GET /api-docs/openapi.json` или
[`docs/openapi.json`](docs/openapi.json) в репозитории.

## Конфигурация

Всё настраивается переменными окружения; сводная таблица с дефолтами и
пояснениями — [AGENTS.md → Конфигурация](AGENTS.md#конфигурация-переменные-окружения).
Минимум для старта — пять переменных из «Быстрого старта» выше.

## Документация

- **Клиентские примеры уровня 3 (TOTP) на 30 языках** —
  [`docs/clients/`](docs/clients/README.md): генерация TOTP-кода из общего секрета
  и вызов защищённой ручки с заголовком `X-TOTP-Code`.
- **Конфиги reverse-proxy для уровня 2 (proxy-secret) на 10 прокси** —
  [`docs/proxy/`](docs/proxy/README.md): как инжектить секрет-заголовок И
  обязательно затирать клиентскую версию (nginx, Traefik, HAProxy, Envoy, Caddy,
  Apache, Kong, AWS ALB/API Gateway, Cloudflare, NGINX Ingress).
- **Observability: логи, метрики, трейсы, ошибки** —
  [`docs/observability.md`](docs/observability.md): что сервис отдаёт наружу, как
  включить и куда оно течёт (stdout/JSON, Prometheus и Zabbix, OpenTelemetry и
  Monium, GlitchTip), сводная таблица переменных и готовые конфиги.
- **OpenAPI** — `GET /api-docs/openapi.json` (security-схемы `proxy_secret`,
  `totp` и `metrics_token` для уровней 2, 3 и 4). Тот же документ лежит в
  репозитории — [`docs/openapi.json`](docs/openapi.json), поэтому изменения
  контракта видно в диффе PR.
- **Прод-деплой: Docker Compose и Kubernetes** —
  [`deployments/prod/`](deployments/prod/README.md): манифесты с пробами на
  `/livez` и `/readyz`, секреты из `.env`/`Secret`, заполненный
  `RATE_LIMIT_TRUSTED_PROXIES`.
- **Архитектура, команды, соглашения и подводные камни** —
  [AGENTS.md](AGENTS.md): карта модулей, устройство auth-middleware и rate
  limiting, полный список переменных окружения и разбор принятых решений.
- **Как сообщить об уязвимости** — [`SECURITY.md`](SECURITY.md): приватный
  канал вместо публичного issue, сроки ответа и раскрытия, поддерживаемые
  версии и что уязвимостью не считается.
- **Аудит истории на секреты** —
  [`docs/security/secret-audit.md`](docs/security/secret-audit.md): чем и по
  каким ссылкам просканирована история, разбор находок и что делать, если
  сканер нашёл настоящий секрет.
- **Аудит CI на PR с форков** —
  [`docs/security/workflow-audit.md`](docs/security/workflow-audit.md): что
  получает автор враждебного PR в публичном репозитории, почему секреты ему
  недоступны и что проверять, добавляя workflow.
- **Что изменилось между версиями образа** — [`CHANGELOG.md`](CHANGELOG.md):
  разделы собираются из истории коммитов, те же тексты уходят в описание
  каждого GitHub Release.

## Стек

Rust (edition 2021, канал `stable` из `rust-toolchain.toml`), actix-web 4,
`openssl` для подписи и проверки, Redis для `jti` и refresh-токенов, `utoipa`
для OpenAPI, `tracing` + OpenTelemetry + Prometheus для телеметрии. Все
зависимости — под permissive-лицензиями (MIT / Apache-2.0): copyleft-крейты не
тянем, потому что образы раздаются публично.

## Участие

Баг-репорты, идеи и pull request'ы приветствуются. Как собрать, что прогнать
перед PR и как оформить коммит — [CONTRIBUTING.md](CONTRIBUTING.md); правила
общения — [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Безопасность

Нашли уязвимость — **не открывайте публичный issue**. Приватный адвайзори на
GitHub (вкладка Security → Report a vulnerability) или письмо на
[security@filipov.dev](mailto:security@filipov.dev). Подтверждение получения —
за 72 часа, вердикт — за 7 дней, раскрытие — скоординированное. Полная политика
со списком того, что уязвимостью не считается, — в [`SECURITY.md`](SECURITY.md).

## Лицензия

[Apache-2.0](LICENSE). Выбрана из-за явного патентного гранта (раздел 3
лицензии): для криптографического сервиса он существеннее краткости MIT.
Форкать, менять и использовать образ в коммерческих продуктах можно —
сохраните текст лицензии и укажите, что файлы менялись.
