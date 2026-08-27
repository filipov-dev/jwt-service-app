# jwt-service-app

HTTP-сервис на Rust (actix-web) для выпуска, проверки и отзыва JWT. Полное
описание архитектуры, команд и конфигурации — в [AGENTS.md](AGENTS.md).

## Многоуровневый доступ к API

Доступ к эндпоинтам разграничен единым auth-middleware по четырём уровням; уровень
задаётся при регистрации роута, разница — только в валидаторе.

| Уровень | Эндпоинты | Защита |
|--------:|-----------|--------|
| **1 — открыт** | `GET /livez`, `GET /readyz`, `GET /api-docs/openapi.json` | нет |
| **2 — proxy-secret** | `POST /tokens/verify` | статический секрет-заголовок от обратного прокси (constant-time) |
| **3 — TOTP** | `POST /tokens`, `DELETE /tokens/{jti}` | TOTP (RFC 6238), internal app-to-app |
| **4 — Bearer-токен** | `GET /metrics` (только если задан токен) | статический токен в `Authorization: Bearer` (constant-time) |

Невалидный или отсутствующий кред → `401`. Защиты основных ручек **обязательны**:
секреты уровней 2 и 3 (`AUTH_PROXY_SECRET`, `AUTH_TOTP_SECRET`) должны быть заданы,
иначе сервис **не стартует**. Уровень 4 — исключение: без `AUTH_METRICS_TOKEN`
сервис стартует, а ручка `/metrics` просто не публикуется (`404`). Переменные
окружения — в [AGENTS.md](AGENTS.md#переменные-окружения).

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
