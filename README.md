# jwt-service-app

HTTP-сервис на Rust (actix-web) для выпуска, проверки и отзыва JWT. Полное
описание архитектуры, команд и конфигурации — в [AGENTS.md](AGENTS.md).

## Многоуровневый доступ к API

Доступ к эндпоинтам разграничен единым auth-middleware по трём уровням; уровень
задаётся при регистрации роута, разница — только в валидаторе.

| Уровень | Эндпоинты | Защита |
|--------:|-----------|--------|
| **1 — открыт** | `GET /livez`, `GET /readyz`, `GET /api-docs/openapi.json` | нет |
| **2 — proxy-secret** | `POST /tokens/verify` | статический секрет-заголовок от обратного прокси (constant-time) |
| **3 — TOTP** | `POST /tokens`, `DELETE /tokens/{jti}` | TOTP (RFC 6238), internal app-to-app |

Невалидный или отсутствующий кред → `401`. Переменные окружения и поведение при
отсутствии секретов описаны в [AGENTS.md](AGENTS.md#переменные-окружения).

## Документация

- **Клиентские примеры уровня 3 (TOTP) на 30 языках** —
  [`docs/clients/`](docs/clients/README.md): генерация TOTP-кода из общего секрета
  и вызов защищённой ручки с заголовком `X-TOTP-Code`.
- **Конфиги reverse-proxy для уровня 2 (proxy-secret) на 10 прокси** —
  [`docs/proxy/`](docs/proxy/README.md): как инжектить секрет-заголовок И
  обязательно затирать клиентскую версию (nginx, Traefik, HAProxy, Envoy, Caddy,
  Apache, Kong, AWS ALB/API Gateway, Cloudflare, NGINX Ingress).
- **OpenAPI** — `GET /api-docs/openapi.json` (security-схемы `proxy_secret` и
  `totp` для уровней 2 и 3).
