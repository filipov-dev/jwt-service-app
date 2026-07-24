# Конфигурация reverse-proxy для уровня 2 (proxy-secret)

Уровень 2 защищён **статическим секрет-заголовком**, который проставляет **только**
обратный прокси. Сервис сравнивает значение заголовка `X-Proxy-Secret`
(constant-time) с секретом из `AUTH_PROXY_SECRET`.

## ⚠️ Обязательное требование

Прокси **ОБЯЗАН затирать клиентскую версию заголовка** перед установкой своей.
Иначе клиент подставит `X-Proxy-Secret` сам и уровень 2 будет полностью обойдён.

Каждый пример ниже выполняет **два** действия в правильном порядке:

1. **удаляет** входящий `X-Proxy-Secret` от клиента;
2. **устанавливает** `X-Proxy-Secret` со значением секрета из переменной
   окружения / секрет-менеджера прокси (в примерах — `PROXY_SECRET`; это секрет
   на стороне прокси, он должен совпадать с `AUTH_PROXY_SECRET` сервиса).

> Секрет не должен лежать в конфиге в открытом виде: подставляйте его при
> шаблонизации/деплое из хранилища секретов (Vault, AWS Secrets Manager, SSM,
> Kubernetes Secret, Worker Secret и т.п.).

## Индекс прокси

| Прокси | Файл | Приём |
|--------|------|-------|
| nginx | [nginx.conf](nginx.conf) | `proxy_set_header` (сброс + установка) |
| Traefik | [traefik.yml](traefik.yml) | middleware `customRequestHeaders` |
| HAProxy | [haproxy.cfg](haproxy.cfg) | `http-request del-header` + `set-header` |
| Envoy | [envoy.yaml](envoy.yaml) | `request_headers_to_remove` + `to_add` |
| Caddy | [Caddyfile](Caddyfile) | `header_up -X…` + `header_up X…` |
| Apache httpd | [apache.conf](apache.conf) | `RequestHeader unset` + `set` |
| Kong | [kong.yml](kong.yml) | плагин `request-transformer` |
| AWS ALB / API Gateway | [aws-alb-apigw.md](aws-alb-apigw.md) | parameter mapping `overwrite:header` |
| Cloudflare | [cloudflare.md](cloudflare.md) | Transform Rules / Workers |
| NGINX Ingress (K8s) | [nginx-ingress-k8s.yaml](nginx-ingress-k8s.yaml) | `configuration-snippet` |

## Переменные окружения сервиса (уровень 2)

| Переменная | Назначение |
|-----------|-----------|
| `AUTH_PROXY_SECRET` | Секрет, который сервис ждёт в заголовке. |
| `AUTH_PROXY_SECRET_HEADER` | Имя заголовка (по умолчанию `X-Proxy-Secret`). |

Полное описание всех уровней и переменных — в [AGENTS.md](../../AGENTS.md).
