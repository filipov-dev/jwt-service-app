# Observability: логи, метрики, трейсы, ошибки

Единая точка входа: **что сервис отдаёт наружу, как это включить и куда оно течёт**.

Вся телеметрия построена на одной шине — `tracing`. Один и тот же span запроса и
одно и то же событие расходятся по разным выходам: в stdout, в Prometheus, в
OpenTelemetry Collector, в GlitchTip. Добавление выхода не меняет код обработчиков.

## Карта сигналов

| Сигнал | Модель доставки | Куда | Включение |
|--------|-----------------|------|-----------|
| **Логи** | stdout (всегда) | сборщик читает контейнерный лог | `LOG_FORMAT=json` для машинного разбора |
| **Логи** | PUSH по OTLP (опц.) | OTel Collector → Monium | `OTEL_LOGS_ENABLED=true` |
| **Метрики** | **PULL** — скрейп `GET /metrics` | Prometheus, Zabbix, Monium | `AUTH_METRICS_TOKEN` |
| **Трейсы** | PUSH по OTLP | OTel Collector → Monium, Jaeger, Tempo | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| **Ошибки / performance / логи** | PUSH (Sentry-envelope) | GlitchTip | `GLITCHTIP_DSN` |

**Важное следствие модели.** Для метрик нужен **входящий** доступ от скрейпера (и
потому ручка закрыта Bearer-токеном). Для трейсов, OTLP-логов и GlitchTip нужен
**исходящий** доступ из пода к коллектору и к GlitchTip — проверьте egress-правила.

## Быстрый старт

Минимум для прода с Monium (метрики + трейсы, логи собираются с stdout):

```bash
LOG_FORMAT=json
AUTH_METRICS_TOKEN=<секрет>                        # включает GET /metrics
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
OTEL_SERVICE_NAME=jwt-service-app
```

Добавить логи по OTLP (вместо/вместе со сбором stdout) и ошибки в GlitchTip:

```bash
OTEL_LOGS_ENABLED=true
GLITCHTIP_DSN=<dsn>
GLITCHTIP_ENVIRONMENT=prod
```

## Сводная таблица переменных

| Переменная | Дефолт | Назначение |
|-----------|--------|-----------|
| `RUST_LOG` | `jwt_service_app=info` | Фильтр уровней (`EnvFilter`). Дефолт применяется, только если переменная не задана |
| `LOG_FORMAT` | `pretty` | `json` — построчный JSON для сборщиков; иначе человекочитаемый вывод с ANSI |
| `AUTH_METRICS_TOKEN` | — (нет) | Bearer-токен для `GET /metrics`. **Не задан → ручки нет (404)** |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — (нет) | **Базовый** URL коллектора; к нему добавляется путь сигнала |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | — (нет) | **Полный** URL для трейсов, используется как есть |
| `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` | — (нет) | **Полный** URL для логов, используется как есть |
| `OTEL_LOGS_ENABLED` | `false` | Слать ли логи по OTLP |
| `OTEL_SERVICE_NAME` | `jwt-service-app` | Атрибут `service.name` в трейсах и логах |
| `GLITCHTIP_DSN` | — (нет) | DSN GlitchTip (принимается и `SENTRY_DSN`). **Секрет** |
| `GLITCHTIP_TRACES_SAMPLE_RATE` | `0.0` | Доля span-ов в Performance (0.0–1.0) |
| `GLITCHTIP_ENABLE_LOGS` | `false` | Слать ли логи в канал Logs GlitchTip |
| `GLITCHTIP_ENVIRONMENT` | — (нет) | Окружение (`prod`/`stage`) для группировки |

Полный список переменных сервиса (включая auth, rate limiting, CORS) — в
[AGENTS.md](../AGENTS.md).

## Логи

Пишутся в stdout всегда. Каждый запрос оборачивается span-ом `http_request`.

**Поля span:** `request_id`, `method`, `path`, `client_ip`, `access_level`,
`status`, `latency_ms`. По завершении — строка `request completed`.

**`request_id`** берётся из входящего заголовка `X-Request-Id` (если он валиден:
ASCII `[A-Za-z0-9_-]`, ≤128 символов), иначе генерируется UUID. Значение
возвращается в ответе тем же заголовком — удобно сшивать логи через прокси.

### Уровни

Выбираются **по виновнику**, а не по «серьёзности» текста. В `tracing` пять
уровней (`TRACE < DEBUG < INFO < WARN < ERROR`); отдельного `CRITICAL`/`FATAL`
**нет** — фатальное фиксируется паникой на старте (fail-fast по конфигурации).

| Уровень | Когда | Примеры |
|--------:|-------|---------|
| `ERROR` | сервис не смог выполнить работу; **годится для алертов** | Redis/JWKS недоступны, сбой крипты при подписи |
| `WARN` | деградация или сигнал безопасности, запрос обработан | проблемы конфигурации, отказ в доступе (401), rate-limit (429) |
| `INFO` | жизненный цикл и бизнес-события | старт, сводка конфигурации, `request completed`, отзыв токена |
| `DEBUG` | вина клиента и детали работы | протухший/битый/подделанный токен, `ttl` вне границ, шаги к JWKS |
| `TRACE` | не используется | — |

> **Клиентские ошибки — это `DEBUG`, а не `ERROR`.** Иначе каждый протухший токен
> поднимал бы ложные алерты. Алертить имеет смысл именно на `ERROR`.

### Что НЕ логируется

Заголовки и тело запроса/ответа не пишутся **никогда** — там секреты
(`X-Proxy-Secret`, `X-TOTP-Code`) и сами токены. DSN GlitchTip тоже не логируется.

## Метрики (Prometheus)

Экспозиция на `GET /metrics` — **уровень доступа 4**, Bearer-токен.

| Метрика | Тип | Лейблы |
|---------|-----|--------|
| `http_requests_total` | counter | `method`, `endpoint`, `status` |
| `http_request_duration_seconds` | histogram | `method`, `endpoint` |
| `jwt_tokens_issued_total` / `jwt_tokens_revoked_total` | counter | — |
| `jwt_tokens_verified_total` | counter | `result` (`success`/`failure`) |
| `jwt_auth_denied_total` | counter | `level` |
| `jwt_rate_limit_exceeded_total` | counter | — |
| `jwks_request_duration_seconds` | histogram | `operation`, `success` |
| `redis_command_duration_seconds` | histogram | `command`, `success` |

> **Кардинальность.** В лейбл `endpoint` идёт **шаблон роута** (`/tokens/{jti}`), а
> не фактический путь — иначе каждый `jti` создавал бы отдельную серию. Не кладите
> в лейблы клиентские данные.

### Prometheus / Managed Prometheus

```yaml
scrape_configs:
  - job_name: jwt-service
    authorization:
      credentials_file: /etc/prometheus/jwt-metrics-token
    static_configs:
      - targets: ['jwt-service-app:8080']
```

### Zabbix

Отдельный экспортёр не нужен — `agent2` с prometheus-плагином читает ту же ручку.
Токен передаётся заголовком:

```
Authorization: Bearer <AUTH_METRICS_TOKEN>
```

### Monium

Через Prometheus-совместимость (Yandex Managed Service for Prometheus) — конфиг
скрейпа такой же, как выше.

> ⚠️ **`/metrics` не публикуют наружу.** Метрики раскрывают операционную картину:
> объём трафика, доли отказов, латентности зависимостей. Прокси должен оставить
> ручку доступной только из внутренней сети — токен это дополнение к сетевой
> изоляции, а не замена.

## Трейсы (OpenTelemetry)

Включаются при заданном `OTEL_EXPORTER_OTLP_ENDPOINT`. Транспорт — **OTLP поверх
HTTP/protobuf** (у коллектора обычно порт **4318**), не gRPC.

**Span-ы:** `http_request` и вложенные `jwks.public_keys`,
`redis.store_jti` / `check_jti` / `delete_jti` / `ping`.

**Propagation (W3C Trace Context)** работает в обе стороны: входящий `traceparent`
делает наш span потомком чужой трассы, а исходящие запросы к `jwks-service-app`
несут свой `traceparent`. Трасса склеивается сквозь сервисы.

> ⚠️ **Путь сигнала обязателен.** `OTEL_EXPORTER_OTLP_ENDPOINT` — это **базовый**
> URL, к которому добавляется `/v1/traces` (или `/v1/logs`). Если передать
> коллектору базовый URL как есть, он ответит `404`, и данные будут **молча
> теряться** — без единой ошибки в логе сервиса.

### Минимальный коллектор

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

exporters:
  otlphttp/monium:
    endpoint: <endpoint Monium>
    headers:
      Authorization: Bearer <токен Monium>

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlphttp/monium]
    logs:
      receivers: [otlp]
      exporters: [otlphttp/monium]
```

Документация Monium: <https://yandex.cloud/ru/docs/monium/>

## Логи по OTLP

Опционально, отдельным флагом `OTEL_LOGS_ENABLED=true`. Включение трейсов логи
**не** включает — они и так идут в stdout, и там, где их собирает агент с
контейнерного лога, отправка по сети была бы дублированием.

**Зачем это нужно:** логи, записанные внутри запроса, несут `Trace ID` и `Span ID`,
поэтому в бэкенде можно переходить от трассы к её логам и обратно:

```
SeverityText: INFO
Body: Str(request completed)
Trace ID: f5bb93b0b6d1773dd5be0fc253be4f19
Span ID:  118851bb95cf37bb
```

## GlitchTip

Sentry-совместимый бэкенд. Включается при заданном `GLITCHTIP_DSN` и закрывает
**три** канала:

| Канал | Что уходит | Включение |
|-------|-----------|-----------|
| **Issues** | паники и события `ERROR` | всегда при DSN |
| **Performance** | span-ы → транзакции | `GLITCHTIP_TRACES_SAMPLE_RATE > 0` |
| **Logs** | структурные логи `DEBUG`/`INFO`/`WARN` | `GLITCHTIP_ENABLE_LOGS=true` |

Раскладка по каналам: `ERROR` → issue, `WARN`/`INFO` → лог + breadcrumb,
`DEBUG` → лог, `TRACE` → игнор.

- **Performance выключен по умолчанию** (`0.0`) — транзакции стоят объёма,
  включайте осознанно.
- **Логи батчатся** и досылаются пачкой (в том числе при остановке процесса) — в
  UI появляются не мгновенно, в отличие от issues.

## Принципы

1. **Телеметрия не роняет сервис.** Все интеграции опциональны и **не fail-fast**:
   недоступный коллектор, кривой DSN или ошибка экспортёра дают предупреждение в
   лог, но запросы обслуживаются как обычно. Исключение — секреты уровней доступа
   2 и 3, там fail-fast сохранён осознанно.
2. **Секреты не попадают в телеметрию.** Заголовки и тела не логируются, DSN не
   пишется в лог, в лейблы метрик не кладутся клиентские данные.
3. **Отсутствие секрета ≠ открытый доступ.** Без `AUTH_METRICS_TOKEN` ручка
   `/metrics` не публикуется вовсе (`404`), а не становится доступной всем.
4. **Одна шина — много выходов.** Новый бэкенд подключается слоем к `tracing`, а
   не правкой обработчиков.
5. **Корректное завершение.** При остановке сервиса досылаются накопленные span-ы,
   логи и события — провайдеры завершаются явно, guard GlitchTip живёт до конца
   процесса.

## Куда смотреть в коде

| Файл | Что |
|------|-----|
| [`src/logging.rs`](../src/logging.rs) | Сборка subscriber-а из слоёв, middleware `RequestLog`, политика уровней |
| [`src/metrics.rs`](../src/metrics.rs) | Метрики Prometheus, рендер экспозиции |
| [`src/tracing_otel.rs`](../src/tracing_otel.rs) | OTLP: трейсы и логи, propagation, правило пути сигнала |
| [`src/sentry_glitchtip.rs`](../src/sentry_glitchtip.rs) | GlitchTip: три канала, раскладка по уровням |
