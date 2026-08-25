# jwt-service-app

Сервис выпуска, проверки и отзыва JWT. Подпись — RS/ES/EdDSA или HMAC, ключи
берутся из внешнего jwks-service-app, выданные `jti` и refresh-токены хранятся
в Redis.

Исходники и полная документация —
[github.com/filipov-dev/jwt-service-app](https://github.com/filipov-dev/jwt-service-app).

```
docker pull filipov/jwt-service-app:1.13.4
```

Образ multi-arch (`linux/amd64`, `linux/arm64`), публикуется в Docker Hub и
`ghcr.io/filipov-dev/jwt-service-app`. Тег `latest` есть, но для боевого стенда
пинуйте версию: откат с `latest` сводится к надежде, что реестр ещё помнит
прошлый образ.

## Зависимости

Сервису нужны **Redis** и **jwks-service-app**. Без них он стартует, но
`GET /readyz` отдаёт `503` и трафик на под слать рано. Недоступность сервиса
ключей проба считает отказом только тогда, когда в памяти нет и пригодного
снимка JWKS: пока он есть, проверка токенов работает, а состояние отдаётся как
`degraded`.

## Ручки и уровни доступа

| Уровень | Ручки | Чем закрыто |
|---|---|---|
| 1 — открыт | `GET /livez`, `GET /readyz`, `GET /api-docs/openapi.json` | ничем |
| 2 — proxy-secret | `POST /tokens/verify` | заголовок `X-Proxy-Secret` |
| 3 — TOTP | `POST /tokens`, `POST /tokens/refresh`, `DELETE /tokens/{jti}`, `DELETE /subjects/{sub}/tokens` | заголовок `X-TOTP-Code` |
| 4 — Bearer | `GET /metrics` | `Authorization: Bearer` |

**Уровень 2 держится на обратном прокси.** Прокси ставит `X-Proxy-Secret` и
**обязан затирать клиентскую версию заголовка** — иначе секрет подставят снаружи
и уровень будет обойдён. Готовые конфиги на 10 прокси (nginx, Traefik, HAProxy,
Envoy, Caddy, Apache, Kong, AWS ALB, Cloudflare, NGINX Ingress) —
в [docs/proxy/](https://github.com/filipov-dev/jwt-service-app/tree/master/docs/proxy).
Отсюда же следует, что порт контейнера не надо публиковать наружу напрямую:
прямой доступ обходит прокси, а значит и уровень 2.

Клиентские примеры для уровня 3 на 30 языках —
в [docs/clients/](https://github.com/filipov-dev/jwt-service-app/tree/master/docs/clients).

## Быстрый старт

```bash
docker run --rm -p 8080:8080 \
  -e HOST=0.0.0.0 \
  -e REDIS_URL=redis://redis:6379 \
  -e JWKS_SERVICE_URL=http://jwks-service-app:8080 \
  -e AUTH_PROXY_SECRET=... \
  -e AUTH_TOTP_SECRET=... \
  filipov/jwt-service-app:1.13.4
```

`HOST=0.0.0.0` обязателен: дефолт `127.0.0.1` слушает только петлю внутри
контейнера и снаружи недоступен. `AUTH_PROXY_SECRET` и `AUTH_TOTP_SECRET`
обязательны — без них сервис не стартует намеренно, чтобы защиты нельзя было
«забыть» включить.

`iss` в токене берётся из заголовка `Host` запроса, а не из конфига.

## Готовые манифесты

Оба варианта лежат в
[deployments/prod/](https://github.com/filipov-dev/jwt-service-app/tree/master/deployments/prod):

**Docker Compose** — сервис и Redis, секреты из `.env`:

```bash
cp .env.example .env   # заполнить секреты
docker compose -p jwt-prod --env-file .env up -d
```

**Kubernetes** — Deployment (3 реплики), Service, PodDisruptionBudget,
NetworkPolicy, образец Secret:

```bash
kubectl apply -k deployments/prod/k8s/
```

Пробы: `livenessProbe` на `/livez`, `readinessProbe` на `/readyz`. Разделение
принципиальное — `/livez` не ходит в зависимости, поэтому недоступный Redis
выводит под из балансировки, но не устраивает ему цикл перезапусков.

Три реплики держатся живыми двумя настройками сразу:
`topologySpreadConstraints` разносят поды по узлам и зонам, а PDB с
`minAvailable: 2` заставляет drain узла отпускать их по одному. Жёсткий разнос
по узлам ждёт кластера минимум из трёх узлов — на меньшем поменяйте
`whenUnsatisfiable` на `ScheduleAnyway`, иначе лишние реплики зависнут в
`Pending`. Меняете число реплик — пересчитайте и `minAvailable`.

NetworkPolicy закрепляет то же, что сказано выше словами: до порта 8080
достают только ingress-контроллер и скрейпер метрик, остальным подам кластера
он недоступен. Имена namespace и меток там кластерозависимы — правьте под свой
стенд. Учтите, что политику исполняет CNI: плагин без её поддержки примет
манифест молча и не сделает ничего.

## Healthcheck своими силами

В образе **нет ни `curl`, ни `wget`** — только рантайм-библиотеки и `bash`.
Готовый healthcheck для compose делает HTTP-запрос через встроенный в bash
`/dev/tcp`:

```yaml
healthcheck:
  test:
    - CMD
    - bash
    - -c
    - 'exec 3<>/dev/tcp/127.0.0.1/8080; printf "GET /livez HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3; grep -q "200 OK" <&3'
```

В Kubernetes это не нужно: `httpGet`-пробы выполняет kubelet снаружи контейнера.

## Конфигурация

Полная таблица переменных окружения —
в [AGENTS.md](https://github.com/filipov-dev/jwt-service-app/blob/master/AGENTS.md).
Что важно не пропустить в проде:

| Переменная | Почему важна |
|---|---|
| `AUTH_PROXY_SECRET` | уровень 2, обязательна |
| `AUTH_TOTP_SECRET` | уровень 3, base32, обязательна |
| `AUTH_TOTP_SECRET_NEXT` | второй активный секрет на время ротации |
| `TOKEN_ISSUER_ALLOWLIST` | список доменов, допустимых в claim `iss`; не задана — `iss` берётся из `Host` без проверки, и при общем `jwks-service-app` можно выпустить токен от имени соседнего инстанса |
| `RATE_LIMIT_TRUSTED_PROXIES` | без неё за прокси все клиенты делят один per-IP лимит: ключом становится адрес прокси |
| `AUTH_TOTP_REPLAY_PROTECTION` | запрет переигрывания TOTP-кода; требует Redis |
| `AUTH_METRICS_TOKEN` | уровень 4; не задана — `/metrics` не публикуется |
| `LOG_FORMAT=json` | построчный JSON для сборщиков логов |
| `SERVER_WORKERS` | число воркер-потоков; не задана — по квоте CPU контейнера, а без квоты — потолок по умолчанию. Задавайте явно, если лимит памяти рассчитан под конкретное число воркеров |

Секреты подставляйте из секрет-менеджера, а не из открытых env в манифесте.

## Наблюдаемость

Метрики Prometheus на `/metrics` (уровень 4), структурные логи в stdout,
трейсы и логи по OTLP, ошибки в GlitchTip. Что включается какими переменными и
куда течёт —
в [docs/observability.md](https://github.com/filipov-dev/jwt-service-app/blob/master/docs/observability.md).

## Изменения между версиями

[CHANGELOG.md](https://github.com/filipov-dev/jwt-service-app/blob/master/CHANGELOG.md).
