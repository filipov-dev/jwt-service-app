# Observability: logs, metrics, traces, errors

A single entry point: **what the service exposes, how to turn it on and where it
flows**.

All telemetry is built on one bus — `tracing`. The same request span and the same
event fan out to different outputs: to stdout, to Prometheus, to an OpenTelemetry
Collector, to GlitchTip. Adding an output does not change the handler code.

## The map of signals

| Signal | Delivery model | Where | Enabled by |
|--------|----------------|-------|------------|
| **Logs** | stdout (always) | the collector reads the container log | `LOG_FORMAT=json` for machine parsing |
| **Logs** | PUSH over OTLP (optional) | OTel Collector → Monium | `OTEL_LOGS_ENABLED=true` |
| **Metrics** | **PULL** — a scrape of `GET /metrics` | Prometheus, Zabbix, Monium | `AUTH_METRICS_TOKEN` |
| **Traces** | PUSH over OTLP | OTel Collector → Monium, Jaeger, Tempo | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| **Errors / performance / logs** | PUSH (a Sentry envelope) | GlitchTip | `GLITCHTIP_DSN` |

**An important consequence of the model.** Metrics need **inbound** access from
the scraper (which is why the endpoint is behind a bearer token). Traces, OTLP
logs and GlitchTip need **outbound** access from the pod to the collector and to
GlitchTip — check the egress rules.

## Quick start

The minimum for production with Monium (metrics plus traces, with logs collected
from stdout):

```bash
LOG_FORMAT=json
AUTH_METRICS_TOKEN=<secret>                        # enables GET /metrics
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
OTEL_SERVICE_NAME=jwt-service-app
```

To add logs over OTLP (instead of or alongside stdout collection) and errors to
GlitchTip:

```bash
OTEL_LOGS_ENABLED=true
GLITCHTIP_DSN=<dsn>
GLITCHTIP_ENVIRONMENT=prod
```

## The summary table of variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `RUST_LOG` | `jwt_service_app=info` | The level filter (`EnvFilter`). The default applies only when the variable is unset |
| `LOG_FORMAT` | `pretty` | `json` gives line-delimited JSON for collectors; anything else gives human-readable output with ANSI |
| `AUTH_METRICS_TOKEN` | — (none) | The bearer token for `GET /metrics`. **Unset → the endpoint does not exist (404)** |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — (none) | The **base** URL of the collector; the signal path is appended to it |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | — (none) | The **full** URL for traces, used as is |
| `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` | — (none) | The **full** URL for logs, used as is |
| `OTEL_LOGS_ENABLED` | `false` | Whether to send logs over OTLP |
| `OTEL_SERVICE_NAME` | `jwt-service-app` | The `service.name` attribute in traces and logs |
| `GLITCHTIP_DSN` | — (none) | The GlitchTip DSN (`SENTRY_DSN` is accepted too). **A secret** |
| `GLITCHTIP_TRACES_SAMPLE_RATE` | `0.0` | The fraction of spans sent to Performance (0.0–1.0) |
| `GLITCHTIP_ENABLE_LOGS` | `false` | Whether to send logs to the GlitchTip Logs channel |
| `GLITCHTIP_ENVIRONMENT` | — (none) | The environment (`prod`/`stage`) for grouping |

The full list of the service's variables (auth, rate limiting and CORS included)
is in [AGENTS.md](../AGENTS.md).

## Logs

They always go to stdout. Every request is wrapped in an `http_request` span.

**The span fields:** `request_id`, `method`, `path`, `client_ip`, `access_level`,
`status`, `latency_ms`. On completion there is a `request completed` line.

**`request_id`** comes from the incoming `X-Request-Id` header (when it is valid:
ASCII `[A-Za-z0-9_-]`, up to 128 characters), otherwise a UUID is generated. The
value is returned in the response in the same header — handy for stitching logs
across a proxy.

### Levels

They are chosen **by who is at fault**, not by how "serious" the text sounds.
`tracing` has five levels (`TRACE < DEBUG < INFO < WARN < ERROR`); there is **no**
separate `CRITICAL`/`FATAL` — fatal is expressed as a panic at startup (fail-fast
on configuration).

| Level | When | Examples |
|------:|------|----------|
| `ERROR` | the service could not do its job; **suitable for alerts** | Redis/JWKS unavailable, a crypto failure while signing |
| `WARN` | degradation or a security signal, request still handled | configuration problems, access denied (401), rate limit (429) |
| `INFO` | lifecycle and business events | startup, the configuration summary, `request completed`, a token revoked |
| `DEBUG` | the client's fault and internal detail | an expired, corrupt or forged token, a `ttl` out of bounds, the steps to the JWKS |
| `TRACE` | unused | — |

> **Client errors are `DEBUG`, not `ERROR`.** Otherwise every expired token would
> raise a false alert. Alerting makes sense on `ERROR` specifically.

### What is NOT logged

Request and response headers and bodies are **never** written — they hold secrets
(`X-Proxy-Secret`, `X-TOTP-Code`) and the tokens themselves. The GlitchTip DSN is
not logged either.

## Metrics (Prometheus)

The exposition is on `GET /metrics` — **access level 4**, a bearer token.

| Metric | Type | Labels |
|--------|------|--------|
| `http_requests_total` | counter | `method`, `endpoint`, `status` |
| `http_request_duration_seconds` | histogram | `method`, `endpoint` |
| `jwt_tokens_issued_total` / `jwt_tokens_revoked_total` | counter | — |
| `jwt_tokens_verified_total` | counter | `result` (`success`/`failure`) |
| `jwt_auth_denied_total` | counter | `level` |
| `jwt_rate_limit_exceeded_total` | counter | — |
| `jwks_request_duration_seconds` | histogram | `operation`, `success` |
| `jwks_cache_total` | counter | `result` (`hit`/`miss`/`throttled`/`stale`) |
| `redis_command_duration_seconds` | histogram | `command`, `success` |

> **Cardinality.** The `endpoint` label carries the **route template**
> (`/tokens/{jti}`), not the actual path — otherwise every `jti` would create its
> own series. Do not put client data into labels.

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

No separate exporter is needed — `agent2` with the prometheus plugin reads the
same endpoint. The token goes in a header:

```
Authorization: Bearer <AUTH_METRICS_TOKEN>
```

### Monium

Through Prometheus compatibility (Yandex Managed Service for Prometheus) — the
scrape config is the same as above.

> ⚠️ **`/metrics` is not exposed publicly.** Metrics reveal the operational
> picture: traffic volume, failure ratios, dependency latencies. The proxy must
> keep the endpoint reachable from the internal network only — the token
> complements network isolation rather than replacing it.

## Traces (OpenTelemetry)

They are enabled when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. The transport is
**OTLP over HTTP/protobuf** (usually port **4318** on the collector), not gRPC.

**The spans:** `http_request` and the nested `jwks.public_keys`,
`redis.store_jti` / `check_jti` / `delete_jti` / `ping`.

**Propagation (W3C Trace Context)** works in both directions: an incoming
`traceparent` makes our span a child of someone else's trace, and outgoing
requests to `jwks-service-app` carry their own `traceparent`. The trace is
stitched across services.

> ⚠️ **The signal path is mandatory.** `OTEL_EXPORTER_OTLP_ENDPOINT` is the
> **base** URL, to which `/v1/traces` (or `/v1/logs`) is appended. Hand the
> collector the base URL as is and it answers `404` while the data is **silently
> lost** — without a single error in the service log.

### A minimal collector

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

exporters:
  otlphttp/monium:
    endpoint: <the Monium endpoint>
    headers:
      Authorization: Bearer <the Monium token>

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlphttp/monium]
    logs:
      receivers: [otlp]
      exporters: [otlphttp/monium]
```

The Monium documentation: <https://yandex.cloud/en/docs/monium/>

## Logs over OTLP

Optional, behind the separate `OTEL_LOGS_ENABLED=true` flag. Enabling traces does
**not** enable logs — they go to stdout anyway, and where an agent collects them
from the container log, sending them over the network would be duplication.

**Why it is useful:** logs written inside a request carry the `Trace ID` and the
`Span ID`, so in the backend you can move from a trace to its logs and back:

```
SeverityText: INFO
Body: Str(request completed)
Trace ID: f5bb93b0b6d1773dd5be0fc253be4f19
Span ID:  118851bb95cf37bb
```

## GlitchTip

A Sentry-compatible backend. It is enabled when `GLITCHTIP_DSN` is set and covers
**three** channels:

| Channel | What goes there | Enabled by |
|---------|-----------------|------------|
| **Issues** | panics and `ERROR` events | always, given a DSN |
| **Performance** | spans → transactions | `GLITCHTIP_TRACES_SAMPLE_RATE > 0` |
| **Logs** | structured `DEBUG`/`INFO`/`WARN` logs | `GLITCHTIP_ENABLE_LOGS=true` |

The split across channels: `ERROR` → issue, `WARN`/`INFO` → log plus breadcrumb,
`DEBUG` → log, `TRACE` → ignored.

- **Performance is off by default** (`0.0`) — transactions cost volume, so enable
  them deliberately.
- **Logs are batched** and flushed in bulk (including at process shutdown) — they
  appear in the UI with a delay, unlike issues.

## Principles

1. **Telemetry never brings the service down.** Every integration is optional and
   **not fail-fast**: an unavailable collector, a malformed DSN or an exporter
   error give a warning in the log while requests are served as usual. The
   exception is the level 2 and level 3 secrets, where fail-fast is kept
   deliberately.
2. **Secrets do not reach telemetry.** Headers and bodies are not logged, the DSN
   is not written to the log, and client data does not go into metric labels.
3. **A missing secret ≠ open access.** Without `AUTH_METRICS_TOKEN` the `/metrics`
   endpoint is not published at all (`404`) rather than becoming available to
   everyone.
4. **One bus, many outputs.** A new backend is attached as a layer over `tracing`
   rather than by editing the handlers.
5. **Clean shutdown.** When the service stops, the accumulated spans, logs and
   events are flushed — the providers are shut down explicitly and the GlitchTip
   guard lives until the end of the process.

## Where to look in the code

| File | What |
|------|------|
| [`src/logging.rs`](../src/logging.rs) | Assembling the subscriber from layers, the `RequestLog` middleware, the level policy |
| [`src/metrics.rs`](../src/metrics.rs) | The Prometheus metrics, rendering the exposition |
| [`src/tracing_otel.rs`](../src/tracing_otel.rs) | OTLP: traces and logs, propagation, the signal path rule |
| [`src/sentry_glitchtip.rs`](../src/sentry_glitchtip.rs) | GlitchTip: the three channels, the split by level |
