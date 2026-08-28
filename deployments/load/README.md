# The `POST /tokens/verify` load test

A throughput measurement of the service's hottest public endpoint. It exists so
that hot-path optimisations have numbers rather than intentions: **JWT-24**
(reusing the Redis connection) and **JWT-25** (the JWKS cache) change exactly
what is measured here.

The procedure: take a baseline **before** the changes, repeat the run afterwards
and compare.

## Contents

| File | Purpose |
|------|---------|
| `docker-compose.yml` | An isolated dependency stand: Redis, Postgres, `jwks-service-app`. |
| `verify.js` | The k6 scenario: constant load on `POST /tokens/verify`. |
| `run.sh` | The whole run: issuing the tokens, the measurement, the metrics summary. |

There is no need to install k6 on the host — `run.sh` runs it in a container.

## The run

### 1. The dependencies

```bash
docker compose -f deployments/load/docker-compose.yml up -d
```

The stand comes up under the project name `jwt-load` and on shifted ports (Redis
`16379`, Postgres `15432`, JWKS `18082`) — it deliberately does not overlap with
`deployments/dev` or with other local stands.

### 2. The service

A release build only: the debug profile distorts the result several times over.

```bash
cargo build --release
```

```bash
RATE_LIMIT_VERIFY_ENABLED=false HOST=127.0.0.1 PORT=8080 REDIS_URL=redis://127.0.0.1:16379 JWKS_SERVICE_URL=http://127.0.0.1:18082 AUTH_PROXY_SECRET=dev-proxy-secret AUTH_TOTP_SECRET=MRSWGYLSMUQGO33WNFXGO4ZAOBWGKYLSFVRW63LOMNXW2ZI AUTH_METRICS_TOKEN=dev-metrics-token RUST_LOG=warn ./target/release/jwt-service-app
```

What matters here beyond the obvious:

- **`RATE_LIMIT_VERIFY_ENABLED=false`** is mandatory. With the default per-IP
  limit (10 rps per address) the run hits 429 and measures the rate limiter
  rather than the service. `run.sh` warns about it, but only starting the service
  can turn the limit off.
- **`AUTH_METRICS_TOKEN`** — without it the `/metrics` endpoint is not published
  at all and the summary is left without its main numbers (the trips to the JWKS
  and to Redis).
- **`RUST_LOG=warn`** — at the `info` level every request writes a line to stdout,
  and under load that becomes a cost item in itself.

### 3. The measurement

```bash
./deployments/load/run.sh
```

The parameters come from environment variables: `VUS` (50 by default), `DURATION`
(`30s`), `TOKENS` (20), `TARGET_URL` (`http://127.0.0.1:8080`).

### 4. Cleaning up

```bash
docker compose -f deployments/load/docker-compose.yml down -v
```

## What to read in the output

`run.sh` prints the RPS and the latencies (p50/p95/p99/max), and beneath them the
two numbers this whole thing exists for:

- **JWKS requests per verification** — currently about 1: `KeyManager::get_jwk`
  creates a new HTTP client and pulls the whole JWKS on every request (JWT-25).
  After the cache it should be close to 0.
- **Redis commands per verification** — currently every command goes over a fresh
  connection (JWT-24). The number of commands does not change; their cost does,
  and that shows in the latency.

## Caveats

The measurement is taken on one machine: the client, the service and the
dependencies share the CPU, and `jwks-service-app` and Postgres come up in Docker
(on macOS that is a virtual machine on top). The absolute values therefore do not
carry over to production — they are only good for a before/after comparison on
one and the same stand. For the comparison to be honest, the runs must happen on
the same machine, in the same configuration and preferably back to back.
