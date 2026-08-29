# jwt-service-app

[![CI](https://github.com/filipov-dev/jwt-service-app/actions/workflows/ci.yml/badge.svg)](https://github.com/filipov-dev/jwt-service-app/actions/workflows/ci.yml)
[![Audit](https://github.com/filipov-dev/jwt-service-app/actions/workflows/audit.yml/badge.svg)](https://github.com/filipov-dev/jwt-service-app/actions/workflows/audit.yml)
[![Docker Hub](https://img.shields.io/docker/v/filipov/jwt-service-app?sort=semver&label=docker%20hub)](https://hub.docker.com/r/filipov/jwt-service-app)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

An HTTP service in Rust (actix-web) that **issues, verifies and revokes JWTs** —
and does nothing else.

If you run several services and they need a shared authentication format, the
usual path is to compile a JWT library into each of them and hand the private
key to everyone. `jwt-service-app` is the alternative: the key never leaves the
key infrastructure, issuing and verification live behind HTTP endpoints, and a
single token can be revoked without waiting for it to expire.

## What it does and what it does not

**It does:**

- issue JWTs with arbitrary claims and a chosen TTL (`POST /tokens`);
- verify the signature, the expiry and `iss`/`aud`, and check whether the token
  has been revoked (`POST /tokens/verify`);
- hand out a refresh token and exchange it for a new pair, with rotation
  (`POST /tokens/refresh`);
- revoke a token by its `jti`, or every token of a subject at once
  (`DELETE /tokens/{jti}`, `DELETE /subjects/{sub}/tokens`);
- sign with RS256/384/512, ES256/384/512 and EdDSA;
- expose Prometheus metrics, structured logs, OpenTelemetry traces and errors to
  GlitchTip/Sentry.

**It does not:**

- **store or generate keys** — that is the job of a separate service,
  `jwks-service-app`, which this one talks to over HTTP;
- **terminate TLS** — a reverse proxy sits in front, and it is also what injects
  the level 2 secret (see below);
- **manage users or check passwords** — this is not an identity service, it only
  formalises a decision somebody else already made: "this subject may have a
  token".

## Where it sits in the system

```
                ┌──────────────────┐        Host → iss
      clients ─▶│  reverse   proxy │───────────────────┐
                │ (TLS, X-Proxy-…) │                   │
                └──────────────────┘                   ▼
                                            ┌──────────────────┐
   your backends ─── X-TOTP-Code ──────────▶│ jwt-service-app  │
                                            └────────┬─────────┘
                                        private key  │  │ jti, refresh
                                         and JWKS    ▼  ▼
                                 ┌──────────────────┐ ┌───────┐
                                 │ jwks-service-app │ │ Redis │
                                 └──────────────────┘ └───────┘
```

Without Redis and `jwks-service-app` the service still starts, but `GET /readyz`
returns `503`: it is too early to route traffic to it.

## Quick start

```bash
docker run --rm -p 8080:8080 \
  -e HOST=0.0.0.0 \
  -e REDIS_URL=redis://redis:6379 \
  -e JWKS_SERVICE_URL=http://jwks-service-app:8080 \
  -e AUTH_PROXY_SECRET=... \
  -e AUTH_TOTP_SECRET=... \
  filipov/jwt-service-app:latest
```

`HOST=0.0.0.0` is required — the default `127.0.0.1` only listens on the
loopback inside the container. `AUTH_PROXY_SECRET` and `AUTH_TOTP_SECRET` are
required too: without them the service **refuses to start**, so that protection
cannot be "forgotten". The image is multi-arch (`linux/amd64`, `linux/arm64`)
and is published to Docker Hub and to `ghcr.io/filipov-dev/jwt-service-app`; pin
a version rather than `latest` for a production deployment.

Ready-made Docker Compose and Kubernetes manifests live in
[`deployments/prod/`](deployments/prod/README.md). The development stand (the
service, Redis, Redis Commander, Postgres, `jwks-service-app`, Swagger UI) comes
up from [`deployments/dev/docker-compose.yml`](deployments/dev/docker-compose.yml):

```bash
docker compose -p jwt-dev -f deployments/dev/docker-compose.yml up -d
```

To build and run without Docker (needs Rust stable, Redis and
`jwks-service-app`):

```bash
cargo run
```

## Endpoints and access levels

Access to the endpoints is split across four levels by a single auth
middleware; the level is chosen when the route is registered, and the only
difference between levels is the validator.

| Level | Endpoints | Protection |
|------:|-----------|------------|
| **1 — open** | `GET /livez`, `GET /readyz`, `GET /api-docs/openapi.json` | none |
| **2 — proxy secret** | `POST /tokens/verify` | a static secret header injected by the reverse proxy (constant-time compare) |
| **3 — TOTP** | `POST /tokens`, `POST /tokens/refresh`, `DELETE /tokens/{jti}`, `DELETE /subjects/{sub}/tokens` | TOTP (RFC 6238), internal app-to-app |
| **4 — bearer token** | `GET /metrics` (only when a token is configured) | a static token in `Authorization: Bearer` (constant-time compare) |

An invalid or missing credential gives `401`. Protection of the main endpoints
is **mandatory**: the level 2 and level 3 secrets (`AUTH_PROXY_SECRET`,
`AUTH_TOTP_SECRET`) must be set or the service **will not start**. Level 4 is
the exception: without `AUTH_METRICS_TOKEN` the service starts and the
`/metrics` endpoint is simply not published (`404`).

**Level 2 rests on the reverse proxy**: it injects `X-Proxy-Secret` and **must
strip the client-supplied version of that header**, otherwise the secret can be
set from the outside and the level is bypassed. It follows that the container
port must not be published directly to the outside world.

The full contract is the OpenAPI spec: `GET /api-docs/openapi.json`, or
[`docs/openapi.json`](docs/openapi.json) in this repository.

## Configuration

Everything is configured through environment variables; the summary table with
defaults and explanations is in
[AGENTS.md → Configuration](AGENTS.md#configuration-environment-variables).
The minimum needed to start is the five variables from "Quick start" above.

## Documentation

- **Client examples for level 3 (TOTP) in 30 languages** —
  [`docs/clients/`](docs/clients/README.md): generating a TOTP code from the
  shared secret and calling a protected endpoint with the `X-TOTP-Code` header.
- **Reverse-proxy configurations for level 2 (proxy secret), 10 proxies** —
  [`docs/proxy/`](docs/proxy/README.md): how to inject the secret header AND,
  crucially, strip the client-supplied one (nginx, Traefik, HAProxy, Envoy,
  Caddy, Apache, Kong, AWS ALB/API Gateway, Cloudflare, NGINX Ingress).
- **Observability: logs, metrics, traces, errors** —
  [`docs/observability.md`](docs/observability.md): what the service exposes,
  how to turn it on and where it flows (stdout/JSON, Prometheus and Zabbix,
  OpenTelemetry and Monium, GlitchTip), a summary table of the variables and
  ready-made configurations.
- **OpenAPI** — `GET /api-docs/openapi.json` (security schemes `proxy_secret`,
  `totp` and `metrics_token` for levels 2, 3 and 4). The same document is
  committed as [`docs/openapi.json`](docs/openapi.json), so a contract change
  shows up in the diff of a pull request.
- **Production deployment: Docker Compose and Kubernetes** —
  [`deployments/prod/`](deployments/prod/README.md): manifests with probes on
  `/livez` and `/readyz`, secrets from `.env`/`Secret`, a filled-in
  `RATE_LIMIT_TRUSTED_PROXIES`.
- **Architecture, commands, conventions and pitfalls** —
  [AGENTS.md](AGENTS.md): the module map, how the auth middleware and rate
  limiting work, the full list of environment variables and the reasoning behind
  the decisions taken.
- **How to report a vulnerability** — [`SECURITY.md`](SECURITY.md): a private
  channel instead of a public issue, response and disclosure timelines,
  supported versions and what is not considered a vulnerability.
- **History scan for secrets** —
  [`docs/security/secret-audit.md`](docs/security/secret-audit.md): what scanned
  the history and over which refs, the findings, and what to do when a scanner
  finds a real secret.
- **CI audit for pull requests from forks** —
  [`docs/security/workflow-audit.md`](docs/security/workflow-audit.md): what the
  author of a hostile pull request gets in a public repository, why the secrets
  are out of reach and what to check when adding a workflow.
- **What changed between image versions** — [`CHANGELOG.md`](CHANGELOG.md): the
  sections are assembled from the commit history, and the same texts go into the
  description of every GitHub release.

## Stack

Rust (edition 2021, the `stable` channel pinned in `rust-toolchain.toml`),
actix-web 4, `openssl` for signing and verification, Redis for `jti` and refresh
tokens, `utoipa` for OpenAPI, `tracing` + OpenTelemetry + Prometheus for
telemetry. Every dependency is permissively licensed (MIT / Apache-2.0):
copyleft crates are kept out because the images are distributed publicly.

## Contributing

Bug reports, ideas and pull requests are welcome. How to build, what to run
before opening a pull request and how to shape a commit —
[CONTRIBUTING.md](CONTRIBUTING.md); the rules of engagement —
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

Found a vulnerability? **Do not open a public issue.** Use a private advisory on
GitHub (the Security tab → Report a vulnerability) or write to
[security@filipov.dev](mailto:security@filipov.dev). Acknowledgement within 72
hours, a verdict within 7 days, coordinated disclosure. The full policy,
including the list of what is not considered a vulnerability, is in
[`SECURITY.md`](SECURITY.md).

## License

[Apache-2.0](LICENSE). Chosen for its explicit patent grant (section 3): for a
cryptographic service that matters more than the brevity of MIT. You may fork
it, change it and use the image in commercial products — keep the license text
and state that the files were modified.
