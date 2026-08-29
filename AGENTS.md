# AGENTS.md

Instructions for AI agents and developers working with this repository.

> **Who this file is for.** It is the working reference of someone changing this
> code: the architecture, the pitfalls and the full configuration, in one file
> and at length. It is not user documentation — for that start from
> [`README.md`](README.md) and the documents it links to.

## Project overview

`jwt-service-app` is an HTTP service in Rust (actix-web) for issuing, verifying
and revoking JWTs. The service **does not store keys itself**: generating and
storing them is the job of the external `jwks-service-app`, reached over HTTP.
Revoked and active tokens are tracked by `jti` in Redis.

- Language: Rust, edition 2021.
- Web framework: actix-web 4.
- Crypto: `openssl` (signing and verification), supporting RS256/384/512,
  ES256/384/512, EdDSA.
- `jti` storage: Redis (the `redis` crate, multiplexed async connection).
- OpenAPI: `utoipa`; the spec is served at `/api-docs/openapi.json` and
  committed to the repository — [`docs/openapi.json`](docs/openapi.json).
- License: Apache-2.0 — [`LICENSE`](LICENSE), the `license` field in
  `Cargo.toml`, the `org.opencontainers.image.licenses` label on the production
  image and `info.license` in the OpenAPI spec. Upstream dependencies are
  permissive (MIT / Apache-2.0); copyleft crates are kept out because the images
  are distributed publicly (see the comment next to `governor` in `Cargo.toml`).
- Security policy: [`SECURITY.md`](SECURITY.md) — the private channel for
  vulnerability reports, response and disclosure timelines, supported versions.
- Documents for an external contributor: [`README.md`](README.md) is the shop
  window (what the service does and does not do, quick start, the documentation
  map), [`CONTRIBUTING.md`](CONTRIBUTING.md) covers building, commands, code and
  commit conventions and the pull request checklist,
  [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) is Contributor Covenant 2.1 with
  `andrey@filipov.dev` as the contact. Issue and pull request templates live in
  [`.github/`](.github) (see "Public repository hygiene").
- **Language: this repository is English.** See "Repository language" under
  "Conventions and pitfalls" — the rule covers code, comments, documentation,
  commit messages and pull request texts, and CI enforces it.

## Architecture

The data flow when a token is issued (`POST /tokens`):

1. `handlers::create_token` reads the `Host` header (it becomes `iss`) and
   checks it against the issuer allowlist (`src/issuer.rs`).
2. `JwtManager::generate_token` asks `KeyManager` for a private key.
3. `KeyManager`, through `JwkService` (`src/jwk.rs`), talks to
   `jwks-service-app`: it fetches an existing key by id or creates a new one.
4. `TokenClaims::create_new` builds the claims and stores the `jti` in Redis
   with a TTL.
5. `JsonWebToken::create_new` signs `header.claims` with the private key.

Verification (`POST /tokens/verify`) is the same path in reverse:
`JsonWebToken::from_string` fetches the public key by `kid` from the JWKS and
checks the signature and the claims (`iss`, `aud`, `nbf`/`iat`/`exp`, presence
of the `jti` in Redis).

Revocation (`DELETE /tokens/{jti}`) deletes the `jti` from Redis. It is
idempotent: revoking a `jti` that does not exist is also `204`. An unavailable
store surfaces as `500` rather than being masked as success.

Renewal (`POST /tokens/refresh`) exchanges a refresh token for a new
access + refresh pair. The refresh token is an opaque string, not a JWT: it is
merely a key into a Redis record, so a leaked token is useless without the store
and revocation is instant.

Bulk revocation (`DELETE /subjects/{sub}/tokens`) kills every token of a
subject. When a token is issued its `jti` goes not only into a flat key but also
into the ZSET group `group:sub:{sub}` with the expiry time as the score;
revocation trims expired entries by score, deletes the remaining `jti` values in
one batch and then the group itself.

### Access levels (auth middleware)

Every endpoint is behind a single middleware ([`auth.rs`](src/auth.rs)); the
level is chosen when the route is registered in `main.rs`, and the only
difference between levels is the validator. An invalid or missing credential
gives `401` (a terse response with no details).

| Level | Endpoints | Validator |
|------:|-----------|-----------|
| **1 — open** | `GET /livez`, `GET /readyz`, `GET /api-docs/openapi.json` | none (lets everything through) |
| **2 — proxy secret** | `POST /tokens/verify` | a static secret header from the proxy, constant-time compare |
| **3 — TOTP** | `POST /tokens`, `POST /tokens/refresh`, `DELETE /tokens/{jti}`, `DELETE /subjects/{sub}/tokens` | TOTP (RFC 6238), internal app-to-app |
| **4 — bearer token** | `GET /metrics` (only when a token is configured) | a static token in `Authorization: Bearer`, constant-time compare |

- **Level 2** is the `X-Proxy-Secret` header (the name is configurable), set
  **only** by the reverse proxy. The comparison against `AUTH_PROXY_SECRET` is
  constant-time (`openssl::memcmp`). **The proxy MUST strip the client-supplied
  version of that header** before setting its own — otherwise the secret can be
  injected from the outside and the level is bypassed. Ready-made configurations
  for 10 proxies are in [`docs/proxy/`](docs/proxy/README.md).
- **Level 3** is a TOTP code in the `X-TOTP-Code` header. The secrets are base32
  values from the environment. **Rotation is supported**: up to two secrets
  (`AUTH_TOTP_SECRET` + `AUTH_TOTP_SECRET_NEXT`) are active at once while the
  swap is in progress. The crypto (HMAC) goes through `openssl`. Client examples
  in 30 languages are in [`docs/clients/`](docs/clients/README.md).
- **Level 4** is a static bearer token (`AUTH_METRICS_TOKEN`) in the
  `Authorization: Bearer <token>` header; the scheme name is case-insensitive
  (RFC 7235) and the token comparison is constant-time. It is a separate level
  rather than a reuse of 2 or 3: monitoring systems cannot do TOTP (they do not
  compute one-time codes), and `X-Proxy-Secret` is stripped by the proxy by
  contract. Bearer is natively supported by Prometheus
  (`authorization: {credentials_file}`), by Zabbix `agent2` and by the OTel
  Collector through which Monium scrapes the metrics.
- **Protection of the main endpoints is mandatory.** The level 2 and level 3
  secrets (`AUTH_PROXY_SECRET`, `AUTH_TOTP_SECRET`) are required: without them
  `AuthConfig::from_env` returns an error and the service **does not start**
  (fail-fast at startup, as with the rest of the critical configuration). These
  levels cannot be turned off.
- **Level 4 is the exception — it is optional.** Metrics are auxiliary, and the
  whole token service should not go down over their configuration. Without
  `AUTH_METRICS_TOKEN` the service starts (with a warning in the log) and the
  `/metrics` route is **not registered at all** — the path returns a plain
  `404`. Returning `401` is deliberately avoided: that way the very existence of
  the endpoint is invisible from the outside. A missing token **never means open
  access** — in that state `MetricsValidator` rejects every request.
- **Replay (level 3):** a TOTP code is by itself replayable within its validity
  window. That is closed by the `AUTH_TOTP_REPLAY_PROTECTION` flag: a fingerprint
  of the code is reserved in Redis with `SET NX` and a TTL equal to the window,
  and a repeat gets `401`.
  - **Off by default** — turning it on adds a Redis dependency to the auth layer
    that it otherwise does not have, and silently changing the behaviour of
    running deployments would be wrong. Enable it explicitly in production.
  - **What goes into Redis is not the code but its HMAC** under the first active
    secret: a bare hash of 6–8 digits is brute-forced instantly and would hide
    nothing.
  - **Fails open when Redis is unavailable.** Both level 3 endpoints go to Redis
    anyway (issuing fails at `store_jti`, revocation is a Redis command in
    itself), so a replayed code achieves nothing while the store is down, and
    failing closed would add one more reason for the service to refuse requests.

### Rate limiting

A separate middleware ([`rate_limit.rs`](src/rate_limit.rs)) on top of the
token bucket (GCRA) from the `governor` crate. The kind of limit matches the
access level — whoever hits the endpoint determines the model. Exceeding it
gives `429 Too Many Requests` (a terse body and a `Retry-After` header in
seconds).

| Endpoint | Kind of limit | Order relative to auth |
|----------|---------------|------------------------|
| `POST /tokens/verify` (level 2) | **per-IP** (keyed by client IP) | **outside** auth — a flood is cut off before the proxy secret is checked |
| `POST /tokens`, `POST /tokens/refresh`, `DELETE /tokens/{jti}`, `DELETE /subjects/{sub}/tokens` (level 3) | **optional global cap** per endpoint (not per-IP) | **inside** auth — only requests that passed TOTP consume the cap |

- **Why this way.** The public `/tokens/verify` has many different clients →
  per-IP. The internal endpoints are hit by one or two trusted clients from a
  single address → per-IP is meaningless; instead there is an optional global
  cap as defense in depth (limiting the blast radius of a leaked TOTP secret)
  and as backpressure for JWKS and Redis against a client stuck in a loop. The
  cap sits **inside** auth on purpose: were it outside, an unauthenticated flood
  would drain the shared cap and lock out the real internal client.
- **The client IP behind a proxy.** The peer address behind a reverse proxy is
  the address of the proxy, so the real IP comes from `X-Forwarded-For`. That
  header is forgeable by the client, so it is trusted **only when the peer is
  listed in `RATE_LIMIT_TRUSTED_PROXIES`** (IP/CIDR). XFF is parsed right to
  left (the first untrusted address is the client, which is correct for a chain
  of proxies). **When the trusted-proxy list is empty, XFF is ignored** and the
  peer address is used as the key (a safe default: an IP cannot be forged from
  the outside, but behind a proxy every client shares one limit — always set the
  list in production behind a proxy). IPv6 is grouped by `/56`.
- **Not fail-fast.** Unlike the auth secrets, configuration errors in rate
  limiting (an unparsable CIDR, a malformed flag) do **not** bring the service
  down — it degrades to the safe mode with a warning in the log. The per-IP
  limit is on by default; the global cap is off.

> **The observability guide** is
> [`docs/observability.md`](docs/observability.md): the map of signals and
> delivery models, the summary table of variables, ready-made configurations for
> Prometheus/Zabbix/Monium/GlitchTip and the log-level policy.

### Module map (`src/`)

| File | Purpose |
|------|---------|
| `main.rs` | Entry point, HTTP server configuration, logging, CORS, routes (with their access levels), serving the OpenAPI spec. |
| `openapi.rs` | The root OpenAPI descriptor (`ApiDoc`), the security schemes and the export of the spec to `docs/openapi.json` (the `spec_file_is_up_to_date` test). |
| `server.rs` | `HttpServer` parameters: the worker count (from the cgroup CPU quota, not from the host core count), connection timeouts (`client_request_timeout`, keep-alive) and the drain period on shutdown (`shutdown_timeout`). |
| `auth.rs` | The multi-level auth middleware: access levels and the validators for the proxy secret, TOTP (RFC 6238) and the metrics bearer token. |
| `logging.rs` | Initialisation of the `tracing` subscriber (format from `LOG_FORMAT`) and the per-request `RequestLog` middleware: `request_id` (`X-Request-Id`), a structured span (method, path, status, latency, `access_level`, IP); the request metric is written from here too. |
| `tracing_otel.rs` | Distributed tracing with OpenTelemetry: OTLP export (enabled by env), W3C propagation (`traceparent`) on the way in and on outgoing requests to the JWKS. |
| `sentry_glitchtip.rs` | The GlitchTip integration (Sentry-compatible): errors and panics → Issues, spans → Performance, structured logs → Logs. Enabled by DSN. |
| `metrics.rs` | Prometheus metrics (the `metrics` facade plus `metrics-exporter-prometheus`): the recorder, the recording helpers and rendering the exposition for `GET /metrics`. |
| `rate_limit.rs` | The rate-limiting middleware (token bucket from `governor`): per-IP on `/tokens/verify` and an optional global cap on the internal endpoints; extracting the IP from `X-Forwarded-For` behind a trusted proxy. |
| `handlers.rs` | The HTTP handlers for the endpoints (generic over `JtiStore`) plus the `utoipa::path` annotations. |
| `issuer.rs` | The issuer allowlist (`TOKEN_ISSUER_ALLOWLIST`): which `Host` values are acceptable in the `iss` claim. |
| `jwt.rs` | `JwtManager` — the facade for generating and verifying tokens. |
| `models/jwt.rs` | `TokenClaims`, `TokenHeaders`, `JsonWebToken`, the `JtiStore` trait (including `ping` for readiness) and the errors. |
| `models/mod.rs` | Request and response DTOs (`ToSchema`) and the JWK/JWKS structures. |
| `key.rs` | `KeyManager` — obtaining the private key and reconstructing the public one from a JWK. |
| `jwk.rs` | `JwkService` — the HTTP client for `jwks-service-app`. |
| `redis.rs` | `RedisClient` — the `JtiStore` implementation on top of Redis. |
| `error.rs` | The shared `Error` with `ResponseError` for actix. It knows nothing about the storage backend: it aggregates `JtiError`, not `redis::RedisError`. |

## Commands

Local development usually goes through Docker Compose (see below), but the crate
also builds directly:

```bash
cargo build            # build
cargo build --release  # release build (as in the production image)
cargo run              # run (needs Redis and jwks-service-app)
cargo clippy           # lint
cargo fmt              # formatting
cargo audit            # check dependencies for vulnerabilities

UPDATE_OPENAPI=1 cargo test openapi   # regenerate docs/openapi.json
```

> **A release build costs noticeably more than a debug one** — `lto = "fat"` and
> `codegen-units = 1` in `[profile.release]` (see "Conventions and pitfalls"): a
> clean build on 8 cores takes 127 s against 88 s. `cargo build` and
> `cargo clippy` are enough for everyday checks — they use the default profile
> and never touch the release one.

The toolchain is pinned in `rust-toolchain.toml` (`channel = "stable"`, the
`clippy` and `rustfmt` components): rustup picks it up automatically, so the
channel and the component set are identical for everyone and match CI.

> **But a channel is not a version: local `stable` can lag behind CI.** The
> toolchain file does not update an already installed stable — rustup silently
> uses the local copy, while CI installs a fresh one on every run, so new lints
> appear there first: the `manual_option_zip` fix in JWT-31 passed locally on
> 1.94 and failed on 1.97. So run `rustup update stable` before the linter. If
> CI complains about a lint you do not have locally, compare
> `cargo clippy --version` instead of arguing with the lint.

Docker builds bypass the toolchain file on purpose: the production image pins
the compiler through `ENV RUSTUP_TOOLCHAIN` (otherwise `cargo chef cook` would
build the dependencies with one compiler and `cargo build` with another, and the
layer cache would be invalidated on every build), while the dev image installs
stable at image build time so that rustup does not download it every time the
container is recreated.

`cargo audit` also runs in CI (`.github/workflows/audit.yml`) on every pull
request, on pushes to `master` and weekly on a schedule: a vulnerability found
blocks the pipeline. Advisories that are deliberately ignored go into
`.cargo/audit.toml` with a comment explaining why.

**Secrets in the history** are checked by `scripts/scan-secrets.sh` — gitleaks
and trufflehog over every ref of the repository, pull request refs included:

```bash
scripts/scan-secrets.sh                 # both scanners
scripts/scan-secrets.sh --reports out   # with JSON reports in ./out
```

The same script runs in CI (`.github/workflows/secrets.yml`) on every pull
request, on pushes to `master` and weekly; a finding fails the pipeline and the
reports are uploaded as an artifact. One script serves both the local run and CI
deliberately — otherwise the flag sets and the allowlists drift apart silently.

Silence a finding **by value only**, never by path: an allowlist on a directory
blinds the scanner to a real secret committed into it. The places to write it
down are `.gitleaks.toml` (gitleaks) or the `TRUFFLEHOG_ALLOWLIST` array inside
the script, always with a reason. The audit report from before the repository
was published, and the procedure for a real finding (revoke the key first,
rewrite the history second), are in
[`docs/security/secret-audit.md`](docs/security/secret-audit.md).

**Vulnerability reports are accepted privately** — the policy is in
[`SECURITY.md`](SECURITY.md): the primary channel is a private advisory on
GitHub, the fallback is `security@filipov.dev`; acknowledgement within 72 hours,
a verdict within 7 days, coordinated disclosure within 90. **Only the latest
release** is supported — nothing is backported to older tags. When editing the
"What is not considered a vulnerability" section, check it against that file: it
lists the deliberate decisions (TOTP replay protection off by default, `404`
instead of `401` on `/metrics`, failing open when Redis is unavailable), and
wording that drifts apart turns documented behaviour into a "confirmed finding".

> **The "Report a vulnerability" link in `SECURITY.md` depends on a repository
> setting** — Private vulnerability reporting, see the settings checklist in
> [`docs/security/workflow-audit.md`](docs/security/workflow-audit.md). With the
> setting off the link leads nowhere and email is the only working channel, so
> check the two together when you touch either.

**CI is built for a public repository**: `ci.yml`, `audit.yml` and `secrets.yml`
run on `pull_request`, which includes pull requests from other people's forks,
and therefore never reference `secrets.` once. The workflows that do use secrets
(`docker.yml`, `release.yml`) run only on privileged events — a tag push, a
release publication, a manual dispatch, a push to `master`. The threat model,
the trigger table and the checklist for a new workflow are in
[`docs/security/workflow-audit.md`](docs/security/workflow-audit.md).
**`pull_request_target` is not used in this repository; do not introduce it as a
drive-by change.**

**CI is strict** (`.github/workflows/ci.yml`, on pull requests and on pushes to
`master`): `cargo fmt --all -- --check` and
`cargo clippy --all-targets -- -D warnings`. Any lint warning and any deviation
from `rustfmt` fails the pipeline, so run `cargo fmt` before committing rather
than after review.

Tests are inline `#[cfg(test)]` modules in the sources; there is no module
without tests. Run them with `cargo test`; CI (`.github/workflows/ci.yml`) runs
`cargo test --verbose` on every pull request and push. The dev image ships
`cargo-tarpaulin` for coverage. Adding a feature means adding tests next to it,
in the same style.

**Access levels are covered by a test** (`main.rs`). Route registration was
extracted into `configure_api` precisely for that: the binding of an endpoint to
a level used to be verified only by reading the code, and that is how the
refresh token exchange ended up on level 2 instead of level 3 with a fully green
run. A "no credentials → 401" check does not catch it — it passes for both
levels; the test sends the internal endpoints a request with a **valid proxy
secret but no TOTP** and expects `401`. Adding an endpoint means adding it to
`internal_endpoints()`.

**Tests must not depend on environment left behind by their neighbours.**
`TokenHeaders::create_new` reads `TOKEN_ALGORITHM`, so unit tests should use
`headers_with_alg` with an explicit algorithm: one such test used to pass only
in the full run and failed on its own.

### Docker Compose (dev)

`deployments/dev/docker-compose.yml` brings up the whole stand: the service
itself, Redis, Redis Commander, Postgres, `jwks-service-app` and Swagger UI. The
`app` container starts with `tail -f /dev/null` — the assumption is hot reload
through `cargo watch` inside the container (the dev image installs
`cargo-watch`).

> **Careful with the project name.** Compose takes the project name from the
> directory name, which is `dev` — and plenty of services have a
> `deployments/dev` directory. Running `docker compose up` from such a directory
> may adopt another stand's containers as its own and recreate them. If other
> projects are running nearby, set the name explicitly:
> `docker compose -p jwt-dev up`.

### Production deployment

`deployments/prod/` holds both ways to run it, and both are written to be
deployed as they are, by the maintainer and by anyone running the public image
alike:
- `docker-compose.yml` — the service and Redis, with the secrets coming from
  `.env` (the sample is `.env.example`; `.env` itself is in `.gitignore`);
- `k8s/` — Deployment, Service, PodDisruptionBudget, NetworkPolicy and a sample
  Secret, applied with `kubectl apply -k deployments/prod/k8s/`.

> **`deployments/prod/README.md` is the Docker Hub description of the image.**
> `docker.yml` pushes it there in the `dockerhub-description` step. That is why
> every link in it is absolute (relative paths do not resolve on Docker Hub) and
> why the text is written for someone who came for the image, not for the
> sources.

What matters when editing the manifests:

- **The runtime image has neither `curl` nor `wget`** — only the runtime
  libraries and `bash`. That is why the Compose healthcheck makes its HTTP
  request through `/dev/tcp`; do not rewrite it to use `curl`, it will not
  appear there. In Kubernetes this is unnecessary: `httpGet` probes are executed
  by the kubelet outside the container.
- **Liveness goes to `/livez`, readiness to `/readyz`.** `/livez` never touches
  the dependencies; a liveness probe on `/readyz` would restart pods whenever
  Redis was unavailable, that is, finish the service off with restarts at
  exactly the moment of the outage.
- **`RATE_LIMIT_TRUSTED_PROXIES` must be filled in**, with different values in
  each case: in Compose it is the docker network subnet (pinned explicitly in
  the manifest so that the proxy address is predictable), in Kubernetes it is
  the pod network of the ingress controller. Empty means the per-IP limit is
  keyed by the proxy address and every client shares a single limit.
- **`SERVER_WORKERS` is set explicitly in Kubernetes (`2`), and that is not
  tuning.** The CPU limit is deliberately absent, which means the cgroup has no
  quota and auto-detection hits the ceiling; by fixing the worker count we make
  the memory limit comparable to it. Change one and recompute the other. In
  Compose the variable is empty (auto): a quota appears there as soon as `cpus`
  is set.
- **The port is not published to the outside.** Level 2 rests on a header set by
  the proxy; direct access to the container bypasses it. For the same reason the
  Kubernetes Service is a `ClusterIP`, and `networkpolicy.yaml` closes the
  remaining gap: a `ClusterIP` is invisible from outside the cluster but
  reachable inside it by any pod of any namespace, which means a cluster
  neighbour can bypass level 2. The policy allows two sources — the ingress
  controller pods and the namespace of the metrics scraper; the names there are
  cluster-specific and are edited per stand. **NetworkPolicy is enforced by the
  CNI**: a plugin without support for it accepts the manifest silently and does
  nothing, so after applying it, verify that an unrelated pod cannot reach port
  8080.
- **The shutdown drain and the grace period are one setting spread over two
  files.** `SERVER_SHUTDOWN_TIMEOUT_SECONDS` (25 s) must be strictly less than
  `terminationGracePeriodSeconds` in Kubernetes (30 s) and `stop_grace_period`
  in Compose (30 s): otherwise SIGKILL arrives exactly as the drain runs out,
  leaving no time for the last request or for flushing telemetry (which is sent
  after `run()` returns). Change one and recompute the other. The actix default
  (30 s) would have coincided with the grace period, which is why the timeout is
  set explicitly.
- **`replicas: 3`, the PDB and `topologySpreadConstraints` are one construct,
  not three independent settings.** Spreading across nodes stops the scheduler
  from packing every replica onto one node (a drain would then take the whole
  service down), and `minAvailable: 2` in `pdb.yaml` forces a drain to release
  pods one at a time. Change the replica count and recompute `minAvailable`:
  with `replicas: 2` the same budget blocks any voluntary eviction outright. A
  hard spread across nodes (`DoNotSchedule`) needs at least three nodes; on a
  smaller cluster the replicas hang in `Pending` and `ScheduleAnyway` is what is
  needed there.
- In `kustomization.yaml` labels are set through `labels`, not `commonLabels`:
  the latter also writes them into the Deployment's `spec.selector`, and a
  selector is immutable after creation, so the update would fail.

### Load test

`deployments/load/` measures `POST /tokens/verify` (k6 in a container — nothing
to install on the host). It also holds an isolated dependency stand with its own
project name and shifted ports, the instructions in
[`deployments/load/README.md`](deployments/load/README.md) and the recorded
baseline in [`BASELINE.md`](deployments/load/BASELINE.md).

Measure with a release build only, and always with
`RATE_LIMIT_VERIFY_ENABLED=false`: with the default per-IP limit (10 rps) the
run measures the rate limiter, not the service.

### The OpenAPI spec in the repository

[`docs/openapi.json`](docs/openapi.json) is a snapshot of the API contract —
exactly the document the service serves at `GET /api-docs/openapi.json`. It is
in git for a reason: while the spec existed only at runtime, a contract change
left no trace in the diff, and a breaking change could not be seen in review.

```bash
cargo test openapi                    # compare the file against the code
UPDATE_OPENAPI=1 cargo test openapi   # regenerate the file
```

One and the same test both exports and compares — `spec_file_is_up_to_date`
([`src/openapi.rs`](src/openapi.rs)). A pair of "separate generator plus
separate checker" would drift apart, and a generator you have to remember to run
is dead by construction: the file would go stale on the very first change. CI
runs the test on every pull request, so a stale file fails the pipeline — with a
hint on how to fix it.

Bumping the version in `Cargo.toml` also requires regeneration: the version goes
into `info.version`. Excluding that field from the comparison was rejected — the
file must be exactly what the service serves, otherwise it is a retelling of the
contract rather than a snapshot of it.

**Keeping the file current is two different guarantees, and two tests stand
watch over them.** `spec_file_is_up_to_date` catches the file drifting from
`ApiDoc`, but on its own it does not save you from the main risk: `ApiDoc` can
drift from the application. Add an endpoint, forget `#[utoipa::path]` — the file
still matches `ApiDoc`, the test is green and the spec lies. That is what
`openapi_spec_lists_all_endpoints` closes: it compares the paths of the spec
against the routes **parsed out of the source** of `configure_api` (plus the
endpoints declared through attribute macros in `handlers.rs`), in both
directions — catching an undocumented endpoint as well as a path in the spec
that no longer exists in the application.

The route parsing is textual because a built actix application cannot enumerate
them: `ResourceMap` is not exposed, and "poke a path and see whether it 404s"
requires knowing the very list we are looking for in advance. Two consequences
for edits follow: routes in `configure_api` are registered with **string
literals** (not constants, not concatenation), and a non-empty
`web::scope("...")` will fail the test — flat parsing would lose the prefix, and
it is better to find that out immediately. There is exactly one explicit
exclusion from the comparison, `/api-docs/openapi.json`: the spec does not
describe itself.

### Releases and the changelog

[`CHANGELOG.md`](CHANGELOG.md) is assembled from the commit history by
[`scripts/changelog.sh`](scripts/changelog.sh) — the file is never edited by
hand:

```bash
scripts/changelog.sh                 # the body of a section: last tag..HEAD
scripts/changelog.sh --insert        # insert the section for the Cargo.toml version into CHANGELOG.md
scripts/changelog.sh --all > CHANGELOG.md   # rebuild the whole file
```

`release.yml` calls the same script and puts the result into the GitHub release
description — the wording in the file and in the release matches by
construction, not because somebody keeps them in sync.

Hence the requirement on commit messages: **conventional commits** (`feat:`,
`fix:`, `docs:`, `perf:`, `refactor:`, `test:`, `ci:`, `style:`) with the task
key in parentheses. The subject of a commit goes into the changelog verbatim —
write it as a changelog line, not as a note to yourself. The type picks the
section (the mapping is in `bucket_for`), and `feat!:` moves the change to
"Breaking changes".

> **`JWT-NNN` is an identifier in the maintainer's own issue tracker**, which is
> not public — so the references to it scattered through this file and through
> the changelog are provenance, not links you can follow. The script does not
> parse the key and nothing breaks without it: a contribution from outside
> carries the GitHub issue number instead (`(#123)`), or no key at all.

> **There are more versions than releases.** The version is bumped by every
> commit, while exactly one tag is created — for the final version of the merge.
> That is why there are gaps in the tags (1.11.0, 1.12.0, 1.12.1): their commits
> went into the next released tag rather than getting lost.

> **The historical entries in `CHANGELOG.md` are in Russian, and that is a
> deliberate decision** (JWT-114): the commit history is not being rewritten, so
> the sections generated from it stay as they are. New entries are English, like
> the commits they come from. The file is the single exception in the language
> gate — see "Repository language".

### Public repository hygiene
The repository is written for an external reader, and the entry documents are
split by role — do not pile everything into one file:

| File | For whom, about what |
|------|----------------------|
| [`README.md`](README.md) | For someone arriving from outside: what the service does and does **not** do, where it sits in the system, the quick start, the map of the rest of the documentation. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | For someone who wants to send a pull request: environment, commands, what CI checks, code and commit conventions, the pull request checklist, the license of contributions. |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | The rules of engagement (Contributor Covenant 2.1), with `andrey@filipov.dev` as the contact for complaints. |
| [`SECURITY.md`](SECURITY.md) | The private channel for vulnerabilities, the timelines, the scope. |
| `AGENTS.md` (this file) | For someone already inside: architecture, pitfalls, the full configuration. |

The templates live in [`.github/`](.github): the issue forms
([`ISSUE_TEMPLATE/bug_report.yml`](.github/ISSUE_TEMPLATE/bug_report.yml),
[`feature_request.yml`](.github/ISSUE_TEMPLATE/feature_request.yml),
[`docs.yml`](.github/ISSUE_TEMPLATE/docs.yml)) and
[`PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md).

> **Blank issues are disabled** (`blank_issues_enabled: false` in
> [`ISSUE_TEMPLATE/config.yml`](.github/ISSUE_TEMPLATE/config.yml)) — otherwise
> triage starts by begging for the version and the steps to reproduce. The same
> file uses `contact_links` to route vulnerabilities to a private advisory and
> questions about keys to `jwks-service-app`: that is the only way to show
> someone the right channel **before** they publish a finding.

The checklist in the pull request template duplicates the rules from "Rules for
agents" (the version, `docs/openapi.json`, `internal_endpoints()`, the generated
`CHANGELOG.md`). Change a rule and change both places, or the template starts
demanding the wrong thing.

**The metadata of the repository itself** (`description`, `homepage`, `topics`)
lives in the GitHub settings rather than in files, which is why it drifts the
most quietly of all. The current values:

```bash
curl -s https://api.github.com/repos/filipov-dev/jwt-service-app \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["description"], d["homepage"], d["topics"], sep="\n")'
```

- `description` — "Issue, verify and revoke JWTs: RS/ES/EdDSA, keys from an
  external JWKS, revocation by `jti`, four access levels". The same statement
  appears in the image label `org.opencontainers.image.description`
  ([`deployments/prod/Dockerfile`](deployments/prod/Dockerfile)) and at the top
  of [`deployments/prod/README.md`](deployments/prod/README.md), the Docker Hub
  description of the image. Change one and check the others.
- `homepage` — the image page on Docker Hub: people read the repository but run
  the image.
- `topics` — `jwt`, `jwks`, `rust`, `actix-web`, `authentication`,
  `authorization`, `microservice`, `redis`, `openapi`, `totp`, `docker`,
  `security`.

## Configuration (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `HOST` | `127.0.0.1` | Bind address. |
| `PORT` | `8080` | Port. |
| `SERVER_WORKERS` | `auto` | Number of worker threads. `auto`/`0`/empty means from the cgroup CPU quota (rounded up), and without a quota a ceiling of 4 — **not** the host core count. |
| `SERVER_CLIENT_REQUEST_TIMEOUT_MS` | `5000` | Time allowed to receive the request headers. `0` means no limit. |
| `SERVER_KEEP_ALIVE_SECONDS` | `5` | Idle time of a keep-alive connection. `0` disables keep-alive. |
| `SERVER_SHUTDOWN_TIMEOUT_SECONDS` | `25` | How long the server keeps serving in-flight requests after a stop signal. `0` tears connections down immediately. Must be **strictly less** than `terminationGracePeriodSeconds` (k8s) / `stop_grace_period` (Compose), otherwise the pod is killed mid-drain. |
| `TOKEN_ALGORITHM` | `RS256` | Signing algorithm (see `SUPPORTED_ALGORITHMS` in `key.rs`). |
| `TOKEN_EXPIRATION_SECONDS` | `3600` | Default token TTL and TTL of the `jti` record in Redis (when `ttl` is not passed in the request). |
| `TOKEN_TTL_MIN_SECONDS` | `1` | Lower bound for a custom `ttl` in the body of `POST /tokens`. |
| `TOKEN_TTL_MAX_SECONDS` | `86400` | Upper bound for a custom `ttl` in the body of `POST /tokens`. |
| `TOKEN_CLAIMS_MAX_COUNT` | `32` | Maximum number of custom claims in the body of `POST /tokens`. |
| `TOKEN_CLAIMS_MAX_BYTES` | `4096` | Maximum total size of the custom claims. A token travels in headers, and a bloated payload breaks proxies. |
| `TOKEN_JKU` | — (none) | When set, it is put into the `jku` header and checked during verification. |
| `TOKEN_ISSUER_ALLOWLIST` | — (none) | Allowed `iss` values, comma-separated (`Host` is taken as is, port included; case-insensitive). Empty means any `Host` (the previous behaviour). |
| `REFRESH_TOKEN_TTL_SECONDS` | `2592000` (30 days) | Lifetime of a refresh token. The long window is safe thanks to rotation: a stolen token works only until the real client next exchanges it. |
| `REDIS_URL` | `redis://redis:6379` | Redis connection. |
| `REDIS_RESPONSE_TIMEOUT_MS` | `1000` | Timeout waiting for a command response. Without it a hung Redis would hold the handler indefinitely. |
| `REDIS_CONNECT_TIMEOUT_MS` | `500` | Connection timeout. |
| `JWKS_SERVICE_URL` | `http://jwks-service-app:8080` | Base URL of the key service. |
| `JWKS_REQUEST_TIMEOUT_MS` | `2000` | Overall timeout of a request to the key service. Without it a hung JWKS would hold a worker until the OS timeout. |
| `JWKS_CONNECT_TIMEOUT_MS` | `500` | Connection timeout to the key service. |
| `JWKS_CACHE_TTL_SECONDS` | `300` | How long a JWKS snapshot is considered fresh. `0` disables the cache (every verification goes to the JWKS, the previous behaviour). |
| `JWKS_CACHE_MISS_REFRESH_SECONDS` | `10` | Minimum interval between cache refreshes triggered by an unknown `kid`. It is also the delay before a new key is picked up during rotation. |
| `JWKS_CACHE_STALE_GRACE_SECONDS` | `10` | How long a JWKS snapshot is still served **beyond** its TTL while the key service is unavailable (stale-while-revalidate). The maximum age of a usable snapshot is TTL + grace. Ten seconds cover a network blip and a JWKS restart; a longer value keeps a revoked key alive for exactly as much longer. `0` disables serving stale snapshots. |
| `RUST_LOG` | — | Log level filter (`tracing-subscriber`, `EnvFilter`; the default is `jwt_service_app=info`). |
| `LOG_FORMAT` | `pretty` | Log format: `json` for line-delimited JSON (for collectors: Monium/ELK); anything else gives the human-readable `pretty` format with ANSI. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — (none) | The **base** URL of the OTLP collector (e.g. `http://otel-collector:4318`); `/v1/traces` is appended to it. Unset means tracing is off. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | — (none) | The **full** URL for traces; used as is and takes precedence over the base one. |
| `OTEL_SERVICE_NAME` | `jwt-service-app` | Service name in traces and logs (the `service.name` attribute). |
| `OTEL_LOGS_ENABLED` | `false` | Whether to send **logs** over OTLP. A separate flag: enabling traces does not enable logs. |
| `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` | — (none) | The **full** URL for logs; used as is and takes precedence over the base one. |
| `GLITCHTIP_DSN` | — (none) | GlitchTip DSN. Unset means the integration is off. `SENTRY_DSN` is accepted too. **A secret; do not commit it.** |
| `GLITCHTIP_TRACES_SAMPLE_RATE` | `0.0` | Fraction of spans sent to Performance (0.0–1.0). `0.0` disables performance. |
| `GLITCHTIP_ENABLE_LOGS` | `false` | Whether to send structured logs to the Logs channel. |
| `GLITCHTIP_ENVIRONMENT` | — (none) | Environment (`prod`/`stage`) for grouping in GlitchTip. |
| `AUTH_PROXY_SECRET` | — (**required**) | Level 2: the expected value of the secret header. The service does not start without it. |
| `AUTH_PROXY_SECRET_HEADER` | `X-Proxy-Secret` | Level 2: the name of the header carrying the secret. |
| `AUTH_TOTP_SECRET` | — (**required**) | Level 3: the primary TOTP secret (base32). The service does not start without it. |
| `AUTH_TOTP_SECRET_NEXT` | — (none) | Level 3: a second active secret for the duration of a rotation (base32). |
| `AUTH_TOTP_HEADER` | `X-TOTP-Code` | Level 3: the name of the header carrying the TOTP code. |
| `AUTH_TOTP_STEP_SECONDS` | `30` | Level 3: the TOTP window step. For a narrower replay window set a smaller value (e.g. `5`) — but then the client and server clocks must be NTP-synchronised, and with drift you need a larger `AUTH_TOTP_SKEW_STEPS`. The default of 30 is not changed in code: it is the shared contract with the clients. |
| `AUTH_TOTP_DIGITS` | `6` | Level 3: number of digits in the code (6–8). |
| `AUTH_TOTP_ALGORITHM` | `SHA1` | Level 3: the HMAC hash (`SHA1`/`SHA256`/`SHA512`). |
| `AUTH_TOTP_SKEW_STEPS` | `1` | Level 3: tolerance in windows in both directions (clock drift). |
| `AUTH_TOTP_REPLAY_PROTECTION` | `false` | Level 3: forbid replaying a TOTP code. Enabling it adds a Redis dependency to the auth layer; with Redis unavailable it fails open. |
| `RATE_LIMIT_VERIFY_ENABLED` | `true` | Per-IP limit on `POST /tokens/verify`. |
| `RATE_LIMIT_VERIFY_PER_SECOND` | `10` | Sustained per-IP rate (requests per second per address). |
| `RATE_LIMIT_VERIFY_BURST` | `20` | Per-IP burst capacity (bucket size). |
| `RATE_LIMIT_INTERNAL_ENABLED` | `false` | Global cap on the internal endpoints (`POST /tokens`, `DELETE /tokens/{jti}`). |
| `RATE_LIMIT_INTERNAL_PER_SECOND` | `50` | Sustained rate of the global cap (requests per second per endpoint). |
| `RATE_LIMIT_INTERNAL_BURST` | `100` | Burst capacity of the global cap. |
| `RATE_LIMIT_TRUSTED_PROXIES` | — (none) | List of trusted proxies (IP/CIDR, comma-separated). `X-Forwarded-For` is trusted only behind them; empty means the key is the peer address. |
| `RATE_LIMIT_FORWARDED_HEADER` | `X-Forwarded-For` | Name of the header carrying the client IP (parsed as a list, right to left). |
| `AUTH_METRICS_TOKEN` | — (none) | Level 4: the static bearer token for scraping `GET /metrics`. Unset means the endpoint is not published (`404`) and the service still starts. |
| `CORS_ALLOWED_ORIGINS` | — (none) | Allowed CORS origins for `POST /tokens/verify` (comma-separated). Empty means `allow_any_origin`. Applies to that endpoint only. |

The `iss` of a token comes **from the `Host` header of the request**, not from
the configuration, but its value is constrained by `TOKEN_ISSUER_ALLOWLIST`. The
list is mandatory wherever several instances share one `jwks-service-app`:
without it instance `A` issues a token with `Host: b.example.com` signed by the
shared key, and instance `B` accepts it as its own. Issuing (`POST /tokens`) and
a refresh exchange with a `Host` outside the list give `403`; verification
(`POST /tokens/verify`) gives `401`, like any other verification failure — a
public endpoint does not reveal the reason.

Secrets (`AUTH_PROXY_SECRET`, `AUTH_TOTP_SECRET*`) are never logged and never
committed; inject them from a secret manager. The default header names
(`X-Proxy-Secret`, `X-TOTP-Code`) are duplicated in the OpenAPI spec as the
`proxy_secret` and `totp` security schemes — when you override them through the
environment, update the scheme descriptions in `main.rs`.

## Conventions and pitfalls

- **The service speaks HTTP/1.1 only: the `http2` feature of `actix-web` is
  off.** It pulled in `h2` 0.3, which never got a patch for RUSTSEC-2026-0258
  (the 0.3 branch has had no release since July 2025, and `actix-http` still
  requires `h2 ^0.3.27`). Nothing is lost functionally: HTTP/2 in actix is
  reachable either through TLS with ALPN (the service does not terminate TLS —
  that is the reverse proxy) or through `bind_auto_h2c()`, while the server
  comes up with a plain `bind()`. In other words the `h2` code was linked in but
  unreachable. Default features are listed explicitly in `Cargo.toml` — when
  upgrading actix the list has to be checked, otherwise a new default feature
  silently stays off. The planned gRPC work (JWT-102) is unaffected: `tonic`
  brings its own server on `hyper` with `h2` 0.4. Turning `http2` back on makes
  sense only if HTTP/2 is needed in the REST API itself — and then check first
  whether a patch for `h2` 0.3 has been released.
- **There is exactly one TLS stack in the binary — `native-tls` (JWT-46).**
  Before that, two were linked at once: `rustls` + `aws-lc-rs` arrived through
  the default features of `reqwest` (in 0.13 `default-tls` no longer means
  `native-tls` but `rustls`), and `native-tls` came from `sentry` (the
  `transport` feature). `native-tls` won because it reuses openssl, which the
  service needs anyway for signing JWTs — and that lets the entire rustls stack
  (`aws-lc-rs`, `rustls-webpki`, `rustls-platform-verifier`, `quinn`) go away
  completely. The result: the release binary went from 19,427,168 to 16,119,848
  bytes (−3.2 MiB, −17%), dependency builds in Docker from 213 s to 169 s (the
  `cmake` build of `aws-lc-sys` disappeared); of the dynamic dependencies only
  `libssl`/`libcrypto` from the runtime image remain.
  - **The trust roots are now the system ones** (`/etc/ssl/certs`) rather than a
    baked-in `webpki-roots`: the `ca-certificates` package in the runtime image
    is mandatory, and without it HTTPS to the JWKS and to OTLP fails certificate
    validation.
  - **The `reqwest` features are listed explicitly** — when upgrading, compare
    the list against the new defaults, or `default-tls` brings rustls back.
  - **A second `jti` backend will bring rustls back**: YDB pulls in `tonic`, and
    that speaks TLS through rustls. One more argument for splitting the builds
    per backend.
- **The release profile: LTO, one codegen unit, stripped symbols (JWT-47).**
  There was no `[profile.release]` section in `Cargo.toml` at all — the
  production image was built with the cargo defaults: LTO off,
  `codegen-units = 16`, the symbol table intact. It is now `lto = "fat"`,
  `codegen-units = 1`, `strip = "symbols"`. The production binary (Docker, build
  without cache) went from 16,119,848 to 8,937,224 bytes (−6.8 MiB, −45%) and
  the image from 172 to 163 MB. Broken down (local build, 8 cores): LTO with one
  unit accounts for −3.5 MiB and `strip` for another −1.5 MiB.
  - **We pay in build time, and in exactly the layer that caches worst.**
    Building the whole image went from 331 s to 423 s, but inside that
    `cargo chef cook` (dependencies, reused from cache in CI) went from 171 s to
    217 s while the final `cargo build --release` went from 11.5 s to 100 s. In
    other words, editing a single source file used to cost ten seconds and now
    costs a minute and a half: fat LTO is one pass of the optimiser over the
    whole graph at link time, and a dependency cache does not help;
    `codegen-units = 1` serialises code generation on top of that. A clean local
    build went from 88 s to 127 s.
  - **Do not add `panic = "abort"`.** It would kill the panic channel into
    GlitchTip (`sentry-panic` installs a hook and manages to send the event
    while the stack unwinds) and the worker isolation of actix: a panic in one
    request would take down the whole process instead of a single connection.
    The savings are not comparable.
  - **`strip = "symbols"` costs the panic stack in GlitchTip.** The event itself
    still arrives (the message and `file:line` are constants baked into the
    binary), but backtrace frames do not resolve without a symbol table: on
    Linux a release build without `strip` gives named frames, and with `strip`
    the frame list is empty. If you need the stack in Issues, switch to
    `strip = "debuginfo"` (+1.5 MiB on the binary) rather than reverting LTO.
- **Domain code (`key.rs`, `jwt.rs`, `models/jwt.rs`) handles errors through
  `Result`/`?`** and the types from `error.rs` / `models/jwt.rs` — no
  `.unwrap()`. Keep to that style; `.unwrap()`/`.expect()` remain only in
  `main.rs` at startup (fail-fast on invalid configuration).
- **Refresh tokens (`jwt.rs`).** They are issued only on explicit request
  (`"refresh": true` in the body of `POST /tokens`) — the contract of existing
  clients does not change.
  - **Rotation on every exchange**, not reuse: the old token is marked used
    immediately. A reusable refresh token with a long TTL is a long-lived
    password with no way to detect compromise.
  - **Reuse detector.** Presenting an already-used token means a leak: the real
    client has exchanged its copy already. There is no way to tell the thief
    from the victim, so the **whole family** is killed — the refresh chain and
    the access tokens issued through it. The price of a false positive (a client
    lost the response and retried) is one more sign-in; that is cheaper than
    leaving the thief a working chain.
  - **Marking a token used must be atomic.** In Redis that is `HSETNX`: there is
    exactly one winner, so two concurrent attempts to exchange the same token
    cannot both get a new pair.
  - **Access tokens go into the family group too.** Otherwise the detector would
    kill only the refresh tokens while the access tokens already issued kept
    working until their `exp`.
  - **The exchange is behind level 3, like issuing.** An exchange *is* issuing a
    token; it just rests on a presented refresh token rather than on a request
    from a trusted backend. Level 2 would be a hole here: the proxy secret is
    static and does not authenticate the caller, so a stolen refresh token would
    give anyone who can reach through the proxy an endless chain of tokens. The
    end application never talks to the service directly — the consuming backend
    does, and it is what holds the TOTP secret.
- **Token groups (`models/jwt.rs`, `redis.rs`).** The mechanism is deliberately
  generic: the store operates on an abstract group key and the caller supplies
  the meaning ([`subject_group`]). That is how the revocation of a refresh token
  family reuses it (JWT-28) — no separate mechanism is needed there.
  - **A ZSET, not a SET**: elements of a set have no TTL of their own, and
    expired `jti` values would pile up in the index as dead weight. The score is
    the expiry moment, so a single `ZREMRANGEBYSCORE` cuts them off.
  - **The index is written fail-fast**, exactly like the `jti` itself: a token
    that did not make it into the index would survive a bulk revocation. Issuing
    such a token silently is more dangerous than not issuing one at all.
  - **Revocation is deliberately not atomic**: a concurrent issue during a
    revocation may add a `jti` after the `ZRANGE`, and such a token survives. The
    window is a fraction of a millisecond, and the cost of atomicity (Lua/WATCH)
    outweighs the benefit: bulk revocation happens on compromise, and the
    subject's credentials are usually rotated right after.
  - **A revocation error surfaces as `500`** rather than being masked as
    success. This applies to both revocation endpoints: a silent "success" for a
    failed revocation of compromised tokens is more dangerous than an honest
    error — the caller considers the job done and does not retry.
    **Idempotency is preserved** at the same time: revoking a `jti` that does
    not exist is `204`, not an error, because the desired state has been
    reached.
- **The `jti` store is reachable only through the `JtiStore` trait (JWT-60).**
  No module above `redis.rs` may mention `RedisClient`, `redis::` or
  `RedisError` — otherwise the seam leaks and a second backend cannot be plugged
  in.
  - **The HTTP handlers are generic over the store**
    (`create_token<S: JtiStore>` and so on), and the concrete type is supplied
    once in `main.rs` (`configure_api::<RedisClient>`). There are no separate
    "production wrappers" over the generic implementations: those took
    `web::Data<RedisClient>` and were exactly where the seam leaked.
  - **That is why routes are assembled by hand**
    (`web::resource(...)`/`.route(...)`) rather than with the actix attribute
    macros (`#[post("/tokens")]`): those cannot handle generic handlers. The
    exception is `livez`, which does not depend on the store.
    `#[utoipa::path]` works on a generic function; the completeness of the spec
    is guarded by the `openapi_spec_lists_all_endpoints` test.
  - **`/readyz` pings the store through `JtiStore::ping`**, not `RedisClient`
    directly. When adding a backend, implement `ping` honestly: readiness means
    "can we serve", and without a store the answer is no.
  - **`where Self: Sized` is not needed in the trait**: an `async fn` in a trait
    already makes it non-object-safe, and the store is always taken by static
    type.
- **A new key is created only on a `404` from the key service.** In
  `JwkService::private_key` the creation branch fires exclusively on
  [`JwkError::NotFound`], which is returned only for an honest `404`; `5xx`, an
  unreadable body and network failures propagate upwards as errors. Otherwise a
  brief JWKS outage would spawn new keys, litter the store and change the active
  `kid` for no reason. Preserve that distinction when editing `get_key`.
- **Token issuing is fail-fast**: if `store_jti` could not write the `jti` (for
  example Redis is unavailable), `create_new` returns `JwtError::StoreError` and
  no token is handed out — that is what guarantees consistency with
  verification, which requires the `jti` to be present. Preserve this behaviour
  when making changes.
- Errors are returned tersely: many handlers return empty `500`/`401`/`422`
  responses with no body. Do not assume the client receives any detail.
- **The Redis connection (`redis.rs`).** The client works through a
  `ConnectionManager`: **one** multiplexed connection per process, which the
  manager re-establishes after a drop. Previously a connection was opened per
  command, and under load that ran into ephemeral port exhaustion
  (`os error 49`) — valid tokens got `401` because `check_jti` never reached the
  store.
  - **Initialisation is lazy, and deliberately so.** A Redis that is unavailable
    at startup does not bring the process down: the service comes up,
    `GET /readyz` answers `503`, no traffic is routed to the pod, and once the
    store appears the connection establishes itself without a restart. A failed
    attempt is not remembered; the next request tries again.
  - **Retries are limited to a single attempt** (the crate default is six with
    exponential backoff, more than six seconds in total). While retries are in
    flight a handler is blocked, `/readyz` included; a long outage is better
    shown in readiness than hidden behind waiting.
- **Custom claims (`models/jwt.rs`).** The `claims` field in the body of
  `POST /tokens` is merged into the payload **alongside** the registered ones
  (`#[serde(flatten)]`): the consumer of the token looks for `role`, not
  `extra.role`.
  - **Reserved names are protected.** `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`,
    `jti` (see `RESERVED_CLAIMS`) cannot be overridden — an attempt gives `422`.
    Otherwise a client could substitute `exp` and bypass the
    `TOKEN_TTL_MIN/MAX_SECONDS` bounds, or issue a token on someone else's
    behalf through `iss`/`sub`.
  - **The limits are mandatory** (`TOKEN_CLAIMS_MAX_COUNT`,
    `TOKEN_CLAIMS_MAX_BYTES`): a token travels in HTTP headers, and a bloated
    payload breaks proxies with their header size limits.
  - **The contents of the claims are never logged** — they may contain personal
    data. Only the name of the conflicting key or the fact that a limit was
    exceeded goes into the log; that is consistent with the general rule of not
    writing bodies and headers.
  - **Claims are NOT carried over on a refresh exchange.** We do not store them
    in the refresh record, and carrying them over was rejected deliberately: it
    would extend roles and scopes granted long ago without a fresh decision
    about permissions. If you need claims in the renewed token, issue a new pair
    through `POST /tokens`.
- **The public key cache (`jwk.rs`).** The JWKS is cached in memory: before
  that, every verification pulled the whole `/.well-known/jwks.json` and created
  a new HTTP client, so load was translated one-to-one onto the key service (the
  measurement is in
  [`deployments/load/BASELINE.md`](deployments/load/BASELINE.md)).
  - **`JwkService` is created once per process** and cloned afterwards: the
    cache and the connection pool sit behind an `Arc` and are shared by every
    copy. Do not create it per request — that is exactly what the problem looked
    like.
  - **A miss on an unknown `kid` is throttled**
    (`JWKS_CACHE_MISS_REFRESH_SECONDS`). Without that the cache would not defend
    against the main scenario: a stream of tokens with random `kid` values would
    miss the cache and bury the JWKS again. The flip side is that a new key
    after a rotation is picked up with a delay of up to that interval.
  - **Refreshes happen under a lock** (`tokio::sync::Mutex`): a burst of
    simultaneous misses turns into a single request to the JWKS while the rest
    wait and take the ready cache.
  - **An unavailable JWKS does not take verification down**
    (`JWKS_CACHE_STALE_GRACE_SECONDS`): if a refresh failed, the last known
    snapshot is served until its age exceeds TTL + grace. That is a trade of
    freshness for availability, which is why the grace is short and mandatory:
    it extends the life of a **revoked key** by exactly as much. Revocation of
    individual tokens (`jti` in Redis) keeps working as usual — the trade
    concerns key compromise only. Every such response is written to the log
    (WARN) and to the `jwks_cache_total{result="stale"}` metric. Repeated trips
    to a downed service are throttled by the same
    `JWKS_CACHE_MISS_REFRESH_SECONDS`: otherwise every request would wait for
    the timeout and verify would be down on latency alone.
  - **`GET /readyz` goes to the JWKS directly, bypassing the cache**, but counts
    an unavailable key service as a failure only when there is **also** no
    usable snapshot in memory. The probe answers "can we serve a request", not
    "is the dependency alive": readiness tied to JWKS liveness would kill the
    pods within ten seconds and traffic would never reach the stale cache — the
    feature would not work in Kubernetes at all. That state is reported as
    `status: "degraded"` (the code stays `200`), and as soon as the snapshot
    stops being usable the pod leaves the load balancer on its own. **Redis gets
    no such leniency** — without it the `jti` cannot be checked and a revoked
    token would become valid. Issuing tokens does not work in the `degraded`
    state anyway (a live JWKS is needed to fetch the private key) and answers
    `500` instead of a `503` from the load balancer — but it did not work before
    either, only back then verification went down with it.
  - **The client has timeouts** (`JWKS_REQUEST_TIMEOUT_MS`,
    `JWKS_CONNECT_TIMEOUT_MS`). `reqwest` does not limit request duration by
    default, so a hung — not crashed, but hanging — JWKS would hold workers
    until the OS timeout. The cache reduced the request rate but does not save
    you from a single hung request.
- **Logging (`logging.rs`).** Every request is wrapped in an `http_request` span
  with a `request_id` (the `X-Request-Id` header: the incoming one is used when
  valid, otherwise a UUID is generated and returned in the response). On
  completion there is a single `request completed` line with the method, path,
  status and latency. **Do not log headers or bodies** — they contain secrets
  (`X-Proxy-Secret`, `X-TOTP-Code`) and tokens. The access level is recorded
  into the span from `auth.rs` (`Span::current().record`).
- **Log levels are chosen by who is at fault**, not by how "serious" the text
  sounds. `tracing` has five (`TRACE < DEBUG < INFO < WARN < ERROR`); there is
  **no** separate `CRITICAL`/`FATAL` — fatal means a panic at startup
  (fail-fast).

  | Level | When | Examples |
  |------:|------|----------|
  | `ERROR` | the service could not do its job; suitable for alerts | Redis/JWKS unavailable, a crypto failure while signing, corrupt key material |
  | `WARN` | degradation or a security signal, request still handled | a configuration problem (with a fallback), access denied (401), rate limit (429) |
  | `INFO` | lifecycle and business events | server start, configuration summary, `request completed`, token revoked |
  | `DEBUG` | the client's fault and internal detail | an expired/forged/corrupt token, a `ttl` out of bounds, the steps of JWKS requests |
  | `TRACE` | unused | — |

  **Client errors are `DEBUG`, not `ERROR`**: otherwise every expired token
  would raise a false alert in production. The error is logged by the layer that
  knows the **cause** (for example `jwk.rs` logs a JWKS failure at `ERROR`);
  layers above record the outcome at `DEBUG` so that there are no duplicates.
- **Tracing (`tracing_otel.rs`).** Enabled **only** when
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set — spans go over OTLP/HTTP to an
  OpenTelemetry Collector, from which Monium (or Jaeger/Tempo) picks them up. It
  is a layer over the same `tracing` bus as the logs, so the `http_request` span
  and the nested `jwks.*`/`redis.*` spans end up in both logs and traces.
  - **The signal path is mandatory.** `OTEL_EXPORTER_OTLP_ENDPOINT` is the
    **base** URL to which the signal path is appended (`/v1/traces`,
    `/v1/logs`). Send the base URL as is and the collector answers `404` while
    the data is **silently lost** (see `signal_endpoint`).
  - **Logs over OTLP are a separate signal with a separate flag**
    (`OTEL_LOGS_ENABLED`). Enabling traces does **not** enable logs: they go to
    stdout anyway, and where an agent collects them from the container log,
    sending them over the network would be duplication. Logs written inside a
    request carry the `Trace ID`/`Span ID` — in the backend you can move from a
    trace to its logs and back.
  - **The exporter client is blocking, deliberately.** The batch processor runs
    on its own dedicated thread without a tokio runtime; an async HTTP client
    panics there ("there is no reactor running"). The main async runtime is
    unaffected.
  - **Propagation (W3C).** An incoming `traceparent` is picked up and makes our
    span a child of someone else's trace; outgoing requests to the JWKS get
    their own `traceparent` — the trace is stitched across services.
  - **Not fail-fast**, like rate limiting: a misconfigured exporter does not
    bring the service down, only a warning into the log. Telemetry must never be
    a cause of unavailability.
  - The tracing status is logged **after** the subscriber is installed: before
    that there is nowhere to write and the message would be lost (which is why
    `init_tracer_provider` returns a [`Status`] instead of logging itself).
- **GlitchTip (`sentry_glitchtip.rs`).** Enabled **only** when `GLITCHTIP_DSN`
  is set (`SENTRY_DSN` is accepted too). It covers **three** channels, not just
  errors — all on top of the same `tracing` bus:

  | Channel | What goes there | Enabled by |
  |---------|-----------------|------------|
  | **Issues** | panics and `ERROR`-level events | always, given a DSN |
  | **Performance** | spans → transactions (`http_request` and nested ones) | `GLITCHTIP_TRACES_SAMPLE_RATE > 0` |
  | **Logs** | structured `DEBUG`/`INFO`/`WARN` logs | `GLITCHTIP_ENABLE_LOGS=true` |

  - The split across channels is defined by the layer's `event_filter`: `ERROR`
    → issue, `WARN`/`INFO` → log plus breadcrumb, `DEBUG` → log, `TRACE` →
    ignored.
  - **Logs are batched** and flushed in bulk (including at process shutdown) —
    unlike issues, they do not appear in the UI instantly.
  - **Not fail-fast**: an invalid DSN does not bring the service down. **The DSN
    is never logged.**
  - Performance is **off** by default (`0.0`): transactions cost volume, so
    enable them deliberately.
- **Metrics (`metrics.rs`).** The Prometheus exposition on `GET /metrics` is
  **access level 4** (the `AUTH_METRICS_TOKEN` bearer token; without it the
  endpoint does not exist — `404`). It is scraped by Prometheus / Yandex Managed
  Prometheus, by Zabbix (`agent2` with the prometheus plugin) and by Monium
  (through Prometheus compatibility); no separate Zabbix exporter is needed. An
  example scrape configuration:

  ```yaml
  scrape_configs:
    - job_name: jwt-service
      authorization:
        credentials_file: /etc/prometheus/jwt-metrics-token
      static_configs:
        - targets: ['jwt-service-app:8080']
  ```

  The token is **not a substitute for network isolation**: the endpoint still
  should not be exposed publicly (metrics reveal the operational picture).

  | Metric | Type | Labels |
  |--------|------|--------|
  | `http_requests_total` | counter | `method`, `endpoint`, `status` |
  | `http_request_duration_seconds` | histogram | `method`, `endpoint` |
  | `jwt_tokens_issued_total` / `jwt_tokens_revoked_total` | counter | — |
  | `jwt_tokens_verified_total` | counter | `result` (`success`/`failure`) |
  | `jwt_auth_denied_total` | counter | `level` (`open`/`proxy_secret`/`totp`) |
  | `jwt_rate_limit_exceeded_total` | counter | — |
  | `jwks_request_duration_seconds` | histogram | `operation`, `success` |
  | `jwks_cache_total` | counter | `result` (`hit`/`miss`/`throttled`) |
  | `redis_command_duration_seconds` | histogram | `command`, `success` |

  **Cardinality:** the `endpoint` label carries the **route template**
  (`/tokens/{jti}`), not the actual path — otherwise every `jti` would spawn its
  own series. Never put anything client-supplied (tokens, secrets, IPs) into
  labels.
- **Server workers and timeouts (`server.rs`) are not left at the actix
  defaults.**
  - **The worker count is derived from the CPU quota, not from the core count.**
    The actix default follows the process cores, that is the **host** cores: a
    pod without a CPU limit on a 64-core node started 64 worker threads that all
    had to fit into the pod memory limit. The order of preference is an explicit
    `SERVER_WORKERS` → the cgroup quota (v2 `cpu.max`, v1 `cpu.cfs_quota_us`) →
    a ceiling of 4. `available_parallelism` is unfit as the source of truth: it
    already accounts for the quota and therefore cannot distinguish "a quota of
    4 cores" from "the host has 4 cores", and the decision differs between the
    two.
  - **`requests.cpu` has no effect on the worker count whatsoever** — it is a
    scheduler guarantee and appears in the cgroup as a weight, not as a quota.
  - **The timeouts are set explicitly** (`client_request_timeout`, keep-alive)
    even though the values match the actix defaults: behind a proxy it is the
    proxy that cuts off slow clients, but the image is distributed publicly and
    gets deployed directly too.
- **Repository language: English, everywhere that is visible from the outside.**
  Code, comments, docstrings, `utoipa` descriptions, documentation, templates,
  workflows, manifests, image labels, commit messages (they end up in the
  changelog and in release bodies) and pull request titles and bodies. No
  exceptions, and no mixed languages inside a file. The gate is
  [`scripts/check-language.sh`](scripts/check-language.sh), run by `ci.yml` on
  every pull request: any Cyrillic in a tracked file fails the pipeline. Its
  allowlist is a per-file list with a reason inside the script; today it holds
  exactly one entry, `CHANGELOG.md`, because the file is generated from a commit
  history that was deliberately left in Russian (JWT-114). Run it locally with
  `scripts/check-language.sh`.
  - **The generated `docs/openapi.json` is checked too**, and the check matters
    most there: Cyrillic reaches it from `utoipa` annotations in `src/` without
    the author noticing, and the spec is served by a live endpoint to everyone
    running the image.
- Version in `Cargo.toml` is a **release trigger**: pushing a `Cargo.toml`
  change to `master` runs `release.yml`, which creates a GitHub release and
  dispatches `docker.yml` to build and publish the images
  (`filipov/jwt-service-app`, `ghcr.io/filipov-dev/jwt-service-app`). Change the
  version deliberately.
- `release.yml` clones with `fetch-depth: 0`. Do not remove it: the release
  description is assembled from the commits since the previous tag, and with an
  ordinary shallow clone the runner has neither history nor tags, so the section
  would come out empty.
- Neither a release nor a tag created by `GITHUB_TOKEN` triggers other
  workflows — a GitHub restriction against infinite loops. That is why
  `docker.yml` is dispatched explicitly through the API with `workflow_dispatch`
  rather than on the `release` event.
- **Permissive CORS applies to `POST /tokens/verify` only** — it is the single
  public endpoint that makes sense to call from a browser. The allowed origins
  come from `CORS_ALLOWED_ORIGINS` (comma-separated); when empty, it is
  `allow_any_origin` (the default, for backwards compatibility).
- **Every other endpoint** (health, OpenAPI, issuing and revoking tokens) gets
  `deny_cors()` — not disabled CORS but **denying** CORS: the list of allowed
  origins is empty and any cross-origin browser request is rejected (a preflight
  `OPTIONS` is refused). Requests without an `Origin` (internal app-to-app,
  `curl`) go through.
- **The rule: exactly one public endpoint may sit under permissive CORS**
  (`/tokens/verify`). New endpoints get `deny_cors()` by default; do not put
  permissive CORS on them without an explicit decision.
- CORS is the outermost layer on an endpoint so that a preflight `OPTIONS` is
  handled before auth and rate limiting.

## Rules for agents

- Respect the existing module structure; keep new crypto and JWT code in
  `key.rs` / `models/jwt.rs` and the HTTP layer in `handlers.rs`.
- Run `cargo build` and `cargo clippy` before calling a task done.
- **Every commit must bump the version** in `Cargo.toml` per semver, choosing
  the digit by the nature of the change:
  - **major** — backwards compatibility is broken (incompatible changes to the
    API, the token format, the configuration and so on);
  - **minor** — new functionality with backwards compatibility preserved;
  - **patch** — a bug fix (or any other change without new functionality:
    refactoring, documentation edits, CI).

  Note that pushing such a change to `master` triggers a release and publishes
  Docker images (see "Conventions and pitfalls").
- **Insert the version section into `CHANGELOG.md` before merging**:
  `scripts/changelog.sh --insert` (see "Releases and the changelog"). The tag
  only appears after the merge, so rebuilding with `--all` at that moment would
  file the changes under "Unreleased" — only `--insert` produces a section with
  a version number.
- **Write in English.** Code, comments, documentation, commit messages, pull
  request titles and bodies — see "Repository language". Run
  `scripts/check-language.sh` before finishing; CI runs it anyway.
- **A rule written into the pull request checklist lives in two places** — in
  this section and in
  [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) (plus a
  short retelling in [`CONTRIBUTING.md`](CONTRIBUTING.md)). Change a rule and
  change every place at once, see "Public repository hygiene".
- Do not commit and do not push without being asked.
- Do not add secrets to the repository; CI credentials live in GitHub Secrets.
- When adding an endpoint, do not forget the `utoipa::path` annotation and the
  registration of the schemas and paths in `ApiDoc` (`openapi.rs`), or it will
  not reach the OpenAPI spec. Paths in `paths(...)` are written as
  `handlers::foo`, not `crate::handlers::foo`: `utoipa` takes the path text as
  the tag name that groups the endpoints in Swagger UI.
- **When editing the spec or the version, regenerate `docs/openapi.json`**:
  `UPDATE_OPENAPI=1 cargo test openapi`. The file is compared against the code
  by the `spec_file_is_up_to_date` test, and a mismatch fails CI. The version
  from `Cargo.toml` goes into `info.version`, so the mandatory version bump is a
  reason to regenerate too.
