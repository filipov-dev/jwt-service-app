# jwt-service-app

A service that issues, verifies and revokes JWTs. Signing with RS/ES/EdDSA or
HMAC, the keys come from an external jwks-service-app, and the issued `jti`
values and refresh tokens are stored in Redis.

The sources and the full documentation are at
[github.com/filipov-dev/jwt-service-app](https://github.com/filipov-dev/jwt-service-app).

```
docker pull filipov/jwt-service-app:1.13.4
```

The image is multi-arch (`linux/amd64`, `linux/arm64`) and is published to
Docker Hub and to `ghcr.io/filipov-dev/jwt-service-app`. A `latest` tag exists,
but pin a version for a production deployment: rolling back from `latest` comes
down to hoping the registry still remembers the previous image.

## Dependencies

The service needs **Redis** and **jwks-service-app**. Without them it still
starts, but `GET /readyz` answers `503` and it is too early to route traffic to
the pod. An unavailable key service counts as a failure only when there is no
usable JWKS snapshot in memory either: while there is one, token verification
works and the state is reported as `degraded`.

## Endpoints and access levels

| Level | Endpoints | Protection |
|---|---|---|
| 1 — open | `GET /livez`, `GET /readyz`, `GET /api-docs/openapi.json` | none |
| 2 — proxy secret | `POST /tokens/verify` | the `X-Proxy-Secret` header |
| 3 — TOTP | `POST /tokens`, `POST /tokens/refresh`, `DELETE /tokens/{jti}`, `DELETE /subjects/{sub}/tokens` | the `X-TOTP-Code` header |
| 4 — bearer | `GET /metrics` | `Authorization: Bearer` |

**Level 2 rests on the reverse proxy.** The proxy sets `X-Proxy-Secret` and
**must strip the client-supplied version of the header** — otherwise the secret
can be injected from the outside and the level is bypassed. Ready-made
configurations for 10 proxies (nginx, Traefik, HAProxy, Envoy, Caddy, Apache,
Kong, AWS ALB, Cloudflare, NGINX Ingress) are in
[docs/proxy/](https://github.com/filipov-dev/jwt-service-app/tree/master/docs/proxy).
It follows that the container port must not be published directly: direct access
bypasses the proxy, and therefore level 2.

Client examples for level 3 in 30 languages are in
[docs/clients/](https://github.com/filipov-dev/jwt-service-app/tree/master/docs/clients).

## Quick start

```bash
docker run --rm -p 8080:8080 \
  -e HOST=0.0.0.0 \
  -e REDIS_URL=redis://redis:6379 \
  -e JWKS_SERVICE_URL=http://jwks-service-app:8080 \
  -e AUTH_PROXY_SECRET=... \
  -e AUTH_TOTP_SECRET=... \
  filipov/jwt-service-app:1.13.4
```

`HOST=0.0.0.0` is required: the default `127.0.0.1` listens only on the loopback
inside the container and is unreachable from outside. `AUTH_PROXY_SECRET` and
`AUTH_TOTP_SECRET` are required — without them the service deliberately does not
start, so that the protection cannot be "forgotten".

The `iss` of a token comes from the `Host` header of the request, not from the
configuration.

## Ready-made manifests

Both options live in
[deployments/prod/](https://github.com/filipov-dev/jwt-service-app/tree/master/deployments/prod):

**Docker Compose** — the service and Redis, with the secrets from `.env`:

```bash
cp .env.example .env   # fill in the secrets
docker compose -p jwt-prod --env-file .env up -d
```

**Kubernetes** — a Deployment (3 replicas), a Service, a PodDisruptionBudget, a
NetworkPolicy and a sample Secret:

```bash
kubectl apply -k deployments/prod/k8s/
```

The probes: `livenessProbe` on `/livez`, `readinessProbe` on `/readyz`. The split
is fundamental — `/livez` does not touch the dependencies, so an unavailable
Redis takes the pod out of the load balancer without putting it into a restart
loop.

Three replicas are kept alive by two settings at once:
`topologySpreadConstraints` spread the pods across nodes and zones, and the PDB
with `minAvailable: 2` forces a node drain to release them one at a time. A hard
spread across nodes expects a cluster of at least three nodes — on a smaller one
change `whenUnsatisfiable` to `ScheduleAnyway`, or the extra replicas hang in
`Pending`. Change the replica count and recompute `minAvailable` too.

The NetworkPolicy enforces what was said in prose above: only the ingress
controller and the metrics scraper can reach port 8080, and the rest of the
cluster's pods cannot. The namespace and label names there are cluster-specific —
edit them for your stand. Note that the policy is enforced by the CNI: a plugin
without support for it accepts the manifest silently and does nothing.

## Rolling your own healthcheck

The image has **neither `curl` nor `wget`** — only the runtime libraries and
`bash`. The ready-made healthcheck for Compose makes its HTTP request through
bash's built-in `/dev/tcp`:

```yaml
healthcheck:
  test:
    - CMD
    - bash
    - -c
    - 'exec 3<>/dev/tcp/127.0.0.1/8080; printf "GET /livez HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3; grep -q "200 OK" <&3'
```

In Kubernetes this is unnecessary: `httpGet` probes are executed by the kubelet
outside the container.

## Configuration

The full table of environment variables is in
[AGENTS.md](https://github.com/filipov-dev/jwt-service-app/blob/master/AGENTS.md).
What not to miss in production:

| Variable | Why it matters |
|---|---|
| `AUTH_PROXY_SECRET` | level 2, mandatory |
| `AUTH_TOTP_SECRET` | level 3, base32, mandatory |
| `AUTH_TOTP_SECRET_NEXT` | the second active secret during a rotation |
| `TOKEN_ISSUER_ALLOWLIST` | the list of domains acceptable in the `iss` claim; unset means `iss` is taken from `Host` without validation, and with a shared `jwks-service-app` a token can be issued on behalf of a neighbouring instance |
| `RATE_LIMIT_TRUSTED_PROXIES` | without it every client behind the proxy shares one per-IP limit: the key becomes the proxy address |
| `AUTH_TOTP_REPLAY_PROTECTION` | forbids replaying a TOTP code; requires Redis |
| `AUTH_METRICS_TOKEN` | level 4; unset means `/metrics` is not published |
| `LOG_FORMAT=json` | line-delimited JSON for log collectors |
| `SERVER_WORKERS` | the number of worker threads; unset means from the container's CPU quota, and without a quota the default ceiling. Set it explicitly when the memory limit is sized for a specific number of workers |
| `SERVER_SHUTDOWN_TIMEOUT_SECONDS` | how long the server keeps serving requests after a stop signal (25 s by default). Keep it strictly below the orchestrator's grace period (`stop_grace_period` in Compose, `terminationGracePeriodSeconds` in Kubernetes), or the container is killed mid-drain |

Inject the secrets from a secret manager rather than from plain env in the
manifest.

## Observability

Prometheus metrics on `/metrics` (level 4), structured logs to stdout, traces and
logs over OTLP, errors to GlitchTip. Which variable turns what on and where it
flows is in
[docs/observability.md](https://github.com/filipov-dev/jwt-service-app/blob/master/docs/observability.md).

## Changes between versions

[CHANGELOG.md](https://github.com/filipov-dev/jwt-service-app/blob/master/CHANGELOG.md).

## License

[Apache-2.0](https://github.com/filipov-dev/jwt-service-app/blob/master/LICENSE)
— the same string sits in the image label `org.opencontainers.image.licenses`:

```
docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.licenses" }}' filipov/jwt-service-app:latest
```

The full text is inside the image as well —
`/usr/share/doc/jwt-service-app/LICENSE`.

The image may be used, including commercially, forked and modified; when
redistributing it, keep the license text and state the changes you made.
