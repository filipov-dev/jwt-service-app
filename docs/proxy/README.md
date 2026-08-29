# Reverse-proxy configuration for level 2 (the proxy secret)

Level 2 is protected by a **static secret header** set by the reverse proxy and
**only** by it. The service compares the value of the `X-Proxy-Secret` header
against the secret from `AUTH_PROXY_SECRET` in constant time.

## ⚠️ A mandatory requirement

The proxy **MUST strip the client-supplied version of the header** before setting
its own. Otherwise the client sets `X-Proxy-Secret` itself and level 2 is
bypassed entirely.

Every example below performs **two** actions, in the right order:

1. it **deletes** the incoming `X-Proxy-Secret` from the client;
2. it **sets** `X-Proxy-Secret` to the secret value from an environment variable
   or from the proxy's secret manager (`PROXY_SECRET` in the examples; that is
   the secret on the proxy side and it must match the service's
   `AUTH_PROXY_SECRET`).

> The secret must not sit in the config in the clear: substitute it at
> templating/deploy time from a secret store (Vault, AWS Secrets Manager, SSM, a
> Kubernetes Secret, a Worker Secret and so on).

## The proxy index

| Proxy | File | Technique |
|-------|------|-----------|
| nginx | [nginx.conf](nginx.conf) | `proxy_set_header` (reset plus set) |
| Traefik | [traefik.yml](traefik.yml) | the `customRequestHeaders` middleware |
| HAProxy | [haproxy.cfg](haproxy.cfg) | `http-request del-header` plus `set-header` |
| Envoy | [envoy.yaml](envoy.yaml) | `request_headers_to_remove` plus `to_add` |
| Caddy | [Caddyfile](Caddyfile) | `header_up -X…` plus `header_up X…` |
| Apache httpd | [apache.conf](apache.conf) | `RequestHeader unset` plus `set` |
| Kong | [kong.yml](kong.yml) | the `request-transformer` plugin |
| AWS ALB / API Gateway | [aws-alb-apigw.md](aws-alb-apigw.md) | parameter mapping `overwrite:header` |
| Cloudflare | [cloudflare.md](cloudflare.md) | Transform Rules / Workers |
| NGINX Ingress (K8s) | [nginx-ingress-k8s.yaml](nginx-ingress-k8s.yaml) | `configuration-snippet` |

## The service environment variables (level 2)

| Variable | Purpose |
|----------|---------|
| `AUTH_PROXY_SECRET` | The secret the service expects in the header. |
| `AUTH_PROXY_SECRET_HEADER` | The header name (`X-Proxy-Secret` by default). |

The full description of every level and variable is in
[AGENTS.md](../../AGENTS.md).
