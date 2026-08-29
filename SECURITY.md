# Security policy

`jwt-service-app` issues and verifies JWTs — the tokens other services use to
let users in. A mistake here costs more than one in an ordinary web application,
so vulnerability reports are accepted privately and handled ahead of any other
work.

## Supported versions

Security updates are released **for the latest release only**. Patches are not
backported to older tags: there are no maintenance branches, and `master` is the
single line of development.

| Version | Supported |
|---------|-----------|
| Latest tag (`1.17.x`, image `:latest`) | :white_check_mark: |
| Anything earlier | :x: |

The version of a running service is visible in `info.version` of the OpenAPI
spec (`GET /api-docs/openapi.json`) and matches the image tag. If you are not on
the latest tag, upgrade first — the finding may already be fixed. What changed
between versions is in [`CHANGELOG.md`](CHANGELOG.md).

## Where to report

**Do not open a public issue and do not describe the finding in a pull
request.** A public issue exposes the vulnerability to everyone running the
image before a patch exists.

1. **Primary channel — a private advisory on GitHub.** The
   [**Security → Report a vulnerability**][advisory] tab of this repository. The
   conversation is visible only to you and the maintainer, and the resulting
   GHSA is published from the advisory itself, together with a private branch
   holding the patch.
2. **Fallback channel — email:**
   [security@filipov.dev](mailto:security@filipov.dev). Use it if GitHub is
   unavailable, if you have no account, or if you would rather stay off the
   platform. Encrypt it if you like — ask for the key in a first message without
   any details of the finding.

[advisory]: https://github.com/filipov-dev/jwt-service-app/security/advisories/new

## What to include

The more reproducible the report, the sooner the patch. Useful:

- the version of the service (image tag or `info.version` from the spec) and how
  it is run (Docker Compose, Kubernetes, `cargo run`);
- the relevant configuration — **without secret values**: which access levels
  are enabled, whether `RATE_LIMIT_TRUSTED_PROXIES` is set, whether
  `AUTH_TOTP_REPLAY_PROTECTION` is on;
- the steps to reproduce: the request (method, path, headers), the expected and
  the actual response. A `curl` invocation or a short script beats a prose
  description;
- why this is a vulnerability: what the attacker gains and what privileges they
  need to get there;
- if the finding is in a dependency — the advisory identifier
  (RUSTSEC/CVE/GHSA).

There is no need to paste secrets, private keys or live tokens into the report:
a description and, if necessary, a truncated example are enough.

## Timelines

| Stage | Deadline |
|-------|----------|
| Acknowledgement of the report | **72 hours** |
| Verdict: confirmed or rejected with reasoning, severity assessed | **7 days** from acknowledgement |
| Coordinated disclosure: GHSA and patch published | **90 days** from acknowledgement, or sooner — as soon as the patch ships |

What happens between the verdict and disclosure:

- severity is scored with CVSS 3.1; critical and high findings jump the queue;
- the patch ships as its own release, and the images are rebuilt automatically
  (version tag plus `latest`);
- the GHSA is published together with the release, listing the affected
  versions, the workaround (if there is one) and the fixed version;
- a line appears in `CHANGELOG.md` in the same release.

If a finding is confirmed but the patch will not fit into 90 days, I will say so
before the deadline and propose a new date. Please do not publish the details
before the agreed date — but treat 90 days of silence from me as sufficient
grounds to disclose on your own.

## Scope

**In scope:** the code in this repository, the published Docker images, the
manifests in [`deployments/prod/`](deployments/prod/README.md), the example
proxy configurations in [`docs/proxy/`](docs/proxy/README.md), and vulnerable
versions of dependencies.

Of particular interest are findings in what the service exists for: forging or
bypassing signature verification, accepting a token with someone else's
`iss`/`aud`, using a revoked `jti`, bypassing any of the four access levels,
leaking a private key or secret values into responses, logs or metrics.

**Out of scope:**

- **`jwks-service-app`** — key generation and storage live in a separate service
  and repository; report those there;
- **other people's deployed instances.** Test against your own copy. The project
  has no public sandbox, and this policy grants no permission to test anyone's
  production;
- **operator misconfiguration** — for example a proxy that fails to strip a
  client-supplied `X-Proxy-Secret`, or an empty `RATE_LIMIT_TRUSTED_PROXIES`
  behind a proxy. Those are documented requirements, not defects in the code; an
  inaccuracy or a gap in the documentation itself, however, is a bug — report
  it.

## What is not considered a vulnerability

Deliberate decisions, documented in [AGENTS.md](AGENTS.md). A report about any
of them will be closed with a link here — unless you demonstrate a concrete
bypass the reasoning does not account for:

- **Replaying a TOTP code within its window** while
  `AUTH_TOTP_REPLAY_PROTECTION` is off. The protection exists and is switched on
  by a flag; it is off by default on purpose (it adds a Redis dependency to the
  auth layer).
- **Replay protection failing open when Redis is unavailable.** Both level 3
  endpoints go to Redis anyway, so a replayed code achieves nothing while the
  store is down.
- **No per-IP limit on the internal level 3 endpoints** — there is an optional
  global cap there; a per-IP limit is meaningless for one or two trusted
  clients.
- **`404` instead of `401` on `/metrics`** without `AUTH_METRICS_TOKEN`: the
  route is not registered at all, deliberately, so that the very existence of
  the endpoint is not visible from the outside.
- **Open `GET /livez`, `GET /readyz` and the OpenAPI spec** — that is level 1 by
  design.
- Scanner output without demonstrated impact, missing headers such as
  `X-Frame-Options` on an API with no UI, theoretical arguments about algorithm
  choice with no exploitation scenario, and findings in dependencies already
  recorded in [`.cargo/audit.toml`](.cargo/audit.toml) with a justification.

## Research rules

Reports are accepted from anyone, without prior arrangement, on simple terms:
work only against your own copy of the service, do not touch other people's data
or instances, do not run load or denial-of-service experiments against
infrastructure that is not yours, and do not take a finding further than needed
to prove it. A report obtained under those terms is a report, not an incident,
and is handled as one.

## Recognition

The project pays no bounties — there is no bug bounty programme. The author of a
confirmed finding is credited in the GHSA and in the `CHANGELOG.md` line if they
want to be; anonymity is the default and identity is never disclosed without
consent.

## Related documents

- [History scan for secrets](docs/security/secret-audit.md) — what scanned the
  history and what to do when a scanner finds a real secret.
- [CI audit for pull requests from forks](docs/security/workflow-audit.md) —
  what the author of a hostile pull request gets and why the secrets are out of
  reach.
- [Access levels and rate limiting](AGENTS.md#access-levels-auth-middleware) —
  the protection model for the endpoints.
