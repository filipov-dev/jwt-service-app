# Baseline `POST /tokens/verify`

Taken **before** the hot-path optimisations (JWT-24, JWT-25), on version
`1.8.4`. Only the numbers and the conditions are here; how to repeat it is in
[README.md](README.md).

The result after the JWKS cache is at the end of the file,
["After JWT-25"](#after-jwt-25-the-jwks-cache).

## Conditions

- macOS, Docker Desktop; the client (k6), the service and the dependencies all on
  one machine.
- The service is a release build started from the host, with
  `RATE_LIMIT_VERIFY_ENABLED=false` and `RUST_LOG=warn`.
- Redis and `jwks-service-app` run in containers from `docker-compose.yml`.
- The signature algorithm is `RS256` (the default), with 10–20 pre-issued tokens
  and 20–30 s per run.

The absolute values do not apply to production hardware. Only a comparison
against a repeat run on this same stand means anything.

## The result

| VU | RPS | Successful | p50 | p95 | p99 | max |
|---:|----:|---------:|----:|----:|----:|----:|
| 1 | 238 | **100 %** | 3.3 ms | 8.0 ms | 16.5 ms | 49 ms |
| 2 | 443 | 90.8 % | 3.7 ms | 8.8 ms | 16.9 ms | 80 ms |
| 5 | 1738 | 15.4 % | 2.0 ms | 6.2 ms | 12.3 ms | 92 ms |
| 50 | 1589 | 16.8 % | 17.4 ms | 89.2 ms | 182.4 ms | 5.3 s |

**The reference row is 1 VU:** the only run without failures, and only its
latencies are comparable with future ones. The 5 and 50 VU rows measure mostly
the speed of failure (a failure is faster than a success, so p50 there is even
lower — the numbers look better than reality).

**The cost of one verification:**

| Metric | Value |
|--------|------:|
| JWKS requests per verification | **1.00** |
| Redis commands per verification | **1.00** |

## What this means

The ceiling is between 1 and 2 VU, that is around **240–440 rps**, and it rests
not on the service itself but on load being translated to `jwks-service-app` one
to one: every verification pulls the whole `/.well-known/jwks.json` (JWT-25). At
2 VU the key service starts failing, and by 5 VU about 15 % of the requests
survive. In the log that shows as a stream of
`JWKS is unavailable ... error sending request`, and in the metrics as
`jwks_request_duration_seconds_count{success="false"}`.

To the client a failure looks like a `401`: the reason for a verification failure
is deliberately not revealed, so telling "the token is invalid" from "the key
service went down" is only possible through the metrics and the logs.

No socket exhaustion happens along the way — no more than a couple of dozen
connections to the JWKS port sit in `TIME_WAIT` during a run.

## What is expected from the optimisations

| Task | What should change |
|------|--------------------|
| JWT-25 (the JWKS cache) | JWKS requests per verification → close to 0. The ceiling stops depending on the key service; the failures at 2–5 VU should disappear. |
| JWT-24 (the Redis connection) | The Redis commands stay at 1.00 — their cost changes, which shows in p50/p95 at 1 VU. |

Repeat the run with the same commands on the same machine and append the result
here as a table alongside.

---

## After JWT-25 (the JWKS cache)

Version `1.9.0`, the same machine and the same commands.

| VU | RPS (before → after) | Successful (before → after) | p50 | p95 | p99 |
|---:|:----------------:|:---------------------:|----:|----:|----:|
| 1 | 238 → **305** | 100 % → 100 % | 3.3 → **0.9** ms | 8.0 → 11.4 ms | 16.5 → 29.5 ms |
| 2 | 443 → **800** | 90.8 % → **100 %** | 3.7 → **1.4** ms | 8.8 → **6.2** ms | 16.9 → **12.7** ms |
| 5 | 1738 → 1254 | 15.4 % → **64.2 %** | — | — | — |

**The cost of one verification:**

| Metric | Before | After |
|--------|-------:|------:|
| JWKS requests per verification | 1.00 | **0.00** |
| Redis commands per verification | 1.00 | 1.00 |

Over a run of 18,599 verifications **one** request went to the JWKS:
`jwks_cache_total{result="hit"} = 18598`, `miss = 1`.

The most telling row is 2 VU — the only mode where before and after have almost
no failures and every percentile is therefore comparable: the throughput doubled
and all three latencies dropped.

Read the 5 VU row as "noticeably better, but there are still failures": the share
of successful requests grew fourfold, while the drop in RPS only means fewer
requests fall over instantly (a failure is cheaper than a success).

### The bottleneck moved to Redis

The limiter became Redis rather than the JWKS: under load the log fills with
`Can't assign requested address (os error 49)` — exhaustion of the local
ephemeral ports, because `get_multiplexed_async_connection()` opens a new
connection for **every** command. That is JWT-24 exactly, and before the cache it
was hidden behind the JWKS failures.

Hence the one metric that did not improve — p95/p99 at 1 VU: the latency tail is
now formed by connections to Redis. After JWT-24 the measurement is worth
repeating and appending as a third column.

---

## After JWT-24 (reusing the Redis connection)

Version `1.9.1`, the same machine and the same commands.

| VU | RPS (baseline → JWT-25 → JWT-24) | Successful |
|---:|:--------------------------------:|:--------:|
| 1 | 238 → 305 → **2836** | 100 % → 100 % → **100 %** |
| 2 | 443 → 800 → **4783** | 90.8 % → 100 % → **100 %** |
| 5 | 1738 → 1254 → **6585** | 15.4 % → 64.2 % → **100 %** |
| 50 | 1589 → — → **4033** | 16.8 % → — → **100 %** |

The latencies at 1 VU:

| Percentile | baseline | after JWT-25 | after JWT-24 |
|------------|---------:|-------------:|-------------:|
| p50 | 3.3 ms | 0.9 ms | **0.3 ms** |
| p95 | 8.0 ms | 11.4 ms | **0.5 ms** |
| p99 | 16.5 ms | 29.5 ms | **1.3 ms** |

**The cost of one verification** stayed the same — 0.00 JWKS requests and 1.00
Redis command. What changed is the cost of the command: the connection is no
longer opened anew.

### The result of both tasks

Throughput grew from **238 to 2836 rps** at one VU (×11.9), and at five from 1738
rps with 15.4 % successful to 6585 rps with 100 %. The failures disappeared in
every mode: `os error 49` no longer appears in the log at all.

p99 improved 12.7 times against the baseline — even though after JWT-25 alone it
was almost twice as bad as the original. That is a good illustration of why both
tasks were worth measuring: the JWKS cache removed the limiter but exposed the
next one, and the "after JWT-25" numbers looked contradictory without that
context.

The 50 VU row shows where the limit is now: there are no failures, but p99 grows
to 101 ms — that is already CPU saturation of the machine hosting the client, the
service, Redis and the key service at once. The next bottleneck, if one is
needed, has to be looked for on separate hardware.
