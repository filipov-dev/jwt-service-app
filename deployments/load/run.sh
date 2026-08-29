#!/usr/bin/env bash
# Runs the `POST /tokens/verify` load test and collects the metrics (JWT-34).
#
# What it does:
#   1. checks that the service is alive and the metrics are reachable;
#   2. issues a batch of tokens (level 3, the TOTP code is computed here);
#   3. reads the counters from `/metrics` BEFORE the run;
#   4. runs k6 (in a container — nothing to install on the host);
#   5. reads the counters AFTER and prints a summary.
#
# The service must be started SEPARATELY, as a release build (see README.md).
set -euo pipefail

cd "$(dirname "$0")"

TARGET_URL="${TARGET_URL:-http://127.0.0.1:8080}"
# The address of the same service from inside the k6 container.
TARGET_URL_FROM_CONTAINER="${TARGET_URL_FROM_CONTAINER:-http://host.docker.internal:8080}"
HOST_HEADER="${HOST_HEADER:-jwt-load.local}"
AUDIENCE="${AUDIENCE:-load-test}"
TOKENS="${TOKENS:-20}"
VUS="${VUS:-50}"
DURATION="${DURATION:-30s}"

PROXY_SECRET="${AUTH_PROXY_SECRET:-dev-proxy-secret}"
PROXY_HEADER="${AUTH_PROXY_SECRET_HEADER:-X-Proxy-Secret}"
TOTP_SECRET="${AUTH_TOTP_SECRET:-MRSWGYLSMUQGO33WNFXGO4ZAOBWGKYLSFVRW63LOMNXW2ZI}"
TOTP_HEADER="${AUTH_TOTP_HEADER:-X-TOTP-Code}"
METRICS_TOKEN="${AUTH_METRICS_TOKEN:-dev-metrics-token}"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# --- TOTP (RFC 6238) -------------------------------------------------------
# Computed here rather than in k6: the scenario only needs the proxy secret, and
# fiddling with base32 and HMAC inside JS buys nothing.
totp() {
    TOTP_SECRET="$TOTP_SECRET" python3 - <<'PY'
import base64, hmac, hashlib, os, struct, time
secret = os.environ["TOTP_SECRET"]
key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
msg = struct.pack(">Q", int(time.time()) // 30)
digest = hmac.new(key, msg, hashlib.sha1).digest()
offset = digest[-1] & 0x0F
code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
print(f"{code % 10**6:06d}")
PY
}

# --- Reading the counters from /metrics ------------------------------------
# What matters is not the histograms in full but `_count` — how MANY TIMES the
# service went to the JWKS and to Redis. Divided by the number of verifications,
# they answer the main question: how many external calls one request costs.
# `--retry` here is not a luxury: under load the service manages to exhaust the
# local ephemeral ports and curl itself can no longer connect. Without retries
# the metrics collection silently returned zeros and the summary showed zero
# deltas.
scrape() {
    curl -sS --retry 5 --retry-all-errors --retry-delay 1 \
        -H "Authorization: Bearer ${METRICS_TOKEN}" "${TARGET_URL}/metrics" | python3 -c '
import sys
verify = jwks = redis = 0.0
for line in sys.stdin:
    if line.startswith("#") or not line.strip():
        continue
    name, _, value = line.rpartition(" ")
    try:
        value = float(value)
    except ValueError:
        continue
    if name.startswith("http_requests_total") and "/tokens/verify" in name:
        verify += value
    elif name.startswith("jwks_request_duration_seconds_count"):
        jwks += value
    elif name.startswith("redis_command_duration_seconds_count"):
        redis += value
print(f"{verify} {jwks} {redis}")
'
}

# --- 0. Preflight checks ---------------------------------------------------
say "Checking the service at ${TARGET_URL}"
curl -fsS -H "Host: ${HOST_HEADER}" "${TARGET_URL}/livez" >/dev/null \
    || { echo "The service does not answer /livez — start it (see README.md)"; exit 1; }
curl -fsS -H "Authorization: Bearer ${METRICS_TOKEN}" "${TARGET_URL}/metrics" >/dev/null \
    || { echo "The metrics are unreachable: check AUTH_METRICS_TOKEN"; exit 1; }

readyz=$(curl -fsS -H "Host: ${HOST_HEADER}" "${TARGET_URL}/readyz")
echo "readyz: ${readyz}"
case "$readyz" in
    *'"status":"ok"'*) ;;
    *) echo "The dependencies are unreachable — the stand is not fully up"; exit 1 ;;
esac

# The rate limit on verify must be off, or it is what gets measured rather than
# the service: at the default 10 rps per address the whole run hits 429.
if [ "${RATE_LIMIT_VERIFY_ENABLED:-unset}" != "false" ]; then
    echo
    echo "WARNING: RATE_LIMIT_VERIFY_ENABLED != false."
    echo "The service must be started with RATE_LIMIT_VERIFY_ENABLED=false, or the run"
    echo "hits the per-IP limit (10 rps) and the numbers are meaningless."
fi

# --- 1. Issuing the tokens --------------------------------------------------
say "Issuing ${TOKENS} tokens"
: > tokens.raw
for i in $(seq 1 "$TOKENS"); do
    # The code is recomputed for every token: the window is 30 seconds and
    # issuing a batch can outlive it.
    code=$(totp)
    token=$(curl -fsS -X POST "${TARGET_URL}/tokens" \
        -H "Host: ${HOST_HEADER}" \
        -H "Content-Type: application/json" \
        -H "${TOTP_HEADER}: ${code}" \
        -d "{\"sub\":\"load-${i}\",\"aud\":[\"${AUDIENCE}\"],\"ttl\":3600}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
    echo "$token" >> tokens.raw
done
python3 -c '
import json
with open("tokens.raw") as f:
    tokens = [line.strip() for line in f if line.strip()]
with open("tokens.json", "w") as f:
    json.dump(tokens, f)
print(f"done: {len(tokens)} tokens")
'
rm -f tokens.raw

# --- 2. The measurement -----------------------------------------------------
read -r verify_before jwks_before redis_before <<<"$(scrape)"

say "Run: ${VUS} VU, ${DURATION}"
# k6 returns a non-zero code when a threshold is not met. That is no reason for
# us to stop: mass failures are a measurement result too and their summary has to
# be shown (that is exactly what a JWKS overload looked like before JWT-25).
k6_status=0
docker run --rm -i \
    -v "$(pwd):/scripts" \
    -e "TARGET_URL=${TARGET_URL_FROM_CONTAINER}" \
    -e "PROXY_SECRET=${PROXY_SECRET}" \
    -e "PROXY_HEADER=${PROXY_HEADER}" \
    -e "AUDIENCE=${AUDIENCE}" \
    -e "HOST_HEADER=${HOST_HEADER}" \
    -e "VUS=${VUS}" \
    -e "DURATION=${DURATION}" \
    grafana/k6 run --summary-export=/scripts/summary.json /scripts/verify.js || k6_status=$?

read -r verify_after jwks_after redis_after <<<"$(scrape)"

if [ "$k6_status" -ne 0 ]; then
    echo
    echo "k6 exited with code ${k6_status} (a threshold was not met) — see the success share below."
fi

# --- 3. The summary ---------------------------------------------------------
say "Summary"
VERIFY_DELTA="$(python3 -c "print(${verify_after} - ${verify_before})")" \
JWKS_DELTA="$(python3 -c "print(${jwks_after} - ${jwks_before})")" \
REDIS_DELTA="$(python3 -c "print(${redis_after} - ${redis_before})")" \
python3 - <<'PY'
import json, os

verify = float(os.environ["VERIFY_DELTA"])
jwks = float(os.environ["JWKS_DELTA"])
redis = float(os.environ["REDIS_DELTA"])

with open("summary.json") as f:
    s = json.load(f)

dur = s["metrics"]["http_req_duration"]
rps = s["metrics"]["http_reqs"]["rate"]
total = s["metrics"]["http_reqs"]["count"]
failed = s["metrics"].get("http_req_failed", {}).get("value", 0.0)

print(f"  requests ............ {total:.0f}")
print(f"  successful .......... {(1 - failed) * 100:.1f} %")
if failed > 0.01:
    print("  WARNING: there are failures — the latencies below are computed mostly")
    print("           from them; a before/after comparison needs a run without")
    print("           failures (fewer VUs).")
print(f"  RPS ................. {rps:.1f}")
print(f"  p50 ................. {dur['med']:.1f} ms")
print(f"  p95 ................. {dur['p(95)']:.1f} ms")
print(f"  p99 ................. {dur['p(99)']:.1f} ms")
print(f"  max ................. {dur['max']:.1f} ms")
print()
print(f"  verifications ....... {verify:.0f}")
if verify:
    print(f"  JWKS requests ....... {jwks:.0f}  ({jwks / verify:.2f} per verification)")
    print(f"  Redis commands ...... {redis:.0f}  ({redis / verify:.2f} per verification)")
print()
print("  The last two numbers are the point of this measurement: JWT-25 should")
print("  drive the JWKS requests to zero and JWT-24 should take the connection")
print("  cost off the Redis commands.")
PY
