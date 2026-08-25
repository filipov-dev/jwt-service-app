#!/usr/bin/env bash
#
# jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
#
# Install: oathtool (oath-toolkit), curl, jq.
#
# Env:
#   AUTH_TOTP_SECRET — shared TOTP secret, base32 (required);
#   JWT_SERVICE_URL  — service base URL, default http://localhost:8080.
#
# The code is recomputed before every request (see totp_code). With replay
# protection on (AUTH_TOTP_REPLAY_PROTECTION) the server rejects a code it has
# already seen with 401, even while that code is still inside its time window.

set -euo pipefail

: "${AUTH_TOTP_SECRET:?AUTH_TOTP_SECRET is required}"
SERVICE="${JWT_SERVICE_URL:-http://localhost:8080}"

# Sent as the Host header and becomes the iss claim. Must be the same on issue
# and on verify, or the token will not verify.
ISSUER_HOST="example.com"

# Computes a fresh TOTP code for right now.
#
# Service defaults: SHA-1, 6 digits, 30-second step.
#
# Prints six decimal digits.
totp_code() {
  oathtool --totp --base32 "$AUTH_TOTP_SECRET"
}

# Issues an access token (POST /tokens).
#
# Arguments:
#   $1 — subject (sub claim);
#   $2 — audience (aud claim);
#   $3 — "true" to also get a refresh token (default false);
#   $4 — custom claims as a JSON object (default none).
#
# Custom claims sit next to the registered ones, so the consumer reads role, not
# extra.role. Reserved names (iss, sub, aud, exp, iat, nbf, jti) give 422 —
# change lifetime through ttl, not exp. Count and size are capped server-side.
#
# Prints {"token":"...","refresh_token":"..."}.
# Exit status is non-zero on 401 (bad code), 422 (bad parameters or forbidden
# claim) and 500 (JWKS or Redis unavailable).
issue_token() {
  local sub="$1" aud="$2" with_refresh="${3:-false}" claims="${4:-}"

  local body="{\"sub\":\"$sub\",\"aud\":[\"$aud\"],\"refresh\":$with_refresh"
  [ -n "$claims" ] && body="$body,\"claims\":$claims"
  body="$body}"

  curl -sS --fail-with-body \
    -X POST "$SERVICE/tokens" \
    -H "X-TOTP-Code: $(totp_code)" \
    -H "Host: $ISSUER_HOST" \
    -H "Content-Type: application/json" \
    -d "$body"
}

# Exchanges a refresh token for a new pair (POST /tokens/refresh).
#
# The old token dies on exchange: store the new one and drop the previous.
#
# Never retry an exchange with the old token when the reply is lost. A second
# presentation reads as theft, and the server revokes the whole family — refresh
# tokens and the access tokens issued from them. Issue a new pair instead.
#
# Arguments:
#   $1 — refresh token from an issue or a previous exchange.
# Prints the new pair.
# Exit status is non-zero on 401 (token unknown, expired or already used).
refresh_tokens() {
  local refresh_token="$1"

  curl -sS --fail-with-body \
    -X POST "$SERVICE/tokens/refresh" \
    -H "X-TOTP-Code: $(totp_code)" \
    -H "Host: $ISSUER_HOST" \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\":\"$refresh_token\"}"
}

# Revokes one token by its jti (DELETE /tokens/{jti}).
#
# Idempotent: revoking an unknown jti is success too (204).
#
# Arguments:
#   $1 — token id from the jti claim.
# Exit status is non-zero on 500 — the store is unreachable and the token is NOT
# revoked, retry.
revoke_token() {
  local jti="$1"

  curl -sS --fail-with-body -o /dev/null \
    -X DELETE "$SERVICE/tokens/$jti" \
    -H "X-TOTP-Code: $(totp_code)" \
    -H "Host: $ISSUER_HOST"
}

# Revokes every active token of a subject (DELETE /subjects/{sub}/tokens).
#
# The compromise path: tokens cannot be killed one by one because the caller
# does not know their jti.
#
# Arguments:
#   $1 — subject whose tokens are killed.
# Prints {"revoked":N}; expired tokens do not count.
revoke_subject() {
  local sub="$1"

  curl -sS --fail-with-body \
    -X DELETE "$SERVICE/subjects/$sub/tokens" \
    -H "X-TOTP-Code: $(totp_code)" \
    -H "Host: $ISSUER_HOST"
}

# Full token lifecycle: issue, refresh, bulk revoke.
main() {
  local issued refresh_token refreshed

  issued="$(issue_token svc-a svc-b true '{"role":"admin"}')"
  echo "issued: $(jq -r '.token[:32]' <<<"$issued")..."

  refresh_token="$(jq -r '.refresh_token' <<<"$issued")"
  refreshed="$(refresh_tokens "$refresh_token")"
  echo "refreshed: $(jq -r '.token[:32]' <<<"$refreshed")..."

  echo "revoked: $(revoke_subject svc-a | jq -r '.revoked')"
}

main "$@"
