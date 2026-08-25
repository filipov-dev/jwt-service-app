#!/usr/bin/env bash
#
# jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
#
# Install: oathtool (oath-toolkit), curl, jq.
# Env: AUTH_TOTP_SECRET (base32), JWT_SERVICE_URL (default http://localhost:8080).
# See README.md for endpoints, error codes and client rules.

set -euo pipefail

: "${AUTH_TOTP_SECRET:?AUTH_TOTP_SECRET is required}"
SERVICE="${JWT_SERVICE_URL:-http://localhost:8080}"

# Sent as the Host header, becomes the iss claim.
ISSUER_HOST="example.com"

# Fresh TOTP code: SHA-1, 6 digits, 30-second step.
totp_code() {
  oathtool --totp --base32 "$AUTH_TOTP_SECRET"
}

# POST /tokens
#
# $1 sub, $2 aud, $3 "true" to also get a refresh token, $4 custom claims as a
# JSON object.
#
# Prints {"token":"...","refresh_token":"..."}.
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

# POST /tokens/refresh — prints a new pair; the old refresh token is dead.
#
# $1 refresh token from an issue or a previous refresh.
refresh_tokens() {
  local refresh_token="$1"

  curl -sS --fail-with-body \
    -X POST "$SERVICE/tokens/refresh" \
    -H "X-TOTP-Code: $(totp_code)" \
    -H "Host: $ISSUER_HOST" \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\":\"$refresh_token\"}"
}

# DELETE /tokens/{jti} — idempotent.
#
# $1 token id from the jti claim.
revoke_token() {
  local jti="$1"

  curl -sS --fail-with-body -o /dev/null \
    -X DELETE "$SERVICE/tokens/$jti" \
    -H "X-TOTP-Code: $(totp_code)" \
    -H "Host: $ISSUER_HOST"
}

# DELETE /subjects/{sub}/tokens — prints {"revoked":N}.
#
# $1 subject whose tokens are revoked.
revoke_subject() {
  local sub="$1"

  curl -sS --fail-with-body \
    -X DELETE "$SERVICE/subjects/$sub/tokens" \
    -H "X-TOTP-Code: $(totp_code)" \
    -H "Host: $ISSUER_HOST"
}

# Issue -> refresh -> revoke.
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
