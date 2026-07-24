#!/usr/bin/env bash
# Bash — утилита: oathtool (пакет oath-toolkit) + curl.
# AUTH_TOTP_SECRET — base32-секрет (oathtool ожидает base32 с флагом --base32).
set -euo pipefail

: "${AUTH_TOTP_SECRET:?нужен AUTH_TOTP_SECRET}"
SERVICE="${JWT_SERVICE_URL:-http://localhost:8080}"

CODE="$(oathtool --totp --base32 "$AUTH_TOTP_SECRET")"   # SHA-1, 6, 30с

curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST "$SERVICE/tokens" \
  -H "X-TOTP-Code: $CODE" \
  -H "Host: example.com" \
  -H "Content-Type: application/json" \
  -d '{"sub":"svc-a","aud":["svc-b"]}'
