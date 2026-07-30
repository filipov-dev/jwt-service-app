#!/usr/bin/env bash
#
# Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
#
# Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
# токена и массовый отзыв токенов субъекта.
#
# Зависимости: oathtool (пакет oath-toolkit), curl, jq.
#
# Окружение:
#   AUTH_TOTP_SECRET — общий TOTP-секрет в base32 (обязательно);
#   JWT_SERVICE_URL  — базовый URL сервиса, по умолчанию http://localhost:8080.
#
# ВАЖНО: код считается заново перед каждым запросом (см. функцию totp_code).
# При включённой на сервере защите от переигрывания (AUTH_TOTP_REPLAY_PROTECTION)
# повторное предъявление того же кода вернёт 401, хотя сам код ещё не истёк.

set -euo pipefail

: "${AUTH_TOTP_SECRET:?нужен AUTH_TOTP_SECRET}"
SERVICE="${JWT_SERVICE_URL:-http://localhost:8080}"

# Значение claim iss. Должно совпадать при выпуске и проверке токена.
ISSUER_HOST="example.com"

# Вычисляет TOTP-код на текущий момент.
#
# Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
#
# Вывод: код из шести десятичных знаков.
totp_code() {
  oathtool --totp --base32 "$AUTH_TOTP_SECRET"
}

# Выпускает access-токен (POST /tokens).
#
# Аргументы:
#   $1 — субъект (claim sub);
#   $2 — получатель (claim aud);
#   $3 — "true", чтобы запросить refresh-токен (по умолчанию false).
# Вывод: JSON вида {"token":"...","refresh_token":"..."}.
# Код возврата: ненулевой при 401 (неверный код), 422 (параметры), 500 (JWKS/Redis).
issue_token() {
  local sub="$1" aud="$2" with_refresh="${3:-false}"

  curl -sS --fail-with-body \
    -X POST "$SERVICE/tokens" \
    -H "X-TOTP-Code: $(totp_code)" \
    -H "Host: $ISSUER_HOST" \
    -H "Content-Type: application/json" \
    -d "{\"sub\":\"$sub\",\"aud\":[\"$aud\"],\"refresh\":$with_refresh}"
}

# Обменивает refresh-токен на новую пару (POST /tokens/refresh).
#
# Старый токен после обмена недействителен: сохраните новый и выбросьте
# предыдущий.
#
# ВНИМАНИЕ: не повторяйте обмен старым токеном при потере ответа. Повторное
# предъявление трактуется как кража и гасит всю семью — и refresh-токены, и
# выданные по ним access-токены. Надёжнее выпустить пару заново.
#
# Аргументы:
#   $1 — refresh-токен из выпуска или прошлого обмена.
# Вывод: JSON с новой парой.
# Код возврата: ненулевой при 401 (токен неизвестен, истёк или уже использован).
refresh_tokens() {
  local refresh_token="$1"

  curl -sS --fail-with-body \
    -X POST "$SERVICE/tokens/refresh" \
    -H "X-TOTP-Code: $(totp_code)" \
    -H "Host: $ISSUER_HOST" \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\":\"$refresh_token\"}"
}

# Отзывает один токен по его jti (DELETE /tokens/{jti}).
#
# Идемпотентно: отзыв несуществующего jti — тоже успех (204).
#
# Аргументы:
#   $1 — идентификатор токена из claim jti.
# Код возврата: ненулевой при 500 — хранилище недоступно, отзыв НЕ выполнен.
revoke_token() {
  local jti="$1"

  curl -sS --fail-with-body -o /dev/null \
    -X DELETE "$SERVICE/tokens/$jti" \
    -H "X-TOTP-Code: $(totp_code)" \
    -H "Host: $ISSUER_HOST"
}

# Отзывает все активные токены субъекта (DELETE /subjects/{sub}/tokens).
#
# Нужен при компрометации: гасить токены по одному нельзя, их jti вызывающему
# неизвестны.
#
# Аргументы:
#   $1 — субъект, чьи токены гасятся.
# Вывод: JSON вида {"revoked":N}; истёкшие токены не считаются.
revoke_subject() {
  local sub="$1"

  curl -sS --fail-with-body \
    -X DELETE "$SERVICE/subjects/$sub/tokens" \
    -H "X-TOTP-Code: $(totp_code)" \
    -H "Host: $ISSUER_HOST"
}

# Демонстрация полного жизненного цикла токена.
main() {
  local issued refresh_token refreshed

  issued="$(issue_token svc-a svc-b true)"
  echo "выпущен: $(jq -r '.token[:32]' <<<"$issued")..."

  refresh_token="$(jq -r '.refresh_token' <<<"$issued")"
  refreshed="$(refresh_tokens "$refresh_token")"
  echo "обновлён: $(jq -r '.token[:32]' <<<"$refreshed")..."

  echo "отозвано токенов: $(revoke_subject svc-a | jq -r '.revoked')"
}

main "$@"
