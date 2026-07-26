#!/usr/bin/env bash
# Прогон нагрузочного теста `POST /tokens/verify` со снятием метрик (JWT-34).
#
# Что делает:
#   1. проверяет, что сервис жив и метрики доступны;
#   2. выпускает пачку токенов (уровень 3, TOTP-код считается здесь же);
#   3. снимает счётчики с `/metrics` ДО прогона;
#   4. гоняет k6 (в контейнере — ставить его на хост не нужно);
#   5. снимает счётчики ПОСЛЕ и печатает сводку.
#
# Сервис должен быть запущен ОТДЕЛЬНО, release-сборкой (см. README.md).
set -euo pipefail

cd "$(dirname "$0")"

TARGET_URL="${TARGET_URL:-http://127.0.0.1:8080}"
# Адрес того же сервиса изнутри контейнера k6.
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
# Считаем здесь, а не в k6: в сценарии нужен только proxy-secret, а возня с
# base32 и HMAC внутри JS ничего не даёт.
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

# --- Снятие счётчиков с /metrics -------------------------------------------
# Нас интересуют не гистограммы целиком, а `_count` — сколько РАЗ сервис ходил
# в JWKS и Redis. Поделённые на число верификаций, они и отвечают на главный
# вопрос: сколько внешних вызовов стоит один запрос.
scrape() {
    curl -fsS -H "Authorization: Bearer ${METRICS_TOKEN}" "${TARGET_URL}/metrics" | python3 -c '
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

# --- 0. Предполётные проверки ----------------------------------------------
say "Проверяю сервис на ${TARGET_URL}"
curl -fsS -H "Host: ${HOST_HEADER}" "${TARGET_URL}/livez" >/dev/null \
    || { echo "Сервис не отвечает на /livez — запустите его (см. README.md)"; exit 1; }
curl -fsS -H "Authorization: Bearer ${METRICS_TOKEN}" "${TARGET_URL}/metrics" >/dev/null \
    || { echo "Метрики недоступны: проверьте AUTH_METRICS_TOKEN"; exit 1; }

readyz=$(curl -fsS -H "Host: ${HOST_HEADER}" "${TARGET_URL}/readyz")
echo "readyz: ${readyz}"
case "$readyz" in
    *'"status":"ok"'*) ;;
    *) echo "Зависимости недоступны — стенд не поднят полностью"; exit 1 ;;
esac

# Rate limit на verify обязан быть выключен, иначе замеряется он, а не сервис:
# при дефолтных 10 rps на адрес весь прогон упрётся в 429.
if [ "${RATE_LIMIT_VERIFY_ENABLED:-unset}" != "false" ]; then
    echo
    echo "ВНИМАНИЕ: RATE_LIMIT_VERIFY_ENABLED != false."
    echo "Сервис нужно запускать с RATE_LIMIT_VERIFY_ENABLED=false, иначе прогон"
    echo "упрётся в per-IP лимит (10 rps) и цифры будут бессмысленны."
fi

# --- 1. Выпуск токенов ------------------------------------------------------
say "Выпускаю ${TOKENS} токенов"
: > tokens.raw
for i in $(seq 1 "$TOKENS"); do
    # Код пересчитываем на каждый токен: окно 30 секунд, а выпуск пачки может
    # его пережить.
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
print(f"готово: {len(tokens)} токенов")
'
rm -f tokens.raw

# --- 2. Замер ---------------------------------------------------------------
read -r verify_before jwks_before redis_before <<<"$(scrape)"

say "Прогон: ${VUS} VU, ${DURATION}"
# k6 возвращает ненулевой код, если не сошёлся threshold. Для нас это не повод
# прерываться: массовые отказы — тоже результат замера, и сводку по ним надо
# показать (именно так выглядит перегруз JWKS до JWT-25).
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
    echo "k6 завершился с кодом ${k6_status} (не сошёлся threshold) — смотрите долю успешных ниже."
fi

# --- 3. Сводка --------------------------------------------------------------
say "Сводка"
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

print(f"  запросов ............ {total:.0f}")
print(f"  успешных ............ {(1 - failed) * 100:.1f} %")
if failed > 0.01:
    print("  ВНИМАНИЕ: есть отказы — латентности ниже считаны в основном по ним,")
    print("            для сравнения «до/после» нужен прогон без отказов (меньше VUS).")
print(f"  RPS ................. {rps:.1f}")
print(f"  p50 ................. {dur['med']:.1f} ms")
print(f"  p95 ................. {dur['p(95)']:.1f} ms")
print(f"  p99 ................. {dur['p(99)']:.1f} ms")
print(f"  max ................. {dur['max']:.1f} ms")
print()
print(f"  верификаций ......... {verify:.0f}")
if verify:
    print(f"  запросов к JWKS ..... {jwks:.0f}  ({jwks / verify:.2f} на верификацию)")
    print(f"  команд Redis ........ {redis:.0f}  ({redis / verify:.2f} на верификацию)")
print()
print("  Два последних числа — главное в этом замере: JWT-25 должен увести")
print("  запросы к JWKS к нулю, JWT-24 — снять стоимость коннекта с команд Redis.")
PY
