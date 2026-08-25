#!/usr/bin/env bash
#
# Прогон сканеров секретов по всей истории репозитория.
#
# Гейт перед переводом репозитория в public (JWT-52) и регулярная проверка
# после: `.github/workflows/secrets.yml` вызывает этот же скрипт, поэтому
# локальный прогон и прогон в CI совпадают по построению, а не потому что
# кто-то следит за синхронностью двух наборов флагов. Отчёт последнего аудита
# и разбор находок — в docs/security/secret-audit.md.
#
# Использование:
#   scripts/scan-secrets.sh                    # оба сканера
#   scripts/scan-secrets.sh --reports DIR      # JSON-отчёты в DIR (иначе временный каталог)
#   scripts/scan-secrets.sh --tool gitleaks    # только gitleaks
#   scripts/scan-secrets.sh --tool trufflehog  # только trufflehog
#
# Ненулевой код возврата — найдены неразобранные секреты.

set -euo pipefail

# Оба сканера, а не один: они ловят разное и плохо заменяют друг друга.
# gitleaks идёт по диффам регулярками и энтропией — берёт любой ключеподобный
# мусор, включая самодельные форматы. trufflehog идёт детекторами под конкретные
# сервисы и умеет проверять находку по сети: живой ключ он отличает от протухшего,
# чего энтропия не умеет в принципе.
readonly GITLEAKS_IMAGE="${GITLEAKS_IMAGE:-zricethezav/gitleaks:v8.30.1}"
readonly TRUFFLEHOG_IMAGE="${TRUFFLEHOG_IMAGE:-trufflesecurity/trufflehog:3.97.1}"

# Разобранные находки trufflehog. Гасим по ЗНАЧЕНИЮ, а не по пути к файлу — по
# тем же соображениям, что и allowlist в .gitleaks.toml: исключённый файл
# перестал бы охраняться целиком. У gitleaks для этого есть конфиг, у trufflehog
# аналога нет, поэтому фильтр живёт здесь и применяется к JSON-выводу.
readonly TRUFFLEHOG_ALLOWLIST=(
    # Демо-креды Postgres в стендах dev и load
    # (deployments/dev/docker-compose.yml, deployments/load/docker-compose.yml).
    # Это строка подключения к контейнеру `postgres` внутри compose-сети:
    # снаружи хост не резолвится, наружу порт не выставлен. Пара user/password
    # задаётся тут же, в environment самого контейнера, — секрета не существует
    # даже теоретически. Postgres нужен не сервису, а соседнему
    # jwks-service-app, который в стенде хранит там ключи.
    'postgres://user:password@postgres:5432'
)

usage() {
    sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
    echo "scan-secrets: $*" >&2
    exit 2
}

# Запуск сканера в контейнере. Репозиторий монтируется read-only: сканеру
# достаточно чтения, а испортить рабочую копию он не должен даже случайно.
#
# GIT_CONFIG_* — против «detected dubious ownership»: внутри контейнера процесс
# идёт от root, а рабочая копия принадлежит хостовому пользователю (на раннере —
# другому uid, чем в контейнере), и git такой репозиторий читать отказывается.
run_scanner() {
    local image="$1" reports="$2"
    shift 2

    docker run --rm \
        -v "${REPO_ROOT}:/repo:ro" \
        -v "${reports}:/out" \
        -e GIT_CONFIG_COUNT=1 \
        -e GIT_CONFIG_KEY_0=safe.directory \
        -e GIT_CONFIG_VALUE_0='*' \
        "$image" "$@"
}

# gitleaks: регулярки и энтропия по диффам всей истории.
#
# --log-opts=--all — по всем ссылкам, а не только по текущей ветке: иначе из
# проверки выпадают ветки и PR-рефы, которые на GitHub остаются доступными.
# Merge-коммиты сканер пропускает (у них нет собственного диффа), поэтому
# «просканировано N коммитов» меньше `git rev-list --count --all`.
scan_gitleaks() {
    local reports="$1" status=0

    echo "==> gitleaks (${GITLEAKS_IMAGE})"
    run_scanner "$GITLEAKS_IMAGE" "$reports" \
        git /repo \
        --config /repo/.gitleaks.toml \
        --log-opts=--all \
        --report-format json \
        --report-path /out/gitleaks.json || status=$?

    if [ "$status" -ne 0 ]; then
        echo "gitleaks: находки в ${reports}/gitleaks.json" >&2
        return 1
    fi

    echo "gitleaks: чисто"
}

# trufflehog: детекторы под конкретные сервисы плюс верификация находок.
#
# Скрипт разбирает JSON сам, а не полагается на --fail: отсеять разобранные
# находки нужно до вердикта, а флагов для этого у сканера нет.
scan_trufflehog() {
    local reports="$1" allow raw="${1}/trufflehog-raw.json" kept="${1}/trufflehog.json"
    local total=0 remaining=0

    command -v jq >/dev/null 2>&1 || die "нужен jq (разбор отчёта trufflehog)"

    echo "==> trufflehog (${TRUFFLEHOG_IMAGE})"
    # --no-update: сканер не должен молча подменять свою версию на свежую,
    # иначе пин образа ничего не гарантирует.
    run_scanner "$TRUFFLEHOG_IMAGE" "$reports" \
        git file:///repo --no-update --json >"$raw"

    allow="$(
        IFS='|'
        echo "${TRUFFLEHOG_ALLOWLIST[*]}"
    )"

    # Строки вывода — по одной находке; служебные записи логгера отсеиваются
    # проверкой на DetectorName. Сравнение по подстроке (contains), а не regex:
    # в значениях хватает символов, которые пришлось бы экранировать.
    total="$(jq -rs '[.[] | select(.DetectorName)] | length' "$raw")"
    jq -c --arg allow "$allow" '
        select(.DetectorName)
        | select(
            ((.Raw // "") + " " + (.RawV2 // "")) as $v
            | ($allow | split("|") | map(. as $a | $v | contains($a)) | any) | not
          )
    ' "$raw" >"$kept"
    remaining="$(wc -l <"$kept" | tr -d ' ')"

    echo "trufflehog: находок ${total}, из них разобранных $((total - remaining))"

    if [ "$remaining" -ne 0 ]; then
        echo "trufflehog: неразобранные находки в ${kept}" >&2
        jq -r '"  \(.DetectorName) | verified=\(.Verified) | \(.SourceMetadata.Data.Git.file // "?"):\(.SourceMetadata.Data.Git.line // "?")"' "$kept" >&2
        return 1
    fi

    echo "trufflehog: чисто"
}

main() {
    local tool=all reports="" status=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --reports)
                reports="$2"
                shift 2
                ;;
            --tool)
                tool="$2"
                shift 2
                ;;
            -h | --help)
                usage
                return 0
                ;;
            *)
                echo "неизвестный аргумент: $1" >&2
                usage >&2
                return 2
                ;;
        esac
    done

    case "$tool" in
        all | gitleaks | trufflehog) ;;
        *) die "--tool: ожидается all, gitleaks или trufflehog (получено: ${tool})" ;;
    esac

    command -v docker >/dev/null 2>&1 || die "нужен docker (сканеры запускаются в контейнерах)"
    REPO_ROOT="$(git rev-parse --show-toplevel)" || die "не git-репозиторий"
    readonly REPO_ROOT

    [ -n "$reports" ] || reports="$(mktemp -d)"
    mkdir -p "$reports"
    # Путь абсолютный: его отдают docker как точку монтирования.
    reports="$(cd "$reports" && pwd)"

    [ "$tool" = trufflehog ] || scan_gitleaks "$reports" || status=1
    [ "$tool" = gitleaks ] || scan_trufflehog "$reports" || status=1

    echo "отчёты: ${reports}"
    return "$status"
}

main "$@"
