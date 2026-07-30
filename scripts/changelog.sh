#!/usr/bin/env bash
#
# Собирает CHANGELOG по conventional commits из истории git.
#
# Один и тот же код используется в двух местах, поэтому формат секций в
# CHANGELOG.md и в теле GitHub Release совпадает по построению:
#   * `--all` — весь файл целиком (так CHANGELOG.md заполнен задним числом);
#   * без аргументов — тело секции для очередного релиза, его кладёт в описание
#     релиза `release.yml`.
#
# Использование:
#   scripts/changelog.sh                        # тело секции: последний тег..HEAD
#   scripts/changelog.sh --heading              # то же плюс «## [версия] - дата»
#   scripts/changelog.sh --insert               # вписать секцию версии в CHANGELOG.md
#   scripts/changelog.sh --range v1.9.0..v1.10.0
#   scripts/changelog.sh --version 1.13.0       # версия в заголовке (иначе из Cargo.toml)
#   scripts/changelog.sh --all > CHANGELOG.md   # перегенерировать файл целиком
#
# Раскладка типов коммитов по разделам — в `bucket_for`.

set -euo pipefail

readonly REPO_URL="https://github.com/filipov-dev/jwt-service-app"

# Разделы в порядке вывода: ключ и заголовок. Пустые разделы не печатаются,
# поэтому у большинства версий их два-три.
readonly SECTIONS=(
    "breaking:Ломающие изменения"
    "added:Добавлено"
    "changed:Изменено"
    "fixed:Исправлено"
    "security:Безопасность"
    "docs:Документация"
    "internal:Внутреннее"
    "other:Прочее"
)

usage() {
    sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'
}

# Раздел, в который попадает коммит данного типа.
#
# Keep a Changelog описывает шесть разделов для пользовательских изменений.
# К ним добавлены два: «Документация» (в этом проекте docs-коммиты — это
# клиентские примеры и инструкции по эксплуатации, то есть тоже наружу) и
# «Внутреннее» (CI, тесты, форматирование). Без второго релизы вроде v1.8.5,
# где был только нагрузочный тест, выглядели бы пустыми.
bucket_for() {
    case "$1" in
        feat) echo added ;;
        fix) echo fixed ;;
        security) echo security ;;
        perf | revert) echo changed ;;
        docs) echo docs ;;
        # `deps` — префикс коммитов dependabot (см. .github/dependabot.yml).
        # Без него обновления зависимостей сыпались в «Прочее».
        refactor | style | test | ci | build | chore | deps) echo internal ;;
        *) echo other ;;
    esac
}

# Разбирает subject'ы коммитов диапазона и раскладывает их по файлам-разделам
# в каталоге $2. Файл существует только у непустого раздела.
collect() {
    local range="$1" dir="$2"
    local subject type scope bang text entry bucket

    rm -rf "$dir"
    mkdir -p "$dir"

    # --reverse: внутри релиза изменения читаются в том порядке, в котором их
    # делали. --format (не --pretty=format) — чтобы последняя строка тоже
    # заканчивалась переводом строки и не терялась в read.
    while IFS= read -r subject; do
        [ -n "$subject" ] || continue

        if [[ $subject =~ ^([a-z]+)(\(([^\)]+)\))?(!)?:[[:space:]]+(.+)$ ]]; then
            type="${BASH_REMATCH[1]}"
            scope="${BASH_REMATCH[3]}"
            bang="${BASH_REMATCH[4]}"
            text="${BASH_REMATCH[5]}"
        else
            # Ранняя история (Init, Build, Clean) — до перехода на conventional
            # commits. Такие коммиты уходят в «Прочее», а не теряются.
            type="_plain"
            scope=""
            bang=""
            text="$subject"
        fi

        if [ -n "$scope" ]; then
            entry="- **${scope}**: ${text}"
        else
            entry="- ${text}"
        fi

        # Восклицательный знак в типе (`feat!:`) по спецификации conventional
        # commits означает слом обратной совместимости — такие изменения важнее
        # своей категории и выносятся в отдельный раздел наверх.
        if [ -n "$bang" ]; then
            bucket=breaking
        else
            bucket="$(bucket_for "$type")"
        fi

        printf '%s\n' "$entry" >>"${dir}/${bucket}"
    done < <(git log --no-merges --reverse --format='%s' "$range")
}

# Печатает непустые разделы из каталога $1.
emit() {
    local dir="$1" pair key title printed=0

    for pair in "${SECTIONS[@]}"; do
        key="${pair%%:*}"
        title="${pair#*:}"

        [ -s "${dir}/${key}" ] || continue

        printf '### %s\n\n' "$title"
        cat "${dir}/${key}"
        printf '\n'
        printed=1
    done

    [ "$printed" = 1 ] || printf '_Изменений нет._\n\n'
}

# Есть ли в диапазоне $1 хоть один коммит (кроме merge-коммитов).
has_commits() {
    [ -n "$(git log --no-merges --format='%s' "$1")" ]
}

# Тело секции для диапазона $1.
section_body() {
    local dir
    dir="$(mktemp -d)"
    collect "$1" "$dir"
    emit "$dir"
    rm -rf "$dir"
}

# Теги в порядке возрастания версии. Релизов меньше, чем поднятий версии:
# в одном PR версия поднимается каждым коммитом, а тег создаётся один — на
# финальную. Поэтому в списке есть пропуски (1.11.0, 1.12.0, 1.12.1 и т.п.),
# и это не потеря истории: их коммиты входят в следующий выпущенный тег.
tags_ascending() {
    git tag --sort=v:refname
}

# Дата коммита, на который указывает ref.
ref_date() {
    git log -1 --format=%ad --date=short "$1"
}

version_from_cargo() {
    grep -m1 '^version' Cargo.toml | cut -d '"' -f 2
}

# Последний выпущенный тег — точка отсчёта для очередного релиза.
last_tag() {
    tags_ascending | tail -n 1
}

# Весь файл: шапка, «Не выпущено» (если есть коммиты после последнего тега),
# затем версии от новых к старым и ссылки на diff между тегами.
render_all() {
    local tags=() tag prev range i

    while IFS= read -r tag; do
        tags+=("$tag")
    done < <(tags_ascending)

    cat <<'HEADER'
# Changelog

Все заметные изменения этого проекта. Формат основан на
[Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии — по
[семантическому версионированию](https://semver.org/lang/ru/).

Файл собран из истории коммитов и перегенерируется командой
`scripts/changelog.sh --all`; тело каждого релиза на GitHub собирает тот же
скрипт. Записи — это subject'ы коммитов дословно, в скобках указан ключ задачи.

К шести разделам Keep a Changelog добавлены «Документация» (клиентские примеры
и инструкции по эксплуатации — изменения для потребителя сервиса) и
«Внутреннее» (CI, тесты, форматирование).

HEADER

    # Раздел «Не выпущено» появляется только когда после последнего тега
    # действительно что-то накопилось: на master сразу после релиза его нет.
    if has_commits "$(last_tag)..HEAD"; then
        printf '## [Не выпущено]\n\n'
        section_body "$(last_tag)..HEAD"
    fi

    for ((i = ${#tags[@]} - 1; i >= 0; i--)); do
        tag="${tags[$i]}"

        if [ "$i" -gt 0 ]; then
            prev="${tags[$((i - 1))]}"
            range="${prev}..${tag}"
        else
            range="$tag"
        fi

        printf '## [%s] - %s\n\n' "${tag#v}" "$(ref_date "$tag")"
        section_body "$range"
    done

    # Ссылки на сравнение версий: из строки «## [1.13.0]» кликом видно диапазон.
    printf '[Не выпущено]: %s/compare/%s...HEAD\n' "$REPO_URL" "$(last_tag)"
    for ((i = ${#tags[@]} - 1; i >= 0; i--)); do
        tag="${tags[$i]}"

        if [ "$i" -gt 0 ]; then
            printf '[%s]: %s/compare/%s...%s\n' \
                "${tag#v}" "$REPO_URL" "${tags[$((i - 1))]}" "$tag"
        else
            printf '[%s]: %s/releases/tag/%s\n' "${tag#v}" "$REPO_URL" "$tag"
        fi
    done
}

# Вставляет секцию версии $1 (диапазон $2) в CHANGELOG.md: и сам раздел после
# шапки, и строку сравнения версий в блок ссылок внизу.
#
# Нужно потому, что версия поднимается в том же PR, что и изменение, а тег
# появляется только после мержа. Перегенерация `--all` в этот момент положила бы
# коммиты в «Не выпущено» — раздел с номером версии можно получить только так.
insert_section() {
    local version="$1" range="$2" file=CHANGELOG.md
    local head body links tmp prev

    if grep -q "^## \[${version}\]" "$file"; then
        echo "секция [${version}] в ${file} уже есть" >&2
        return 1
    fi

    tmp="$(mktemp -d)"

    # Файл делится на три части: шапка до первого раздела, разделы и блок
    # ссылок. Новая секция идёт в начало разделов — Keep a Changelog требует
    # обратного хронологического порядка.
    head="${tmp}/head"
    body="${tmp}/body"
    links="${tmp}/links"

    awk -v head="$head" -v body="$body" -v links="$links" '
        /^## \[/ { part = 2 }
        /^\[[^]]+\]: http/ { if (part != 3) part = 3 }
        { print > (part == 3 ? links : part == 2 ? body : head) }
    ' part=1 "$file"

    prev="$(last_tag)"

    {
        cat "$head"
        printf '## [%s] - %s\n\n' "$version" "$(date +%F)"
        section_body "$range"
        cat "$body"
        # Строка «Не выпущено» всегда первая в блоке ссылок, новая версия
        # встаёт сразу за ней.
        head -n 1 "$links"
        printf '[%s]: %s/compare/%s...v%s\n' "$version" "$REPO_URL" "$prev" "$version"
        tail -n +2 "$links"
    } >"${tmp}/out"

    mv "${tmp}/out" "$file"
    rm -rf "$tmp"

    echo "добавлена секция [${version}] в ${file}" >&2
}

main() {
    local mode=section range="" version="" heading=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --all)
                mode=all
                shift
                ;;
            --insert)
                mode=insert
                shift
                ;;
            --heading)
                heading=1
                shift
                ;;
            --range)
                range="$2"
                shift 2
                ;;
            --version)
                version="$2"
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

    if [ "$mode" = all ]; then
        render_all
        return 0
    fi

    if [ -z "$range" ]; then
        local from
        from="$(last_tag)"
        # Первый релиз в репозитории без тегов — берём историю целиком.
        range="${from:+${from}..}HEAD"
    fi

    if [ "$mode" = insert ]; then
        [ -n "$version" ] || version="$(version_from_cargo)"
        insert_section "$version" "$range"
        return 0
    fi

    if [ "$heading" = 1 ]; then
        [ -n "$version" ] || version="$(version_from_cargo)"
        printf '## [%s] - %s\n\n' "$version" "$(date +%F)"
    fi

    section_body "$range"
}

main "$@"
