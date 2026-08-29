#!/usr/bin/env bash
#
# Builds the CHANGELOG from conventional commits in the git history.
#
# The same code is used in two places, so the format of the sections in
# CHANGELOG.md and in the body of a GitHub release matches by construction:
#   * `--all` — the whole file, and the only thing that ever writes
#     CHANGELOG.md;
#   * no arguments — the body of the section for the next release, which
#     `release.yml` puts into the release description.
#
# Usage:
#   scripts/changelog.sh                        # section body: last tag..HEAD
#   scripts/changelog.sh --heading              # the same plus "## [version] - date"
#   scripts/changelog.sh --range v1.9.0..v1.10.0
#   scripts/changelog.sh --version 1.13.0       # the version in the heading (otherwise from Cargo.toml)
#   scripts/changelog.sh --all > CHANGELOG.md   # regenerate the whole file
#   scripts/changelog.sh --check                # is the committed file that regeneration?
#
# The mapping of commit types to sections is in `bucket_for`.

set -euo pipefail

readonly REPO_URL="https://github.com/filipov-dev/jwt-service-app"

# The sections in output order: key and heading. Empty sections are not printed,
# so most versions have two or three.
readonly SECTIONS=(
    "breaking:Breaking changes"
    "added:Added"
    "changed:Changed"
    "fixed:Fixed"
    "security:Security"
    "docs:Documentation"
    "internal:Internal"
    "other:Other"
)

usage() {
    sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'
}

# The section a commit of a given type lands in.
#
# Keep a Changelog describes six sections for user-facing changes. Two more are
# added here: "Documentation" (in this project docs commits are client examples
# and operating instructions, which face outwards too) and "Internal" (CI, tests,
# formatting). Without the latter, releases like v1.8.5 — which held only a load
# test — would look empty.
bucket_for() {
    case "$1" in
        feat) echo added ;;
        fix) echo fixed ;;
        security) echo security ;;
        perf | revert) echo changed ;;
        docs) echo docs ;;
        # `deps` is the prefix of dependabot commits (see
        # .github/dependabot.yml). Without it, dependency updates fell into
        # "Other".
        refactor | style | test | ci | build | chore | deps) echo internal ;;
        *) echo other ;;
    esac
}

# Parses the commit subjects of a range and files them into per-section files in
# the directory $2. A file exists only for a non-empty section.
collect() {
    local range="$1" dir="$2"
    local subject type scope bang text entry bucket

    rm -rf "$dir"
    mkdir -p "$dir"

    # --reverse: within a release the changes read in the order they were made.
    # --format (not --pretty=format) so that the last line also ends with a
    # newline and is not lost by read.
    while IFS= read -r subject; do
        [ -n "$subject" ] || continue

        if [[ $subject =~ ^([a-z]+)(\(([^\)]+)\))?(!)?:[[:space:]]+(.+)$ ]]; then
            type="${BASH_REMATCH[1]}"
            scope="${BASH_REMATCH[3]}"
            bang="${BASH_REMATCH[4]}"
            text="${BASH_REMATCH[5]}"
        else
            # The early history (Init, Build, Clean) predates the move to
            # conventional commits. Such commits go into "Other" rather than
            # getting lost.
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

        # An exclamation mark in the type (`feat!:`) means a break of backwards
        # compatibility per the conventional commits specification — such changes
        # matter more than their category and are moved to a separate section at
        # the top.
        if [ -n "$bang" ]; then
            bucket=breaking
        else
            bucket="$(bucket_for "$type")"
        fi

        printf '%s\n' "$entry" >>"${dir}/${bucket}"
    done < <(git log --no-merges --reverse --format='%s' "$range")
}

# Prints the non-empty sections from the directory $1.
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

    [ "$printed" = 1 ] || printf '_No changes._\n\n'
}

# Whether the range $1 holds at least one commit (merge commits aside).
has_commits() {
    [ -n "$(git log --no-merges --format='%s' "$1")" ]
}

# The section body for the range $1.
section_body() {
    local dir
    dir="$(mktemp -d)"
    collect "$1" "$dir"
    emit "$dir"
    rm -rf "$dir"
}

# The tags in ascending version order. There are fewer releases than version
# bumps: within one pull request the version is bumped by every commit while a
# single tag is created, for the final one. That is why the list has gaps
# (1.11.0, 1.12.0, 1.12.1 and so on), and it is not lost history: those commits
# are part of the next released tag.
tags_ascending() {
    git tag --sort=v:refname
}

# The date of the commit a ref points at.
ref_date() {
    git log -1 --format=%ad --date=short "$1"
}

version_from_cargo() {
    grep -m1 '^version' Cargo.toml | cut -d '"' -f 2
}

# The last released tag — the starting point for the next release.
last_tag() {
    tags_ascending | tail -n 1
}

# The whole file: the header, "Unreleased" (when there are commits after the
# last tag), then the versions from newest to oldest and the links to the diffs
# between tags.
render_all() {
    local tags=() tag prev range i

    while IFS= read -r tag; do
        tags+=("$tag")
    done < <(tags_ascending)

    cat <<'HEADER'
# Changelog

All notable changes to this project. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the versions follow
[semantic versioning](https://semver.org/).

The file is assembled from the commit history and regenerated with
`scripts/changelog.sh --all`; the body of every GitHub release is built by the
same script. The entries are commit subjects verbatim, with the task key in
parentheses — `JWT-NNN` is an identifier in the maintainer's own issue tracker,
which is not public, so it records where a change came from rather than linking
anywhere.

**One section per release, not per version bump.** The version is bumped by
every commit while a tag is created only for the last of them, so the numbers
here have gaps (1.11.0, 1.12.0, 1.12.1). Nothing is lost: those commits belong
to the section of the tag that followed them.

Two sections are added to the six of Keep a Changelog: "Documentation" (client
examples and operating instructions — changes for the consumer of the service)
and "Internal" (CI, tests, formatting).

Entries before 1.17.13 are in Russian: the repository switched to English in
JWT-114 and the commit history was deliberately left as it was.

HEADER

    # The "Unreleased" section appears only when something has actually
    # accumulated after the last tag: on master right after a release there is
    # none.
    if has_commits "$(last_tag)..HEAD"; then
        printf '## [Unreleased]\n\n'
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

    # Version comparison links: from a "## [1.13.0]" line one click shows the range.
    printf '[Unreleased]: %s/compare/%s...HEAD\n' "$REPO_URL" "$(last_tag)"
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

# The "Unreleased" section is the one part of the file that depends on HEAD: on a
# pull request branch it holds that branch's commits, on master usually nothing.
# Everything else is a function of the tags alone and is therefore identical
# wherever it is generated — so a comparison that drops this one section is the
# same comparison on a branch and on master.
strip_unreleased() {
    awk '
        /^## \[Unreleased\]/ { skip = 1; next }
        /^## \[/ { skip = 0 }
        !skip
    ' "$1"
}

# Compares CHANGELOG.md against what the history would generate today.
#
# The file used to be grown section by section as each pull request was merged,
# which is why it drifted: a section carried the date it was written rather than
# the date of the tag, it was filed under the version in Cargo.toml even when no
# tag ever got that number (leaving a compare link to a tag that does not
# exist), and any commit made after the section was written was simply missing
# from it. Generating the whole file is the only mode now, and this check is
# what keeps it the only mode.
check_file() {
    local file=CHANGELOG.md tmp status=0

    if [ -z "$(tags_ascending)" ]; then
        echo "changelog: no tags in this clone — fetch them first (git fetch --tags)" >&2
        return 2
    fi

    tmp="$(mktemp -d)"
    render_all >"${tmp}/generated"
    strip_unreleased "$file" >"${tmp}/committed"
    strip_unreleased "${tmp}/generated" >"${tmp}/expected"

    diff -u --label "CHANGELOG.md (committed)" --label "CHANGELOG.md (generated)" \
        "${tmp}/committed" "${tmp}/expected" || status=$?
    rm -rf "$tmp"

    if [ "$status" = 0 ]; then
        echo "changelog: up to date" >&2
        return 0
    fi

    cat >&2 <<'MSG'

changelog: the committed CHANGELOG.md is not what the history generates.
Regenerate it and commit the result:

    scripts/changelog.sh --all > CHANGELOG.md

MSG
    return 1
}

main() {
    local mode=section range="" version="" heading=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --all)
                mode=all
                shift
                ;;
            --check)
                mode=check
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
                echo "unknown argument: $1" >&2
                usage >&2
                return 2
                ;;
        esac
    done

    if [ "$mode" = all ]; then
        render_all
        return 0
    fi

    if [ "$mode" = check ]; then
        check_file
        return $?
    fi

    if [ -z "$range" ]; then
        local from
        from="$(last_tag)"
        # The first release in a repository without tags — take the whole history.
        range="${from:+${from}..}HEAD"
    fi

    if [ "$heading" = 1 ]; then
        [ -n "$version" ] || version="$(version_from_cargo)"
        printf '## [%s] - %s\n\n' "$version" "$(date +%F)"
    fi

    section_body "$range"
}

main "$@"
