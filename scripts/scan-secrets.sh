#!/usr/bin/env bash
#
# Runs the secret scanners over the whole repository history.
#
# The gate before switching the repository to public (JWT-52) and a regular check
# afterwards: `.github/workflows/secrets.yml` calls this very script, so a local
# run and a CI run match by construction rather than because somebody keeps two
# sets of flags in sync. The report of the last audit and the analysis of the
# findings are in docs/security/secret-audit.md.
#
# Usage:
#   scripts/scan-secrets.sh                    # both scanners
#   scripts/scan-secrets.sh --reports DIR      # JSON reports into DIR (otherwise a temporary directory)
#   scripts/scan-secrets.sh --tool gitleaks    # gitleaks only
#   scripts/scan-secrets.sh --tool trufflehog  # trufflehog only
#
# A non-zero exit code means unreviewed secrets were found.

set -euo pipefail

# Both scanners rather than one: they catch different things and substitute for
# each other poorly. gitleaks walks the diffs with regexes and entropy — it picks
# up any key-like junk, home-grown formats included. trufflehog uses detectors
# for specific services and can verify a finding over the network: it tells a
# live key from an expired one, which entropy cannot do in principle.
readonly GITLEAKS_IMAGE="${GITLEAKS_IMAGE:-zricethezav/gitleaks:v8.30.1}"
readonly TRUFFLEHOG_IMAGE="${TRUFFLEHOG_IMAGE:-trufflesecurity/trufflehog:3.97.1}"

# The reviewed trufflehog findings. Silencing is by VALUE, never by file path —
# for the same reasons as the allowlist in .gitleaks.toml: an excluded file would
# stop being guarded entirely. gitleaks has a config for this; trufflehog has no
# equivalent, so the filter lives here and is applied to the JSON output.
readonly TRUFFLEHOG_ALLOWLIST=(
    # Demo Postgres credentials in the dev and load stands
    # (deployments/dev/docker-compose.yml, deployments/load/docker-compose.yml).
    # This is a connection string to the `postgres` container inside the compose
    # network: the host does not resolve from the outside and the port is not
    # published. The user/password pair is set right there, in the environment of
    # that same container — there is no secret here even in theory. Postgres is
    # needed not by this service but by the neighbouring jwks-service-app, which
    # stores its keys there in the stand.
    'postgres://user:password@postgres:5432'
)

usage() {
    sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
    echo "scan-secrets: $*" >&2
    exit 2
}

# Runs a scanner in a container. The repository is mounted read-only: reading is
# all a scanner needs, and it must not damage the working copy even by accident.
#
# GIT_CONFIG_* guards against "detected dubious ownership": inside the container
# the process runs as root while the working copy belongs to the host user (on a
# runner, a different uid than in the container), and git refuses to read such a
# repository.
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

# gitleaks: regexes and entropy over the diffs of the whole history.
#
# --log-opts=--all covers every ref rather than just the current branch:
# otherwise the branches and pull request refs that stay reachable on GitHub drop
# out of the check. The scanner skips merge commits (they have no diff of their
# own), which is why "scanned N commits" is lower than
# `git rev-list --count --all`.
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
        echo "gitleaks: findings in ${reports}/gitleaks.json" >&2
        return 1
    fi

    echo "gitleaks: clean"
}

# trufflehog: detectors for specific services plus verification of the findings.
#
# The script parses the JSON itself rather than relying on --fail: the reviewed
# findings have to be filtered out before the verdict, and the scanner has no
# flags for that.
scan_trufflehog() {
    local reports="$1" allow raw="${1}/trufflehog-raw.json" kept="${1}/trufflehog.json"
    local total=0 remaining=0

    command -v jq >/dev/null 2>&1 || die "jq is required (parsing the trufflehog report)"

    echo "==> trufflehog (${TRUFFLEHOG_IMAGE})"
    # --no-update: the scanner must not silently swap its version for a newer
    # one, or pinning the image guarantees nothing.
    run_scanner "$TRUFFLEHOG_IMAGE" "$reports" \
        git file:///repo --no-update --json >"$raw"

    allow="$(
        IFS='|'
        echo "${TRUFFLEHOG_ALLOWLIST[*]}"
    )"

    # The output lines are one per finding; the logger's own records are filtered
    # out by the DetectorName check. The comparison is by substring (contains)
    # rather than regex: the values hold plenty of characters that would have to
    # be escaped.
    total="$(jq -rs '[.[] | select(.DetectorName)] | length' "$raw")"
    jq -c --arg allow "$allow" '
        select(.DetectorName)
        | select(
            ((.Raw // "") + " " + (.RawV2 // "")) as $v
            | ($allow | split("|") | map(. as $a | $v | contains($a)) | any) | not
          )
    ' "$raw" >"$kept"
    remaining="$(wc -l <"$kept" | tr -d ' ')"

    echo "trufflehog: ${total} findings, $((total - remaining)) of them reviewed"

    if [ "$remaining" -ne 0 ]; then
        echo "trufflehog: unreviewed findings in ${kept}" >&2
        jq -r '"  \(.DetectorName) | verified=\(.Verified) | \(.SourceMetadata.Data.Git.file // "?"):\(.SourceMetadata.Data.Git.line // "?")"' "$kept" >&2
        return 1
    fi

    echo "trufflehog: clean"
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
                echo "unknown argument: $1" >&2
                usage >&2
                return 2
                ;;
        esac
    done

    case "$tool" in
        all | gitleaks | trufflehog) ;;
        *) die "--tool: expected all, gitleaks or trufflehog (got: ${tool})" ;;
    esac

    command -v docker >/dev/null 2>&1 || die "docker is required (the scanners run in containers)"
    REPO_ROOT="$(git rev-parse --show-toplevel)" || die "not a git repository"
    readonly REPO_ROOT

    [ -n "$reports" ] || reports="$(mktemp -d)"
    mkdir -p "$reports"
    # The path is absolute: it is handed to docker as a mount point.
    reports="$(cd "$reports" && pwd)"

    [ "$tool" = trufflehog ] || scan_gitleaks "$reports" || status=1
    [ "$tool" = gitleaks ] || scan_trufflehog "$reports" || status=1

    echo "reports: ${reports}"
    return "$status"
}

main "$@"
