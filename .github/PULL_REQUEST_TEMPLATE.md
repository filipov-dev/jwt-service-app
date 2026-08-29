## What changed

<!-- Short and to the point: what now works differently. -->

## Why

<!-- The task, the issue or the tracker key. If the change reverses a decision
     taken earlier (they are documented in AGENTS.md), explain why the previous
     one no longer holds. -->

## How it was verified

<!-- What you ran locally and what you checked by hand: a curl against the
     endpoint, a stand you brought up, a new test. "It compiles" is not a
     verification. -->

## Checklist

- [ ] `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` are clean
- [ ] `cargo test` is green and the new code has tests next to it
- [ ] `scripts/check-language.sh` is clean — everything is in English
- [ ] the version in `Cargo.toml` is bumped per semver
- [ ] `docs/openapi.json` is regenerated if endpoints, schemas or the version
      changed (`UPDATE_OPENAPI=1 cargo test openapi`)
- [ ] the documentation (`README.md`, `AGENTS.md`, `docs/`) is updated together
      with the code
- [ ] a new internal endpoint is listed in `internal_endpoints()` (`src/main.rs`)
- [ ] there are no secrets, private keys or live tokens in the diff
- [ ] `CHANGELOG.md` was not edited by hand — it is generated
      (`scripts/changelog.sh --check` is clean, or rebuild it with `--all`)

<!-- The commit subject goes into the changelog verbatim: conventional commits
     (feat/fix/docs/perf/refactor/test/ci/style) with the task key in
     parentheses. The details are in CONTRIBUTING.md. -->

<!-- Found a vulnerability? Do not describe it here and do not send the patch as
     a public pull request: use a private advisory or security@filipov.dev, see
     SECURITY.md. -->
