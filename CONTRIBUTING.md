# Contributing

Thanks for your interest in `jwt-service-app`. Bug reports, ideas and pull
requests are accepted from anyone, no prior arrangement needed. Everything below
is what you need to know to get a contribution into `master` without extra
rounds of review.

**This repository is English.** Code, comments, `utoipa` descriptions,
documentation, commit messages (conventional commits — they end up in the
release body), pull request titles and bodies. No exceptions, and no mixed
languages inside a file. CI enforces it (see "What CI checks").

## Three exceptions first

1. **Found a vulnerability? Do not open an issue.** Use a private advisory on
   GitHub (Security → Report a vulnerability) or write to
   [security@filipov.dev](mailto:security@filipov.dev). The full policy, the
   timelines and the list of what is not considered a vulnerability are in
   [SECURITY.md](SECURITY.md).
2. **Keys and JWKS live in another repository.** This service neither generates
   nor stores keys — `jwks-service-app` does. File bugs about key rotation,
   formats or storage over there.
3. **Communication follows the [Code of Conduct](CODE_OF_CONDUCT.md).** It is
   short, and it amounts to "behave like an adult".

## Bug reports and proposals

File them through [issues](https://github.com/filipov-dev/jwt-service-app/issues)
using the forms: **Bug** (needs the version, the configuration without secrets,
the steps to reproduce, expected and actual behaviour) and **Proposal** (needs
the problem you are solving, not only the implementation you have in mind).

Worth a look before you file:

- [CHANGELOG.md](CHANGELOG.md) — it may already be fixed in a newer tag;
- the "What is not considered a vulnerability" section of
  [SECURITY.md](SECURITY.md) and "Conventions and pitfalls" in
  [AGENTS.md](AGENTS.md#conventions-and-pitfalls) — some of the surprising
  behaviour is deliberate and explained there.

"How does this work?" is a fine issue too: if the answer had to be dug out of
the code, the documentation is missing something, and that is a documentation
bug.

## Development environment

You need Rust `stable` — the channel and the components (`clippy`, `rustfmt`)
are pinned in [`rust-toolchain.toml`](rust-toolchain.toml), and rustup picks the
file up on its own. Update the toolchain before running the linter: `rustup
update stable`. A channel is not a version; CI installs a fresh stable on every
run, so new lints show up there before they show up in your local copy.

Besides the compiler you need Redis and `jwks-service-app`. The easiest way is
to bring the whole stand up at once — Docker Compose from
[`deployments/dev/`](deployments/dev/docker-compose.yml) (the service, Redis,
Redis Commander, Postgres, `jwks-service-app`, Swagger UI):

```bash
docker compose -p jwt-dev -f deployments/dev/docker-compose.yml up -d
```

Set the project name (`-p jwt-dev`) explicitly: otherwise Compose takes the
directory name — `dev` — and plenty of other services have a `deployments/dev`
directory too, so the run may recreate somebody else's containers.

## Commands

```bash
cargo build            # build
cargo test             # tests (inline #[cfg(test)] modules next to the code)
cargo clippy --all-targets -- -D warnings   # exactly the lint CI runs
cargo fmt --all        # formatting
cargo audit            # vulnerabilities in dependencies

UPDATE_OPENAPI=1 cargo test openapi   # regenerate docs/openapi.json
scripts/scan-secrets.sh               # gitleaks + trufflehog over the history
scripts/check-language.sh             # the language gate: no Cyrillic in tracked files
```

`cargo build --release` uses the same profile as the production image
(`lto = "fat"`, `codegen-units = 1`) and is therefore noticeably slower than a
debug build. `cargo build` and `cargo clippy` are enough for everyday checks.

## What CI checks

The pipeline is strict, and it fails on exactly the things you can run locally:

| Workflow | What it does |
|----------|--------------|
| `ci.yml` | `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --verbose`, `scripts/check-language.sh` |
| `audit.yml` | `cargo audit` — a vulnerable dependency blocks the merge |
| `secrets.yml` | `scripts/scan-secrets.sh` — gitleaks and trufflehog over every ref, pull request refs included |

Any lint warning and any deviation from `rustfmt` fails the build, so run
`cargo fmt` before committing rather than after review. Advisories that are
deliberately ignored go into [`.cargo/audit.toml`](.cargo/audit.toml) with a
comment explaining why; false positives from the secret scanners are silenced
**by value only**, never by path (an allowlist on a directory blinds the scanner
to a real secret committed into it).

A pull request from a fork runs the same three workflows: they never touch
`secrets.`, which is what makes them safe to run on someone else's code.
Workflows that do have access to secrets (`docker.yml`, `release.yml`) do not
run on pull requests at all. The details are in the
[CI audit](docs/security/workflow-audit.md).

## Code conventions

- **Keep the module structure.** Crypto and JWT logic goes to `src/key.rs` and
  `src/models/jwt.rs`, the HTTP layer to `src/handlers.rs`. The module map is in
  [AGENTS.md](AGENTS.md#module-map-src).
- **Tests live next to the code**, in a `#[cfg(test)]` module in the same file;
  there is no module without tests in this project. A test must not depend on
  environment left behind by its neighbours: `TokenHeaders::create_new` reads
  `TOKEN_ALGORITHM`, so unit tests should use `headers_with_alg` with an
  explicit algorithm.
- **Added an endpoint?** Add the `utoipa::path` annotation, register the path
  and the schemas in `ApiDoc` (`src/openapi.rs`) and regenerate the spec
  (`UPDATE_OPENAPI=1 cargo test openapi`). The file is compared against the code
  by the `spec_file_is_up_to_date` test, and a stale one fails CI.
- **Added an internal endpoint?** List it in `internal_endpoints()` in
  `src/main.rs`. The access-level test sends a request there with a valid proxy
  secret but no TOTP and expects `401`; without the entry the endpoint goes
  unchecked, and a "level 2 instead of level 3" mistake is not caught by a
  "no credentials → 401" check.
- **A comment explains "why", not "what".** The code and the documentation
  record the reasons behind decisions (why `http2` is off, why there is exactly
  one TLS stack, why `/metrics` answers `404` instead of `401`) — if your change
  reverses such a decision, remove the explanation as well instead of leaving it
  to contradict the code.
- **New dependencies must be permissive** (MIT / Apache-2.0). Copyleft crates
  are kept out because the images are distributed publicly. Default features of
  large dependencies are listed explicitly in `Cargo.toml` — otherwise an
  upgrade silently enables a new one.

## Commits

Messages are [conventional commits](https://www.conventionalcommits.org/) with
the task key in parentheses:

```
docs: contributing guide, code of conduct and issue/PR templates (JWT-58)
fix: do not lose the jti when Redis is unavailable (JWT-77)
feat!: move the refresh token format to v2 (JWT-90)
```

Types: `feat`, `fix`, `docs`, `perf`, `refactor`, `test`, `ci`, `style`. The
type picks the section of [CHANGELOG.md](CHANGELOG.md), and `feat!` moves the
entry to "Breaking changes". **The subject goes into the changelog verbatim** —
write it as a changelog line, not as a note to yourself. `CHANGELOG.md` itself
is never edited by hand: [`scripts/changelog.sh`](scripts/changelog.sh)
assembles it from the commit history, and the same script fills in the body of
each GitHub release.

**Every commit bumps the version in `Cargo.toml`** per semver: major — broken
compatibility, minor — new functionality, patch — a bug fix, a refactor, a
documentation or CI change. The version travels into `info.version` of the
OpenAPI spec, so regenerate `docs/openapi.json` after bumping it. If the rule
feels excessive for your change, leave it alone — the maintainer will bump the
version on merge and fix the resulting spec mismatch too.

## Pull request

Branch off `master` (it is the only line of development); name the branch after
the task or after what the change does. Before opening a pull request:

- [ ] `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` are clean;
- [ ] `cargo test` is green and the new code has tests next to it;
- [ ] `scripts/check-language.sh` is clean — no Cyrillic anywhere;
- [ ] the spec is regenerated if endpoints, schemas or the version changed;
- [ ] the version in `Cargo.toml` is bumped;
- [ ] documentation is updated together with the code: behaviour changed means
      `AGENTS.md`/`README.md` changed, not "we will write it up later";
- [ ] there are no secrets in the diff.

The description says what changed and **why**, links the issue or the task, and
states what you ran locally. A small diff is easier to review: three unrelated
changes are better as three pull requests than as one.

What must not be in a pull request:

- **`pull_request_target`** in a workflow — that trigger is deliberately absent
  from this repository, and it is not to be introduced as a drive-by change;
- **secrets and private keys** — CI credentials live in GitHub Secrets;
- **`panic = "abort"`** in the release profile — it would kill the panic channel
  into GlitchTip;
- hand-written edits to `CHANGELOG.md` — the file is generated.

## License of contributions

The project is under [Apache-2.0](LICENSE). By opening a pull request you agree
that your contribution is distributed under the same terms (section 5 of the
license). There is no CLA to sign.
