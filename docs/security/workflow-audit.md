# The GitHub Actions security audit for pull requests from forks

The gate before switching the repository to public (JWT-52), alongside the
[history audit for secrets](secret-audit.md).

A public repository means **anyone can open a pull request**, and a pull request
starts workflows. Everything that reaches the runner in the process is someone
else's code: it is compiled and executed by the tests and the build scripts. The
question this audit answers is not "do we trust the author of the pull request"
(we do not, by construction) but "what is the most somebody arriving with a
hostile pull request can get".

## The verdict

**The secrets are out of reach from a fork.** As of 2026-08-26 not a single
workflow with access to `DOCKER_HUB_TOKEN` or with write permissions is started
by an event an outsider can cause. There is no `pull_request_target` anywhere in
the repository. The changes made by this audit do not close a hole; they narrow
what sits in the runner next to someone else's code.

What remains is **arbitrary code execution in an unprivileged runner** — that is
not eliminated but bounded: see "Residual risks".

## The threat model

What GitHub grants a `pull_request` from a fork in a public repository:

| | From a fork | From an own branch / `master` |
|---|---|---|
| `secrets.*` (other than `GITHUB_TOKEN`) | **empty** | available |
| `GITHUB_TOKEN` | **read-only**, regardless of the `permissions` block | as declared in `permissions` |
| Writing to the `master` cache | no (the pull request cache is isolated) | yes |
| Starting `workflow_dispatch` | no (write access to the repository is required) | yes |
| Executing code in the runner | **yes** | yes |

The key point: a `permissions` block in a workflow can only **narrow**. For a
fork the ceiling is read-only anyway, so `permissions` protects against our own
future mistakes and against somebody who obtained write access — not against an
anonymous pull request.

## The triggers: what starts from where

| Workflow | Triggers | Reachable from a fork | Secrets in the jobs |
|---|---|---|---|
| `ci.yml` | `pull_request` → `master`, `push` → `master`, `workflow_dispatch` | **yes**, through `pull_request` | not a single reference to `secrets.*` |
| `audit.yml` | `pull_request` → `master`, `push` → `master`, `schedule`, `workflow_dispatch` | **yes**, through `pull_request` | not a single reference to `secrets.*` |
| `secrets.yml` | `pull_request` → `master`, `push` → `master`, `schedule`, `workflow_dispatch` | **yes**, through `pull_request` | not a single reference to `secrets.*` |
| `docker.yml` | a tag `push`, `release: published`, `workflow_dispatch` | **no** | `DOCKER_HUB_USERNAME`, `DOCKER_HUB_TOKEN`, `GITHUB_TOKEN` |
| `release.yml` | `push` → `master` on the `Cargo.toml` path | **no** | `GITHUB_TOKEN` (write) |

The three workflows a fork can see never reference `secrets.` — verified by grep
rather than by eye. The two workflows with secrets start only on events that
require write access to the repository: a tag push, a release publication, a
manual dispatch. A push to `master` with a `Cargo.toml` change is a privileged
action too: a fork pushes to its own copy, not here.

**`pull_request_target` is not used anywhere.** It is the primary way to shoot
yourself in the foot: it runs the workflow from the base branch but with the
secrets and a write token in the context of somebody else's pull request, and a
single `checkout` of `github.event.pull_request.head.sha` turns it into execution
of foreign code with full permissions. Introducing `pull_request_target` into this
repository requires a decision of its own, not a drive-by change.

## The `permissions` of `GITHUB_TOKEN`

There is an explicit block in every workflow — anything not listed is zeroed out:

| Workflow | `permissions` | What for |
|---|---|---|
| `ci.yml` | `contents: read` | checkout only |
| `audit.yml` | `contents: read` | checkout only |
| `secrets.yml` | `contents: read` | checkout; the report artifact is uploaded by its own mechanism and needs no `contents` permission |
| `docker.yml` | `contents: read`, `packages: write` | checkout plus pushing the images to GHCR (both jobs need it) |
| `release.yml` | `contents: write`, `actions: write` | creating the tag and the release; dispatching `docker.yml` through `workflow_dispatch` |

There is nothing left to narrow: removing `packages: write` from `docker.yml` or
`contents: write` from `release.yml` means breaking their main job.

## Substituting event data into a shell

The classic injection is `${{ github.event.pull_request.title }}` inside a `run:`:
the pull request title is written by an outsider, and it is substituted into the
script **before** the shell starts, that is, as code rather than as data. There
are no such substitutions in this repository: the only references to the event
context are `${{ github.actor }}` in `docker.yml` (the username for the GHCR
login, not in a `run:`) and `${{ matrix.platform }}` from a static matrix.

The rule for the future: put event data into a step's `env:` and read it in the
script through `"$VAR"` — the shell then receives it as a variable value.

## What this audit changed

- **`persist-credentials: false` on every `actions/checkout`.** By default
  checkout leaves the token in the working directory's `.git/config` for the rest
  of the job. In `ci.yml`, `audit.yml` and `secrets.yml` the steps that follow run
  code from the pull request (`cargo build`, `cargo test`, the build scripts of
  the dependencies, `scripts/scan-secrets.sh` itself — all from the author's
  branch), and a token lying next to it is available to that code. For a fork the
  token is read-only, so the value of such a find is low, but there is no need for
  it either: not a single step in any workflow talks to git over the network. In
  `docker.yml` and `release.yml` the same flag is set for a different reason —
  there the token is write-scoped, and keeping it on the filesystem longer than
  necessary is pointless.
- **`concurrency` with cancellation of the previous run in `ci.yml`, `audit.yml`
  and `secrets.yml`.** A public repository also means the runner queue can be
  occupied by a series of pushes to a pull request. A new push to the same branch
  cancels an unfinished run of the same pull request; runs on `master` are never
  cancelled (`cancel-in-progress` is enabled only for `github.event_name ==
  'pull_request'`), or a quick series of merges would leave the default branch
  unchecked.

## Required in the repository settings

Not fixable by code; done by hand in Settings before publication:

- **Settings → Actions → Workflow permissions: `Read repository contents`.**
  At the time of the audit the repository had `write`
  (`default_workflow_permissions`, read through the API). It does not affect the
  current workflows — all five have an explicit `permissions` block that
  overrides the default — but the very first workflow added without such a block
  would silently get a write token.
- **Settings → Actions → Fork pull request workflows: `Require approval for all
  external contributors`.** The default for public repositories is approval only
  for first-time contributors; after the first merged pull request the runs become
  automatic.
- **An environment with required reviewers for publishing the images** — should
  the wish arise to run `docker.yml` other than manually and other than from a
  tag.
- **Settings → Advanced Security → Private vulnerability reporting: on.** The
  setting exists only for public repositories, so it cannot be switched on in
  advance — the API answers `404` for `/private-vulnerability-reporting` while
  the repository is private. It is what makes the "Report a vulnerability" link
  in [`SECURITY.md`](../../SECURITY.md) work; until it is on, the private
  channel documented there is email only. Enable it in the same sitting as the
  switch to public, not later.

## Residual risks

- **Arbitrary code execution in the runner.** Any CI that builds a pull request
  executes foreign code: the `build.rs` of the dependencies, the tests, the
  scripts. The bound is the absence of secrets and a read-only token, not a
  sandbox. The runner is disposable and its network is open; assume that the
  contents of a runner on a pull request from a fork are public.
- **The actions are pinned to tags rather than to SHAs.**
  `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`,
  `docker/login-action@v4.5.2`, `peter-evans/dockerhub-description@v5` — tags are
  mutable, and a compromise upstream puts foreign code in our jobs, `docker.yml`
  next to `DOCKER_HUB_TOKEN` included. This has nothing to do with forks, and the
  versions are updated by dependabot (`github-actions`, weekly). Moving to SHA
  pinning is a task of its own.
- **The `Swatinem/rust-cache` cache on a pull request from a fork.** The `master`
  cache cannot be poisoned from a pull request: GitHub isolates the caches of a
  pull request branch from the base one. The other direction is normal: a pull
  request reads the `master` cache, and that is merely compiled dependencies.

## The routine: adding a workflow means checking

1. Do the triggers include `pull_request`? If so, the jobs must not contain a
   single reference to `secrets.` (`GITHUB_TOKEN` is the exception, it is
   read-only).
2. `pull_request_target` — no. If it seems necessary, that is grounds for a
   discussion, not for a commit.
3. An explicit `permissions` block with the minimum set of permissions.
4. `actions/checkout` with `persist-credentials: false`, unless there are git
   commands over the network below.
5. Event data (`github.event.*`) only through a step's `env:`, never substituted
   directly into a `run:`.
