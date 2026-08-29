# The repository history audit for secrets

The gate before switching the repository to public (JWT-52) and the routine for
checks afterwards.

Publishing a repository is irreversible: clones, forks and search indexes appear
faster than you can change your mind. So the question "is there a secret in the
history" is settled by running scanners over **every** commit rather than by
grepping for familiar variable names: a grep finds what you were looking for,
while what leaks is usually what nobody thought of — a high-entropy string in a
one-off script, a key in an example, a config dump in a debugging commit.

## The verdict

**The history is clean.** As of 2026-08-25 (`1ec2040`, master) two independent
scanners report zero unreviewed findings. Everything they found consists of demo
values from the local stands, reviewed one by one below.

Not a single **verified** secret (trufflehog verifies findings over the network):
`verified_secrets: 0`.

## What was scanned

| | |
|---|---|
| Point of check | `1ec2040`, master, 2026-08-25 |
| Commits in the history | 155 (54 of them merge commits) |
| Scanned by gitleaks | 101 commits (merge commits are skipped: they have no diff of their own) |
| Scanned by trufflehog | 1598 chunks, ~1.3 MB |
| Unique paths over the whole history | 94 added, 108 objects counting renames |
| Ref coverage | 22 local branches, 53 remote ones, 49 tags and **74 pull request refs** |

**The pull request refs (`refs/pull/*/head`) are in scope deliberately.** A commit
removed from a branch by a force push stays reachable on GitHub through the pull
request link indefinitely. A "by branches" check does not see such commits — but
the public does. They are fetched explicitly:

```bash
git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'
```

In this repository the pull request refs added 6 commits beyond those reachable
from branches; there are no findings in them.

## What it was scanned with

There are two scanners because on its own each is blind in its own half:

- **gitleaks v8.30.1** — regexes and entropy over the diffs. It picks up key-like
  junk in any format, home-grown ones included, but cannot tell a live key from a
  made-up one.
- **trufflehog 3.97.1** — detectors for specific services plus **verification of a
  finding over the network**. It knows formats less well but answers the main
  question: can this key be used right now or not.

The run is a single command, the same one CI uses:

```bash
scripts/scan-secrets.sh                 # both scanners over the whole history
scripts/scan-secrets.sh --reports out   # with JSON reports in ./out
```

The image versions are pinned in the script: "scanned with the latest version" is
not a reproducible statement, while an image sha plus a date is.

## The findings and their analysis

All four are demo values from the stands. None of them grants access to anything
beyond `docker compose up` on your own machine.

| Scanner | Value | Where | Why it is not a secret |
|---------|-------|-------|------------------------|
| gitleaks (`generic-api-key`, entropy 4.31) | `MRSWGYLSMUQGO33WNFXGO4ZAOBWGKYLSFVRW63LOMNXW2ZI` | `deployments/dev/docker-compose.yml`, `deployments/load/run.sh`, `deployments/load/README.md`, the tests in `src/main.rs` | The dev stand's `AUTH_TOTP_SECRET`. It has to be valid base32 or the service does not start — hence the entropy and the hit. It decodes to `decare govings plear-comncome`, that is, generated nonsense tied to no environment at all. |
| gitleaks | `dev-proxy-secret`, `dev-metrics-token` | the same places | The dev stand's `AUTH_PROXY_SECRET` and `AUTH_METRICS_TOKEN`; they are in the allowlist for the future — the current rules do not pick them up. |
| trufflehog (`Postgres`, unverified) | `postgres://user:password@postgres:5432` | `deployments/dev/docker-compose.yml`, `deployments/load/docker-compose.yml` | A connection string to a container inside the compose network: the `postgres` host does not resolve from the outside, the port is not published, and the `user`/`password` pair is set right there in the `environment` of that same container. Postgres is needed not by this service but by the neighbouring `jwks-service-app`. |

The findings are silenced **by value, not by file path** — in
[`.gitleaks.toml`](../../.gitleaks.toml) and in the `TRUFFLEHOG_ALLOWLIST` list in
[`scripts/scan-secrets.sh`](../../scripts/scan-secrets.sh). The difference is
fundamental: an allowlist on `deployments/dev/**` would also blind the scanner to
a real secret accidentally committed into the same file — and that slip is most
likely in the dev stand of all places.

## What was checked besides the scanners

The scanners answer the question "are there secret-like strings in the history".
Separately, it was checked that no files were committed that hold no secret by
name but do by nature — over **every object** of every ref rather than over the
working tree:

```bash
git rev-list --objects --all | awk 'NF>1{ $1=""; print }' | sort -u | grep -Ei '...'
```

- `AGENTS_INTERNAL.md` (internal notes, accesses) — never committed;
- `.idea/` — never tracked;
- `deployments/prod/.env` and `deployments/prod/k8s/secret.yaml` — never
  committed; only the `.env.example` and `secret.example.yaml` templates are in
  the repository, and the secret values in them are empty or `"replace me"`;
- `deployments/load/tokens.json` and `summary.json` (real signed JWTs from a load
  run) — never committed;
- there are no files with the extensions `.pem`, `.key`, `.p12`, `.pfx`, `.jks`,
  `.ppk` or similar anywhere in the history.

Everything listed is covered by `.gitignore`, but `.gitignore` only protects the
future: a file that entered the index before the rule stays in the history
forever. Hence a check over the objects rather than over the current ignore
rules.

## What this report does not cover

- **Unreachable objects on the GitHub side.** A local `git fsck` sees them, but
  the scanners walk the refs. Pull request refs — the main leak channel of that
  kind — are in scope (see above); the remaining tail (objects from deleted
  forks, unreachable from any ref) can only be removed by contacting GitHub
  support, and is moot in this repository: no unreachable commits were found at
  all, so the history never needed rewriting.
- **Future commits.** A one-off audit goes stale with the very next push — which
  is why it was turned into a CI gate, see below.
- **Secrets that do not look like secrets.** No scanner will find an internal
  hostname or a person's name in a comment. That is a matter of review, not of
  regexes.

## The regression: the check in CI

The gate is held by
[`.github/workflows/secrets.yml`](../../.github/workflows/secrets.yml): the same
`scripts/scan-secrets.sh` on every pull request, on pushes to `master`, weekly on
a schedule and on demand. A finding fails the pipeline and the JSON reports are
uploaded as an artifact (`secret-scan-reports`, 14 days) — they are what a finding
is investigated from, without going back to the log.

One and the same script locally and in CI — so that the flag set and the
allowlists cannot drift between a developer and a runner by construction, rather
than because somebody watches over it.

The weekly run is not redundant: the scanners keep adding signatures, and a
history that was clean yesterday can turn out dirty today without a single new
commit.

## If a scanner finds a real secret

The order of operations is not intuitive, so point by point:

1. **Revoke and reissue the secret first, everything else second.** From the
   moment of the push it is compromised; rewriting the history does not undo
   that, it only makes the attacker's search harder. Until the key is revoked,
   any git manipulation is a waste of time.
2. Remove the value from the working tree, replacing it with a read from the
   environment.
3. Purge it from the history (`git filter-repo`), overwrite the branches with a
   force push **and** delete or recreate the affected pull requests — otherwise
   the value stays reachable through `refs/pull/*`.
4. If the repository is already public — ask GitHub support to remove the
   unreachable objects and assume the value is already indexed.
5. Add it to the allowlist **only** if the analysis showed it is not a secret —
   with the reason in the entry's description. An allowlist entry without an
   explanation is indistinguishable, six months later, from "to make CI green".
