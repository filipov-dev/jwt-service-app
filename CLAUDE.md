# CLAUDE.md

The main project instructions live in [AGENTS.md](AGENTS.md) — read it first.
It covers the architecture, the module map, the commands, the configuration and
the pitfalls.

What follows are only the additions specific to Claude Code.

- Do not commit and do not push without being asked. Pushing a `Cargo.toml`
  version change to `master` triggers a release and publishes Docker images —
  do not touch the version without a reason.
- Run `cargo build` and `cargo clippy` after making changes, before calling the
  task done.
