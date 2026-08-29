# A multi-stage build with cargo-chef: the dependencies are compiled in a
# separate layer that is invalidated only when Cargo.toml/Cargo.lock changes. An
# edit to the sources no longer forces openssl/actix-web to be rebuilt from
# scratch — the dependency layer is reused (in CI through the GHA cache, see
# docker.yml).
#
# Rust 1.90 slim-bookworm: bookworm is needed to link against libssl3 as the
# runner does. Rust 1.85+ is required: the transitive dependency `time-core`
# (edition 2024) does not parse with an older cargo.
FROM rust:1.90-slim-bookworm AS chef

# The image pins its toolchain over `rust-toolchain.toml` in the repository root.
# `RUSTUP_TOOLCHAIN` takes precedence over the toolchain file, and without it
# cargo inside the image would download the latest stable: first, the compiler
# version of the release binary would stop being reproducible, and second,
# `cargo chef cook` runs BEFORE the sources (and the toolchain file) are copied,
# so the dependencies would be built with one compiler and `cargo build` with
# another, and the whole dependency layer cache would be rebuilt every time.
ENV RUSTUP_TOOLCHAIN=1.90.0

# openssl-sys needs pkg-config and the libssl headers at build time.
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
      pkg-config \
      libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# cargo-chef is installed once into the base layer — it is cached and reused by
# both stages below (planner and builder).
RUN cargo install cargo-chef --locked --version 0.1.77

WORKDIR /app

# The planner stage: from the full source tree we prepare a "recipe" — the list
# of dependencies without the code itself. The recipe changes only when the
# dependencies do.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# The builder stage: first we build ONLY the dependencies from the recipe (the
# cacheable layer), then we copy the sources and build the crate itself.
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Compiling the dependencies is the heaviest step; it stays cached until
# recipe.json (that is, Cargo.toml/Cargo.lock) changes.
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

# Final stage: Debian Slim (bookworm — the same OpenSSL 3 version as the builder).
FROM debian:bookworm-slim AS runner

# Install runtime dependencies
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# The OCI labels. The key one is `licenses`: the image is distributed publicly on
# Docker Hub and GHCR, and before JWT-56 there was no way at all to tell the
# terms of use from it. The string matches the `license` field in `Cargo.toml`
# and `LICENSE` in the repository root; a license change edits all three.
# `version` is deliberately absent: the tags are set by `docker.yml` from
# `Cargo.toml`, and a label baked into the Dockerfile would go stale silently.
LABEL org.opencontainers.image.title="jwt-service-app" \
      org.opencontainers.image.description="Issue, verify and revoke JWTs" \
      org.opencontainers.image.source="https://github.com/filipov-dev/jwt-service-app" \
      org.opencontainers.image.licenses="Apache-2.0"

# Copy the built application from the builder stage
COPY --from=builder /app/target/release/jwt-service-app /usr/local/bin/jwt-service-app

# The license text goes inside the image: Apache-2.0 (section 4) requires giving
# recipients of the work a copy of the license, and the recipient of the binary
# here is whoever pulled the image, not whoever visited the repository.
COPY LICENSE /usr/share/doc/jwt-service-app/LICENSE

# Set the working directory
WORKDIR /app

# Set the entry point
ENTRYPOINT ["/usr/local/bin/jwt-service-app"]
