# Dev image for development.
# Rust 1.85+ is required: the transitive dependency `time-core` (edition 2024)
# does not parse with an older cargo.
FROM rust:1.90 as dev

# Install cargo-watch for hot reload during development
RUN cargo install cargo-watch

# The toolchain matching `rust-toolchain.toml` (channel = "stable") is installed
# at image build time: otherwise rustup would download stable on the very first
# `cargo` inside the container — again after every recreation. The linter in the
# dev container must run the same version as CI, which is what the toolchain file
# exists for.
RUN rustup toolchain install stable --component clippy,rustfmt && \
    rustup default stable

# Install cargo-audit for security vulnerability checks
RUN cargo install cargo-audit

RUN cargo install cargo-tarpaulin

# Set the working directory inside the container
WORKDIR /app