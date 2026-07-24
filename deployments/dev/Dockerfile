# Dev image for development.
# Rust 1.85+ обязателен: транзитивная зависимость `time-core` (edition 2024) не
# парсится более старым cargo.
FROM rust:1.90 as dev

# Install cargo-watch for hot reload during development
RUN cargo install cargo-watch

# Add Rust tools for linting and formatting
RUN rustup component add clippy
RUN rustup component add rustfmt

# Install cargo-audit for security vulnerability checks
RUN cargo install cargo-audit

RUN cargo install cargo-tarpaulin

# Set the working directory inside the container
WORKDIR /app