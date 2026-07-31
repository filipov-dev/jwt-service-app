# Dev image for development.
# Rust 1.85+ обязателен: транзитивная зависимость `time-core` (edition 2024) не
# парсится более старым cargo.
FROM rust:1.90 as dev

# Install cargo-watch for hot reload during development
RUN cargo install cargo-watch

# Тулчейн под `rust-toolchain.toml` (channel = "stable") ставим на этапе сборки
# образа: иначе rustup качал бы stable при первом же `cargo` внутри контейнера —
# заново после каждого пересоздания. Линт в dev-контейнере должен идти той же
# версией, что и в CI, ради чего toolchain-файл и заведён.
RUN rustup toolchain install stable --component clippy,rustfmt && \
    rustup default stable

# Install cargo-audit for security vulnerability checks
RUN cargo install cargo-audit

RUN cargo install cargo-tarpaulin

# Set the working directory inside the container
WORKDIR /app