# Builder image.
# Rust 1.85+ обязателен: транзитивная зависимость `time-core` (edition 2024) не
# парсится более старым cargo. Bookworm — чтобы линковаться с libssl3, как в runner.
FROM rust:1.90-slim-bookworm as builder

# Install dependencies for PostgreSQL
RUN apt-get update --fix-missing && \
    apt-get install -y \
      pkg-config \
      libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /app

# Copy the source code and build the project
COPY . .

# Build the project in release mode
RUN cargo build --release

# Final stage: Debian Slim (bookworm — совпадает с builder по версии OpenSSL 3).
FROM debian:bookworm-slim as runner

# Install runtime dependencies
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# Copy the built application from the builder stage
COPY --from=builder /app/target/release/jwt-service-app /usr/local/bin/jwt-service-app

# Set the working directory
WORKDIR /app

# Set the entry point
ENTRYPOINT ["/usr/local/bin/jwt-service-app"]
