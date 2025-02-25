# Dev image for development
FROM rust:1.84.1-slim-bullseye as builder

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

# Final stage: use the latest version of Debian Slim
FROM debian:bullseye-slim as runner

# Install runtime dependencies
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
        libssl1.1 \
        && rm -rf /var/lib/apt/lists/*

# Copy the built application from the builder stage
COPY --from=builder /app/target/release/jwt-service-app /usr/local/bin/jwt-service-app

# Set the working directory
WORKDIR /app

# Set the entry point
ENTRYPOINT ["/usr/local/bin/jwt-service-app"]