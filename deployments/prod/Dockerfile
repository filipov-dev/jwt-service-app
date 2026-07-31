# Многослойная сборка с cargo-chef: зависимости компилируются в отдельном слое,
# который инвалидируется только при изменении Cargo.toml/Cargo.lock. Любая правка
# исходников больше НЕ заставляет пересобирать openssl/actix-web с нуля — слой с
# зависимостями переиспользуется (в CI — через GHA cache, см. docker.yml).
#
# Rust 1.90 slim-bookworm: bookworm нужен, чтобы линковаться с libssl3 как в
# runner. Rust 1.85+ обязателен: транзитивная зависимость `time-core`
# (edition 2024) не парсится более старым cargo.
FROM rust:1.90-slim-bookworm AS chef

# Пин тулчейна образа поверх `rust-toolchain.toml` в корне репозитория.
# `RUSTUP_TOOLCHAIN` приоритетнее toolchain-файла, и без него cargo внутри
# образа скачивал бы свежий stable: во-первых, версия компилятора релизного
# бинаря перестала бы быть воспроизводимой, во-вторых — `cargo chef cook`
# выполняется ДО копирования исходников (и toolchain-файла), поэтому
# зависимости собрались бы одним компилятором, а `cargo build` — другим, и
# весь кеш слоя с зависимостями пересобирался бы каждый раз.
ENV RUSTUP_TOOLCHAIN=1.90.0

# openssl-sys требует pkg-config и заголовки libssl на этапе сборки.
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
      pkg-config \
      libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# cargo-chef ставим один раз в базовый слой — он кешируется и переиспользуется
# обоими нижележащими стадиями (planner и builder).
RUN cargo install cargo-chef --locked --version 0.1.77

WORKDIR /app

# Стадия planner: из полного дерева исходников готовим "рецепт" — список
# зависимостей без самого кода. Рецепт меняется только при смене зависимостей.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Стадия builder: сначала собираем ТОЛЬКО зависимости по рецепту (кешируемый
# слой), затем копируем исходники и собираем сам crate.
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Компиляция зависимостей — самый тяжёлый шаг; он кешируется до тех пор, пока
# recipe.json (т.е. Cargo.toml/Cargo.lock) не изменится.
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

# Final stage: Debian Slim (bookworm — совпадает с builder по версии OpenSSL 3).
FROM debian:bookworm-slim AS runner

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
