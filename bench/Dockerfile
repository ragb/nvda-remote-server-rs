# Stage 1: Cache dependencies
FROM rust:1.92-slim AS deps
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src target/release/.fingerprint/nvda-remote-bench*

# Stage 2: Build actual source
FROM deps AS builder
COPY src ./src
RUN cargo build --release

# Stage 3: Minimal runtime
FROM debian:trixie-slim
COPY --from=builder /app/target/release/bench /usr/local/bin/
ENTRYPOINT ["bench"]
