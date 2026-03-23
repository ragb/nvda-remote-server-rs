# Stage 1: Cache dependencies
FROM rust:1.92-slim AS deps
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
# Create dummy src so cargo can resolve and cache deps
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release && rm -rf src target/release/.fingerprint/nvdaremote*

# Stage 2: Build actual source
FROM deps AS builder
COPY src ./src
RUN cargo build --release

# Stage 3: Minimal runtime
FROM debian:trixie-slim
COPY --from=builder /app/target/release/nvdaremote-server-rs /usr/local/bin/
COPY config /etc/nvdaremote-server-rs/config
WORKDIR /etc/nvdaremote-server-rs
ENV NVDAREMOTE__NETWORK__BIND_IPV4=0.0.0.0
EXPOSE 6837
CMD ["nvdaremote-server-rs"]
