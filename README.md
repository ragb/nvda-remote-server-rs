# nvdaremote-server-rs

[![CI](https://github.com/ragb/nvda-remote-server-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/ragb/nvda-remote-server-rs/actions/workflows/ci.yml)
[![Docker](https://github.com/ragb/nvda-remote-server-rs/actions/workflows/docker.yml/badge.svg)](https://github.com/ragb/nvda-remote-server-rs/actions/workflows/docker.yml)

A high-performance NVDA Remote relay server written in Rust.

This is a drop-in replacement for the [Python NVDA Remote server](https://github.com/jmdaweb/NVDARemoteServer), compatible with the [NVDA Remote](https://nvdaremote.com/) client (protocol v1 and v2), with proposed v3 E2E encryption support.

## What it does

The NVDA Remote relay server connects NVDA screen reader users over the internet. A "master" (controller) and "slave" (controlled) client join the same channel, and the server relays keyboard input, speech, braille, and clipboard data between them.

## Features

- Full NVDA Remote protocol support (v1, v2, and proposed v3 with E2E encryption)
- TLS with auto-generated self-signed certificates
- Channel key generation (9-digit codes)
- Message of the day (MOTD)
- Dual-stack IPv4/IPv6 binding
- Protocol v2 `origin` field injection and v1 backwards-compatible field stripping
- Periodic ping keep-alive (120s)
- Structured logging via `tracing` (env-filter configurable)
- Concurrent channel state via `DashMap`

## Building

```sh
cargo build --release
```

## Running

```sh
cargo run --release
```

Or run the binary directly:

```sh
./target/release/nvdaremote-server-rs
```

The server reads configuration from `config/config.toml`.

### Configuration

```toml
[motd]
message = "Welcome to the NVDA Remote server"
always_send = true

[network]
bind_ipv4 = "127.0.0.1"
bind_ipv6 = "::"
port = 6837
```

- `motd.message` - Message displayed to clients on join
- `motd.always_send` - If `true`, always show MOTD; maps to `force_display` in the protocol
- `network.bind_ipv4` - IPv4 address to bind (remove to disable)
- `network.bind_ipv6` - IPv6 address to bind (remove to disable)
- `network.port` - TCP port (default: 6837)

### Logging

Control log level via the `RUST_LOG` environment variable:

```sh
RUST_LOG=debug cargo run    # verbose
RUST_LOG=info cargo run     # default
RUST_LOG=warn cargo run     # quiet
```

## Protocol

The server implements the NVDA Remote relay protocol:

1. Client connects via TCP+TLS to port 6837
2. Client sends `{"type":"protocol_version","version":2}`
3. Client either:
   - Requests a key: `{"type":"generate_key"}` -> receives `{"type":"generate_key","key":"123456789"}`, then disconnects and reconnects with that key
   - Joins a channel: `{"type":"join","channel":"123456789","connection_type":"master"}`
4. Server responds with `channel_joined` (existing members) and `motd`
5. All subsequent messages from the client are relayed to other channel members
6. On disconnect, server sends `client_left` to remaining members

The server does not parse relayed message content -- it forwards key events, speech, braille, clipboard, and any other message types as-is.

### Protocol v3: End-to-End Encryption (proposed)

> **Status**: Protocol v3 is a proposed extension. The server side is implemented and ready, but the NVDA client side has not been implemented yet and no PR has been submitted to NVDA. This is a design proposal — the protocol may change based on feedback from the NVDA community.

Protocol v3 adds end-to-end encryption (E2E) support so the relay server cannot read user data. Clients that send `protocol_version: 3` are marked as `e2e_supported: true` in their `ClientInfo`. The server:

- Exposes `e2e_supported` per client in `channel_joined`, `client_joined`, `client_left`
- Includes `e2e_available` in `channel_joined` (configurable via `[e2e] allow` in config)
- Includes `user_id` in `channel_joined` (client's own assigned ID)
- Relays `e2e_pubkey` and `e2e_data` messages opaquely (no crypto on the server)

E2E is all-or-nothing: if any peer in the channel doesn't support E2E, the entire channel operates in plaintext. The server does zero cryptographic work — it only reports peer capabilities. All encryption uses X25519 key exchange and XChaCha20-Poly1305, implemented client-side.

Configuration:

```toml
[e2e]
allow = true  # Set to false to disable E2E (e2e_available will be false in channel_joined)
```

See [docs/e2e-encryption.md](docs/e2e-encryption.md) for the full protocol specification, security properties, and Signal protocol comparison. See [docs/llm-implementation-guide.md](docs/llm-implementation-guide.md) for step-by-step client implementation instructions.

## Docker

Pre-built images are available on GitHub Container Registry:

```sh
docker pull ghcr.io/ragb/nvda-remote-server-rs:edge
docker run -p 6837:6837 ghcr.io/ragb/nvda-remote-server-rs:edge
```

Multi-arch images (amd64/arm64) are published automatically:
- `edge` — latest master build
- `v1.0.0`, `1.0`, `1`, `latest` — tagged releases

Or build locally:

```sh
docker build -t nvdaremote-server .
docker run -p 6837:6837 nvdaremote-server
```

Configuration can be overridden with environment variables using the `NVDAREMOTE` prefix and `__` separator:

```sh
docker run -p 6837:6837 -e NVDAREMOTE__NETWORK__PORT=7000 ghcr.io/ragb/nvda-remote-server-rs:edge
```

## Benchmarks

The `bench/` directory contains a benchmark tool that compares this server against the Python implementations.

```sh
# Run all servers in Docker and benchmark them
docker compose -f bench/docker-compose.yml up --build
```

Or run the bench tool directly against a running server:

```sh
cd bench
cargo run --release -- --targets rust=localhost:6837 --pairs 50 --messages 200
```

**Ramp mode** tests escalating concurrent sessions to find server limits:

```sh
cargo run --release -- --targets rust=localhost:6837 --ramp 100,500,1000,2000,5000 --messages 5
```

### Results (50 pairs, 200 messages each, all in Docker)

| Server | Throughput | p50 latency | p95 latency | p99 latency |
|---|---|---|---|---|
| **nvdaremote-server-rs** | **182,596 msg/s** | **101 μs** | **201 μs** | **268 μs** |
| Go ([tech10/nvdaRemoteServer](https://github.com/tech10/nvdaRemoteServer)) | 2,412 msg/s | 148 μs | 1,677 μs | 3,303 μs |
| Python async ([nvda-remote](https://github.com/a2hsh/nvda-remote)) | 2,089 msg/s | 2,331 μs | 2,852 μs | 3,169 μs |
| Python threaded ([NVDARemoteServer](https://github.com/jmdaweb/NVDARemoteServer)) | 615 msg/s | 10,249 μs | 10,684 μs | 11,152 μs |

The Rust server handles 5,000+ concurrent session pairs. The other servers struggle beyond 50.

## Testing

```sh
cargo test
```

70 tests: 34 unit tests (protocol serialization, server state, message transforms), 25 integration tests simulating real NVDA client flows, and 11 E2E crypto tests (key exchange, encrypted relay, attack scenarios).

## License

This project is licensed under the [GNU General Public License v2.0](LICENSE).
