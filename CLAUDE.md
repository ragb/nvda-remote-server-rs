# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A high-performance NVDA Remote relay server in Rust — drop-in replacement for the Python NVDA Remote server. Supports protocol v1 and v2, TLS with self-signed certs, channel-based message relay between master/slave pairs.

## Commands

```bash
cargo build --release          # Build
cargo test                     # All 52 tests (34 unit + 18 integration)
cargo test --lib               # Unit tests only
cargo test --test integration  # Integration tests only
cargo test parse_protocol      # Single test by name
RUST_LOG=debug cargo run       # Run with debug logging
```

**Bench tool** (separate crate in `bench/`):
```bash
cd bench && cargo run -- --targets rust=localhost:6837 --pairs 50 --messages 200
cd bench && cargo run -- --ramp 100,500,1000,2000,5000 --targets rust=localhost:6837
docker compose -f bench/docker-compose.yml up --build   # All servers in Docker
```

## Architecture

```
TCP Accept → TLS (rcgen self-signed) → handle_client() → ClientSession
    ↓
read_loop: parse line-delimited JSON → pre-join state machine or channel relay
    ↓
ServerState: DashMap<String, Channel> (lock-free concurrent channels)
    ↓
broadcast_to_channel → per-client mpsc queue → spawn_writer task → TLS write
```

**Modules:**
- `main.rs` — TLS setup, dual IPv4/IPv6 accept loops
- `server.rs` — `ServerState` with DashMap channels, broadcast, key generation
- `client.rs` — `handle_client()` per-connection handler, read loop, writer/ping tasks, `add_origin()` for v2
- `protocol.rs` — `ClientMessage`/`ServerMessage` enums with serde `tag="type"`
- `config.rs` — TOML + env overrides (`NVDAREMOTE__NETWORK__BIND_IPV4`)

**Key patterns:**
- `Arc<ServerState>` shared across all connection tasks
- Unbounded mpsc channels for outbound queues (no backpressure by design)
- Protocol v2 adds `origin` field to relayed messages; v1 clients get fields stripped via `strip_v2_fields()`
- 120s ping keep-alive per connection

## Configuration

File: `config/config.toml`. Environment overrides with prefix `NVDAREMOTE` and `__` separator.

Default port is 6837. IPv6 is commented out by default. The Dockerfile sets `NVDAREMOTE__NETWORK__BIND_IPV4=0.0.0.0`.

## Testing

Integration tests use `tokio::io::duplex()` for in-memory streams (no real TLS). Test helpers: `setup_server()`, `connect_client()`, `send_write()`, `recv()` in `tests/integration.rs`.

## Docker

- Server: `rust:1.92-slim` build → `debian:trixie-slim` runtime (must match glibc)
- Bench: same pattern, separate `bench/Dockerfile`
- `bench/docker-compose.yml` runs rust-server + two Python servers + bench tool on shared network
