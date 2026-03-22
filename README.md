# nvdaremote-server-rs

A high-performance NVDA Remote relay server written in Rust.

This is a drop-in replacement for the [Python NVDA Remote server](https://github.com/jmdaweb/NVDARemoteServer), compatible with the [NVDA Remote](https://nvdaremote.com/) client addon (protocol v1 and v2).

## What it does

The NVDA Remote relay server connects NVDA screen reader users over the internet. A "master" (controller) and "slave" (controlled) client join the same channel, and the server relays keyboard input, speech, braille, and clipboard data between them.

## Features

- Full NVDA Remote protocol support (v1 and v2)
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

## Testing

```sh
cargo test
```

52 tests: 34 unit tests (protocol serialization, server state, message transforms) and 18 integration tests simulating real NVDA client flows.

## License

TBD
