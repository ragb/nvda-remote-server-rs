# End-to-End Encryption Protocol (v3)

This document specifies the protocol-level additions for E2E encryption in NVDA Remote. All cryptographic operations happen in the client — the server relays E2E messages opaquely.

For the full design rationale, threat model, and client implementation details, see the [ADR in the NVDA repository](https://github.com/nvaccess/nvda/blob/master/projectDocs/dev/adr-remote-e2e.md).

## Protocol versions

- **v1**: bare protocol — line-delimited JSON messages
- **v2**: adds `origin` (sender's `user_id`), `client`, `clients` fields to relayed messages. Server strips these for v1 clients.
- **v3**: adds E2E encryption support. `e2e_supported: true` in `ClientInfo`. Extensible for future capabilities without another version bump.

## Scope

E2E applies **only to relay server connections**. Direct connections (point-to-point TLS) do not need E2E — the server sets `e2e_available: false` to signal this.

## Server protocol support

### `e2e_supported` derived from protocol version

The server derives `e2e_supported = protocol_version >= 3` for each client. No extra fields in `join` — the version number is sufficient.

### Channel key hashing

V3 clients with E2E enabled hash the channel key with SHA-256 before sending it in the `join` message:

```text
channel = SHA-256(channel_key).hex()
```

The server uses the hash to group clients into channels but never learns the real channel key. This is critical for E2E security — the channel key is used as HKDF salt during key derivation, so the server cannot derive encryption keys even if it substitutes ephemeral public keys.

**Note:** Because the hash differs from the raw key, E2E clients and non-E2E clients joining with the same key end up in separate channels. This is intentional — mixed plaintext/E2E channels would defeat the purpose.

### `channel_joined` response

```json
{
  "type": "channel_joined",
  "channel": "a]f2d8...",
  "user_id": 5,
  "user_ids": [1, 2],
  "clients": [{"id": 1, "connection_type": "master", "e2e_supported": true}],
  "e2e_available": true
}
```

- **`user_id`**: The client's own assigned ID — needed to filter `e2e_data` messages via the `to` field.
- **`user_ids`**: IDs of existing channel members.
- **`clients`**: Detailed info for each existing member, including `e2e_supported`.
- **`e2e_available`**: Server-level flag (configurable via `[e2e] allow` in `config.toml`, env: `NVDAREMOTE__E2E__ALLOW`). When `false`, clients must not initiate E2E.

### `client_joined` / `client_left` notifications

```json
{
  "type": "client_joined",
  "user_id": 5,
  "client": {"id": 5, "connection_type": "slave", "e2e_supported": true}
}
```

```json
{
  "type": "client_left",
  "user_id": 5,
  "client": {"id": 5, "connection_type": "slave", "e2e_supported": true}
}
```

### E2E message types

The server does not parse `e2e_pubkey` or `e2e_data` — they are unknown types that fall through the relay path with `origin` added, like `key`, `speak`, etc.

#### `e2e_pubkey`

Broadcast by each client after joining to exchange ephemeral public keys:

```json
{"type": "e2e_pubkey", "pubkey": "<base64 X25519 public key>", "nonce_prefix": "<base64 4 bytes>"}
```

The server relays this to all channel members with `origin` added.

#### `e2e_data`

Encrypted data-plane message addressed to a specific peer:

```json
{"type": "e2e_data", "to": 2, "ciphertext": "<base64>", "nonce": "<base64 24 bytes>"}
```

The server relays this with `origin` added, using targeted forwarding (see below).

### `to`-based targeted forwarding

When any relayed message includes a `to` field, the server forwards it only to the peer with that `user_id` instead of broadcasting. If `to` is absent, the server broadcasts as usual (v2 behavior). If no client with the target ID exists in the channel, the message is silently dropped.

This avoids sending useless ciphertext to peers who cannot decrypt it.

### All-or-nothing E2E

E2E does not support mixed channels. Two conditions must be met:

1. **`e2e_available: true`** in `channel_joined` — server allows E2E.
2. **All peers `e2e_supported: true`** — checked from `clients` in `channel_joined` and subsequent `client_joined` notifications.

If any peer is v2/v1, E2E is not possible. This is a client-side policy decision — the server reports capabilities but does not enforce E2E.

## Cryptographic design

### Overview

- **Key exchange**: Pairwise X25519 Diffie-Hellman between each pair of clients, using ephemeral keys generated per session.
- **Key derivation**: `HKDF-SHA256(ikm=DH_shared_secret, salt=channel_key, info="nvda-remote-e2e")` — the real channel key (not the hash) is used as HKDF salt.
- **Encryption**: XSalsa20-Poly1305 (SecretBox) authenticated encryption with the HKDF-derived 32-byte key.
- **No persistent identity keys**: No Ed25519 keys, no TOFU, no fingerprints. The channel key (shared out-of-band) serves as the authentication root.
- **Channel size**: Optimized for 2-4 clients (pairwise keys scale fine at this size).

### Nonce construction

24-byte nonce for XSalsa20-Poly1305:

```text
[4 bytes: sender's nonce_prefix] [12 bytes: zero padding] [8 bytes: big-endian counter]
```

Each client generates a random 4-byte `nonce_prefix` per session (broadcast in `e2e_pubkey`). The counter increments per message per peer.

### Key exchange flow

1. Client generates ephemeral X25519 keypair and random 4-byte nonce prefix.
2. Client broadcasts `e2e_pubkey` with public key and nonce prefix.
3. On receiving a peer's `e2e_pubkey` (via relay with `origin`):
   - Compute X25519 DH shared secret.
   - Derive encryption key: `HKDF-SHA256(ikm=DH_shared, salt=channel_key_bytes, info=b"nvda-remote-e2e")`.
   - Store pairwise key indexed by peer's `user_id`.

### Data-plane encryption

- Encrypt the original JSON message (with `type` field) as plaintext.
- Produce one `e2e_data` message per peer, each with `to` set to the recipient's `user_id`.
- The `ciphertext` and `nonce` are base64-encoded.

### Data-plane decryption

- Look up the pairwise key using `origin` from the relayed message.
- Decrypt with XSalsa20-Poly1305 using the provided nonce.
- Parse the decrypted plaintext as JSON and dispatch the inner message.
- If `origin` is wrong (server lies), the wrong pairwise key is used and AEAD decryption fails — the message is rejected.

### Encrypted message types

All data-plane messages are encrypted when E2E is active:

- `key`, `speak`, `cancel`, `pause_speech`, `tone`, `wave`, `send_sas`
- `display`, `braille_input`, `set_braille_info`, `set_display_size`
- `set_clipboard_text`

Control-plane messages stay plaintext: `protocol_version`, `join`, `generate_key`.

## Security properties

### Why MITM is cryptographically impossible

The channel key is used as HKDF salt during key derivation. A MITM attacker (including the relay operator) who substitutes ephemeral public keys completes separate DH exchanges with each client. However, the attacker does not know the real channel key (the server only receives its SHA-256 hash). Without the real channel key, the attacker derives different encryption keys, and all encrypted messages fail Poly1305 MAC verification.

This eliminates the need for persistent identity keys, signatures, TOFU, or fingerprint verification.

### Protected

- All data-plane content (keystrokes, speech, braille, clipboard) between E2E peers
- Forward secrecy per session (ephemeral keys discarded on disconnect)
- MITM resistance via channel key binding
- Sender authenticity via pairwise keys (wrong `origin` causes AEAD failure)

### The `origin` field and server trust

The relay server adds `origin` to all relayed messages. This is **untrusted metadata** set by the server, not the sender.

- The outer `origin` on `e2e_data` is used only for pairwise key lookup.
- If the server lies about `origin`, the receiver uses the wrong pairwise key and AEAD decryption fails.

**Recommendation**: Include `_from` (sender's `user_id`) inside the encrypted payload as defense-in-depth. The receiver checks `_from == origin` after decryption.

### Not protected

- **Metadata**: server sees who is in which channel, timing, message sizes
- **Control plane**: `join`, `protocol_version`, `generate_key` stay cleartext (channel key is hashed)
- **Weak channel keys**: low-entropy keys (e.g. 9-digit numeric from `generate_key`, ~30 bits) could be brute-forced from the SHA-256 hash. For higher security, use longer random channel keys.

## Example message flow

```text
Client A (master, v3)              Server (relay)             Client B (slave, v3)
─────────────────────              ──────────────             ────────────────────
protocol_version(3) ──────→
join(SHA256("room"),"master") ─→
                     ←────── channel_joined(e2e_available=true, peers=[])
                                                             protocol_version(3) ──────→
                                                             join(SHA256("room"),"slave") ─→
                     ←── client_joined(id=2,e2e=true)        ←── channel_joined(peers=[{id=1,e2e=true}])

e2e_pubkey(pk_a, np_a) ────────→ relay(origin=1) ─────────→ add_peer(1, pk_a, np_a)
                                                             DH + HKDF(dh_secret, "room", "nvda-remote-e2e")
                     ←── relay(origin=2) ← e2e_pubkey(pk_b, np_b)
add_peer(2, pk_b, np_b)
DH + HKDF(dh_secret, "room", "nvda-remote-e2e")

[Both now have pairwise SecretBox(HKDF-derived key)]
[Server cannot derive key — it never saw the real channel key "room"]

e2e_data(to=2,ct,n) ─────→ targeted relay ────────────────→ decrypt → {"type":"key","vk_code":65}
                     ←──────────── targeted relay ←────────  e2e_data(to=1,ct,n)
decrypt → {"type":"speak",...}                               encrypt(speak, sequence=[...])
```

## Server configuration

E2E availability is controlled by `[e2e] allow` in `config/config.toml`:

```toml
[e2e]
allow = true  # default
```

Environment override: `NVDAREMOTE__E2E__ALLOW=true`

When `false`, the server sets `e2e_available: false` in `channel_joined` and clients must not initiate E2E.
