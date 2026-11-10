# End-to-End Encryption Protocol (v3)

This document specifies the protocol-level additions for E2E encryption in NVDA Remote. All cryptographic operations happen in the client — the server relays E2E messages opaquely.

For the full design rationale, threat model, and client implementation details, see the [ADR in the NVDA repository](https://github.com/nvaccess/nvda/blob/master/projectDocs/dev/adr-remote-e2e.md).

## Protocol versions

- **v1**: bare protocol — line-delimited JSON messages
- **v2**: adds `origin` (sender's id), `client`, `clients` fields to relayed messages, and `origin` (the client's own id) in `channel_joined`. Server strips these for v1 clients.
- **v3**: marker for E2E-capable clients. The server treats v3 exactly like v2 — there are no v3-specific server fields. E2E works through any v2+ relay that forwards unknown message types.

## Scope

E2E applies to **all connections**: through a relay server and through NVDA's built-in server (which relays between its clients like any relay).

## Design principle: the server sends no E2E signals

Whether E2E is used is decided by the client alone, never by the server:

- A client that joins with the **hashed** channel key (E2E enabled) must use E2E. It never sends data-plane messages in plaintext; data to a peer is held back until the key exchange with that peer has completed.
- A client that joins with the **raw** channel key (user disabled E2E) does not use E2E, and the user is warned.

There are no server capability flags (`e2e_available`, `e2e_supported`). Such flags would let a malicious server trigger a downgrade to plaintext by lying about itself or about a peer. A server can still drop or block messages (denial of service), but it cannot cause a downgrade.

## Server protocol support

### Channel key hashing

Clients with E2E enabled hash the channel key with SHA-256 before sending it in the `join` message:

```text
channel = SHA-256(channel_key).hex()
```

The server uses the hash as an opaque routing label and never learns the real channel key. This is critical for E2E security — the channel key is used as HKDF salt during key derivation, so the server cannot derive encryption keys even if it substitutes ephemeral public keys.

Because the hash differs from the raw key, E2E clients and non-E2E clients joining with the same key end up in separate channels. Every member of a hashed channel is therefore an E2E client, which is why no per-peer capability flag is needed.

### `channel_joined` response

```json
{
  "type": "channel_joined",
  "channel": "af2d8...",
  "origin": 5,
  "user_ids": [1, 2],
  "clients": [{"id": 1, "connection_type": "master"}, {"id": 2, "connection_type": "slave"}]
}
```

- **`origin`**: The client's own assigned id (v2+ clients only), matching the reference Python relay (nvaccess/remote-server). Clients use it to recognise `e2e_data` messages addressed to them via `to`.
- **`user_ids`**: IDs of existing channel members.
- **`clients`**: Info for each existing member.

### `client_joined` / `client_left` notifications

```json
{
  "type": "client_joined",
  "user_id": 5,
  "client": {"id": 5, "connection_type": "slave"}
}
```

```json
{
  "type": "client_left",
  "user_id": 5,
  "client": {"id": 5, "connection_type": "slave"}
}
```

### E2E message types

The server does not parse `e2e_pubkey` or `e2e_data` — they are unknown types that fall through the relay path with `origin` added, like `key`, `speak`, etc.

#### `e2e_pubkey`

Broadcast by each client after joining, and again whenever a new peer joins, to exchange ephemeral public keys:

```json
{"type": "e2e_pubkey", "pubkey": "<base64 X25519 public key>", "nonce_prefix": "<base64 4 bytes>"}
```

The server relays this to all channel members with `origin` added.

#### `e2e_data`

Encrypted data-plane message addressed to a specific peer:

```json
{"type": "e2e_data", "to": 2, "ciphertext": "<base64>", "nonce": "<base64 24 bytes>"}
```

The server relays this with `origin` added.

### `to`-based targeted forwarding (optional)

When a relayed message includes a `to` field, this server forwards it only to the peer with that id instead of broadcasting. If `to` is absent, the server broadcasts as usual. If no client with the target id exists in the channel, the message is silently dropped.

This is a bandwidth optimization only. Clients filter incoming `e2e_data` by `to` themselves, so relays that broadcast everything (such as the reference Python relay) remain fully correct.

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
   - Store pairwise key indexed by peer's id (`origin`).

### Data-plane encryption

- Encrypt the original JSON message (with `type` field) as plaintext.
- Produce one `e2e_data` message per peer, each with `to` set to the recipient's id.
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

**Recommendation**: Include `_from` (sender's id) inside the encrypted payload as defense-in-depth. The receiver checks `_from == origin` after decryption.

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
                     ←────── channel_joined(origin=1, peers=[])
                                                             protocol_version(3) ──────→
                                                             join(SHA256("room"),"slave") ─→
                     ←── client_joined(id=2)                  ←── channel_joined(origin=2, peers=[{id=1}])

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

## Post-quantum cryptography considerations

### Vulnerability summary

| Component | Algorithm | PQ-safe? | Notes |
|-----------|-----------|----------|-------|
| Key exchange | X25519 | No | Broken by Shor's algorithm |
| Key derivation | HKDF-SHA256 | Yes | 128-bit effective PQ security |
| Symmetric encryption | XSalsa20-Poly1305 | Yes | 128-bit effective PQ security (Grover) |
| Channel key hash | SHA-256 | Yes | But low-entropy keys (~30 bits) are classically brutable regardless |

The only PQ-vulnerable component is the X25519 key exchange. An attacker performing "harvest now, decrypt later" could record `e2e_pubkey` messages and `e2e_data` ciphertext today, then recover X25519 shared secrets with a future quantum computer. Combined with brute-forcing a low-entropy channel key from its SHA-256 hash, they could derive the HKDF keys and decrypt stored sessions.

### Practical risk for NVDA Remote

The risk is low. The encrypted content is ephemeral screen reader data (keystrokes, speech, braille) — not long-term secrets. An attacker who stores relay traffic for 10+ years to eventually decrypt a screen reader session has a theoretical rather than practical threat model. Sessions are short-lived and keys are discarded on disconnect.

### Upgrade path

The protocol is already PQC-ready. The server relays `e2e_pubkey` and `e2e_data` opaquely — it does not parse pubkey format, length, or content. A client upgrade to hybrid key exchange requires **no server changes and no protocol version bump**.

The recommended approach is hybrid X25519 + ML-KEM (FIPS 203, formerly Kyber):

1. Client generates both an X25519 keypair and an ML-KEM keypair.
2. Client sends both public keys in the existing `e2e_pubkey` message (the `pubkey` field grows from ~44 to ~1620 bytes base64, which the server relays unchanged).
3. On receiving a peer's pubkey, the client performs both X25519 DH and ML-KEM decapsulation, concatenates both shared secrets, and feeds them into HKDF: `HKDF-SHA256(ikm=X25519_secret || KEM_secret, salt=channel_key, info="nvda-remote-e2e")`.
4. Symmetric encryption (XSalsa20-Poly1305) and nonce construction stay unchanged.

This gives classical security from X25519 and post-quantum security from ML-KEM. If either algorithm is broken, the other still protects the session.

### Wire impact

The `e2e_pubkey` message grows from ~90 bytes to ~1.6 KB (ML-KEM-768 public keys are 1184 bytes). For 2-4 clients exchanging keys once per session, this is negligible. Data-plane messages (`e2e_data`) stay the same size since the symmetric cipher is unchanged.

### Dependency status

ML-KEM is not yet available in PyNaCl (which wraps libsodium). The Python client would need `pqcrypto` or `liboqs-python`. This is a client-side concern — the server needs zero changes.
