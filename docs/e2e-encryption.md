# End-to-End Encryption for NVDA Remote (Protocol v3)

This document specifies how to implement end-to-end encryption (E2E) in the NVDA Remote client so that the relay server cannot read user data (keystrokes, speech, braille, clipboard).

The server side is already implemented — it relays E2E messages opaquely and exposes `e2e_supported` in `ClientInfo`. All cryptographic operations happen in the NVDA client (Python).

## Scope: relay connections only

This E2E extension applies **only to relay server connections** — where a third-party server sits between the two NVDA instances and can read all traffic.

**Direct connections do not need E2E.** When one NVDA instance connects directly to another (via `server.py` in the client), the TLS tunnel runs point-to-point between the two machines with no intermediary. The only parties that can read the traffic are the two endpoints, which already have full access to the screen reader. Adding E2E on top of a direct TLS connection would add complexity for zero security benefit.

**How the client knows**: Two checks are needed before initiating E2E:

1. **`e2e_available`** in `channel_joined` — server-level flag. The relay server sets this to `true` (configurable). The NVDA direct-connection server (`server.py`) should set it to `false` or omit it (client defaults to `false`). Old relay servers that don't know about E2E also won't send it, so the client safely defaults to no E2E.

2. **All peers must be `e2e_supported: true`** — checked from the `clients` list in `channel_joined` and subsequent `client_joined` notifications. If any peer is v2/v1, E2E is not possible (all-or-nothing rule).

```python
# In session.py, when handling channel_joined:
def _handleChannelJoined(self, channel, user_id, user_ids, clients, e2e_available=False, **kwargs):
    all_peers_e2e = all(c.get("e2e_supported") for c in clients) if clients else True
    if e2e_available and all_peers_e2e:
        self.e2e = E2ESession()
        self.transport.send(RemoteMessageType.E2E_PUBKEY, **self.e2e.get_pubkey_message())
    else:
        self.e2e = None  # Direct connection, legacy server, or non-E2E peers present
```

This way the client doesn't need to inspect its own transport type — it reads two server-provided signals: "does the server allow E2E?" and "do all peers support it?"

## Overview

This design uses the same well-known cryptographic primitives as Signal (X25519, authenticated encryption, fingerprint verification) but is intentionally much simpler. Signal solves harder problems — offline messaging, persistent identity, per-message forward secrecy — that don't apply to a real-time screen reader relay with 2–4 simultaneous clients. See [Design compromises vs Signal protocol](#design-compromises-vs-signal-protocol) for a detailed comparison of every tradeoff and why it's acceptable for NVDA Remote.

- **Key exchange**: Pairwise X25519 Diffie-Hellman between each pair of clients
- **Encryption**: XChaCha20-Poly1305 authenticated encryption
- **Channel size**: Optimized for 2–4 clients (pairwise keys scale fine at this size)
- **Library**: `PyNaCl` (Python binding to libsodium) — provides X25519, XChaCha20-Poly1305, and BLAKE2b in a single dependency

## Server protocol support

### Protocol version 3

E2E requires protocol version 3. The version number gates capability:

- **v1**: bare protocol
- **v2**: adds `origin`, `client`, `clients` fields to relayed messages
- **v3**: adds E2E encryption support (extensible for future capabilities without another version bump)

Clients that send `{"type": "protocol_version", "version": 3}` are marked as `e2e_supported: true` in `ClientInfo`. The server derives this from the version number — no extra fields needed in `join`.

### All-or-nothing E2E

**E2E does not support mixed channels.** If even one client in the channel doesn't support E2E, the server sees the plaintext anyway (from or to that client), defeating the purpose. The rule is:

- **All v3 clients**: E2E key exchange happens, all data-plane messages are encrypted. Server is blind.
- **Any v2/v1 client in the channel**: No E2E. All communication is plaintext. V3 clients see `e2e_supported: false` on the v2 peer in `channel_joined` and must not initiate key exchange.
- **Client policy**: When a v3 client sees a non-E2E peer, it should either warn the user and fall back to plaintext, or refuse to join. This is a client-side UX decision.

### What the server exposes

`ClientInfo` includes `e2e_supported` on `channel_joined`, `client_joined`, and `client_left`:

```json
{
  "type": "client_joined",
  "user_id": 5,
  "client": {
    "id": 5,
    "connection_type": "slave",
    "e2e_supported": true
  }
}
```

`channel_joined` also includes `e2e_available` — a server-level flag (configurable via `[e2e] allow` in `config.toml`, env: `NVDAREMOTE__E2E__ALLOW`) that tells clients whether the server permits E2E at all:

```json
{"type": "channel_joined", "channel": "...", "user_id": 5, "user_ids": [...], "clients": [...], "e2e_available": true}
```

The server does not parse `e2e_pubkey` or `e2e_data` messages — they are unknown types that fall through the relay path with `origin` added, just like `key`, `speak`, etc.

## Client implementation guide

All changes are in the NVDA source tree under `source/_remoteClient/`.

### Step 1: Bump protocol version and add E2E message types

In `protocol.py`:

```python
PROTOCOL_VERSION: int = 3  # Was 2

class RemoteMessageType(StrEnum):
    # ... existing types ...

    # E2E Encryption Messages
    E2E_PUBKEY = "e2e_pubkey"
    E2E_DATA = "e2e_data"
```

The `RelayTransport.onConnected()` in `transport.py` already sends `PROTOCOL_VERSION` with the constant — no changes needed there. The server derives `e2e_supported` from `protocol_version >= 3`.

### Step 2: Create the E2E module

Create `source/_remoteClient/e2e.py` to hold all crypto logic:

```python
"""End-to-end encryption for NVDA Remote.

Uses X25519 key exchange and XChaCha20-Poly1305 authenticated encryption
to protect data-plane messages (keystrokes, speech, braille, clipboard)
from the relay server.

Requires PyNaCl (libsodium Python binding).
"""

import base64
import json
import os
import struct
from typing import Any

from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random as nacl_random
from logHandler import log


class PeerKeyState:
    """Tracks the E2E state for a single peer."""

    __slots__ = ("peer_id", "public_key", "nonce_prefix", "box", "send_counter")

    def __init__(self, peer_id: int, public_key: PublicKey, nonce_prefix: bytes):
        self.peer_id = peer_id
        self.public_key = public_key
        self.nonce_prefix = nonce_prefix
        self.box: Box | None = None  # Set after we derive the shared key
        self.send_counter: int = 0


class E2ESession:
    """Manages E2E encryption for one channel session.

    Usage:
        session = E2ESession()
        # After joining, broadcast your public key:
        pubkey_msg = session.get_pubkey_message()
        transport.send(RemoteMessageType.E2E_PUBKEY, **pubkey_msg)

        # When receiving a peer's pubkey:
        session.add_peer(origin_id, pubkey_b64, nonce_prefix_b64)

        # Encrypt outbound data-plane messages:
        for msg in session.encrypt(RemoteMessageType.KEY, vk_code=65, pressed=True):
            transport.send(RemoteMessageType.E2E_DATA, **msg)

        # Decrypt inbound:
        msg_type, kwargs = session.decrypt(origin_id, ciphertext_b64, nonce_b64)
    """

    def __init__(self) -> None:
        self._private_key = PrivateKey.generate()
        self._public_key = self._private_key.public_key
        self._nonce_prefix = nacl_random(4)  # 4 bytes, unique per session
        self._peers: dict[int, PeerKeyState] = {}

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(bytes(self._public_key)).decode("ascii")

    @property
    def nonce_prefix_b64(self) -> str:
        return base64.b64encode(self._nonce_prefix).decode("ascii")

    def get_pubkey_message(self) -> dict[str, str]:
        """Returns kwargs for transport.send(RemoteMessageType.E2E_PUBKEY, **kwargs)."""
        return {
            "pubkey": self.public_key_b64,
            "nonce_prefix": self.nonce_prefix_b64,
        }

    def add_peer(self, peer_id: int, pubkey_b64: str, nonce_prefix_b64: str) -> None:
        """Process a received e2e_pubkey message from a peer.

        Derives the shared secret and stores the pairwise encryption box.
        """
        peer_pubkey = PublicKey(base64.b64decode(pubkey_b64))
        nonce_prefix = base64.b64decode(nonce_prefix_b64)
        peer = PeerKeyState(peer_id, peer_pubkey, nonce_prefix)
        peer.box = Box(self._private_key, peer_pubkey)
        self._peers[peer_id] = peer
        log.debug(f"E2E: Established pairwise key with peer {peer_id}")

    def remove_peer(self, peer_id: int) -> None:
        """Remove a peer's key state (on disconnect)."""
        self._peers.pop(peer_id, None)

    def has_peer(self, peer_id: int) -> bool:
        return peer_id in self._peers

    @property
    def peer_ids(self) -> list[int]:
        return list(self._peers.keys())

    def _make_nonce(self, peer: PeerKeyState) -> bytes:
        """Build a 24-byte nonce: 4-byte sender prefix + 4-byte zero pad + 8-byte counter.

        XChaCha20-Poly1305 uses 24-byte nonces (vs 12 for regular ChaCha20-Poly1305),
        making random/prefixed nonces safe against collision.
        """
        counter_bytes = struct.pack(">Q", peer.send_counter)
        peer.send_counter += 1
        # 4 (prefix) + 12 (padding + counter) = 24 bytes for XChaCha20-Poly1305
        return self._nonce_prefix + b"\x00" * 12 + counter_bytes

    def encrypt(self, type: str, **kwargs: Any) -> list[dict[str, Any]]:
        """Encrypt a data-plane message for all peers.

        Returns a list of dicts, one per peer, each suitable as kwargs for:
            transport.send(RemoteMessageType.E2E_DATA, **msg)

        The inner plaintext is the original JSON message (with type field).
        """
        plaintext = json.dumps({"type": type, **kwargs}).encode("utf-8")
        messages = []
        for peer in self._peers.values():
            if peer.box is None:
                continue
            nonce = self._make_nonce(peer)
            ciphertext = peer.box.encrypt(plaintext, nonce).ciphertext
            messages.append({
                "to": peer.peer_id,
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
            })
        return messages

    def decrypt(self, origin_id: int, ciphertext_b64: str, nonce_b64: str) -> tuple[str, dict[str, Any]] | None:
        """Decrypt an e2e_data message from a peer.

        Returns (message_type, kwargs) or None if decryption fails.
        """
        peer = self._peers.get(origin_id)
        if peer is None or peer.box is None:
            log.warning(f"E2E: No key for peer {origin_id}, cannot decrypt")
            return None
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            nonce = base64.b64decode(nonce_b64)
            plaintext = peer.box.decrypt(ciphertext, nonce)
            obj = json.loads(plaintext.decode("utf-8"))
            msg_type = obj.pop("type")
            return (msg_type, obj)
        except Exception:
            log.warning(f"E2E: Decryption failed for message from peer {origin_id}", exc_info=True)
            return None

    def get_fingerprint(self, peer_id: int) -> str | None:
        """Compute a verification fingerprint for a pairwise key.

        Both sides get the same fingerprint because we sort the public keys.
        Users compare this out-of-band (phone call, separate chat) to detect MITM.

        Returns a hex string like "a3f2 91d0 e8c4 7b5a" or None if peer unknown.
        """
        peer = self._peers.get(peer_id)
        if peer is None:
            return None
        keys = sorted([bytes(self._public_key), bytes(peer.public_key)])
        # Use BLAKE2b (available in libsodium/PyNaCl) for the fingerprint hash
        import hashlib
        digest = hashlib.blake2b(keys[0] + keys[1], digest_size=8).hexdigest()
        # Format as groups of 4 hex chars: "a3f2 91d0 e8c4 7b5a"
        return " ".join(digest[i:i+4] for i in range(0, len(digest), 4))
```

### Step 3: Integrate into the transport layer

In `transport.py`, modify `TCPTransport.parse()` to handle E2E decryption, and modify `send()` to handle E2E encryption.

The cleanest approach is to add E2E as a layer inside the session, not the transport. The transport stays unchanged — it already relays any `RemoteMessageType`. The session intercepts at the handler level.

In `session.py`, the `RemoteSession` base class is where to hook E2E:

```python
from ._remoteClient.e2e import E2ESession
from ._remoteClient.protocol import RemoteMessageType

class RemoteSession:
    def __init__(self, transport, localMachine):
        # ... existing init ...
        self.e2e: E2ESession | None = None
        self._e2eAvailable: bool = False  # Server-level flag from channel_joined

        # Register E2E message handlers
        transport.registerInbound(RemoteMessageType.E2E_PUBKEY, self._handleE2EPubkey)
        transport.registerInbound(RemoteMessageType.E2E_DATA, self._handleE2EData)
        transport.registerInbound(RemoteMessageType.CHANNEL_JOINED, self._handleChannelJoined)
        transport.registerInbound(RemoteMessageType.CLIENT_JOINED, self._handleClientJoined)
        transport.registerInbound(RemoteMessageType.CLIENT_LEFT, self._handleClientLeft)

    def _canDoE2E(self, clients: list[dict]) -> bool:
        """Check if E2E is possible: server allows it and all peers support it."""
        if not self._e2eAvailable:
            return False
        return all(c.get("e2e_supported") for c in clients) if clients else True

    def _handleChannelJoined(self, channel, user_id, user_ids, clients,
                              e2e_available=False, **kwargs):
        """After joining, init E2E if the server allows it and all peers support it."""
        self._e2eAvailable = e2e_available
        if self._canDoE2E(clients):
            self.e2e = E2ESession()
            self.transport.send(RemoteMessageType.E2E_PUBKEY, **self.e2e.get_pubkey_message())
        else:
            self.e2e = None
        # Existing channel_joined handling continues...

    def _handleClientJoined(self, user_id, client, **kwargs):
        """When a new peer joins, check if E2E is still possible."""
        if not client.get("e2e_supported"):
            # Non-E2E peer joined — tear down E2E, warn user
            if self.e2e is not None:
                log.warning("E2E disabled: peer %d does not support encryption", user_id)
                self.e2e = None
                # TODO: warn user via UI
        elif self.e2e is not None:
            # E2E peer joined — send them our pubkey
            self.transport.send(RemoteMessageType.E2E_PUBKEY, **self.e2e.get_pubkey_message())

    def _handleClientLeft(self, user_id, client, **kwargs):
        """Remove peer's key state on disconnect."""
        if self.e2e is not None:
            self.e2e.remove_peer(user_id)

    def _handleE2EPubkey(self, pubkey, nonce_prefix, origin, **kwargs):
        """Process a peer's public key and derive the shared secret."""
        if self.e2e is not None:
            self.e2e.add_peer(origin, pubkey, nonce_prefix)

    def _handleE2EData(self, ciphertext, nonce, origin, to, **kwargs):
        """Decrypt an E2E message and dispatch the inner message."""
        if self.e2e is None:
            return
        if to != self.myUserId:
            return  # Not addressed to us
        result = self.e2e.decrypt(origin, ciphertext, nonce)
        if result is None:
            return
        msg_type, msg_kwargs = result
        # Dispatch the decrypted message through the normal handler path
        messageType = RemoteMessageType(msg_type)
        extensionPoint = self.transport.inboundHandlers.get(messageType)
        if extensionPoint:
            extensionPoint.notify(**msg_kwargs)
```

### Step 4: Encrypt outbound data-plane messages

Modify the `send()` calls for data-plane messages to go through E2E when available. The outbound extension points in `session.py` (`LeaderSession` / `FollowerSession`) call `transport.send()` directly. Wrap these:

```python
class RemoteSession:
    # ...

    def sendEncrypted(self, type: RemoteMessageType, **kwargs):
        """Send a message, encrypting it for all E2E peers.

        Only called when E2E is active (all peers are v3 and e2e_available is true).
        If E2E is not active, callers use self.transport.send() directly.
        """
        if self.e2e is not None and self.e2e.peer_ids:
            for msg in self.e2e.encrypt(type.value, **kwargs):
                self.transport.send(RemoteMessageType.E2E_DATA, **msg)
        else:
            # No E2E peers yet (before key exchange completes) — send plaintext
            self.transport.send(type, **kwargs)
```

Since E2E is all-or-nothing, there is no mixed mode. Either all peers support E2E and everything is encrypted, or E2E is not used and everything is plaintext. No duplicate suppression needed.

Then replace `self.transport.send(RemoteMessageType.KEY, ...)` with `self.sendEncrypted(RemoteMessageType.KEY, ...)` for all data-plane message types:

- `KEY`, `SPEAK`, `CANCEL`, `PAUSE_SPEECH`, `TONE`, `WAVE`, `SEND_SAS`
- `DISPLAY`, `BRAILLE_INPUT`, `SET_BRAILLE_INFO`, `SET_DISPLAY_SIZE`
- `SET_CLIPBOARD_TEXT`

Control-plane messages (`PROTOCOL_VERSION`, `JOIN`, `GENERATE_KEY`) stay as plain `transport.send()`.

### Step 5: Track own user_id

The session needs to know its own `user_id` to filter `e2e_data` messages addressed to it. Capture this from the `channel_joined` response — the server assigns IDs and the client's own ID is not in `user_ids` (those are *existing* members). The client's own ID is available from the server's assignment; you need to track it. One approach: the server could include `your_id` in `channel_joined`, or the client can infer it from the `client_joined` notification that others receive. The simplest approach is to add a field to the server's `channel_joined` response:

**Alternative (no server change)**: Use the `origin` field on your own relayed messages. When you receive a `client_joined` about yourself, your `user_id` is there. Actually, you don't receive your own `client_joined` — others do.

**Recommended approach**: The client already gets `user_ids` (list of existing member IDs) in `channel_joined`. The server should also send the client's own assigned ID. This requires a small server change — add `user_id` to `ChannelJoined`:

```json
{"type": "channel_joined", "channel": "...", "user_id": 5, "user_ids": [1, 2], "clients": [...]}
```

See "Server addition" section below.

### Step 6: Fingerprint verification UI

Add a dialog or NVDA message that shows the fingerprint for each E2E peer:

```python
fingerprint = self.e2e.get_fingerprint(peer_id)
# Display via NVDA speech/UI:
# "Security fingerprint for peer 5: alpha 3 foxtrot 2 nine 1 delta 0"
```

Users compare fingerprints out-of-band (phone, separate chat). If they match, no MITM. Optionally implement trust-on-first-use (TOFU): store the fingerprint and warn if it changes.

## Server changes summary (already implemented)

### `e2e_supported` derived from protocol version

The server derives `e2e_supported = protocol_version >= 3` for each client. No extra fields in `join` — the version number is sufficient. This keeps `join` backward compatible and makes E2E a protocol-level capability, not a per-message opt-in.

### `channel_joined` includes new fields

```json
{
  "type": "channel_joined",
  "channel": "123456789",
  "user_id": 5,
  "user_ids": [1, 2],
  "clients": [{"id": 1, "connection_type": "master", "e2e_supported": true}],
  "e2e_available": true
}
```

- **`user_id`**: The client's own assigned ID — needed so it can filter `e2e_data` messages addressed to it via the `to` field.
- **`e2e_available`**: Server-level flag (configurable via `[e2e] allow` in `config.toml`, env: `NVDAREMOTE__E2E__ALLOW`). When `false`, clients should not initiate E2E. The NVDA direct-connection server (`server.py`) should set this to `false` (or omit it — clients should default to `false`).

### Protocol version semantics

- **v1**: bare protocol
- **v2**: adds `origin`, `client`, `clients` fields (server strips these for v1 clients)
- **v3**: adds E2E capability. `e2e_supported: true` in `ClientInfo`. Extensible for future capabilities without another version bump.

## Mixed-version channels

E2E is all-or-nothing. There is no mixed encrypted/plaintext mode — if one peer can't encrypt, the server sees everything anyway, defeating the purpose.

When a v3 client joins a channel and sees any peer with `e2e_supported: false`, it must **not** initiate E2E. The client should:

1. **Warn the user**: "Peer X does not support encryption. This session will not be encrypted."
2. **Fall back to plaintext**: Send all messages unencrypted, same as v2.
3. **Optionally refuse**: If the user requires encryption, disconnect or reject the session.

When a v2 client joins a channel where v3 clients already have E2E active:
- The v3 clients receive `client_joined` with `e2e_supported: false`
- They should **tear down E2E** and warn the user that encryption is no longer possible
- All subsequent messages are plaintext

This is a client-side policy decision. The server just reports `e2e_supported` per client — it doesn't enforce E2E.

## Security properties

### Protected
- All data-plane content (keystrokes, speech, braille, clipboard) between E2E peers
- Forward secrecy (ephemeral keys per session)
- **Sender authenticity via pairwise keys**: each peer pair has a unique shared secret. If the server lies about the `origin` field on the outer `e2e_data` envelope, decryption fails because the receiver would use the wrong pairwise key and AEAD authentication rejects the ciphertext. This means a passive or semi-active server cannot forge sender identity.

### The `origin` field and server trust

The relay server adds an `origin` field to all relayed messages (including `e2e_data`). This `origin` is **untrusted metadata** — it's set by the server, not the sender. In our design:

- The **outer** `origin` on `e2e_data` is used only for pairwise key lookup (which peer's key to use for decryption).
- If the server sets a wrong `origin`, the receiver uses the wrong key → AEAD decryption fails → message is rejected. The server cannot trick a client into accepting a forged message.
- In a **full MITM** scenario (server substituted keys during exchange), the server has its own pairwise keys with each client and can set `origin` correctly for its fake sessions. This is detectable only via fingerprint verification.

**Recommendation for clients**: include the sender's `user_id` inside the encrypted payload as an additional authenticity check. The receiver can then verify that the decrypted sender ID matches the outer `origin`. This is defense-in-depth — the pairwise AEAD already prevents forgery, but the inner ID makes the authentication explicit and auditable. Example:

```json
// Inside the encrypted plaintext:
{"type": "key", "vk_code": 65, "pressed": true, "_from": 5}
```

The `_from` field is set by the sender before encryption. The receiver checks `_from == origin` after decryption. A mismatch indicates tampering.

### Not protected
- **Metadata**: server sees who is in which channel, timing, message sizes
- **Control plane**: `join`, `protocol_version`, `generate_key` stay cleartext
- **MITM**: a malicious server can swap pubkeys during exchange — detectable only via fingerprint verification

## Design compromises vs Signal protocol

This E2E design is intentionally simpler than the Signal protocol. The table below documents every deliberate compromise, why it's acceptable for NVDA Remote, and what it would cost to close the gap.

### Comparison at a glance

| Property | Signal | NVDA Remote E2E | Gap acceptable? |
|----------|--------|-----------------|-----------------|
| Key exchange | X3DH (triple DH with identity keys, signed prekeys, one-time prekeys) | Single ephemeral X25519 DH | Yes — see below |
| Message encryption | Double Ratchet (DH ratchet + symmetric ratchet) | Static session key + counter nonce | Yes — see below |
| Forward secrecy | Per-message | Per-session | Yes — see below |
| Offline messaging | Prekey bundles allow E2E before peer is online | Not supported — both peers must be online | Yes — see below |
| Identity persistence | Long-term identity keys stored across sessions | None — ephemeral only | Acceptable — see below |
| Group messaging | Sender Keys with group ratchet | Pairwise keys (O(n^2)) | Yes — see below |
| Post-compromise security | Double Ratchet self-heals after key compromise | No self-healing within a session | Acceptable — see below |

### Detailed rationale for each compromise

#### 1. No X3DH — single DH instead

**What Signal does**: X3DH uses three DH operations combining a long-term identity key, a medium-term signed prekey, and one-time prekeys. This provides authentication (you know who you're talking to), offline initiation (start E2E without the peer being online), and forward secrecy even for the first message.

**What we do**: A single ephemeral X25519 DH exchange after both clients join the channel.

**Why this is fine**: NVDA Remote is a real-time relay. Both clients are always online when communicating — there is no "send a message and the other person reads it later" use case. The identity key problem (knowing *who* you're talking to) is handled out-of-band via fingerprint verification, which is the same trust model Signal falls back to anyway (safety numbers). X3DH's prekey server infrastructure would add significant complexity for zero benefit.

**Cost to close the gap**: Would require a key server, persistent identity keys on each NVDA installation, and a signed prekey rotation scheme. Not worth it for a real-time relay.

#### 2. No Double Ratchet — static session key

**What Signal does**: The Double Ratchet advances the encryption key after every message using both a DH ratchet (new DH exchange periodically) and a symmetric ratchet (hash chain). This means each message has a unique key, and compromising one key doesn't reveal other messages.

**What we do**: One DH exchange per session produces a static key. All messages in the session use that key with an incrementing nonce.

**Why this is fine**: NVDA Remote sessions are short-lived (minutes to hours of screen reader use). The threat model is protecting against a passive server operator logging traffic — not against an attacker who somehow extracts the session key from a client's memory mid-session. If an attacker can read process memory, they can read the screen reader output directly. The session key lives only in RAM and is discarded on disconnect.

**Cost to close the gap**: Moderate. Adding a symmetric ratchet (hash the key forward after each message) would give per-message forward secrecy without much complexity. Adding a full DH ratchet would require periodic new DH exchanges mid-session, adding round trips and latency. The symmetric-only ratchet is a reasonable middle ground if this compromise becomes unacceptable later.

#### 3. Per-session forward secrecy, not per-message

**What Signal provides**: If an attacker records ciphertext and later compromises a message key, they can only decrypt that one message. Past and future messages use different keys.

**What we provide**: If an attacker records ciphertext and later compromises the session key, they can decrypt all messages from that session. But the next session uses a completely new ephemeral keypair — past sessions are safe.

**Why this is fine**: The attack scenario — "record encrypted traffic now, steal the session key later" — requires the attacker to (a) have access to the encrypted traffic (they're the server operator, so yes), and (b) later compromise the client machine's memory to extract the key. But if they compromise the client machine, they have access to everything NVDA can see anyway. The session key is never written to disk and is gone after disconnect.

**Future improvement path**: A symmetric ratchet (`key = HKDF(key, "ratchet")` after each message, discard old key) would close this gap with minimal added complexity and no extra network traffic. This could be added later without protocol changes — it's purely a client-side enhancement.

#### 4. No offline messaging support

**What Signal provides**: You can send a message to someone who is offline. The server stores the ciphertext, and the recipient decrypts it when they come online. Prekey bundles make this possible without ever having been online at the same time.

**What we do**: Both clients must be connected to the relay server simultaneously. No message storage.

**Why this is fine**: NVDA Remote is a real-time screen reader relay. There is no meaningful "offline message" — a keystroke or speech event only makes sense in real-time. If the peer is offline, there's nothing to relay. The server is stateless by design and stores nothing.

**Cost to close the gap**: Would require server-side message storage, prekey bundles, and identity management. Fundamentally changes the relay architecture for no practical benefit.

#### 5. No persistent identity keys

**What Signal provides**: Each device has a long-term identity key that persists across sessions. This allows trust continuity — if you verified a safety number once, it stays valid until the other person changes devices.

**What we do**: Ephemeral keys only. Each session generates a new keypair. Fingerprints change every session.

**Why this is fine for now**: NVDA Remote users typically connect to the same small set of people. Verifying a fingerprint each session is a minor inconvenience for 2-4 person channels. The alternative (persistent identity keys) would require secure key storage on each NVDA installation, key backup/restore mechanisms, and key change notifications — significant complexity.

**Future improvement path**: Implement trust-on-first-use (TOFU) — store the peer's public key after first verification and warn if it changes. This gives Signal-like trust continuity without the full identity key infrastructure. The NVDA config system (`configuration.py`) already stores trusted TLS certificate fingerprints, so the pattern exists.

#### 6. Pairwise keys instead of group protocol

**What Signal provides**: The Sender Keys protocol allows a sender to encrypt once for the whole group rather than once per recipient.

**What we do**: Pairwise keys — for N peers, each client maintains N-1 keys and sends N-1 encrypted copies of each message.

**Why this is fine**: NVDA Remote channels have 2-4 clients. With 4 clients, each message produces 3 encrypted copies — trivial overhead. The pairwise approach is far simpler, has no single-point-of-failure group key, and naturally handles joins/leaves without rekeying.

**When this would matter**: Only if channels grew to 10+ members, where O(n) encrypted copies per message would add noticeable bandwidth. This is not an expected use case for screen reader relay.

#### 7. No post-compromise security (self-healing)

**What Signal provides**: The Double Ratchet's DH ratchet means that even if an attacker compromises the current state, future messages become secure again after a new DH exchange "heals" the chain.

**What we do**: If the session key is compromised, all remaining messages in that session are exposed. Security is restored only by starting a new session (reconnecting).

**Why this is fine**: Same reasoning as #3 — compromising the session key requires access to the client's process memory, at which point the attacker can already read everything NVDA displays. Reconnecting (which generates new keys) is the natural recovery action after any suspected compromise.

### Summary

These compromises are acceptable because NVDA Remote is:
- **Real-time only** — no offline messaging, no stored messages
- **Short sessions** — minutes to hours, not weeks
- **Small groups** — 2-4 clients, not hundreds
- **Same trust boundary** — if you compromise the client, you have everything anyway

The design protects against the primary threat: **an honest-but-curious server operator logging relay traffic**. For that threat, single-DH with ephemeral keys and authenticated encryption is sufficient and well-understood.

If stronger guarantees are needed later, the most impactful upgrade would be adding a **symmetric ratchet** (client-side only change, no protocol change) to get per-message forward secrecy.

## Dependency

Add `PyNaCl` to NVDA's dependencies. PyNaCl bundles libsodium as a compiled binary, so it works on Windows without extra setup:

```
pip install pynacl
```

PyNaCl is well-maintained, widely used (by Paramiko, Matrix, etc.), and provides constant-time operations needed for crypto.

## Example message flow

```
Client A (master, v3)              Server (relay)             Client B (slave, v3)
─────────────────────              ──────────────             ────────────────────
protocol_version(3) ──────→
join("room","master") ────→
                     ←────── channel_joined(e2e_available=true, peers=[])
                                                             protocol_version(3) ──────→
                                                             join("room","slave") ─────→
                     ←── client_joined(id=2,e2e=true)        ←── channel_joined(peers=[{id=1,e2e=true}])

e2e_pubkey(pk_a,np_a) ───→ relay with origin=1 ──────────→  add_peer(1, pk_a, np_a)
                     ←──────────── relay with origin=2 ←──── e2e_pubkey(pk_b,np_b)
add_peer(2, pk_b, np_b)

[Both now have pairwise Box(private_self, public_peer)]

e2e_data(to=2,ct,n) ─────→ relay (opaque blob) ──────────→  decrypt → {"type":"key","vk_code":65}
                     ←────────────── relay (opaque) ←──────  e2e_data(to=1,ct,n)
decrypt → {"type":"speak",...}                               encrypt(speak, sequence=[...])
```
