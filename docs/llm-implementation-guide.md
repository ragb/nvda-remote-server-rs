# LLM Implementation Guide: E2E Encryption for NVDA Remote Client

This document provides complete instructions for an LLM (or developer) to implement end-to-end encryption in the NVDA Remote client. The server side is already implemented and deployed. Read this entire document before writing any code.

## Context

NVDA Remote relays keystrokes, speech, braille, and clipboard data between NVDA instances through a relay server. Currently the server can read all traffic. This task adds E2E encryption so the server only sees opaque ciphertext.

**Related NVDA issue**: https://github.com/nvaccess/nvda/issues/17784 — read the issue and all comments before implementing. Key points from the discussion:

- **tech10** raised that the `origin` field (injected by the server) should not be trusted for authentication since E2E means the server shouldn't be able to modify message content. Our design handles this: pairwise AEAD keys mean a wrong `origin` causes decryption failure. As defense-in-depth, include the sender's `user_id` inside the encrypted payload (`_from` field) so the receiver can verify `_from == origin`.
- **SaschaCowley** (assignee, NV Access) noted that protocol documentation is required and that `origin` as metadata doesn't need encryption but may need HMAC-like authenticity — our pairwise AEAD provides this implicitly.
- The issue is milestoned for **2027.1** and assigned to SaschaCowley. Coordinate with NV Access before submitting a PR.

The relay server (Rust) already supports:
- Protocol v3: clients sending `protocol_version: 3` are marked `e2e_supported: true` in `ClientInfo`
- `channel_joined` includes `user_id` (client's own ID) and `e2e_available` (server config flag)
- `e2e_pubkey` and `e2e_data` message types relay opaquely through the existing path
- Configurable `[e2e] allow` in server config

**Your job is the Python client side only.** The NVDA source is at `source/_remoteClient/`.

## Codebase orientation

Read these files carefully before making changes:

### Files you MUST read first
- `source/_remoteClient/protocol.py` — `PROTOCOL_VERSION = 2`, `RemoteMessageType` enum, `SERVER_PORT`
- `source/_remoteClient/transport.py` — `Transport` (abstract), `TCPTransport` (SSL sockets, read loop, message queue), `RelayTransport` (extends TCP, sends protocol_version + join on connect)
- `source/_remoteClient/serializer.py` — `JSONSerializer`, line-delimited JSON, speech command encoding
- `source/_remoteClient/session.py` — `RemoteSession` (base), `FollowerSession`, `LeaderSession`. This is where message handlers are registered and data-plane messages are sent.
- `source/_remoteClient/client.py` — `RemoteClient` orchestrator. `processKeyInput()` at line ~532 sends `KEY` messages via `self.leaderTransport.send()`.
- `source/_remoteClient/server.py` — The NVDA direct-connection server (NOT the relay). Its `channel_joined` response needs updating.

### Architecture you must understand

```
RemoteClient (client.py)
  ├── LeaderSession (session.py) — controlling side
  │   ├── registers inbound handlers: SPEAK, CANCEL, PAUSE_SPEECH, TONE, WAVE, DISPLAY, etc.
  │   ├── sends: KEY (via client.py processKeyInput), BRAILLE_INPUT, SET_BRAILLE_INFO, SET_CLIPBOARD_TEXT
  │   └── uses: self.transport.send(RemoteMessageType.X, **kwargs)
  │
  └── FollowerSession (session.py) — controlled side
      ├── registers inbound handlers: KEY, BRAILLE_INPUT, SEND_SAS, SET_BRAILLE_INFO, SET_DISPLAY_SIZE
      ├── sends: SPEAK, CANCEL, PAUSE_SPEECH, TONE, WAVE, DISPLAY, SET_CLIPBOARD_TEXT
      └── outbound via: self.transport.send() and self.transport.registerOutbound() extension points
```

**Message flow**: `transport.send()` → `serializer.serialize()` → JSON bytes + `\n` → socket queue → server relay → other client's `processIncomingSocketData()` → `parse()` → `RemoteMessageType` lookup → `wx.CallAfter(handler, **kwargs)`

**Threading model**: Socket I/O on background threads. All inbound message handlers execute on the wx main thread via `wx.CallAfter()`. This is important — your E2E handlers will also run on the main thread.

## Design rules

1. **All-or-nothing E2E.** If any peer in the channel doesn't support E2E, the entire channel falls back to plaintext. No mixed mode.
2. **E2E only on relay connections.** Direct connections (`server.py`) are already point-to-point TLS. The direct server must advertise `e2e_available: false`.
3. **Server is a dumb relay.** It doesn't parse `e2e_pubkey` or `e2e_data`. It adds `origin` and forwards. All crypto is client-side.
4. **Protocol v3 = E2E capability.** Derived from `protocol_version >= 3` on the server. The client bumps `PROTOCOL_VERSION` to 3.

## Implementation steps

### Step 1: Add PyNaCl dependency

Add `PyNaCl` to NVDA's dependencies (requirements file or build system). PyNaCl bundles libsodium as a compiled binary, works on Windows without extra setup.

```
PyNaCl>=1.5.0
```

### Step 2: Bump protocol version and add message types

**File: `source/_remoteClient/protocol.py`**

```python
PROTOCOL_VERSION: int = 3  # Was 2
```

Add to `RemoteMessageType`:

```python
class RemoteMessageType(StrEnum):
    # ... all existing types stay ...

    # E2E Encryption Messages (protocol v3)
    E2E_PUBKEY = "e2e_pubkey"
    E2E_DATA = "e2e_data"
```

**No other changes to protocol.py.** The `RelayTransport.onConnected()` in `transport.py` already sends `PROTOCOL_VERSION` from the constant, so it will automatically send 3.

### Step 3: Create the E2E crypto module

**Create new file: `source/_remoteClient/e2e.py`**

This module handles all cryptographic operations. It must be self-contained — no NVDA-specific imports except `logHandler`.

```python
"""End-to-end encryption for NVDA Remote.

Uses X25519 key exchange and XChaCha20-Poly1305 authenticated encryption
to protect data-plane messages from the relay server.

Requires PyNaCl (libsodium Python binding).
"""

import base64
import json
import struct
from typing import Any

from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random as nacl_random
from logHandler import log
import hashlib


class PeerKeyState:
    """Tracks the E2E state for a single peer."""

    __slots__ = ("peer_id", "public_key", "nonce_prefix", "box", "send_counter")

    def __init__(self, peer_id: int, public_key: PublicKey, nonce_prefix: bytes):
        self.peer_id = peer_id
        self.public_key = public_key
        self.nonce_prefix = nonce_prefix
        self.box: Box | None = None
        self.send_counter: int = 0


class E2ESession:
    """Manages E2E encryption for one channel session.

    Lifecycle:
    1. Created when channel_joined arrives with e2e_available=True and all peers e2e_supported
    2. Broadcasts public key via e2e_pubkey message
    3. Receives peer pubkeys, derives pairwise shared secrets
    4. Encrypts all outbound data-plane messages
    5. Decrypts all inbound e2e_data messages
    6. Destroyed on disconnect or when a non-E2E peer joins
    """

    def __init__(self) -> None:
        self._private_key = PrivateKey.generate()
        self._public_key = self._private_key.public_key
        self._nonce_prefix = nacl_random(4)
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
        """Process a received e2e_pubkey message from a peer."""
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
        """Build a 24-byte nonce for XChaCha20-Poly1305."""
        counter_bytes = struct.pack(">Q", peer.send_counter)
        peer.send_counter += 1
        return self._nonce_prefix + b"\x00" * 12 + counter_bytes

    def encrypt(self, type: str, **kwargs: Any) -> list[dict[str, Any]]:
        """Encrypt a data-plane message for all peers.

        Returns a list of dicts, one per peer, each suitable as kwargs for:
            transport.send(RemoteMessageType.E2E_DATA, **msg)
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

    def decrypt(
        self, origin_id: int, ciphertext_b64: str, nonce_b64: str
    ) -> tuple[str, dict[str, Any]] | None:
        """Decrypt an e2e_data message. Returns (message_type, kwargs) or None."""
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
            log.warning(
                f"E2E: Decryption failed for message from peer {origin_id}",
                exc_info=True,
            )
            return None

    def get_fingerprint(self, peer_id: int) -> str | None:
        """Compute a verification fingerprint for MITM detection.

        Both sides compute the same fingerprint (keys are sorted).
        Returns hex string like "a3f2 91d0 e8c4 7b5a" or None.
        """
        peer = self._peers.get(peer_id)
        if peer is None:
            return None
        keys = sorted([bytes(self._public_key), bytes(peer.public_key)])
        digest = hashlib.blake2b(keys[0] + keys[1], digest_size=8).hexdigest()
        return " ".join(digest[i : i + 4] for i in range(0, len(digest), 4))
```

### Step 4: Integrate E2E into sessions

**File: `source/_remoteClient/session.py`**

This is the most complex step. You need to:

1. Add E2E state and handlers to `RemoteSession` (base class)
2. Add a `sendEncrypted()` method that wraps `transport.send()`
3. Change all data-plane sends to use `sendEncrypted()`
4. Intercept inbound `e2e_data` and dispatch decrypted messages

#### 4a: Add to `RemoteSession.__init__()`

Add these instance variables and handler registrations. **Be careful not to conflict with existing handler registrations** — `CHANNEL_JOINED` and `CLIENT_JOINED`/`CLIENT_LEFT` are already registered in the subclasses (`LeaderSession.handleChannelJoined`, `FollowerSession.handleChannelJoined`, `RemoteSession.handleClientConnected`, `RemoteSession.handleClientDisconnected`). You must integrate E2E logic into the existing handlers, not register competing ones.

```python
from .e2e import E2ESession

class RemoteSession:
    def __init__(self, localMachine, transport):
        # ... existing init code stays ...
        self.e2e: E2ESession | None = None
        self._e2eAvailable: bool = False
        self._myUserId: int | None = None
        self._peerE2ESupport: dict[int, bool] = {}  # Track peer capabilities

        # Register E2E-specific message handlers
        self.transport.registerInbound(RemoteMessageType.E2E_PUBKEY, self._handleE2EPubkey)
        self.transport.registerInbound(RemoteMessageType.E2E_DATA, self._handleE2EData)
```

#### 4b: Modify existing `handleChannelJoined` in both subclasses

Both `LeaderSession.handleChannelJoined()` and `FollowerSession.handleChannelJoined()` need to be updated. They currently look like:

```python
# Current (both subclasses have similar code):
def handleChannelJoined(self, channel, clients=None, origin=None):
    if clients is None:
        clients = []
    for client in clients:
        self.handleClientConnected(client)
```

**Change to** (in both `LeaderSession` and `FollowerSession`):

```python
def handleChannelJoined(self, channel, clients=None, origin=None,
                         user_id=None, e2e_available=False, **kwargs):
    if clients is None:
        clients = []
    # Store own user_id and E2E server flag
    self._myUserId = user_id
    self._e2eAvailable = e2e_available
    # Track peer E2E support
    for client in clients:
        self._peerE2ESupport[client["id"]] = client.get("e2e_supported", False)
        self.handleClientConnected(client)
    # Init E2E if server allows it and all existing peers support it
    self._tryInitE2E()
```

#### 4c: Modify existing `handleClientConnected` and `handleClientDisconnected`

In `RemoteSession.handleClientConnected()`:

```python
def handleClientConnected(self, client: dict[str, Any] | None) -> None:
    log.info(f"Client connected: {client!r}")
    cues.clientConnected()
    if client is not None:
        self._peerE2ESupport[client["id"]] = client.get("e2e_supported", False)
        if not client.get("e2e_supported", False) and self.e2e is not None:
            # Non-E2E peer joined — tear down E2E
            log.warning("E2E disabled: peer %d does not support encryption", client["id"])
            self.e2e = None
            # TODO: warn user via ui.message()
        elif client.get("e2e_supported", False) and self.e2e is not None:
            # E2E peer joined — send them our pubkey
            self.transport.send(RemoteMessageType.E2E_PUBKEY, **self.e2e.get_pubkey_message())
```

In `RemoteSession.handleClientDisconnected()`:

```python
def handleClientDisconnected(self, client: dict[str, Any] | None = None) -> None:
    cues.clientDisconnected()
    if client is not None:
        self._peerE2ESupport.pop(client.get("id"), None)
        if self.e2e is not None:
            self.e2e.remove_peer(client.get("id", 0))
```

#### 4d: Add E2E helper methods to `RemoteSession`

```python
def _tryInitE2E(self) -> None:
    """Init E2E if conditions are met: server allows it and all peers support it."""
    if not self._e2eAvailable:
        self.e2e = None
        return
    all_peers_e2e = all(self._peerE2ESupport.values()) if self._peerE2ESupport else True
    if all_peers_e2e:
        self.e2e = E2ESession()
        self.transport.send(RemoteMessageType.E2E_PUBKEY, **self.e2e.get_pubkey_message())
    else:
        self.e2e = None

def _handleE2EPubkey(self, pubkey, nonce_prefix, origin, **kwargs):
    """Process a peer's public key and derive shared secret."""
    if self.e2e is not None:
        self.e2e.add_peer(origin, pubkey, nonce_prefix)

def _handleE2EData(self, ciphertext, nonce, origin, to, **kwargs):
    """Decrypt an E2E message and dispatch the inner message."""
    if self.e2e is None:
        return
    if self._myUserId is not None and to != self._myUserId:
        return  # Not addressed to us
    result = self.e2e.decrypt(origin, ciphertext, nonce)
    if result is None:
        return
    msg_type, msg_kwargs = result
    try:
        messageType = RemoteMessageType(msg_type)
    except ValueError:
        log.warning(f"E2E: Unknown decrypted message type: {msg_type}")
        return
    extensionPoint = self.transport.inboundHandlers.get(messageType)
    if extensionPoint:
        extensionPoint.notify(**msg_kwargs)

def sendEncrypted(self, type: RemoteMessageType, **kwargs):
    """Send a message, encrypting it if E2E is active."""
    if self.e2e is not None and self.e2e.peer_ids:
        for msg in self.e2e.encrypt(type.value, **kwargs):
            self.transport.send(RemoteMessageType.E2E_DATA, **msg)
    else:
        self.transport.send(type, **kwargs)
```

### Step 5: Route data-plane messages through `sendEncrypted`

This is the most tedious but straightforward step. Every place that sends a data-plane message via `transport.send()` must be changed to `sendEncrypted()`.

**IMPORTANT**: The session object needs to be accessible where messages are sent. For most sends this is already the case since they're in session methods. For `client.py`'s `processKeyInput`, the transport is accessed directly — this needs to be routed through the session instead.

#### In `FollowerSession` (session.py):

| Method | Current code | Change to |
|--------|-------------|-----------|
| `sendSpeech()` | `self.transport.send(RemoteMessageType.SPEAK, ...)` | `self.sendEncrypted(RemoteMessageType.SPEAK, ...)` |
| `pauseSpeech()` | `self.transport.send(type=RemoteMessageType.PAUSE_SPEECH, ...)` | `self.sendEncrypted(RemoteMessageType.PAUSE_SPEECH, ...)` |
| `display()` | `self.transport.send(type=RemoteMessageType.DISPLAY, ...)` | `self.sendEncrypted(RemoteMessageType.DISPLAY, ...)` |

Also, `FollowerSession` uses `self.transport.registerOutbound()` to bridge extension points to message types (for `TONE`, `CANCEL`, `WAVE`, `PAUSE_SPEECH`). These go through `RemoteExtensionPoint.remoteBridge()` → `self.transport.send()`. You need to modify `RemoteExtensionPoint` to use `sendEncrypted` when E2E is active, or change the approach to register handlers that call `sendEncrypted` directly.

**Recommended approach for outbound extension points**: Instead of modifying `RemoteExtensionPoint`, replace the `registerOutbound` calls with explicit handler methods that call `self.sendEncrypted()`:

```python
# Instead of:
self.transport.registerOutbound(tones.decide_beep, RemoteMessageType.TONE)

# Use:
def _handleToneOutbound(self, *args, **kwargs):
    self.sendEncrypted(RemoteMessageType.TONE, **kwargs)
    return True

tones.decide_beep.register(self._handleToneOutbound)
```

Apply the same pattern for `CANCEL`, `WAVE`, `PAUSE_SPEECH`.

#### In `LeaderSession` (session.py):

| Method | Current code | Change to |
|--------|-------------|-----------|
| `sendBrailleInfo()` | `self.transport.send(type=RemoteMessageType.SET_BRAILLE_INFO, ...)` | `self.sendEncrypted(RemoteMessageType.SET_BRAILLE_INFO, ...)` |
| `handleDecideExecuteGesture()` | `self.transport.send(type=RemoteMessageType.BRAILLE_INPUT, ...)` | `self.sendEncrypted(RemoteMessageType.BRAILLE_INPUT, ...)` |

#### In `RemoteSession` base (session.py):

The `SET_CLIPBOARD_TEXT` handler is registered as inbound in `RemoteSession.__init__()`:
```python
self.transport.registerInbound(RemoteMessageType.SET_CLIPBOARD_TEXT, self.localMachine.setClipboardText)
```
This is for *receiving* clipboard — no change needed for inbound. But *sending* clipboard also goes through `transport.send()`. Search for all `SET_CLIPBOARD_TEXT` sends.

#### In `client.py`:

`processKeyInput()` at line ~579 sends `KEY` via `self.leaderTransport.send()`. Change this to go through the session:

```python
# Current:
self.leaderTransport.send(
    RemoteMessageType.KEY,
    vk_code=vkCode,
    extended=extended,
    pressed=pressed,
    scan_code=scanCode,
)

# Change to:
self.leaderSession.sendEncrypted(
    RemoteMessageType.KEY,
    vk_code=vkCode,
    extended=extended,
    pressed=pressed,
    scan_code=scanCode,
)
```

### Step 6: Update the direct-connection server

**File: `source/_remoteClient/server.py`**

The direct server's `channel_joined` response (around line 522) must include `e2e_available: false` so v3 clients connecting directly don't try to start E2E:

```python
# Current:
self.send(
    type=RemoteMessageType.CHANNEL_JOINED,
    channel=self.server.password,
    user_ids=clientIds,
    clients=clients,
)

# Change to:
self.send(
    type=RemoteMessageType.CHANNEL_JOINED,
    channel=self.server.password,
    user_ids=clientIds,
    clients=clients,
    user_id=self.id,        # Client's own ID
    e2e_available=False,     # Direct connections don't need E2E
)
```

Also ensure each client in the `clients` list includes `e2e_supported: false` (or just let it be absent — the client defaults to `false`).

### Step 7: Fingerprint verification UI

Add a way for users to verify the E2E fingerprint. This prevents MITM attacks by the server.

**Suggested approach**: Add a gesture/script that speaks the fingerprint for each connected E2E peer:

```python
# In client.py or session.py:
def announceE2EFingerprints(self):
    """Speak E2E verification fingerprints for all peers."""
    if self.e2e is None:
        ui.message(pgettext("remote", "End-to-end encryption is not active"))
        return
    for peer_id in self.e2e.peer_ids:
        fp = self.e2e.get_fingerprint(peer_id)
        if fp:
            # Translators: Spoken when announcing E2E fingerprint for a peer.
            # {peer_id} is the numeric ID, {fingerprint} is the hex fingerprint.
            ui.message(pgettext("remote",
                f"Peer {peer_id} fingerprint: {fp}"))
```

Both users compare fingerprints out-of-band (phone call, separate chat). If they match, no MITM.

**Optional TOFU**: Store fingerprints in `configuration.py` (similar pattern to `trustedCertificates`) and warn if a peer's fingerprint changes.

## Messages the server sends/receives (reference)

### New fields in existing messages

**`channel_joined`** (server → client):
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

**`client_joined`** / **`client_left`** (server → client):
```json
{
  "type": "client_joined",
  "user_id": 5,
  "client": {"id": 5, "connection_type": "slave", "e2e_supported": true}
}
```

### New message types (client ↔ client, relayed by server)

**`e2e_pubkey`** — broadcast after joining:
```json
{"type": "e2e_pubkey", "pubkey": "<base64 32-byte X25519 public key>", "nonce_prefix": "<base64 4-byte>"}
```
Server adds `origin` field when relaying.

**`e2e_data`** — encrypted data-plane message:
```json
{"type": "e2e_data", "to": 3, "ciphertext": "<base64>", "nonce": "<base64 24-byte>"}
```
Server adds `origin` field when relaying. `to` is the intended recipient's user_id.

## Testing checklist

After implementation, verify:

- [ ] v3 client connects to relay server, `channel_joined` includes `e2e_available: true` and `user_id`
- [ ] Two v3 clients in a channel: key exchange happens, messages are encrypted
- [ ] Keystrokes relay correctly through E2E (type on leader, appears on follower)
- [ ] Speech relays correctly through E2E (follower speaks, leader hears)
- [ ] Braille relays correctly through E2E
- [ ] Clipboard relay works through E2E
- [ ] v3 client + v2 client in same channel: E2E does NOT activate, plaintext works normally
- [ ] v3 client connecting directly (not via relay): E2E does NOT activate
- [ ] Disconnecting a peer cleans up key state
- [ ] Non-E2E peer joining active E2E channel tears down E2E
- [ ] Fingerprint verification produces matching fingerprints on both sides
- [ ] Three v3 clients: pairwise keys work, each only decrypts messages addressed to them

## Common pitfalls

1. **Don't register competing handlers.** `CHANNEL_JOINED` is already handled by `LeaderSession` and `FollowerSession`. Integrate E2E logic into existing handlers, don't add parallel ones.

2. **`wx.CallAfter` is mandatory.** All inbound handlers run on the wx main thread. When `_handleE2EData` dispatches decrypted messages via `extensionPoint.notify()`, those handlers are already on the main thread — don't double-wrap with `CallAfter`.

3. **Outbound extension points.** `registerOutbound` creates `RemoteExtensionPoint` objects that call `transport.send()` directly. These bypass `sendEncrypted()`. Replace with explicit handler methods or modify `RemoteExtensionPoint`.

4. **`origin` field.** The server adds `origin` to relayed messages. E2E messages (`e2e_pubkey`, `e2e_data`) will have `origin` when received. Use it to identify the sender for key lookup and decryption.

5. **Speech command serialization.** The `JSONSerializer` uses a custom encoder for speech commands (`SpeechCommandJSONEncoder`). When encrypting, you serialize to plain JSON inside `E2ESession.encrypt()` using `json.dumps()`. The receiving side decrypts to plain JSON and dispatches through the normal handler path — the `asSequence` hook in `JSONSerializer.deserialize()` won't fire because you're calling `extensionPoint.notify(**msg_kwargs)` directly. **You need to handle speech command deserialization manually** in the `SPEAK` message path, or route decrypted messages back through the serializer's `deserialize()`.

6. **Session not available for all sends.** In `client.py`, `processKeyInput()` uses `self.leaderTransport.send()` directly. You need access to the `leaderSession` object to call `sendEncrypted()`. `self.leaderSession` already exists on `RemoteClient`.

7. **The `SpeechCommandJSONEncoder` pitfall (critical).** When the follower sends `SPEAK` messages, the speech command objects (like `SynthCommand`) are serialized by the custom `SpeechCommandJSONEncoder` in the transport's serializer. But `E2ESession.encrypt()` uses plain `json.dumps()` which won't handle these objects. **You must use the transport's serializer for the inner plaintext**, or pre-serialize speech commands before passing to `encrypt()`. The simplest fix: make `encrypt()` accept pre-serialized bytes, or have `sendEncrypted()` serialize using the transport's serializer first, then encrypt the bytes.

## Protocol documentation in the NVDA source

**This is important.** The NVDA source currently has **no formal protocol specification** for NVDA Remote — not for v1, v2, or v3. The protocol is defined only through code. For E2E encryption, a formal spec is essential since it involves cryptographic properties that must be auditable.

You must create a protocol specification document at:

```
projectDocs/design/remoteProtocol.md
```

This is alongside the existing `projectDocs/design/technicalDesignOverview.md`, which is NVDA's design documentation directory. There is no existing protocol doc in `projectDocs/dev/` or anywhere else in the tree — you are creating the first one.

The document must cover the **entire** protocol (v1, v2, and v3), not just the E2E additions. It should be written for security auditors and future contributors who need to understand the protocol without reading the code. Include:

### Required sections

1. **Protocol overview** — line-delimited JSON over TLS, port 6837, connection lifecycle
2. **Version history** — what v1, v2, and v3 each add
3. **Connection handshake** — `protocol_version` → `join`/`generate_key` → `channel_joined` + `motd`
4. **Message reference** — every `RemoteMessageType` with its fields, direction (client→server, server→client, client→client via relay), and which version introduced it
5. **Relay behavior** — how the server forwards messages, `origin` injection (v2+), field stripping for v1 clients
6. **E2E encryption specification (v3)** — this is the auditable part:
   - Cryptographic primitives: X25519, XChaCha20-Poly1305, HKDF-SHA256, BLAKE2b
   - Key exchange flow: `e2e_pubkey` message format, DH derivation, HKDF parameters (`salt="nvdaremote-e2e-v1"`, `info=""`)
   - Nonce construction: 4-byte sender prefix + 12-byte zero padding + 8-byte big-endian counter = 24 bytes
   - `e2e_data` message format: `to`, `ciphertext` (base64), `nonce` (base64)
   - All-or-nothing rule and channel teardown on non-E2E peer join
   - Fingerprint computation: `BLAKE2b(sort(pubkey_a, pubkey_b), digest_size=8)`
   - Threat model: what is protected (data-plane content, forward secrecy), what is not (metadata, MITM without fingerprint verification)
   - Explicit non-goals and Signal protocol comparison (reference `docs/e2e-encryption.md` in the relay server repo for the detailed tradeoff analysis)
7. **Direct connection mode** — why E2E is not used (`e2e_available: false`), TLS is sufficient
8. **Wire format examples** — complete JSON examples for every message in a typical E2E session

This document is a **hard requirement** for the PR to NVDA. Any security-relevant protocol change must have a specification that can be audited independently of the implementation.
