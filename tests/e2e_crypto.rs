//! End-to-end encryption integration tests.
//!
//! These tests simulate the full E2E protocol: key exchange, encryption,
//! relay through the server, decryption, and various attack scenarios.
//! Uses the same crypto primitives specified in docs/e2e-encryption.md
//! (X25519 + XChaCha20-Poly1305 + HKDF-SHA256).

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::time::timeout;
use x25519_dalek::{PublicKey, StaticSecret};

use sha2::Digest;

const RECV_TIMEOUT: Duration = Duration::from_secs(2);

/// Hash a channel key with SHA-256, as v3 clients must do per the protocol spec.
fn hash_channel(key: &str) -> String {
    let mut hasher = <Sha256 as Digest>::new();
    Digest::update(&mut hasher, key.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn setup_server() -> Arc<nvdaremote_server_rs::server::ServerState> {
    nvdaremote_server_rs::server::ServerState::new(
        nvdaremote_server_rs::config::MotdConfig {
            message: String::new(),
            always_send: false,
        },
        true,
    )
}

fn connect_client(state: &Arc<nvdaremote_server_rs::server::ServerState>) -> DuplexStream {
    let (server_stream, client_stream) = tokio::io::duplex(8192);
    let state = state.clone();
    tokio::spawn(async move {
        nvdaremote_server_rs::client::handle_client(server_stream, state).await;
    });
    client_stream
}

fn split_client(
    stream: DuplexStream,
) -> (
    tokio::io::WriteHalf<DuplexStream>,
    tokio::io::Lines<BufReader<tokio::io::ReadHalf<DuplexStream>>>,
) {
    let (read, write) = tokio::io::split(stream);
    let reader = BufReader::new(read).lines();
    (write, reader)
}

async fn send_write(writer: &mut tokio::io::WriteHalf<DuplexStream>, msg: &str) {
    writer.write_all(msg.as_bytes()).await.unwrap();
    if !msg.ends_with('\n') {
        writer.write_all(b"\n").await.unwrap();
    }
    writer.flush().await.unwrap();
}

async fn recv(
    reader: &mut tokio::io::Lines<BufReader<tokio::io::ReadHalf<DuplexStream>>>,
) -> serde_json::Value {
    let line = timeout(RECV_TIMEOUT, reader.next_line())
        .await
        .expect("Timed out waiting for response")
        .expect("IO error reading response")
        .expect("Stream closed unexpectedly");
    serde_json::from_str(&line).expect("Invalid JSON from server")
}

/// Simulates one E2E client: generates keypair, nonce prefix, can encrypt/decrypt.
/// Uses StaticSecret instead of EphemeralSecret so we can derive keys with multiple peers.
struct E2EClient {
    secret: StaticSecret,
    public_key: PublicKey,
    nonce_prefix: [u8; 4],
    user_id: u64,
    /// The real channel key (plaintext, not hashed) — used as HKDF salt
    channel_key: String,
    /// Pairwise shared keys indexed by peer user_id
    peer_keys: std::collections::HashMap<u64, Vec<u8>>,
    /// Nonce counter per peer
    nonce_counters: std::collections::HashMap<u64, u64>,
}

impl E2EClient {
    fn new(channel_key: &str) -> Self {
        use rand::RngExt;
        let mut rng = rand::rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill(&mut secret_bytes);
        let secret = StaticSecret::from(secret_bytes);
        let public_key = PublicKey::from(&secret);
        let mut nonce_prefix = [0u8; 4];
        rng.fill(&mut nonce_prefix);
        Self {
            secret,
            public_key,
            nonce_prefix,
            user_id: 0,
            channel_key: channel_key.to_string(),
            peer_keys: std::collections::HashMap::new(),
            nonce_counters: std::collections::HashMap::new(),
        }
    }

    fn pubkey_b64(&self) -> String {
        BASE64.encode(self.public_key.as_bytes())
    }

    fn nonce_prefix_b64(&self) -> String {
        BASE64.encode(self.nonce_prefix)
    }

    fn pubkey_message(&self) -> String {
        format!(
            r#"{{"type":"e2e_pubkey","pubkey":"{}","nonce_prefix":"{}"}}"#,
            self.pubkey_b64(),
            self.nonce_prefix_b64()
        )
    }

    /// Derive shared key from peer's public key using HKDF-SHA256
    fn add_peer(&mut self, peer_id: u64, peer_pubkey_b64: &str) {
        let peer_pubkey_bytes: [u8; 32] =
            BASE64.decode(peer_pubkey_b64).unwrap().try_into().unwrap();
        let peer_pubkey = PublicKey::from(peer_pubkey_bytes);

        // X25519 DH
        let shared_secret = self.secret.diffie_hellman(&peer_pubkey);

        // HKDF-SHA256: ikm=DH_shared_secret, salt=channel_key, info="nvda-remote-e2e"
        let hkdf = Hkdf::<Sha256>::new(Some(self.channel_key.as_bytes()), shared_secret.as_bytes());
        let mut key = vec![0u8; 32];
        hkdf.expand(b"nvda-remote-e2e", &mut key).unwrap();

        self.peer_keys.insert(peer_id, key);
        self.nonce_counters.insert(peer_id, 0);
    }

    /// Build a 24-byte nonce for XChaCha20-Poly1305
    fn make_nonce(&mut self, peer_id: u64) -> [u8; 24] {
        let counter = self.nonce_counters.get_mut(&peer_id).unwrap();
        let mut nonce = [0u8; 24];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        // bytes 4..16 are zero padding
        nonce[16..24].copy_from_slice(&counter.to_be_bytes());
        *counter += 1;
        nonce
    }

    /// Encrypt a JSON message for a specific peer
    fn encrypt(&mut self, peer_id: u64, plaintext_json: &str) -> (String, String) {
        let key = self.peer_keys.get(&peer_id).expect("No key for peer");
        let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
        let nonce_bytes = self.make_nonce(peer_id);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext_json.as_bytes())
            .expect("Encryption failed");
        (BASE64.encode(&ciphertext), BASE64.encode(nonce_bytes))
    }

    /// Decrypt a ciphertext from a peer
    fn decrypt(&self, peer_id: u64, ciphertext_b64: &str, nonce_b64: &str) -> Option<String> {
        let key = self.peer_keys.get(&peer_id)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key).unwrap();
        let ciphertext = BASE64.decode(ciphertext_b64).ok()?;
        let nonce_bytes = BASE64.decode(nonce_b64).ok()?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
        Some(String::from_utf8(plaintext).ok()?)
    }
}

/// Helper: join two v3 clients to a channel, consume the setup messages,
/// return (writer1, reader1, user_id1, writer2, reader2, user_id2)
async fn join_two_v3_clients(
    state: &Arc<nvdaremote_server_rs::server::ServerState>,
    channel: &str,
) -> (
    tokio::io::WriteHalf<DuplexStream>,
    tokio::io::Lines<BufReader<tokio::io::ReadHalf<DuplexStream>>>,
    u64,
    tokio::io::WriteHalf<DuplexStream>,
    tokio::io::Lines<BufReader<tokio::io::ReadHalf<DuplexStream>>>,
    u64,
) {
    let channel_hash = hash_channel(channel);

    let stream1 = connect_client(state);
    let (mut w1, mut r1) = split_client(stream1);
    send_write(&mut w1, r#"{"type":"protocol_version","version":3}"#).await;
    send_write(
        &mut w1,
        &format!(r#"{{"type":"join","channel":"{channel_hash}","connection_type":"master"}}"#),
    )
    .await;
    let msg = recv(&mut r1).await; // channel_joined
    let uid1 = msg["user_id"].as_u64().unwrap();

    let stream2 = connect_client(state);
    let (mut w2, mut r2) = split_client(stream2);
    send_write(&mut w2, r#"{"type":"protocol_version","version":3}"#).await;
    send_write(
        &mut w2,
        &format!(r#"{{"type":"join","channel":"{channel_hash}","connection_type":"slave"}}"#),
    )
    .await;
    let msg = recv(&mut r2).await; // channel_joined
    let uid2 = msg["user_id"].as_u64().unwrap();

    let _ = recv(&mut r1).await; // client_joined for client 2

    (w1, r1, uid1, w2, r2, uid2)
}

// ============================================================================
// TEST: Full E2E flow — key exchange, encrypt, relay, decrypt
// ============================================================================

#[tokio::test]
async fn e2e_full_flow_encrypt_relay_decrypt() {
    let state = setup_server();
    let (mut w1, mut r1, uid1, mut w2, mut r2, uid2) =
        join_two_v3_clients(&state, "e2e_full").await;

    // Create E2E clients with channel key for HKDF derivation
    let mut client_a = E2EClient::new("e2e_full");
    client_a.user_id = uid1;
    let mut client_b = E2EClient::new("e2e_full");
    client_b.user_id = uid2;

    // Exchange public keys through the relay
    send_write(&mut w1, &client_a.pubkey_message()).await;
    let msg = recv(&mut r2).await;
    assert_eq!(msg["type"], "e2e_pubkey");
    let pubkey_a_b64 = msg["pubkey"].as_str().unwrap().to_string();

    send_write(&mut w2, &client_b.pubkey_message()).await;
    let msg = recv(&mut r1).await;
    assert_eq!(msg["type"], "e2e_pubkey");
    let pubkey_b_b64 = msg["pubkey"].as_str().unwrap().to_string();

    // Derive shared keys
    client_a.add_peer(uid2, &pubkey_b_b64);
    client_b.add_peer(uid1, &pubkey_a_b64);

    // Client A encrypts a keystroke message for client B
    let plaintext = r#"{"type":"key","vk_code":65,"pressed":true}"#;
    let (ciphertext, nonce) = client_a.encrypt(uid2, plaintext);

    // Send through relay
    let e2e_msg = format!(
        r#"{{"type":"e2e_data","to":{uid2},"ciphertext":"{ciphertext}","nonce":"{nonce}"}}"#
    );
    send_write(&mut w1, &e2e_msg).await;

    // Client B receives and decrypts
    let msg = recv(&mut r2).await;
    assert_eq!(msg["type"], "e2e_data");
    let decrypted = client_b
        .decrypt(
            uid1,
            msg["ciphertext"].as_str().unwrap(),
            msg["nonce"].as_str().unwrap(),
        )
        .expect("Decryption should succeed");

    let decrypted_json: serde_json::Value = serde_json::from_str(&decrypted).unwrap();
    assert_eq!(decrypted_json["type"], "key");
    assert_eq!(decrypted_json["vk_code"], 65);
    assert_eq!(decrypted_json["pressed"], true);
}

// ============================================================================
// TEST: Server cannot decrypt E2E data (it only sees opaque ciphertext)
// ============================================================================

#[tokio::test]
async fn e2e_server_cannot_read_encrypted_content() {
    let state = setup_server();
    let (mut w1, mut r1, uid1, mut w2, mut r2, uid2) =
        join_two_v3_clients(&state, "e2e_opaque").await;

    let mut client_a = E2EClient::new("e2e_opaque");
    client_a.user_id = uid1;
    let mut client_b = E2EClient::new("e2e_opaque");
    client_b.user_id = uid2;

    // Key exchange
    send_write(&mut w1, &client_a.pubkey_message()).await;
    let msg = recv(&mut r2).await;
    let pubkey_a_b64 = msg["pubkey"].as_str().unwrap().to_string();

    send_write(&mut w2, &client_b.pubkey_message()).await;
    let msg = recv(&mut r1).await;
    let pubkey_b_b64 = msg["pubkey"].as_str().unwrap().to_string();

    client_a.add_peer(uid2, &pubkey_b_b64);
    client_b.add_peer(uid1, &pubkey_a_b64);

    // Encrypt sensitive data
    let secret_text = r#"{"type":"set_clipboard_text","text":"my-secret-password-123"}"#;
    let (ciphertext, nonce) = client_a.encrypt(uid2, secret_text);

    // Send through relay
    let e2e_msg = format!(
        r#"{{"type":"e2e_data","to":{uid2},"ciphertext":"{ciphertext}","nonce":"{nonce}"}}"#
    );
    send_write(&mut w1, &e2e_msg).await;

    // What the server sees (the relayed message)
    let msg = recv(&mut r2).await;

    // The server relayed it with origin added — but the ciphertext is opaque
    let ct_b64 = msg["ciphertext"].as_str().unwrap();
    let ct_bytes = BASE64.decode(ct_b64).unwrap();

    // The ciphertext should NOT contain the plaintext
    let ct_str = String::from_utf8_lossy(&ct_bytes);
    assert!(
        !ct_str.contains("my-secret-password-123"),
        "Ciphertext must not contain plaintext password"
    );
    assert!(
        !ct_str.contains("set_clipboard_text"),
        "Ciphertext must not contain message type"
    );

    // But the intended recipient CAN decrypt it
    let decrypted = client_b
        .decrypt(uid1, ct_b64, msg["nonce"].as_str().unwrap())
        .unwrap();
    assert!(decrypted.contains("my-secret-password-123"));
}

// ============================================================================
// TEST: Wrong key cannot decrypt (attacker with different keypair)
// ============================================================================

#[tokio::test]
async fn e2e_wrong_key_cannot_decrypt() {
    let state = setup_server();
    let (mut w1, mut r1, uid1, mut w2, mut r2, uid2) =
        join_two_v3_clients(&state, "e2e_wrongkey").await;

    let mut client_a = E2EClient::new("e2e_wrongkey");
    client_a.user_id = uid1;
    let mut client_b = E2EClient::new("e2e_wrongkey");
    client_b.user_id = uid2;

    // Normal key exchange
    send_write(&mut w1, &client_a.pubkey_message()).await;
    let msg = recv(&mut r2).await;
    let pubkey_a_b64 = msg["pubkey"].as_str().unwrap().to_string();

    send_write(&mut w2, &client_b.pubkey_message()).await;
    let msg = recv(&mut r1).await;
    let pubkey_b_b64 = msg["pubkey"].as_str().unwrap().to_string();

    client_a.add_peer(uid2, &pubkey_b_b64);
    client_b.add_peer(uid1, &pubkey_a_b64);

    // Encrypt a message
    let (ciphertext, nonce) = client_a.encrypt(uid2, r#"{"type":"key","vk_code":65}"#);

    // An attacker with a DIFFERENT keypair tries to decrypt
    let mut attacker = E2EClient::new("e2e_wrongkey");
    // The attacker derives a key with client A's public key but their own secret
    // This produces a DIFFERENT shared secret
    attacker.add_peer(uid1, &client_a.pubkey_b64());

    let result = attacker.decrypt(uid1, &ciphertext, &nonce);
    assert!(
        result.is_none(),
        "Attacker with wrong key must not be able to decrypt"
    );
}

// ============================================================================
// TEST: Tampered ciphertext is rejected (authentication tag fails)
// ============================================================================

#[tokio::test]
async fn e2e_tampered_ciphertext_rejected() {
    let state = setup_server();
    let (mut w1, mut r1, uid1, mut w2, mut r2, uid2) =
        join_two_v3_clients(&state, "e2e_tamper").await;

    let mut client_a = E2EClient::new("e2e_tamper");
    client_a.user_id = uid1;
    let mut client_b = E2EClient::new("e2e_tamper");
    client_b.user_id = uid2;

    // Key exchange
    send_write(&mut w1, &client_a.pubkey_message()).await;
    let msg = recv(&mut r2).await;
    let pubkey_a_b64 = msg["pubkey"].as_str().unwrap().to_string();

    send_write(&mut w2, &client_b.pubkey_message()).await;
    let msg = recv(&mut r1).await;
    let pubkey_b_b64 = msg["pubkey"].as_str().unwrap().to_string();

    client_a.add_peer(uid2, &pubkey_b_b64);
    client_b.add_peer(uid1, &pubkey_a_b64);

    // Encrypt
    let (ciphertext_b64, nonce) = client_a.encrypt(uid2, r#"{"type":"key","vk_code":65}"#);

    // Tamper with the ciphertext (flip a byte)
    let mut ct_bytes = BASE64.decode(&ciphertext_b64).unwrap();
    if let Some(byte) = ct_bytes.first_mut() {
        *byte ^= 0xFF;
    }
    let tampered_b64 = BASE64.encode(&ct_bytes);

    // Decryption must fail
    let result = client_b.decrypt(uid1, &tampered_b64, &nonce);
    assert!(
        result.is_none(),
        "Tampered ciphertext must be rejected by AEAD authentication"
    );
}

// ============================================================================
// TEST: Tampered nonce is rejected
// ============================================================================

#[tokio::test]
async fn e2e_tampered_nonce_rejected() {
    let state = setup_server();
    let (mut w1, mut r1, uid1, mut w2, mut r2, uid2) =
        join_two_v3_clients(&state, "e2e_nonce_tamper").await;

    let mut client_a = E2EClient::new("e2e_nonce_tamper");
    client_a.user_id = uid1;
    let mut client_b = E2EClient::new("e2e_nonce_tamper");
    client_b.user_id = uid2;

    send_write(&mut w1, &client_a.pubkey_message()).await;
    let msg = recv(&mut r2).await;
    let pubkey_a_b64 = msg["pubkey"].as_str().unwrap().to_string();

    send_write(&mut w2, &client_b.pubkey_message()).await;
    let msg = recv(&mut r1).await;
    let pubkey_b_b64 = msg["pubkey"].as_str().unwrap().to_string();

    client_a.add_peer(uid2, &pubkey_b_b64);
    client_b.add_peer(uid1, &pubkey_a_b64);

    let (ciphertext, nonce_b64) =
        client_a.encrypt(uid2, r#"{"type":"speak","sequence":["hello"]}"#);

    // Tamper with the nonce
    let mut nonce_bytes = BASE64.decode(&nonce_b64).unwrap();
    if let Some(byte) = nonce_bytes.last_mut() {
        *byte ^= 0x01;
    }
    let tampered_nonce = BASE64.encode(&nonce_bytes);

    let result = client_b.decrypt(uid1, &ciphertext, &tampered_nonce);
    assert!(
        result.is_none(),
        "Wrong nonce must cause decryption failure"
    );
}

// ============================================================================
// TEST: Bidirectional encryption — both sides can encrypt and decrypt
// ============================================================================

#[tokio::test]
async fn e2e_bidirectional_encryption() {
    let state = setup_server();
    let (mut w1, mut r1, uid1, mut w2, mut r2, uid2) =
        join_two_v3_clients(&state, "e2e_bidir").await;

    let mut client_a = E2EClient::new("e2e_bidir");
    client_a.user_id = uid1;
    let mut client_b = E2EClient::new("e2e_bidir");
    client_b.user_id = uid2;

    // Key exchange
    send_write(&mut w1, &client_a.pubkey_message()).await;
    let msg = recv(&mut r2).await;
    let pubkey_a_b64 = msg["pubkey"].as_str().unwrap().to_string();

    send_write(&mut w2, &client_b.pubkey_message()).await;
    let msg = recv(&mut r1).await;
    let pubkey_b_b64 = msg["pubkey"].as_str().unwrap().to_string();

    client_a.add_peer(uid2, &pubkey_b_b64);
    client_b.add_peer(uid1, &pubkey_a_b64);

    // A → B: keystroke
    let (ct, nonce) = client_a.encrypt(uid2, r#"{"type":"key","vk_code":65}"#);
    send_write(
        &mut w1,
        &format!(r#"{{"type":"e2e_data","to":{uid2},"ciphertext":"{ct}","nonce":"{nonce}"}}"#),
    )
    .await;
    let msg = recv(&mut r2).await;
    let decrypted = client_b
        .decrypt(
            uid1,
            msg["ciphertext"].as_str().unwrap(),
            msg["nonce"].as_str().unwrap(),
        )
        .unwrap();
    assert!(decrypted.contains("vk_code"));

    // B → A: speech
    let (ct, nonce) = client_b.encrypt(uid1, r#"{"type":"speak","sequence":["hello"]}"#);
    send_write(
        &mut w2,
        &format!(r#"{{"type":"e2e_data","to":{uid1},"ciphertext":"{ct}","nonce":"{nonce}"}}"#),
    )
    .await;
    let msg = recv(&mut r1).await;
    let decrypted = client_a
        .decrypt(
            uid2,
            msg["ciphertext"].as_str().unwrap(),
            msg["nonce"].as_str().unwrap(),
        )
        .unwrap();
    assert!(decrypted.contains("speak"));
    assert!(decrypted.contains("hello"));
}

// ============================================================================
// TEST: Multiple messages use different nonces (counter increments)
// ============================================================================

#[tokio::test]
async fn e2e_nonces_are_unique_per_message() {
    let state = setup_server();
    let (mut w1, mut r1, uid1, mut w2, mut r2, uid2) =
        join_two_v3_clients(&state, "e2e_nonces").await;

    let mut client_a = E2EClient::new("e2e_nonces");
    client_a.user_id = uid1;
    let mut client_b = E2EClient::new("e2e_nonces");
    client_b.user_id = uid2;

    send_write(&mut w1, &client_a.pubkey_message()).await;
    let msg = recv(&mut r2).await;
    let pubkey_a_b64 = msg["pubkey"].as_str().unwrap().to_string();

    send_write(&mut w2, &client_b.pubkey_message()).await;
    let msg = recv(&mut r1).await;
    let pubkey_b_b64 = msg["pubkey"].as_str().unwrap().to_string();

    client_a.add_peer(uid2, &pubkey_b_b64);
    client_b.add_peer(uid1, &pubkey_a_b64);

    // Send 5 messages, collect nonces
    let mut nonces = Vec::new();
    let mut ciphertexts = Vec::new();
    for i in 0..5 {
        let plaintext = format!(r#"{{"type":"key","vk_code":{}}}"#, 65 + i);
        let (ct, nonce) = client_a.encrypt(uid2, &plaintext);

        send_write(
            &mut w1,
            &format!(r#"{{"type":"e2e_data","to":{uid2},"ciphertext":"{ct}","nonce":"{nonce}"}}"#),
        )
        .await;

        let msg = recv(&mut r2).await;
        nonces.push(msg["nonce"].as_str().unwrap().to_string());
        ciphertexts.push(msg["ciphertext"].as_str().unwrap().to_string());

        // Each should decrypt correctly
        let decrypted = client_b.decrypt(uid1, &ciphertexts[i], &nonces[i]).unwrap();
        let json: serde_json::Value = serde_json::from_str(&decrypted).unwrap();
        assert_eq!(json["vk_code"], 65 + i as u64);
    }

    // All nonces must be unique
    let unique_nonces: std::collections::HashSet<_> = nonces.iter().collect();
    assert_eq!(
        unique_nonces.len(),
        5,
        "Each message must use a unique nonce"
    );

    // All ciphertexts must be different (even for similar plaintext lengths)
    let unique_cts: std::collections::HashSet<_> = ciphertexts.iter().collect();
    assert_eq!(
        unique_cts.len(),
        5,
        "Each ciphertext must be unique due to different nonce"
    );
}

// ============================================================================
// TEST: MITM attack fails due to channel key binding in HKDF
// ============================================================================

#[tokio::test]
async fn e2e_mitm_fails_without_channel_key() {
    // A MITM attacker (e.g. malicious relay server) intercepts key exchange and
    // substitutes its own ephemeral keys. The attacker completes separate DH exchanges
    // with A and B, but does NOT know the real channel key. Since the channel key is
    // mixed into HKDF as salt, the attacker derives different encryption keys and
    // cannot decrypt or forge messages.

    let channel_key = "secret_room_key";

    // Legitimate clients share the real channel key
    let mut client_a = E2EClient::new(channel_key);
    let mut client_b = E2EClient::new(channel_key);

    // Attacker does NOT know the real channel key — uses the SHA-256 hash
    // (which is what the server sees in the join message)
    let mut attacker_for_a = E2EClient::new(&hash_channel(channel_key));
    let mut attacker_for_b = E2EClient::new(&hash_channel(channel_key));

    // MITM: attacker intercepts A's pubkey and gives A the attacker's key instead of B's
    attacker_for_a.add_peer(1, &client_a.pubkey_b64());
    client_a.add_peer(2, &attacker_for_a.pubkey_b64()); // A thinks this is B

    // MITM: attacker intercepts B's pubkey and gives B the attacker's key instead of A's
    attacker_for_b.add_peer(2, &client_b.pubkey_b64());
    client_b.add_peer(1, &attacker_for_b.pubkey_b64()); // B thinks this is A

    // A encrypts a message "for B" (actually using attacker's key)
    let (ct, nonce) = client_a.encrypt(2, r#"{"type":"key","vk_code":65}"#);

    // Attacker tries to decrypt A's message — fails because channel key doesn't match
    let result = attacker_for_a.decrypt(1, &ct, &nonce);
    assert!(
        result.is_none(),
        "Attacker without real channel key must not decrypt (HKDF salt mismatch)"
    );

    // B also can't decrypt — different DH shared secret (B did DH with attacker, not A)
    let result = client_b.decrypt(1, &ct, &nonce);
    assert!(
        result.is_none(),
        "B cannot decrypt A's message when MITM substituted keys"
    );
}

// ============================================================================
// TEST: Replay attack — replaying an old message still "decrypts" but
// the application layer should handle dedup (we verify the crypto works)
// ============================================================================

#[tokio::test]
async fn e2e_replayed_message_decrypts_identically() {
    // Note: Replay protection is an application-layer concern, not crypto-layer.
    // XChaCha20-Poly1305 will happily decrypt the same (ciphertext, nonce) pair
    // multiple times. The client should track seen nonces to prevent replays.
    // This test documents the behavior.

    let state = setup_server();
    let (mut w1, mut r1, uid1, mut w2, mut r2, uid2) =
        join_two_v3_clients(&state, "e2e_replay").await;

    let mut client_a = E2EClient::new("e2e_replay");
    client_a.user_id = uid1;
    let mut client_b = E2EClient::new("e2e_replay");
    client_b.user_id = uid2;

    send_write(&mut w1, &client_a.pubkey_message()).await;
    let msg = recv(&mut r2).await;
    let pubkey_a_b64 = msg["pubkey"].as_str().unwrap().to_string();

    send_write(&mut w2, &client_b.pubkey_message()).await;
    let msg = recv(&mut r1).await;
    let pubkey_b_b64 = msg["pubkey"].as_str().unwrap().to_string();

    client_a.add_peer(uid2, &pubkey_b_b64);
    client_b.add_peer(uid1, &pubkey_a_b64);

    // Encrypt once
    let (ct, nonce) = client_a.encrypt(uid2, r#"{"type":"send_SAS"}"#);

    // Send it twice (replay)
    let e2e_msg =
        format!(r#"{{"type":"e2e_data","to":{uid2},"ciphertext":"{ct}","nonce":"{nonce}"}}"#);
    send_write(&mut w1, &e2e_msg).await;
    send_write(&mut w1, &e2e_msg).await;

    // Both decrypt to the same thing — crypto doesn't prevent replay
    let msg1 = recv(&mut r2).await;
    let msg2 = recv(&mut r2).await;

    let d1 = client_b
        .decrypt(
            uid1,
            msg1["ciphertext"].as_str().unwrap(),
            msg1["nonce"].as_str().unwrap(),
        )
        .unwrap();
    let d2 = client_b
        .decrypt(
            uid1,
            msg2["ciphertext"].as_str().unwrap(),
            msg2["nonce"].as_str().unwrap(),
        )
        .unwrap();

    assert_eq!(d1, d2, "Replayed message decrypts identically");
    assert!(d1.contains("send_SAS"), "Decrypted content is correct");
    // NOTE: Client-side replay detection (nonce tracking) is needed to reject duplicates
}

// ============================================================================
// TEST: Three clients — pairwise encryption works correctly
// ============================================================================

#[tokio::test]
async fn e2e_three_clients_pairwise() {
    let state = setup_server();

    // Join 3 clients (channel key hashed with SHA-256 per protocol spec)
    let channel_hash = hash_channel("e2e_3way");

    let stream1 = connect_client(&state);
    let (mut w1, mut r1) = split_client(stream1);
    send_write(&mut w1, r#"{"type":"protocol_version","version":3}"#).await;
    send_write(
        &mut w1,
        &format!(r#"{{"type":"join","channel":"{channel_hash}","connection_type":"master"}}"#),
    )
    .await;
    let msg = recv(&mut r1).await;
    let uid1 = msg["user_id"].as_u64().unwrap();

    let stream2 = connect_client(&state);
    let (mut w2, mut r2) = split_client(stream2);
    send_write(&mut w2, r#"{"type":"protocol_version","version":3}"#).await;
    send_write(
        &mut w2,
        &format!(r#"{{"type":"join","channel":"{channel_hash}","connection_type":"slave"}}"#),
    )
    .await;
    let msg = recv(&mut r2).await;
    let uid2 = msg["user_id"].as_u64().unwrap();
    let _ = recv(&mut r1).await; // client_joined

    let stream3 = connect_client(&state);
    let (mut w3, mut r3) = split_client(stream3);
    send_write(&mut w3, r#"{"type":"protocol_version","version":3}"#).await;
    send_write(
        &mut w3,
        &format!(r#"{{"type":"join","channel":"{channel_hash}","connection_type":"slave"}}"#),
    )
    .await;
    let msg = recv(&mut r3).await;
    let uid3 = msg["user_id"].as_u64().unwrap();
    let _ = recv(&mut r1).await; // client_joined for 3
    let _ = recv(&mut r2).await; // client_joined for 3

    // Each client generates a keypair. In real protocol, each broadcasts pubkey.
    // For this test, we create separate E2EClient pairs since EphemeralSecret is consumed.
    // Client A needs separate secrets for B and C.
    // This mirrors the real implementation where you'd use StaticSecret or
    // generate separate sessions per peer.

    // For simplicity, we test: A encrypts for B, A encrypts for C with separate keypairs.
    // (In real impl, A would use one keypair and derive separate shared secrets.)

    // A↔B key exchange
    let mut a_for_b = E2EClient::new("e2e_3way");
    let mut b_for_a = E2EClient::new("e2e_3way");
    // Exchange through relay
    send_write(&mut w1, &a_for_b.pubkey_message()).await;
    let msg_b = recv(&mut r2).await;
    let _ = recv(&mut r3).await; // client 3 also gets A's pubkey
    let pk_a_b64 = msg_b["pubkey"].as_str().unwrap().to_string();

    send_write(&mut w2, &b_for_a.pubkey_message()).await;
    let msg_a = recv(&mut r1).await;
    let _ = recv(&mut r3).await; // client 3 also gets B's pubkey
    let pk_b_b64 = msg_a["pubkey"].as_str().unwrap().to_string();

    a_for_b.add_peer(uid2, &pk_b_b64);
    b_for_a.add_peer(uid1, &pk_a_b64);

    // A↔C key exchange
    let mut a_for_c = E2EClient::new("e2e_3way");
    let mut c_for_a = E2EClient::new("e2e_3way");
    send_write(&mut w1, &a_for_c.pubkey_message()).await;
    let msg_c = recv(&mut r3).await;
    let _ = recv(&mut r2).await;
    let pk_a2_b64 = msg_c["pubkey"].as_str().unwrap().to_string();

    send_write(&mut w3, &c_for_a.pubkey_message()).await;
    let msg_a = recv(&mut r1).await;
    let _ = recv(&mut r2).await;
    let pk_c_b64 = msg_a["pubkey"].as_str().unwrap().to_string();

    a_for_c.add_peer(uid3, &pk_c_b64);
    c_for_a.add_peer(uid1, &pk_a2_b64);

    // A sends encrypted message to B
    let (ct_b, nonce_b) = a_for_b.encrypt(uid2, r#"{"type":"key","vk_code":66}"#);
    send_write(
        &mut w1,
        &format!(r#"{{"type":"e2e_data","to":{uid2},"ciphertext":"{ct_b}","nonce":"{nonce_b}"}}"#),
    )
    .await;

    // A sends encrypted message to C
    let (ct_c, nonce_c) = a_for_c.encrypt(uid3, r#"{"type":"key","vk_code":67}"#);
    send_write(
        &mut w1,
        &format!(r#"{{"type":"e2e_data","to":{uid3},"ciphertext":"{ct_c}","nonce":"{nonce_c}"}}"#),
    )
    .await;

    // B receives only its targeted message (to-based forwarding)
    let msg = recv(&mut r2).await;
    assert_eq!(msg["to"], uid2);
    let d = b_for_a
        .decrypt(
            uid1,
            msg["ciphertext"].as_str().unwrap(),
            msg["nonce"].as_str().unwrap(),
        )
        .unwrap();
    assert!(d.contains("66"), "B should decrypt vk_code 66");
    // B should NOT receive C's message — targeted forwarding skips non-addressed peers

    // C receives only its targeted message
    let msg = recv(&mut r3).await;
    assert_eq!(msg["to"], uid3);
    let d = c_for_a
        .decrypt(
            uid1,
            msg["ciphertext"].as_str().unwrap(),
            msg["nonce"].as_str().unwrap(),
        )
        .unwrap();
    assert!(d.contains("67"), "C should decrypt vk_code 67");
    // C should NOT receive B's message — targeted forwarding skips non-addressed peers
}
