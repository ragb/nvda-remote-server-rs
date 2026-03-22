//! Integration tests simulating real NVDA Remote client behavior.
//!
//! These tests use `tokio::io::duplex` to create in-memory streams, bypassing TLS
//! since `handle_client` is generic over any AsyncRead + AsyncWrite.
//! This tests the full protocol flow as an NVDA Remote client would experience it.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::time::timeout;

// We need to reference the crate's public API.
// Since this is a binary crate, we use a helper module approach.
// For integration tests to work, we need the crate to expose its internals.
// We'll use a test helper that mirrors the server setup.

/// Timeout for receiving a response in tests.
const RECV_TIMEOUT: Duration = Duration::from_secs(2);

/// Helper: create server state and spawn a client handler, returning the client-side stream.
fn setup_server() -> Arc<nvdaremote_server_rs::server::ServerState> {
    nvdaremote_server_rs::server::ServerState::new(nvdaremote_server_rs::config::MotdConfig {
        message: "Welcome to test server".to_string(),
        always_send: true,
    })
}

/// Spawn a client handler and return the client-side duplex stream for writing/reading.
fn connect_client(state: &Arc<nvdaremote_server_rs::server::ServerState>) -> DuplexStream {
    let (server_stream, client_stream) = tokio::io::duplex(8192);
    let state = state.clone();
    tokio::spawn(async move {
        nvdaremote_server_rs::client::handle_client(server_stream, state).await;
    });
    client_stream
}

/// Helper to receive a JSON line from the server, with timeout.
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

/// Helper to split a duplex stream and get a line reader.
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

/// Send a line directly on the write half.
async fn send_write(writer: &mut tokio::io::WriteHalf<DuplexStream>, msg: &str) {
    writer.write_all(msg.as_bytes()).await.unwrap();
    if !msg.ends_with('\n') {
        writer.write_all(b"\n").await.unwrap();
    }
    writer.flush().await.unwrap();
}

// ============================================================================
// Test: Basic NVDA client connection flow
// Client sends protocol_version, then join, expects channel_joined + motd
// ============================================================================

#[tokio::test]
async fn client_join_receives_channel_joined_and_motd() {
    let state = setup_server();
    let stream = connect_client(&state);
    let (mut writer, mut reader) = split_client(stream);

    // NVDA client always sends protocol_version first
    send_write(&mut writer, r#"{"type":"protocol_version","version":2}"#).await;

    // Then join a channel
    send_write(
        &mut writer,
        r#"{"type":"join","channel":"123456789","connection_type":"master"}"#,
    )
    .await;

    // Should receive channel_joined
    let msg = recv(&mut reader).await;
    assert_eq!(msg["type"], "channel_joined");
    assert_eq!(msg["channel"], "123456789");
    assert!(
        msg["user_ids"].as_array().unwrap().is_empty(),
        "First client should see no existing users"
    );
    assert!(msg["clients"].as_array().unwrap().is_empty());

    // Should receive motd
    let msg = recv(&mut reader).await;
    assert_eq!(msg["type"], "motd");
    assert_eq!(msg["motd"], "Welcome to test server");
    assert_eq!(msg["force_display"], true);
}

// ============================================================================
// Test: Generate key flow
// Client sends generate_key, receives a key response with 9-digit key
// ============================================================================

#[tokio::test]
async fn generate_key_returns_9_digit_key() {
    let state = setup_server();
    let stream = connect_client(&state);
    let (mut writer, mut reader) = split_client(stream);

    send_write(&mut writer, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(&mut writer, r#"{"type":"generate_key"}"#).await;

    let msg = recv(&mut reader).await;
    assert_eq!(msg["type"], "generate_key");
    let key = msg["key"].as_str().unwrap();
    assert_eq!(key.len(), 9);
    assert!(key.chars().all(|c| c.is_ascii_digit()));
}

// ============================================================================
// Test: Two clients join the same channel
// Second client sees first in channel_joined, first gets client_joined notification
// ============================================================================

#[tokio::test]
async fn two_clients_join_same_channel() {
    let state = setup_server();

    // Client 1 joins
    let stream1 = connect_client(&state);
    let (mut w1, mut r1) = split_client(stream1);

    send_write(&mut w1, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w1,
        r#"{"type":"join","channel":"shared","connection_type":"master"}"#,
    )
    .await;

    // Client 1 receives channel_joined (empty channel)
    let msg = recv(&mut r1).await;
    assert_eq!(msg["type"], "channel_joined");
    assert!(msg["user_ids"].as_array().unwrap().is_empty());

    // Client 1 receives motd
    let msg = recv(&mut r1).await;
    assert_eq!(msg["type"], "motd");

    // Client 2 joins the same channel
    let stream2 = connect_client(&state);
    let (mut w2, mut r2) = split_client(stream2);

    send_write(&mut w2, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w2,
        r#"{"type":"join","channel":"shared","connection_type":"slave"}"#,
    )
    .await;

    // Client 2 receives channel_joined — should see client 1
    let msg = recv(&mut r2).await;
    assert_eq!(msg["type"], "channel_joined");
    let user_ids = msg["user_ids"].as_array().unwrap();
    assert_eq!(user_ids.len(), 1, "Should see 1 existing user");
    let clients = msg["clients"].as_array().unwrap();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0]["connection_type"], "master");

    // Client 2 receives motd
    let msg = recv(&mut r2).await;
    assert_eq!(msg["type"], "motd");

    // Client 1 should receive client_joined notification about client 2
    let msg = recv(&mut r1).await;
    assert_eq!(msg["type"], "client_joined");
    assert_eq!(msg["client"]["connection_type"], "slave");
}

// ============================================================================
// Test: Client disconnect sends client_left to remaining members
// ============================================================================

#[tokio::test]
async fn client_disconnect_sends_client_left() {
    let state = setup_server();

    // Client 1 joins
    let stream1 = connect_client(&state);
    let (mut w1, mut r1) = split_client(stream1);
    send_write(&mut w1, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w1,
        r#"{"type":"join","channel":"room","connection_type":"master"}"#,
    )
    .await;
    let _ = recv(&mut r1).await; // channel_joined
    let _ = recv(&mut r1).await; // motd

    // Client 2 joins
    let stream2 = connect_client(&state);
    let (w2, mut r2) = split_client(stream2);
    send_write(&mut w1, "").await; // yield
    // need a mutable reference
    let mut w2 = w2;
    send_write(&mut w2, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w2,
        r#"{"type":"join","channel":"room","connection_type":"slave"}"#,
    )
    .await;
    let _ = recv(&mut r2).await; // channel_joined
    let _ = recv(&mut r2).await; // motd
    let _ = recv(&mut r1).await; // client_joined for client 2

    // Client 2 disconnects by dropping writer
    drop(w2);
    // Also drop the reader to fully close the stream
    drop(r2);

    // Client 1 should receive client_left
    let msg = recv(&mut r1).await;
    assert_eq!(msg["type"], "client_left");
    assert_eq!(msg["client"]["connection_type"], "slave");
}

// ============================================================================
// Test: Message relay between two clients
// Messages sent by one client are forwarded to the other
// ============================================================================

#[tokio::test]
async fn messages_are_relayed_between_clients() {
    let state = setup_server();

    // Client 1 (master)
    let stream1 = connect_client(&state);
    let (mut w1, mut r1) = split_client(stream1);
    send_write(&mut w1, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w1,
        r#"{"type":"join","channel":"relay_test","connection_type":"master"}"#,
    )
    .await;
    let _ = recv(&mut r1).await; // channel_joined
    let _ = recv(&mut r1).await; // motd

    // Client 2 (slave)
    let stream2 = connect_client(&state);
    let (mut w2, mut r2) = split_client(stream2);
    send_write(&mut w2, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w2,
        r#"{"type":"join","channel":"relay_test","connection_type":"slave"}"#,
    )
    .await;
    let _ = recv(&mut r2).await; // channel_joined
    let _ = recv(&mut r2).await; // motd
    let _ = recv(&mut r1).await; // client_joined

    // Master sends a key event — should be forwarded to slave
    send_write(&mut w1, r#"{"type":"key","vk_code":65,"pressed":true}"#).await;

    let msg = recv(&mut r2).await;
    assert_eq!(msg["type"], "key");
    assert_eq!(msg["vk_code"], 65);
    assert_eq!(msg["pressed"], true);
    // Should have origin field added (protocol v2)
    assert!(
        msg.get("origin").is_some(),
        "Forwarded message should have origin field"
    );

    // Slave sends a speak event — should be forwarded to master
    send_write(&mut w2, r#"{"type":"speak","sequence":["hello world"]}"#).await;

    let msg = recv(&mut r1).await;
    assert_eq!(msg["type"], "speak");
    assert_eq!(msg["sequence"][0], "hello world");
    assert!(msg.get("origin").is_some());
}

// ============================================================================
// Test: Sender does not receive their own forwarded messages
// ============================================================================

#[tokio::test]
async fn sender_does_not_receive_own_messages() {
    let state = setup_server();

    // Only one client in channel — messages should go nowhere, not echo back
    let stream = connect_client(&state);
    let (mut writer, mut reader) = split_client(stream);
    send_write(&mut writer, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut writer,
        r#"{"type":"join","channel":"solo","connection_type":"master"}"#,
    )
    .await;
    let _ = recv(&mut reader).await; // channel_joined
    let _ = recv(&mut reader).await; // motd

    // Send a message
    send_write(&mut writer, r#"{"type":"key","vk_code":65}"#).await;

    // Should NOT receive anything back (no echo)
    let result = timeout(Duration::from_millis(200), reader.next_line()).await;
    assert!(
        result.is_err(),
        "Should timeout — sender should not receive their own message"
    );
}

// ============================================================================
// Test: Empty channel name returns error
// ============================================================================

#[tokio::test]
async fn join_empty_channel_returns_error() {
    let state = setup_server();
    let stream = connect_client(&state);
    let (mut writer, mut reader) = split_client(stream);

    send_write(&mut writer, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut writer,
        r#"{"type":"join","channel":"","connection_type":"master"}"#,
    )
    .await;

    let msg = recv(&mut reader).await;
    assert_eq!(msg["type"], "error");
    assert_eq!(msg["error"], "invalid_parameters");
}

// ============================================================================
// Test: Whitespace-only channel name returns error
// ============================================================================

#[tokio::test]
async fn join_whitespace_channel_returns_error() {
    let state = setup_server();
    let stream = connect_client(&state);
    let (mut writer, mut reader) = split_client(stream);

    send_write(&mut writer, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut writer,
        r#"{"type":"join","channel":"   ","connection_type":"master"}"#,
    )
    .await;

    let msg = recv(&mut reader).await;
    assert_eq!(msg["type"], "error");
    assert_eq!(msg["error"], "invalid_parameters");
}

// ============================================================================
// Test: Protocol v1 client does not receive origin/client/clients fields
// ============================================================================

#[tokio::test]
async fn v1_client_does_not_receive_v2_fields() {
    let state = setup_server();

    // Client 1: v2 sender
    let stream1 = connect_client(&state);
    let (mut w1, mut r1) = split_client(stream1);
    send_write(&mut w1, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w1,
        r#"{"type":"join","channel":"v1test","connection_type":"master"}"#,
    )
    .await;
    let _ = recv(&mut r1).await; // channel_joined
    let _ = recv(&mut r1).await; // motd

    // Client 2: v1 receiver (no protocol_version sent, defaults to 1)
    let stream2 = connect_client(&state);
    let (mut w2, mut r2) = split_client(stream2);
    // v1 client doesn't send protocol_version — just joins directly
    send_write(
        &mut w2,
        r#"{"type":"join","channel":"v1test","connection_type":"slave"}"#,
    )
    .await;
    let _ = recv(&mut r2).await; // channel_joined
    let _ = recv(&mut r2).await; // motd
    let _ = recv(&mut r1).await; // client_joined

    // v2 client sends a message
    send_write(&mut w1, r#"{"type":"key","vk_code":65}"#).await;

    // v1 client receives it — should NOT have origin field
    let msg = recv(&mut r2).await;
    assert_eq!(msg["type"], "key");
    assert_eq!(msg["vk_code"], 65);
    assert!(
        msg.get("origin").is_none(),
        "v1 client should not receive origin field"
    );
}

// ============================================================================
// Test: Channel is cleaned up when all clients leave
// ============================================================================

#[tokio::test]
async fn channel_destroyed_when_empty() {
    let state = setup_server();

    let stream = connect_client(&state);
    let (mut writer, mut reader) = split_client(stream);
    send_write(&mut writer, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut writer,
        r#"{"type":"join","channel":"temp","connection_type":"master"}"#,
    )
    .await;
    let _ = recv(&mut reader).await; // channel_joined
    let _ = recv(&mut reader).await; // motd

    assert!(state.channels.contains_key("temp"));

    // Disconnect
    drop(writer);
    drop(reader);

    // Give the handler time to process the disconnect
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        !state.channels.contains_key("temp"),
        "Channel should be destroyed after last client leaves"
    );
}

// ============================================================================
// Test: Multiple different channels are isolated
// ============================================================================

#[tokio::test]
async fn different_channels_are_isolated() {
    let state = setup_server();

    // Client 1 in channel A
    let stream1 = connect_client(&state);
    let (mut w1, mut r1) = split_client(stream1);
    send_write(&mut w1, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w1,
        r#"{"type":"join","channel":"channel_a","connection_type":"master"}"#,
    )
    .await;
    let _ = recv(&mut r1).await; // channel_joined
    let _ = recv(&mut r1).await; // motd

    // Client 2 in channel B
    let stream2 = connect_client(&state);
    let (mut w2, mut r2) = split_client(stream2);
    send_write(&mut w2, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w2,
        r#"{"type":"join","channel":"channel_b","connection_type":"slave"}"#,
    )
    .await;
    let _ = recv(&mut r2).await; // channel_joined
    let _ = recv(&mut r2).await; // motd

    // Client 1 sends a message in channel A
    send_write(&mut w1, r#"{"type":"key","vk_code":65}"#).await;

    // Client 2 should NOT receive it (different channel)
    let result = timeout(Duration::from_millis(200), r2.next_line()).await;
    assert!(
        result.is_err(),
        "Client in different channel should not receive the message"
    );
}

// ============================================================================
// Test: Invalid JSON is silently ignored (connection stays alive)
// ============================================================================

#[tokio::test]
async fn invalid_json_does_not_crash_connection() {
    let state = setup_server();
    let stream = connect_client(&state);
    let (mut writer, mut reader) = split_client(stream);

    // Send garbage
    send_write(&mut writer, "this is not json").await;
    send_write(&mut writer, "").await;
    send_write(&mut writer, "{broken").await;

    // Now send a valid generate_key — should still work
    send_write(&mut writer, r#"{"type":"generate_key"}"#).await;

    let msg = recv(&mut reader).await;
    assert_eq!(msg["type"], "generate_key");
    assert!(msg["key"].as_str().is_some());
}

// ============================================================================
// Test: Unknown message types before joining are silently ignored
// ============================================================================

#[tokio::test]
async fn unknown_message_before_join_is_ignored() {
    let state = setup_server();
    let stream = connect_client(&state);
    let (mut writer, mut reader) = split_client(stream);

    // Send unknown message type before joining
    send_write(&mut writer, r#"{"type":"speak","sequence":["hello"]}"#).await;

    // Should still be able to generate a key
    send_write(&mut writer, r#"{"type":"generate_key"}"#).await;

    let msg = recv(&mut reader).await;
    assert_eq!(msg["type"], "generate_key");
}

// ============================================================================
// Test: Three clients in same channel, relay goes to all others
// ============================================================================

#[tokio::test]
async fn three_clients_relay_to_all_others() {
    let state = setup_server();

    // Join 3 clients
    let stream1 = connect_client(&state);
    let (mut w1, mut r1) = split_client(stream1);
    send_write(&mut w1, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w1,
        r#"{"type":"join","channel":"group","connection_type":"master"}"#,
    )
    .await;
    let _ = recv(&mut r1).await; // channel_joined
    let _ = recv(&mut r1).await; // motd

    let stream2 = connect_client(&state);
    let (mut w2, mut r2) = split_client(stream2);
    send_write(&mut w2, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w2,
        r#"{"type":"join","channel":"group","connection_type":"slave"}"#,
    )
    .await;
    let _ = recv(&mut r2).await; // channel_joined
    let _ = recv(&mut r2).await; // motd
    let _ = recv(&mut r1).await; // client_joined

    let stream3 = connect_client(&state);
    let (mut w3, mut r3) = split_client(stream3);
    send_write(&mut w3, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w3,
        r#"{"type":"join","channel":"group","connection_type":"slave"}"#,
    )
    .await;
    let _ = recv(&mut r3).await; // channel_joined
    let _ = recv(&mut r3).await; // motd
    let _ = recv(&mut r1).await; // client_joined for client3
    let _ = recv(&mut r2).await; // client_joined for client3

    // Client 1 sends a message — clients 2 and 3 should both receive it
    send_write(&mut w1, r#"{"type":"key","vk_code":13}"#).await;

    let msg2 = recv(&mut r2).await;
    assert_eq!(msg2["type"], "key");
    assert_eq!(msg2["vk_code"], 13);

    let msg3 = recv(&mut r3).await;
    assert_eq!(msg3["type"], "key");
    assert_eq!(msg3["vk_code"], 13);
}

// ============================================================================
// Test: Braille display messages are relayed correctly
// ============================================================================

#[tokio::test]
async fn braille_messages_relayed() {
    let state = setup_server();

    let stream1 = connect_client(&state);
    let (mut w1, mut r1) = split_client(stream1);
    send_write(&mut w1, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w1,
        r#"{"type":"join","channel":"braille","connection_type":"master"}"#,
    )
    .await;
    let _ = recv(&mut r1).await;
    let _ = recv(&mut r1).await;

    let stream2 = connect_client(&state);
    let (mut w2, mut r2) = split_client(stream2);
    send_write(&mut w2, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w2,
        r#"{"type":"join","channel":"braille","connection_type":"slave"}"#,
    )
    .await;
    let _ = recv(&mut r2).await;
    let _ = recv(&mut r2).await;
    let _ = recv(&mut r1).await; // client_joined

    // Slave sends braille info
    send_write(
        &mut w2,
        r#"{"type":"set_braille_info","name":"test_display","numCells":40}"#,
    )
    .await;

    let msg = recv(&mut r1).await;
    assert_eq!(msg["type"], "set_braille_info");
    assert_eq!(msg["name"], "test_display");
    assert_eq!(msg["numCells"], 40);
}

// ============================================================================
// Test: Clipboard messages are relayed correctly
// ============================================================================

#[tokio::test]
async fn clipboard_messages_relayed() {
    let state = setup_server();

    let stream1 = connect_client(&state);
    let (mut w1, mut r1) = split_client(stream1);
    send_write(&mut w1, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w1,
        r#"{"type":"join","channel":"clip","connection_type":"master"}"#,
    )
    .await;
    let _ = recv(&mut r1).await;
    let _ = recv(&mut r1).await;

    let stream2 = connect_client(&state);
    let (mut w2, mut r2) = split_client(stream2);
    send_write(&mut w2, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut w2,
        r#"{"type":"join","channel":"clip","connection_type":"slave"}"#,
    )
    .await;
    let _ = recv(&mut r2).await;
    let _ = recv(&mut r2).await;
    let _ = recv(&mut r1).await;

    send_write(
        &mut w1,
        r#"{"type":"set_clipboard_text","text":"hello clipboard"}"#,
    )
    .await;

    let msg = recv(&mut r2).await;
    assert_eq!(msg["type"], "set_clipboard_text");
    assert_eq!(msg["text"], "hello clipboard");
}

// ============================================================================
// Test: Protocol version can be sent without joining (just sets state)
// ============================================================================

#[tokio::test]
async fn protocol_version_without_join_is_fine() {
    let state = setup_server();
    let stream = connect_client(&state);
    let (mut writer, mut reader) = split_client(stream);

    // Send protocol version multiple times — should not crash
    send_write(&mut writer, r#"{"type":"protocol_version","version":1}"#).await;
    send_write(&mut writer, r#"{"type":"protocol_version","version":2}"#).await;

    // Then join — should still work
    send_write(
        &mut writer,
        r#"{"type":"join","channel":"vtest","connection_type":"master"}"#,
    )
    .await;

    let msg = recv(&mut reader).await;
    assert_eq!(msg["type"], "channel_joined");
}

// ============================================================================
// Test: MOTD with always_send=false and non-empty message still sends
// ============================================================================

#[tokio::test]
async fn motd_sent_when_message_not_empty() {
    let state =
        nvdaremote_server_rs::server::ServerState::new(nvdaremote_server_rs::config::MotdConfig {
            message: "Custom MOTD".to_string(),
            always_send: false,
        });

    let stream = connect_client(&state);
    let (mut writer, mut reader) = split_client(stream);

    send_write(&mut writer, r#"{"type":"protocol_version","version":2}"#).await;
    send_write(
        &mut writer,
        r#"{"type":"join","channel":"motd_test","connection_type":"master"}"#,
    )
    .await;

    let _ = recv(&mut reader).await; // channel_joined

    let msg = recv(&mut reader).await;
    assert_eq!(msg["type"], "motd");
    assert_eq!(msg["motd"], "Custom MOTD");
    assert_eq!(msg["force_display"], false);
}
