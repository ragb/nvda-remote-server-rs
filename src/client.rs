use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, instrument, warn};

use crate::observability::metrics as m;
use crate::protocol::{ClientInfo, ClientMessage, ConnectionType, ServerMessage};
use crate::server::{ChannelMember, ServerState};

const PING_INTERVAL: Duration = Duration::from_secs(120);

/// Per-client session state. Owns the outbound sender and tracks protocol state.
struct ClientSession {
    id: u64,
    protocol_version: u8,
    channel: Option<String>,
    connection_type: Option<ConnectionType>,
    tx: mpsc::UnboundedSender<String>,
    state: Arc<ServerState>,
}

impl ClientSession {
    fn new(id: u64, tx: mpsc::UnboundedSender<String>, state: Arc<ServerState>) -> Self {
        Self {
            id,
            protocol_version: 1,
            channel: None,
            connection_type: None,
            tx,
            state,
        }
    }

    fn send(&self, msg: &ServerMessage) {
        let _ = self.tx.send(msg.to_line());
    }

    fn handle_protocol_version(&mut self, version: u8) {
        self.protocol_version = version;
        info!(version, "Protocol version set");
    }

    fn handle_generate_key(&self) {
        let key = self.state.generate_key();
        info!(key = %key, "Generated key");
        self.send(&ServerMessage::GenerateKey { key });
        metrics::counter!(m::KEYS_GENERATED_TOTAL).increment(1);
    }

    fn handle_join(&mut self, channel: String, connection_type: Option<ConnectionType>) {
        let channel = channel.trim().to_string();
        if channel.is_empty() {
            warn!("Join rejected: empty channel name");
            self.send(&ServerMessage::Error {
                error: "invalid_parameters".to_string(),
            });
            metrics::counter!(m::JOIN_FAILURES_TOTAL).increment(1);
            return;
        }

        let e2e_supported = self.protocol_version >= 3;

        info!(channel = %channel, connection_type = ?connection_type, e2e_supported, "Joining channel");

        let member = ChannelMember {
            id: self.id,
            connection_type,
            protocol_version: self.protocol_version,
            sender: self.tx.clone(),
        };
        let (existing_ids, existing_clients) = self.state.join_channel(&channel, member);

        info!(
            channel = %channel,
            existing_members = existing_ids.len(),
            "Joined channel"
        );

        self.send(&ServerMessage::ChannelJoined {
            channel: channel.clone(),
            user_id: self.id,
            user_ids: existing_ids,
            clients: existing_clients,
            e2e_available: self.state.e2e_available,
        });

        if self.state.motd.always_send || !self.state.motd.message.is_empty() {
            self.send(&ServerMessage::Motd {
                motd: self.state.motd.message.clone(),
                force_display: self.state.motd.always_send,
            });
        }

        self.state.notify_channel(
            &channel,
            self.id,
            &ServerMessage::ClientJoined {
                user_id: self.id,
                client: ClientInfo {
                    id: self.id,
                    connection_type,
                    e2e_supported,
                },
            },
        );

        self.connection_type = connection_type;
        self.channel = Some(channel);
    }

    fn handle_relay(&self, raw_message: &str) {
        if let Some(ref channel) = self.channel {
            let forwarded = add_origin(raw_message, self.id);
            // If the message has a "to" field, forward only to that specific client
            if let Some(target_id) = extract_to_field(raw_message) {
                debug!(channel = %channel, target = target_id, "Targeted relay");
                self.state.send_to_client(channel, target_id, &forwarded);
                metrics::counter!(m::TARGETED_MESSAGES_TOTAL).increment(1);
            } else {
                debug!(channel = %channel, "Relaying message");
                self.state
                    .broadcast_to_channel(channel, self.id, &forwarded);
            }
            metrics::counter!(m::MESSAGES_RELAYED_TOTAL).increment(1);
            metrics::counter!(m::BYTES_RELAYED_TOTAL).increment(forwarded.len() as u64);
        }
    }

    fn disconnect(&mut self) {
        let Some(ref channel) = self.channel else {
            return;
        };
        info!(channel = %channel, "Leaving channel");
        if let Some(member) = self.state.leave_channel(channel, self.id) {
            self.state.notify_channel(
                channel,
                self.id,
                &ServerMessage::ClientLeft {
                    user_id: self.id,
                    client: ClientInfo {
                        id: self.id,
                        connection_type: member.connection_type,
                        e2e_supported: member.protocol_version >= 3,
                    },
                },
            );
        }
        self.channel = None;
    }
}

/// Handle a single client connection.
#[instrument(skip_all, fields(client_id))]
pub async fn handle_client<S>(stream: S, state: Arc<ServerState>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let client_id = state.next_client_id();
    tracing::Span::current().record("client_id", client_id);

    info!("Connected");
    metrics::counter!(m::CONNECTIONS_TOTAL).increment(1);
    metrics::gauge!(m::ACTIVE_CONNECTIONS).increment(1.0);

    let (reader, writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    let (tx, rx) = mpsc::unbounded_channel::<String>();

    let mut session = ClientSession::new(client_id, tx.clone(), state);
    let write_handle = spawn_writer(writer, rx);
    let ping_handle = spawn_ping(tx.clone());

    read_loop(&mut session, &mut lines).await;

    session.disconnect();
    ping_handle.abort();
    drop(tx);
    let _ = write_handle.await;

    info!("Disconnected");
    metrics::counter!(m::DISCONNECTIONS_TOTAL).increment(1);
    metrics::gauge!(m::ACTIVE_CONNECTIONS).decrement(1.0);
}

async fn read_loop<R: tokio::io::AsyncRead + Unpin>(
    session: &mut ClientSession,
    lines: &mut Lines<BufReader<tokio::io::ReadHalf<R>>>,
) {
    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => return,
            Err(e) => {
                debug!("Read error: {e}");
                return;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if session.channel.is_some() {
            handle_in_channel(session, trimmed);
        } else {
            handle_pre_join(session, trimmed);
        }
    }
}

fn handle_pre_join(session: &mut ClientSession, raw: &str) {
    let msg: ClientMessage = match serde_json::from_str(raw) {
        Ok(msg) => msg,
        Err(e) => {
            warn!(raw = raw, "Ignoring unparseable message: {e}");
            return;
        }
    };

    match msg {
        ClientMessage::ProtocolVersion { version } => session.handle_protocol_version(version),
        ClientMessage::GenerateKey => session.handle_generate_key(),
        ClientMessage::Join {
            channel,
            connection_type,
        } => {
            session.handle_join(channel, connection_type);
        }
    }
}

fn handle_in_channel(session: &mut ClientSession, raw: &str) {
    if let Ok(ClientMessage::ProtocolVersion { version }) = serde_json::from_str(raw) {
        session.handle_protocol_version(version);
    } else {
        session.handle_relay(raw);
    }
}

#[instrument(skip_all)]
fn spawn_writer<W: tokio::io::AsyncWrite + Unpin + Send + 'static>(
    mut writer: W,
    mut rx: mpsc::UnboundedReceiver<String>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if writer.write_all(msg.as_bytes()).await.is_err() {
                warn!("Write failed, closing writer");
                break;
            }
            if writer.flush().await.is_err() {
                warn!("Flush failed, closing writer");
                break;
            }
        }
    })
}

fn spawn_ping(tx: mpsc::UnboundedSender<String>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PING_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            if tx.send(ServerMessage::Ping.to_line()).is_err() {
                break;
            }
        }
    })
}

/// Extract the `to` field from a raw JSON message, if present.
/// Used for targeted forwarding — when `to` is set, the message goes only to that user_id.
fn extract_to_field(message: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(message)
        .ok()
        .and_then(|v| v.get("to")?.as_u64())
}

/// Add `origin` field to a forwarded message for protocol v2 clients.
pub(crate) fn add_origin(message: &str, client_id: u64) -> String {
    match serde_json::from_str::<serde_json::Value>(message) {
        Ok(mut value) => {
            if let Some(obj) = value.as_object_mut() {
                obj.insert("origin".to_string(), serde_json::Value::from(client_id));
            }
            let mut s = serde_json::to_string(&value).unwrap_or_else(|_| message.to_string());
            s.push('\n');
            s
        }
        Err(_) => format!("{message}\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_origin_inserts_origin_field() {
        let msg = r#"{"type":"key","vk_code":65}"#;
        let result = add_origin(msg, 42);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["origin"], 42);
        assert_eq!(json["type"], "key");
        assert_eq!(json["vk_code"], 65);
    }

    #[test]
    fn add_origin_overwrites_existing_origin() {
        let msg = r#"{"type":"key","origin":1}"#;
        let result = add_origin(msg, 99);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["origin"], 99);
    }

    #[test]
    fn add_origin_ends_with_newline() {
        let msg = r#"{"type":"speak"}"#;
        let result = add_origin(msg, 1);
        assert!(result.ends_with('\n'));
    }

    #[test]
    fn add_origin_handles_invalid_json() {
        let msg = "not json";
        let result = add_origin(msg, 1);
        assert!(result.contains("not json"));
        assert!(result.ends_with('\n'));
    }
}
