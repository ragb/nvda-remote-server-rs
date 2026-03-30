use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::config::MotdConfig;
use crate::protocol::{ClientInfo, ConnectionType, ServerMessage};

/// Shared server state, wrapped in Arc for sharing across tasks.
pub struct ServerState {
    pub channels: DashMap<String, Channel>,
    pub motd: MotdConfig,
    pub e2e_available: bool,
    next_client_id: AtomicU64,
}

pub struct Channel {
    pub members: Vec<ChannelMember>,
}

pub struct ChannelMember {
    pub id: u64,
    pub connection_type: Option<ConnectionType>,
    pub protocol_version: u8,
    pub sender: mpsc::UnboundedSender<String>,
}

impl ServerState {
    pub fn new(motd: MotdConfig, e2e_available: bool) -> Arc<Self> {
        Arc::new(Self {
            channels: DashMap::new(),
            motd,
            e2e_available,
            next_client_id: AtomicU64::new(1),
        })
    }

    pub fn next_client_id(&self) -> u64 {
        self.next_client_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn generate_key(&self) -> String {
        use rand::RngExt;
        let mut rng = rand::rng();
        loop {
            let key: String = (0..9)
                .map(|_| rng.random_range(0..10).to_string())
                .collect();
            if !self.channels.contains_key(&key) {
                return key;
            }
        }
    }

    /// Add a client to a channel (creating it if needed).
    /// Returns the list of existing members' info (before adding) and their user_ids.
    pub fn join_channel(
        &self,
        channel_name: &str,
        member: ChannelMember,
    ) -> (Vec<u64>, Vec<ClientInfo>) {
        let mut channel = self
            .channels
            .entry(channel_name.to_string())
            .or_insert_with(|| {
                info!(channel = channel_name, "Channel created");
                Channel {
                    members: Vec::new(),
                }
            });

        let existing_ids: Vec<u64> = channel.members.iter().map(|m| m.id).collect();
        let existing_clients: Vec<ClientInfo> = channel
            .members
            .iter()
            .map(|m| ClientInfo {
                id: m.id,
                connection_type: m.connection_type,
                e2e_supported: m.protocol_version >= 3,
            })
            .collect();

        let member_id = member.id;
        channel.members.push(member);

        debug!(
            channel = channel_name,
            client_id = member_id,
            members = channel.members.len(),
            "Client added to channel"
        );

        (existing_ids, existing_clients)
    }

    /// Remove a client from a channel. Returns the removed member's info if found.
    /// Cleans up empty channels.
    pub fn leave_channel(&self, channel_name: &str, client_id: u64) -> Option<ChannelMember> {
        let mut removed = None;

        if let Some(mut channel) = self.channels.get_mut(channel_name)
            && let Some(pos) = channel.members.iter().position(|m| m.id == client_id)
        {
            removed = Some(channel.members.remove(pos));
        }

        self.channels.remove_if(channel_name, |_, channel| {
            let empty = channel.members.is_empty();
            if empty {
                info!(channel = channel_name, "Channel destroyed (empty)");
            } else {
                debug!(
                    channel = channel_name,
                    remaining = channel.members.len(),
                    "Client removed from channel"
                );
            }
            empty
        });

        removed
    }

    /// Broadcast a message to all members of a channel except the sender.
    /// For protocol v1 clients, strips origin/client/clients fields from forwarded messages.
    pub fn broadcast_to_channel(&self, channel_name: &str, sender_id: u64, message: &str) {
        if let Some(channel) = self.channels.get(channel_name) {
            for member in &channel.members {
                if member.id != sender_id {
                    let msg = if member.protocol_version < 2 {
                        strip_v2_fields(message)
                    } else {
                        message.to_string()
                    };
                    let _ = member.sender.send(msg);
                }
            }
        }
    }

    /// Send a message to a specific client in a channel by user_id.
    /// Used for `to`-based targeted forwarding (e.g. e2e_data messages).
    /// Returns true if the target was found and the message was sent.
    pub fn send_to_client(&self, channel_name: &str, target_id: u64, message: &str) -> bool {
        if let Some(channel) = self.channels.get(channel_name) {
            for member in &channel.members {
                if member.id == target_id {
                    let msg = if member.protocol_version < 2 {
                        strip_v2_fields(message)
                    } else {
                        message.to_string()
                    };
                    let _ = member.sender.send(msg);
                    return true;
                }
            }
        }
        false
    }

    /// Send a server message to all members of a channel except the given client.
    pub fn notify_channel(&self, channel_name: &str, except_id: u64, msg: &ServerMessage) {
        let line = msg.to_line();
        if let Some(channel) = self.channels.get(channel_name) {
            for member in &channel.members {
                if member.id != except_id {
                    let _ = member.sender.send(line.clone());
                }
            }
        }
    }
}

/// Stats for the admin dashboard and metrics endpoints.
impl ServerState {
    /// Total number of connected clients across all channels.
    pub fn connection_count(&self) -> usize {
        self.channels.iter().map(|c| c.members.len()).sum()
    }

    /// Number of active channels.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Per-channel details: (channel_name, member_count).
    pub fn channel_details(&self) -> Vec<(String, usize)> {
        self.channels
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().members.len()))
            .collect()
    }
}

/// Strip protocol v2 fields (origin, client, clients) from a JSON message
/// for backwards compatibility with v1 clients.
pub(crate) fn strip_v2_fields(message: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(message) {
        if let Some(obj) = value.as_object_mut() {
            obj.remove("origin");
            obj.remove("client");
            obj.remove("clients");
        }
        let mut s = serde_json::to_string(&value).unwrap_or_else(|_| message.to_string());
        if !s.ends_with('\n') {
            s.push('\n');
        }
        s
    } else {
        message.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MotdConfig;

    fn test_motd() -> MotdConfig {
        MotdConfig {
            message: "Test MOTD".to_string(),
            always_send: true,
        }
    }

    fn make_member(
        id: u64,
        conn_type: Option<ConnectionType>,
        version: u8,
    ) -> (ChannelMember, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let member = ChannelMember {
            id,
            connection_type: conn_type,
            protocol_version: version,
            sender: tx,
        };
        (member, rx)
    }

    #[test]
    fn client_ids_are_sequential() {
        let state = ServerState::new(test_motd(), true);
        assert_eq!(state.next_client_id(), 1);
        assert_eq!(state.next_client_id(), 2);
        assert_eq!(state.next_client_id(), 3);
    }

    #[test]
    fn generate_key_is_9_digits() {
        let state = ServerState::new(test_motd(), true);
        for _ in 0..20 {
            let key = state.generate_key();
            assert_eq!(key.len(), 9);
            assert!(key.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn generate_key_avoids_existing_channels() {
        let state = ServerState::new(test_motd(), true);
        // Fill a bunch of channels — keys should still be unique
        let (member, _rx) = make_member(1, None, 2);
        state.join_channel("000000000", member);
        let key = state.generate_key();
        assert_ne!(key, "000000000");
    }

    #[test]
    fn join_creates_channel() {
        let state = ServerState::new(test_motd(), true);
        let (member, _rx) = make_member(1, Some(ConnectionType::Master), 2);
        let (ids, clients) = state.join_channel("testchan", member);
        assert!(ids.is_empty());
        assert!(clients.is_empty());
        assert!(state.channels.contains_key("testchan"));
    }

    #[test]
    fn join_returns_existing_members() {
        let state = ServerState::new(test_motd(), true);

        let (m1, _rx1) = make_member(1, Some(ConnectionType::Master), 2);
        state.join_channel("chan", m1);

        let (m2, _rx2) = make_member(2, Some(ConnectionType::Slave), 2);
        let (ids, clients) = state.join_channel("chan", m2);

        assert_eq!(ids, vec![1]);
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].id, 1);
        assert_eq!(clients[0].connection_type, Some(ConnectionType::Master));
    }

    #[test]
    fn leave_removes_member() {
        let state = ServerState::new(test_motd(), true);

        let (m1, _rx1) = make_member(1, Some(ConnectionType::Master), 2);
        let (m2, _rx2) = make_member(2, Some(ConnectionType::Slave), 2);
        state.join_channel("chan", m1);
        state.join_channel("chan", m2);

        let removed = state.leave_channel("chan", 1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, 1);

        // Channel still exists with member 2
        assert!(state.channels.contains_key("chan"));
        let chan = state.channels.get("chan").unwrap();
        assert_eq!(chan.members.len(), 1);
        assert_eq!(chan.members[0].id, 2);
    }

    #[test]
    fn leave_last_member_destroys_channel() {
        let state = ServerState::new(test_motd(), true);

        let (m1, _rx1) = make_member(1, None, 2);
        state.join_channel("chan", m1);

        state.leave_channel("chan", 1);
        assert!(!state.channels.contains_key("chan"));
    }

    #[test]
    fn leave_nonexistent_returns_none() {
        let state = ServerState::new(test_motd(), true);
        let result = state.leave_channel("nonexistent", 999);
        assert!(result.is_none());
    }

    #[test]
    fn broadcast_sends_to_others_not_self() {
        let state = ServerState::new(test_motd(), true);

        let (m1, mut rx1) = make_member(1, None, 2);
        let (m2, mut rx2) = make_member(2, None, 2);
        let (m3, mut rx3) = make_member(3, None, 2);
        state.join_channel("chan", m1);
        state.join_channel("chan", m2);
        state.join_channel("chan", m3);

        state.broadcast_to_channel("chan", 1, "{\"type\":\"key\",\"origin\":1}\n");

        // Sender (1) should NOT receive
        assert!(rx1.try_recv().is_err());
        // Others should receive
        assert!(rx2.try_recv().is_ok());
        assert!(rx3.try_recv().is_ok());
    }

    #[test]
    fn broadcast_strips_v2_fields_for_v1_clients() {
        let state = ServerState::new(test_motd(), true);

        let (m1, _rx1) = make_member(1, None, 2); // sender, v2
        let (m2, mut rx2) = make_member(2, None, 1); // receiver, v1
        let (m3, mut rx3) = make_member(3, None, 2); // receiver, v2
        state.join_channel("chan", m1);
        state.join_channel("chan", m2);
        state.join_channel("chan", m3);

        let msg = "{\"type\":\"key\",\"origin\":1,\"client\":{\"id\":1}}\n";
        state.broadcast_to_channel("chan", 1, msg);

        let v1_msg = rx2.try_recv().unwrap();
        let v1_json: serde_json::Value = serde_json::from_str(&v1_msg).unwrap();
        assert!(
            v1_json.get("origin").is_none(),
            "v1 client should not receive origin field"
        );
        assert!(
            v1_json.get("client").is_none(),
            "v1 client should not receive client field"
        );

        let v2_msg = rx3.try_recv().unwrap();
        let v2_json: serde_json::Value = serde_json::from_str(&v2_msg).unwrap();
        assert!(
            v2_json.get("origin").is_some(),
            "v2 client should receive origin field"
        );
    }

    #[test]
    fn notify_channel_sends_to_others() {
        let state = ServerState::new(test_motd(), true);

        let (m1, mut rx1) = make_member(1, None, 2);
        let (m2, mut rx2) = make_member(2, None, 2);
        state.join_channel("chan", m1);
        state.join_channel("chan", m2);

        state.notify_channel("chan", 1, &ServerMessage::Ping);

        assert!(rx1.try_recv().is_err());
        let msg = rx2.try_recv().unwrap();
        let json: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(json["type"], "ping");
    }

    #[test]
    fn strip_v2_fields_removes_origin_client_clients() {
        let input = r#"{"type":"key","origin":1,"client":{"id":1},"clients":[{"id":1}],"key":"a"}"#;
        let result = strip_v2_fields(input);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json.get("origin").is_none());
        assert!(json.get("client").is_none());
        assert!(json.get("clients").is_none());
        assert_eq!(json["type"], "key");
        assert_eq!(json["key"], "a");
    }

    #[test]
    fn strip_v2_fields_preserves_other_fields() {
        let input = r#"{"type":"speak","sequence":["hello"]}"#;
        let result = strip_v2_fields(input);
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["type"], "speak");
        assert_eq!(json["sequence"][0], "hello");
    }

    #[test]
    fn strip_v2_fields_adds_newline() {
        let input = r#"{"type":"key"}"#;
        let result = strip_v2_fields(input);
        assert!(result.ends_with('\n'));
    }

    #[test]
    fn strip_v2_fields_handles_invalid_json() {
        let input = "not json at all";
        let result = strip_v2_fields(input);
        assert_eq!(result, input);
    }
}
