use serde::{Deserialize, Serialize};

/// Messages sent from client to server.
/// Only the types the server needs to understand are parsed explicitly.
/// All other messages are forwarded as-is to channel peers.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    ProtocolVersion {
        version: u8,
    },
    Join {
        channel: String,
        connection_type: Option<ConnectionType>,
    },
    GenerateKey,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionType {
    Master,
    Slave,
}

/// Messages sent from server to client.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Motd {
        motd: String,
        force_display: bool,
    },
    GenerateKey {
        key: String,
    },
    ChannelJoined {
        channel: String,
        user_id: u64,
        user_ids: Vec<u64>,
        clients: Vec<ClientInfo>,
        e2e_available: bool,
    },
    ClientJoined {
        user_id: u64,
        client: ClientInfo,
    },
    ClientLeft {
        user_id: u64,
        client: ClientInfo,
    },
    Error {
        error: String,
    },
    Ping,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientInfo {
    pub id: u64,
    pub connection_type: Option<ConnectionType>,
    pub e2e_supported: bool,
}

impl ServerMessage {
    pub fn to_line(&self) -> String {
        let mut s = serde_json::to_string(self).expect("ServerMessage serialization cannot fail");
        s.push('\n');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_protocol_version() {
        let json = r#"{"type":"protocol_version","version":2}"#;
        let msg: ClientMessage = serde_json::from_str(json).unwrap();
        match msg {
            ClientMessage::ProtocolVersion { version } => assert_eq!(version, 2),
            _ => panic!("Expected ProtocolVersion"),
        }
    }

    #[test]
    fn parse_join_master() {
        let json = r#"{"type":"join","channel":"123456789","connection_type":"master"}"#;
        let msg: ClientMessage = serde_json::from_str(json).unwrap();
        match msg {
            ClientMessage::Join {
                channel,
                connection_type,
            } => {
                assert_eq!(channel, "123456789");
                assert_eq!(connection_type, Some(ConnectionType::Master));
            }
            _ => panic!("Expected Join"),
        }
    }

    #[test]
    fn parse_join_slave() {
        let json = r#"{"type":"join","channel":"key123","connection_type":"slave"}"#;
        let msg: ClientMessage = serde_json::from_str(json).unwrap();
        match msg {
            ClientMessage::Join {
                channel,
                connection_type,
            } => {
                assert_eq!(channel, "key123");
                assert_eq!(connection_type, Some(ConnectionType::Slave));
            }
            _ => panic!("Expected Join"),
        }
    }

    #[test]
    fn parse_join_no_connection_type() {
        let json = r#"{"type":"join","channel":"key123"}"#;
        let msg: ClientMessage = serde_json::from_str(json).unwrap();
        match msg {
            ClientMessage::Join {
                connection_type, ..
            } => {
                assert_eq!(connection_type, None);
            }
            _ => panic!("Expected Join"),
        }
    }

    #[test]
    fn parse_generate_key() {
        let json = r#"{"type":"generate_key"}"#;
        let msg: ClientMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, ClientMessage::GenerateKey));
    }

    #[test]
    fn unknown_type_fails_parse() {
        let json = r#"{"type":"speak","sequence":[]}"#;
        let result = serde_json::from_str::<ClientMessage>(json);
        assert!(result.is_err());
    }

    #[test]
    fn serialize_motd() {
        let msg = ServerMessage::Motd {
            motd: "Welcome".to_string(),
            force_display: true,
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(json["type"], "motd");
        assert_eq!(json["motd"], "Welcome");
        assert_eq!(json["force_display"], true);
    }

    #[test]
    fn serialize_channel_joined() {
        let msg = ServerMessage::ChannelJoined {
            channel: "test".to_string(),
            user_id: 3,
            user_ids: vec![1, 2],
            e2e_available: true,
            clients: vec![
                ClientInfo {
                    id: 1,
                    connection_type: Some(ConnectionType::Master),
                    e2e_supported: true,
                },
                ClientInfo {
                    id: 2,
                    connection_type: Some(ConnectionType::Slave),
                    e2e_supported: false,
                },
            ],
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(json["type"], "channel_joined");
        assert_eq!(json["channel"], "test");
        assert_eq!(json["user_id"], 3);
        assert_eq!(json["user_ids"], serde_json::json!([1, 2]));
        assert_eq!(json["clients"][0]["connection_type"], "master");
        assert_eq!(json["clients"][0]["e2e_supported"], true);
        assert_eq!(json["clients"][1]["connection_type"], "slave");
        assert_eq!(json["clients"][1]["e2e_supported"], false);
        assert_eq!(json["e2e_available"], true);
    }

    #[test]
    fn serialize_client_joined() {
        let msg = ServerMessage::ClientJoined {
            user_id: 5,
            client: ClientInfo {
                id: 5,
                connection_type: Some(ConnectionType::Master),
                e2e_supported: true,
            },
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(json["type"], "client_joined");
        assert_eq!(json["user_id"], 5);
        assert_eq!(json["client"]["id"], 5);
        assert_eq!(json["client"]["e2e_supported"], true);
    }

    #[test]
    fn serialize_client_left() {
        let msg = ServerMessage::ClientLeft {
            user_id: 3,
            client: ClientInfo {
                id: 3,
                connection_type: Some(ConnectionType::Slave),
                e2e_supported: false,
            },
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(json["type"], "client_left");
        assert_eq!(json["user_id"], 3);
        assert_eq!(json["client"]["e2e_supported"], false);
    }

    #[test]
    fn serialize_generate_key_response() {
        let msg = ServerMessage::GenerateKey {
            key: "123456789".to_string(),
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(json["type"], "generate_key");
        assert_eq!(json["key"], "123456789");
    }

    #[test]
    fn serialize_error() {
        let msg = ServerMessage::Error {
            error: "invalid_parameters".to_string(),
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(json["type"], "error");
        assert_eq!(json["error"], "invalid_parameters");
    }

    #[test]
    fn serialize_ping() {
        let msg = ServerMessage::Ping;
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(json["type"], "ping");
    }

    #[test]
    fn to_line_ends_with_newline() {
        let msg = ServerMessage::Ping;
        let line = msg.to_line();
        assert!(line.ends_with('\n'));
        assert!(!line[..line.len() - 1].contains('\n'));
    }

    #[test]
    fn client_info_none_connection_type() {
        let info = ClientInfo {
            id: 1,
            connection_type: None,
            e2e_supported: false,
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&info).unwrap()).unwrap();
        assert_eq!(json["id"], 1);
        assert!(json["connection_type"].is_null());
        assert_eq!(json["e2e_supported"], false);
    }
}
