pub mod client {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum Message {
        ProtocolVersion {
            version: u8,
        },
        Join {
            channel: String,
            connection_type: ConnectionType,
        },
        GenerateKey,
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "snake_case")]
    pub enum ConnectionType {
        Master,
        Slave,
    }
}

pub mod server {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum Message {
        Motd { motd: String },
        Error { error: String },
        Ping,
    }
}
