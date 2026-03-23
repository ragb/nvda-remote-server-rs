use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub network: NetworkConfig,
    pub motd: MotdConfig,
    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub bind_ipv4: Option<String>,
    pub bind_ipv6: Option<String>,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MotdConfig {
    pub message: String,
    pub always_send: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let config = config::Config::builder()
            .add_source(config::File::with_name("config/config"))
            .add_source(config::Environment::with_prefix("NVDAREMOTE").separator("__"))
            .build()
            .context("Failed to load configuration")?;

        config
            .try_deserialize()
            .context("Failed to deserialize configuration")
    }
}
