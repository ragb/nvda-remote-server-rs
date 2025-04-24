use anyhow::Context;
use serde::{Deserialize, Serialize};
pub const DEFAULT_CONFIG_PATH: &str = "config/config.toml";

#[derive(Serialize, Deserialize, Debug)]
pub struct AppConfig {
    pub network: NetworkConfig,
    pub motd: Motd,
}

impl AppConfig {
    pub fn load() -> anyhow::Result<Self> {
        config::Config::builder()
            .add_source(config::File::with_name(DEFAULT_CONFIG_PATH))
            .build()
            .context("Failed to load app config")?
            .try_deserialize()
            .context("Failed to parse app config")
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkConfig {
    pub bind_ipv4: Option<std::net::Ipv4Addr>,
    pub bind_ipv6: Option<std::net::Ipv6Addr>,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Motd {
    pub message: String,
    pub always_send: bool,
}
