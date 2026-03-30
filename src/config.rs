use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub network: NetworkConfig,
    pub motd: MotdConfig,
    #[serde(default)]
    pub e2e: E2eConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
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

#[derive(Debug, Deserialize, Clone)]
pub struct E2eConfig {
    pub allow: bool,
}

impl Default for E2eConfig {
    fn default() -> Self {
        Self { allow: true }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "MetricsConfig::default_bind")]
    pub bind: String,
    #[serde(default = "MetricsConfig::default_port")]
    pub port: u16,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: Self::default_bind(),
            port: Self::default_port(),
        }
    }
}

impl MetricsConfig {
    fn default_bind() -> String {
        "127.0.0.1".to_string()
    }
    fn default_port() -> u16 {
        9090
    }
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
