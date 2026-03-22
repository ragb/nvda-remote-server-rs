mod client;
mod config;
mod protocol;
mod server;

use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, instrument, warn};

use crate::config::AppConfig;
use crate::server::ServerState;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = AppConfig::load()?;
    info!("Configuration loaded");

    let cert = generate_simple_self_signed(vec!["localhost".to_string()])
        .context("Failed to generate self-signed certificate")?;
    info!("Self-signed TLS certificate generated");

    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .context("Failed to build TLS config")?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let state = ServerState::new(config.motd);

    let mut listeners = Vec::new();

    if let Some(ref addr) = config.network.bind_ipv4 {
        let bind = format!("{addr}:{}", config.network.port);
        let listener = TcpListener::bind(&bind)
            .await
            .with_context(|| format!("Failed to bind to {bind}"))?;
        info!(address = %bind, "Listening (IPv4)");
        listeners.push(listener);
    }

    if let Some(ref addr) = config.network.bind_ipv6 {
        let bind = format!("[{addr}]:{}", config.network.port);
        let listener = TcpListener::bind(&bind)
            .await
            .with_context(|| format!("Failed to bind to {bind}"))?;
        info!(address = %bind, "Listening (IPv6)");
        listeners.push(listener);
    }

    if listeners.is_empty() {
        anyhow::bail!("No bind addresses configured");
    }

    let mut handles = Vec::new();
    for listener in listeners {
        let acceptor = acceptor.clone();
        let state = state.clone();
        handles.push(tokio::spawn(accept_loop(listener, acceptor, state)));
    }

    for handle in handles {
        if let Err(e) = handle.await {
            error!("Accept loop panicked: {e}");
        }
    }

    Ok(())
}

#[instrument(skip_all, fields(addr = %listener.local_addr().unwrap()))]
async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, state: Arc<ServerState>) {
    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to accept TCP connection: {e}");
                continue;
            }
        };

        if let Err(e) = tcp_stream.set_nodelay(true) {
            warn!(peer = %peer_addr, "Failed to set TCP_NODELAY: {e}");
        }

        let acceptor = acceptor.clone();
        let state = state.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    warn!(peer = %peer_addr, "TLS handshake failed: {e}");
                    return;
                }
            };

            client::handle_client(tls_stream, state).await;
        });
    }
}
