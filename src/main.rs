mod client;
mod config;
mod protocol;
mod server;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, instrument, warn};

use crate::config::AppConfig;
use crate::server::ServerState;

fn load_tls_from_files(
    cert_path: &str,
    key_path: &str,
) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> {
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("Failed to read cert file: {cert_path}"))?;
    let key_pem =
        std::fs::read(key_path).with_context(|| format!("Failed to read key file: {key_path}"))?;

    let cert = rustls_pemfile::certs(&mut &cert_pem[..])
        .next()
        .ok_or_else(|| anyhow::anyhow!("No certificate found in {cert_path}"))??;
    let key = rustls_pemfile::pkcs8_private_keys(&mut &key_pem[..])
        .next()
        .ok_or_else(|| anyhow::anyhow!("No PKCS8 private key found in {key_path}"))??;

    Ok((cert, key))
}

fn generate_and_save_tls(
    cert_path: &str,
    key_path: &str,
) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()])
        .context("Failed to generate self-signed certificate")?;

    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    std::fs::write(cert_path, &cert_pem)
        .with_context(|| format!("Failed to write cert file: {cert_path}"))?;
    std::fs::write(key_path, &key_pem)
        .with_context(|| format!("Failed to write key file: {key_path}"))?;

    info!("Self-signed TLS certificate generated and saved");

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    Ok((cert_der, key_der))
}

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

    let cert_path = config.tls.cert_path.as_deref().unwrap_or("cert.pem");
    let key_path = config.tls.key_path.as_deref().unwrap_or("key.pem");

    let (cert_der, key_der) = if Path::new(cert_path).exists() && Path::new(key_path).exists() {
        info!("Loading TLS certificate from disk");
        load_tls_from_files(cert_path, key_path)?
    } else {
        generate_and_save_tls(cert_path, key_path)?
    };

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
