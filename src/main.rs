use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::sync::Arc;

use anyhow::{Context, Ok};
use futures::prelude::*;
use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::pem::PemObject;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_util::codec::AnyDelimiterCodec;
use tokio_util::codec::FramedRead;
use tracing::info;

mod app_config;
mod channel;
mod protocol;
mod server;
mod user;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let app_config = app_config::AppConfig::load().context("Failed to load app config")?;

    info!("Generating self signed certificate");

    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()])
        .context("Failed to generate self signed certificate")?;

    let mut bind_addresses: Vec<SocketAddr> = Vec::new();

    if let Some(bind_ipv6) = app_config.network.bind_ipv6 {
        let addrv6 = SocketAddrV6::new(bind_ipv6, app_config.network.port, 0, 0);
        bind_addresses.push(SocketAddr::V6(addrv6));
    }

    if let Some(bind_ipv4) = app_config.network.bind_ipv4 {
        let addrv4 = SocketAddrV4::new(bind_ipv4, app_config.network.port);
        bind_addresses.push(SocketAddr::V4(addrv4));
    }

    let mut server_sockets = Vec::new();
    
    for bind_address in bind_addresses {
        let server_socket = TcpListener::bind(bind_address).await.context("Failed to bind socket")?;
        info!("Bound to {:?}", server_socket.local_addr()?);

        server_sockets.push(server_socket);
    }
    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(
                PrivatePkcs8KeyDer::from_pem_slice(cert.key_pair.serialize_pem().as_bytes())
                    .context("Error selializing private key")?,
            ),
        )
        .context("Failed to build tls config")?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));


    let server = Arc::new(server::Server::<TlsStream<TcpStream>>::new());

    let mut join_handles = Vec::new();
    for server_socket in server_sockets {
        let server = server.clone();
        let tls_acceptor = tls_acceptor.clone();
            let handle = tokio::spawn(async move {
                loop {
        if let Err(error) =
            accept_connection(&server_socket, &tls_acceptor.clone(), server.clone()).await
        {
            tracing::error!("Error accepting connection: {:?}", error);
        }
    }
});
join_handles.push(handle);
}
    for handle in join_handles {
        handle.await?;
    }
    Ok(())
}

async fn accept_connection(
    listener: &TcpListener,
    tls_acceptor: &TlsAcceptor,
    server: Arc<server::Server<TlsStream<TcpStream>>>,
) -> anyhow::Result<()> {
    let (socket, remote_addr) = listener
        .accept()
        .await
        .context("Failed to accept connection")?;
    socket
        .set_nodelay(true)
        .context("Failed to set nodelay on socket")?;

    info!("Accepted connection from {}", remote_addr);
    let ssl_socket = tls_acceptor
        .accept(socket)
        .await
        .context("Failed to accept tls connection")?;

    info!("Accepted SSL connection from {}", remote_addr);
    tokio::spawn(async move {
        handle_connection(ssl_socket, server).await?;
        info!("Finished processing connection from {}", remote_addr);
        Ok(())
    });

    Ok(())
}

#[tracing::instrument]
async fn handle_connection(
    socket: TlsStream<TcpStream>,
    server: Arc<server::Server<TlsStream<TcpStream>>>,
) -> anyhow::Result<()> {
    let lines_codec_bytes =
        AnyDelimiterCodec::new_with_max_length(b"\n".to_vec(), b"\n".to_vec(), 1024 * 1024);

    let mut read_lines = FramedRead::new(socket, lines_codec_bytes);

    let handle = tokio::spawn(async move {
        while let Some(line_bytes) = read_lines.try_next().await.context("Failed to read line")? {
            let json: Value = serde_json::from_slice(&line_bytes).context("Error parsing json")?;
            info!("Received json: {:?}", json);

            let message: anyhow::Result<protocol::client::Message> =
                serde_json::from_value(json).context("Error parsing message");

            info!("Received message: {:?}", message);
        }
        Ok(())
    });

    handle.await??;
    Ok(())
}
