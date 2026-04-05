//! TCP+TLS configuration using tokio-rustls.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream};

/// Create a TCP+TLS server listener.
pub async fn server_listener(
    bind: SocketAddr,
    tls_config: rustls::ServerConfig,
) -> Result<(TcpListener, TlsAcceptor), std::io::Error> {
    let listener = TcpListener::bind(bind).await?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    Ok((listener, acceptor))
}

/// Accept and TLS-handshake a single TCP connection.
pub async fn accept_tls(
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
) -> Result<(ServerTlsStream<TcpStream>, SocketAddr), std::io::Error> {
    let (stream, addr) = listener.accept().await?;
    let tls_stream = acceptor.accept(stream).await?;
    Ok((tls_stream, addr))
}

/// Connect to a TCP+TLS server.
pub async fn client_connect(
    addr: SocketAddr,
    hostname: &str,
    tls_config: rustls::ClientConfig,
) -> Result<ClientTlsStream<TcpStream>, std::io::Error> {
    let connector = TlsConnector::from(Arc::new(tls_config));
    let stream = TcpStream::connect(addr).await?;
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let tls_stream = connector.connect(server_name, stream).await?;
    Ok(tls_stream)
}
