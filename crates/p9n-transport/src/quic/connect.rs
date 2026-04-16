//! QUIC client connect helper.
//!
//! Performs a full 1-RTT handshake. 0-RTT is deliberately not attempted:
//! 9P negotiation messages (Tversion, Tcaps, Tsession) are classified as
//! Metadata and routed via QUIC datagrams, and datagrams sent during the
//! 0-RTT window may be silently dropped before the handshake is confirmed,
//! triggering a 30-second response timeout. See `docs/ARCH_DESIGN_DECISION.md`.

use std::net::SocketAddr;

/// Connect to a QUIC server using a full 1-RTT handshake.
pub async fn connect(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    server_name: &str,
) -> Result<quinn::Connection, Box<dyn std::error::Error + Send + Sync>> {
    let conn = endpoint.connect(addr, server_name)?.await?;
    Ok(conn)
}
