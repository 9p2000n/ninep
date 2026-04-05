//! QUIC 0-RTT connection support.
//!
//! When a client reconnects to a server it has previously connected to (and the
//! endpoint still holds a TLS session ticket), quinn can establish the connection
//! with zero additional round-trips, allowing early data to be sent immediately.
//!
//! Requirements for 0-RTT to succeed:
//! - rustls `ClientConfig::enable_early_data` must be `true`
//! - rustls `ServerConfig::max_early_data_size` must be `0xFFFF_FFFF` (for QUIC)
//! - The client must reuse the same `quinn::Endpoint` (session tickets are stored
//!   in the rustls `ClientSessionStore` inside the endpoint's `ClientConfig`)

use std::net::SocketAddr;

/// Result of a 0-RTT-aware connection attempt.
pub struct ConnectResult {
    pub conn: quinn::Connection,
    /// `true` if 0-RTT early data was attempted (session ticket was available).
    /// Note: even when `true`, the server may reject the early data — quinn
    /// falls back to 1-RTT transparently in that case.
    pub used_0rtt: bool,
}

/// Connect to a QUIC server, attempting 0-RTT when a session ticket is available.
///
/// Falls back to a normal 1-RTT handshake if no ticket is cached (first connection)
/// or if the server does not support 0-RTT.
pub async fn connect(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    server_name: &str,
) -> Result<ConnectResult, Box<dyn std::error::Error + Send + Sync>> {
    let connecting = endpoint.connect(addr, server_name)?;

    match connecting.into_0rtt() {
        Ok((conn, zero_rtt_accepted)) => {
            // 0-RTT path: connection is usable immediately.
            // Spawn a background task to log whether the server accepted the early data.
            tokio::spawn(async move {
                if zero_rtt_accepted.await {
                    tracing::debug!("0-RTT accepted by server");
                } else {
                    tracing::debug!("0-RTT rejected by server, fell back to 1-RTT");
                }
            });
            Ok(ConnectResult {
                conn,
                used_0rtt: true,
            })
        }
        Err(connecting) => {
            // No session ticket — full 1-RTT handshake.
            let conn = connecting.await?;
            Ok(ConnectResult {
                conn,
                used_0rtt: false,
            })
        }
    }
}
