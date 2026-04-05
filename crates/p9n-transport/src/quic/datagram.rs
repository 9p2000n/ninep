//! QUIC datagram handling for metadata messages with retry.

use super::framing;
use crate::error::TransportError;
use p9n_proto::fcall::Fcall;
use std::time::Duration;

/// Maximum retry attempts for datagram sends.
const MAX_RETRIES: u32 = 3;
/// Base delay for exponential backoff (doubled each retry).
const BASE_DELAY_MS: u64 = 10;

/// Send a message via QUIC datagram with retry on transient failures.
///
/// Returns `Ok(false)` if the message is too large for datagrams (caller should
/// use a stream instead). Returns `Ok(true)` on successful send.
pub async fn send_datagram(
    conn: &quinn::Connection,
    fc: &Fcall,
) -> Result<bool, TransportError> {
    let data = framing::encode(fc)?;

    let max = conn.max_datagram_size().unwrap_or(0);
    if data.len() > max {
        return Ok(false); // too large for datagram, use stream
    }

    let bytes: bytes::Bytes = data.into();

    for attempt in 0..MAX_RETRIES {
        match conn.send_datagram(bytes.clone()) {
            Ok(()) => return Ok(true),
            Err(e) => {
                if attempt + 1 < MAX_RETRIES {
                    let delay = Duration::from_millis(BASE_DELAY_MS << attempt);
                    tracing::debug!(
                        "datagram send failed (attempt {}/{}), retrying in {delay:?}: {e}",
                        attempt + 1,
                        MAX_RETRIES
                    );
                    tokio::time::sleep(delay).await;
                } else {
                    return Err(TransportError::Other(format!(
                        "datagram send failed after {MAX_RETRIES} attempts: {e}"
                    )));
                }
            }
        }
    }

    Ok(true)
}

/// Read a datagram from the connection.
pub async fn recv_datagram(conn: &quinn::Connection) -> Result<Fcall, TransportError> {
    let data = conn.read_datagram().await?;
    framing::decode(&data)
}
