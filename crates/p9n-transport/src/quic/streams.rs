//! QUIC stream management for data operations.

use super::framing;
use crate::error::TransportError;
use p9n_proto::fcall::Fcall;

/// Send a message on a new bidirectional stream and read the response.
pub async fn stream_rpc(
    conn: &quinn::Connection,
    fc: &Fcall,
) -> Result<Fcall, TransportError> {
    let (mut send, mut recv) = conn.open_bi().await?;

    framing::write_message(&mut send, fc).await?;
    send.finish()?;

    let response = framing::read_message(&mut recv).await?;
    Ok(response)
}

/// Accept a server-push unidirectional stream and read messages from it.
pub async fn accept_push_stream(
    conn: &quinn::Connection,
) -> Result<quinn::RecvStream, TransportError> {
    let recv = conn.accept_uni().await?;
    Ok(recv)
}
