//! Transport-agnostic 9P message framing.
//!
//! Works with any `AsyncRead`/`AsyncWrite` — QUIC streams, TCP sockets, etc.

use crate::error::TransportError;
use p9n_proto::buf::Buf;
use p9n_proto::codec;
use p9n_proto::fcall::Fcall;
use p9n_proto::types::HEADER_SIZE;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Serialize an Fcall to wire bytes (zero-copy).
pub fn encode(fc: &Fcall) -> Result<Vec<u8>, TransportError> {
    let mut buf = Buf::new(256);
    codec::marshal(&mut buf, fc)?;
    Ok(buf.into_vec())
}

/// Deserialize wire bytes to an Fcall (zero-copy, takes ownership).
pub fn decode_owned(data: Vec<u8>) -> Result<Fcall, TransportError> {
    let mut buf = Buf::from_bytes(data);
    let fc = codec::unmarshal(&mut buf)?;
    Ok(fc)
}

/// Deserialize from borrowed bytes.
pub fn decode(data: &[u8]) -> Result<Fcall, TransportError> {
    let mut buf = Buf::from_bytes(data.to_vec());
    let fc = codec::unmarshal(&mut buf)?;
    Ok(fc)
}

/// Read a single framed 9P message from any async reader.
pub async fn read_message<R: AsyncReadExt + Unpin>(
    recv: &mut R,
) -> Result<Fcall, TransportError> {
    let mut size_buf = [0u8; 4];
    recv.read_exact(&mut size_buf).await.map_err(|e| TransportError::Io(e))?;
    let size = u32::from_le_bytes(size_buf) as usize;

    if size < HEADER_SIZE {
        return Err(TransportError::Other(format!("message too small: {size}")));
    }

    let mut msg_buf = vec![0u8; size];
    msg_buf[..4].copy_from_slice(&size_buf);
    recv.read_exact(&mut msg_buf[4..]).await.map_err(|e| TransportError::Io(e))?;

    decode_owned(msg_buf)
}

/// Write a single framed 9P message to any async writer.
pub async fn write_message<W: AsyncWriteExt + Unpin>(
    send: &mut W,
    fc: &Fcall,
) -> Result<(), TransportError> {
    let data = encode(fc)?;
    send.write_all(&data).await.map_err(|e| TransportError::Io(e))?;
    Ok(())
}
