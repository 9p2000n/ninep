//! QUIC-specific framing wrappers.
//!
//! Delegates to the transport-agnostic framing module.

use crate::error::TransportError;
use p9n_proto::fcall::Fcall;

// Re-export generic functions for backward compatibility
pub use crate::framing::{decode, decode_owned, encode};

/// Read a 9P message from a QUIC RecvStream.
pub async fn read_message(recv: &mut quinn::RecvStream) -> Result<Fcall, TransportError> {
    crate::framing::read_message(recv).await
}

/// Write a 9P message to a QUIC SendStream.
pub async fn write_message(
    send: &mut quinn::SendStream,
    fc: &Fcall,
) -> Result<(), TransportError> {
    crate::framing::write_message(send, fc).await
}

/// Write pre-encoded wire bytes directly (zero-copy fast path).
pub async fn write_raw(
    send: &mut quinn::SendStream,
    data: &[u8],
) -> Result<(), TransportError> {
    crate::framing::write_raw(send, data).await
}
