//! Routes 9P messages to QUIC datagrams or streams based on classification.

use p9n_proto::classify::{classify, MessageClass};
use p9n_proto::fcall::Fcall;

/// Determine if a message should go via datagram.
pub fn should_use_datagram(fc: &Fcall, max_datagram_size: usize) -> bool {
    let class = classify(fc.msg_type);
    if class != MessageClass::Metadata {
        return false;
    }
    // Estimate size -- metadata messages are small, but check just in case.
    // The actual serialized size will be checked at send time.
    // For now, assume metadata fits in datagrams (typically < 1200 bytes).
    let _ = max_datagram_size;
    true
}
