//! gRPC length-prefixed frame encoding/decoding.
//!
//! Each gRPC message on the wire is prefixed with a 5-byte header:
//!   [compressed: u8][length: u32 big-endian]
//! followed by `length` bytes of protobuf payload.

use bytes::{Buf, BytesMut};

/// Encode a protobuf payload into a gRPC frame (uncompressed).
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(0); // compressed = false
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Incremental decoder that handles gRPC messages spanning multiple HTTP/2 DATA frames.
pub struct Decoder {
    buf: BytesMut,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
        }
    }

    /// Append a chunk of data received from the HTTP/2 stream.
    pub fn push(&mut self, chunk: bytes::Bytes) {
        self.buf.extend_from_slice(&chunk);
    }

    /// Try to extract the next complete gRPC message payload.
    /// Returns `None` if not enough data is available yet.
    pub fn next_message(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < 5 {
            return None;
        }
        let _compressed = self.buf[0];
        let len = u32::from_be_bytes(self.buf[1..5].try_into().unwrap()) as usize;
        if self.buf.len() < 5 + len {
            return None;
        }
        self.buf.advance(5);
        Some(self.buf.split_to(len).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_round_trip() {
        let payload = b"hello protobuf";
        let frame = encode(payload);
        assert_eq!(frame[0], 0); // not compressed
        assert_eq!(u32::from_be_bytes(frame[1..5].try_into().unwrap()), 14);

        let mut dec = Decoder::new();
        dec.push(bytes::Bytes::from(frame));
        let got = dec.next_message().unwrap();
        assert_eq!(got, payload);
        assert!(dec.next_message().is_none());
    }

    #[test]
    fn test_empty_payload() {
        let frame = encode(&[]);
        let mut dec = Decoder::new();
        dec.push(bytes::Bytes::from(frame));
        let got = dec.next_message().unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn test_fragmented_delivery() {
        let payload = b"split across frames";
        let frame = encode(payload);

        let mut dec = Decoder::new();
        // Push first 3 bytes (partial header)
        dec.push(bytes::Bytes::copy_from_slice(&frame[..3]));
        assert!(dec.next_message().is_none());
        // Push rest
        dec.push(bytes::Bytes::copy_from_slice(&frame[3..]));
        let got = dec.next_message().unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn test_multiple_messages_in_one_chunk() {
        let f1 = encode(b"msg1");
        let f2 = encode(b"msg2");
        let mut combined = f1;
        combined.extend_from_slice(&f2);

        let mut dec = Decoder::new();
        dec.push(bytes::Bytes::from(combined));
        assert_eq!(dec.next_message().unwrap(), b"msg1");
        assert_eq!(dec.next_message().unwrap(), b"msg2");
        assert!(dec.next_message().is_none());
    }
}
