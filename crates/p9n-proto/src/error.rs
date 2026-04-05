//! Protocol error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("wire format error: {0}")]
    Wire(#[from] WireError),

    #[error("version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: String, got: String },

    #[error("required capability not negotiated: {0}")]
    CapabilityRequired(String),

    #[error("9P error: {ename} (errno={errno})")]
    Nine { ename: String, errno: u32 },
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("short buffer: need {need} bytes, have {have}")]
    ShortBuffer { need: usize, have: usize },

    #[error("unknown message type: {0}")]
    UnknownType(u8),

    #[error("invalid data: {0}")]
    InvalidData(String),

    #[error("message too large: {size} > {max}")]
    MessageTooLarge { size: u32, max: u32 },
}

impl From<WireError> for std::io::Error {
    fn from(e: WireError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    }
}

impl From<ProtoError> for std::io::Error {
    fn from(e: ProtoError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
    }
}
