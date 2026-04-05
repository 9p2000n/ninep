//! Error types for the importer.

use std::fmt;

/// A 9P error that preserves the errno from Rlerror.
#[derive(Debug)]
pub enum RpcError {
    /// Numeric error (Rlerror).
    NineP { ecode: u32 },
    /// 9P2000 string error (Rerror).
    NinePString { ename: String },
    /// Transport / IO error.
    Transport(Box<dyn std::error::Error + Send + Sync>),
}

impl RpcError {
    /// Return the errno if this is a 9P numeric error.
    pub fn errno(&self) -> Option<i32> {
        match self {
            Self::NineP { ecode } => Some(*ecode as i32),
            _ => None,
        }
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NineP { ecode } => write!(f, "9P error: errno={ecode}"),
            Self::NinePString { ename } => write!(f, "9P error: {ename}"),
            Self::Transport(e) => write!(f, "transport: {e}"),
        }
    }
}

impl std::error::Error for RpcError {}

impl From<&str> for RpcError {
    fn from(s: &str) -> Self {
        Self::Transport(s.into())
    }
}

impl From<String> for RpcError {
    fn from(s: String) -> Self {
        Self::Transport(s.into())
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for RpcError {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::Transport(e)
    }
}
