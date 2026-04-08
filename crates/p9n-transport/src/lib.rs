//! Transport layer for 9P2000.N: QUIC (primary) and TCP+TLS (compatibility).

pub mod error;
pub mod framing;
pub mod quic;
pub mod tcp;

pub use error::TransportError;
pub use quic::QuicTransport;
pub use tcp::TcpTransport;

#[cfg(feature = "rdma")]
pub mod rdma;
