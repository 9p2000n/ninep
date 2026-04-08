//! RDMA transport for 9P2000.N: InfiniBand/RoCE verbs-based data plane
//! with TCP+TLS bootstrap for SPIFFE mTLS authentication.

pub mod ffi;
pub mod verbs;
pub mod mr_pool;
pub mod config;
pub mod connection;

pub use connection::RdmaTransport;
