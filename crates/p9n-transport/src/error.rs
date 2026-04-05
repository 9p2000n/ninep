use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("QUIC connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    #[error("QUIC write error: {0}")]
    Write(#[from] quinn::WriteError),

    #[error("QUIC read error: {0}")]
    ReadExact(#[from] quinn::ReadExactError),

    #[error("QUIC send datagram error: {0}")]
    SendDatagram(#[from] quinn::SendDatagramError),

    #[error("QUIC stream closed")]
    ClosedStream(#[from] quinn::ClosedStream),

    #[error("protocol error: {0}")]
    Proto(#[from] p9n_proto::error::ProtoError),

    #[error("wire error: {0}")]
    Wire(#[from] p9n_proto::error::WireError),

    #[error("datagram too large: {size} > {max}")]
    DatagramTooLarge { size: usize, max: usize },

    #[error("timeout")]
    Timeout,

    #[error("transport closed")]
    Closed,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
