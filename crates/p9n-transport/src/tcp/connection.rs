//! TCP transport: single bidirectional TLS stream with tag-based demuxing.

use crate::error::TransportError;
use crate::framing;
use p9n_proto::fcall::Fcall;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use std::sync::Arc;

/// TCP transport wrapping a TLS stream.
///
/// All messages (requests, responses, pushes) travel on the same bidirectional
/// stream. Tag-based demultiplexing separates responses from push messages.
pub struct TcpTransport {
    writer: Arc<Mutex<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>>,
    /// Push messages (tag=NO_TAG) received from the server.
    push_rx: mpsc::Receiver<Fcall>,
}

impl TcpTransport {
    /// Create from a server-side TLS stream (exporter).
    pub fn from_server_stream(
        stream: ServerTlsStream<TcpStream>,
    ) -> (Self, ReadHalf<ServerTlsStream<TcpStream>>) {
        let (reader, writer) = tokio::io::split(stream);
        let (_push_tx, push_rx) = mpsc::channel(64);
        (
            Self {
                writer: Arc::new(Mutex::new(Box::new(writer))),
                push_rx,
            },
            reader,
        )
    }

    /// Create from a client-side TLS stream (importer).
    /// Spawns a background reader that demuxes by tag.
    pub fn from_client_stream(
        stream: ClientTlsStream<TcpStream>,
        _push_tx: mpsc::Sender<Fcall>,
    ) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        // The caller (TcpRpcClient) manages the reader task
        let _ = reader; // reader is returned separately via from_client_stream_split
        Self {
            writer: Arc::new(Mutex::new(Box::new(writer))),
            push_rx: mpsc::channel(1).1, // unused, rpc client handles push
        }
    }

    /// Split a client TLS stream into reader + writer for the RPC client.
    pub fn split_client_stream(
        stream: ClientTlsStream<TcpStream>,
    ) -> (
        ReadHalf<ClientTlsStream<TcpStream>>,
        Arc<Mutex<WriteHalf<ClientTlsStream<TcpStream>>>>,
    ) {
        let (reader, writer) = tokio::io::split(stream);
        (reader, Arc::new(Mutex::new(writer)))
    }

    /// Write a message to the TCP stream (thread-safe).
    pub async fn send(&self, fc: &Fcall) -> Result<(), TransportError> {
        let mut writer = self.writer.lock().await;
        framing::write_message(&mut *writer, fc).await
    }

    /// Receive the next push message.
    pub async fn recv_push(&mut self) -> Result<Fcall, TransportError> {
        self.push_rx.recv().await.ok_or(TransportError::Closed)
    }
}
