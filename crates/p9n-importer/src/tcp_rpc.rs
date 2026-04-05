//! TCP+TLS RPC client with tag-based demultiplexing.
//!
//! Parallel to `rpc.rs` (QUIC) but for TCP. All messages travel on a single
//! bidirectional TLS stream. A background reader task demultiplexes responses
//! by tag and routes push messages (tag=NO_TAG) to a separate channel.

use crate::error::RpcError;
use dashmap::DashMap;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::tag::TagAllocator;
use p9n_proto::types::{MsgType, NO_TAG};
use p9n_transport::framing;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, WriteHalf};
use tokio::sync::{mpsc, oneshot, Mutex};

/// Generic TCP RPC client that works over any async read/write stream.
pub struct TcpRpcClient<W: AsyncWrite + Unpin + Send + 'static> {
    writer: Arc<Mutex<WriteHalf<W>>>,
    tags: TagAllocator,
    inflight: Arc<DashMap<u16, oneshot::Sender<Fcall>>>,
}

impl<W: AsyncRead + AsyncWrite + Unpin + Send + 'static> TcpRpcClient<W> {
    /// Create a new TCP RPC client from any bidirectional async stream.
    ///
    /// Spawns a background reader that demuxes by tag.
    /// Push messages (tag=NO_TAG) are sent to `push_tx`.
    pub fn new(stream: W, push_tx: mpsc::Sender<Fcall>) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        let inflight: Arc<DashMap<u16, oneshot::Sender<Fcall>>> = Arc::new(DashMap::new());

        // Background reader: demux by tag
        let inflight2 = inflight.clone();
        let push_tx2 = push_tx;
        tokio::spawn(async move {
            let mut reader = reader;
            loop {
                match framing::read_message(&mut reader).await {
                    Ok(fc) => {
                        if fc.tag == NO_TAG {
                            // Server push message
                            let _ = push_tx2.send(fc).await;
                        } else if let Some((_, tx)) = inflight2.remove(&fc.tag) {
                            let _ = tx.send(fc);
                        } else {
                            tracing::warn!("tcp: response for unknown tag {}", fc.tag);
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            writer: Arc::new(Mutex::new(writer)),
            tags: TagAllocator::new(),
            inflight,
        }
    }

    /// Check whether the TCP connection is likely alive.
    ///
    /// Uses `try_lock` on the writer mutex as a heuristic — if the lock is
    /// available, the connection has not been shut down by us. The actual peer
    /// state is only observable on the next send/recv.
    pub fn is_alive(&self) -> bool {
        self.writer.try_lock().is_ok()
    }

    /// Gracefully close the TCP connection by shutting down the write half.
    ///
    /// The background reader task will exit when it detects the connection is closed.
    pub async fn close(&self) {
        use tokio::io::AsyncWriteExt;
        let mut writer = self.writer.lock().await;
        let _ = writer.shutdown().await;
    }

    /// Send a request and wait for the matching response.
    ///
    /// Tag is automatically allocated and freed (via RAII guard) even on error.
    pub async fn call(
        &self,
        msg_type: MsgType,
        msg: Msg,
    ) -> Result<Fcall, RpcError> {
        let guard = self.tags.alloc_guard().ok_or(RpcError::from("tag pool exhausted"))?;
        let tag = guard.tag();

        let fc = Fcall {
            size: 0,
            msg_type,
            tag,
            msg,
        };

        let (tx, rx) = oneshot::channel();
        self.inflight.insert(tag, tx);

        // Send on TCP (serialized via Mutex)
        {
            let mut writer = self.writer.lock().await;
            if let Err(e) = framing::write_message(&mut *writer, &fc).await {
                self.inflight.remove(&tag);
                return Err(RpcError::Transport(e.into()));
            }
        }

        // Await response
        let response = tokio::time::timeout(std::time::Duration::from_secs(30), rx)
            .await
            .map_err(|_| {
                self.inflight.remove(&tag);
                RpcError::from("TCP RPC timeout (30s)")
            })?
            .map_err(|_| RpcError::from("TCP RPC channel closed (connection lost)"))?;

        drop(guard);

        // Check for error response — preserve errno
        match &response.msg {
            Msg::Lerror { ecode } => Err(RpcError::NineP { ecode: *ecode }),
            Msg::Error { ename } => Err(RpcError::NinePString { ename: ename.clone() }),
            _ => Ok(response),
        }
    }
}
