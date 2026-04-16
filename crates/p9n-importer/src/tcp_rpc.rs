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
    conn_id: u64,
}

impl<W: AsyncRead + AsyncWrite + Unpin + Send + 'static> TcpRpcClient<W> {
    /// Create a new TCP RPC client from any bidirectional async stream.
    ///
    /// Spawns a background reader that demuxes by tag.
    /// Push messages (tag=NO_TAG) are sent to `push_tx`.
    pub fn new(stream: W, push_tx: mpsc::Sender<Fcall>, conn_id: u64) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        let inflight: Arc<DashMap<u16, oneshot::Sender<Fcall>>> = Arc::new(DashMap::new());
        tracing::debug!(conn_id, "TcpRpcClient starting background reader");

        // Background reader: demux by tag
        let inflight2 = inflight.clone();
        let push_tx2 = push_tx;
        tokio::spawn(async move {
            tracing::trace!(conn_id, "TcpRpcClient reader started");
            let mut reader = reader;
            loop {
                match framing::read_message(&mut reader).await {
                    Ok(fc) => {
                        let mt_name = fc.msg_type.name();
                        if fc.tag == NO_TAG {
                            tracing::trace!(conn_id, msg_type = mt_name, "tcp push received");
                            let _ = push_tx2.send(fc).await;
                        } else if let Some((_, tx)) = inflight2.remove(&fc.tag) {
                            tracing::trace!(
                                conn_id, tag = fc.tag, msg_type = mt_name,
                                "tcp response dispatched",
                            );
                            let _ = tx.send(fc);
                        } else {
                            tracing::warn!(
                                conn_id, tag = fc.tag, msg_type = mt_name,
                                "tcp response for unknown tag",
                            );
                        }
                    }
                    Err(e) => {
                        tracing::debug!(conn_id, error = %e, "tcp reader exited");
                        break;
                    }
                }
            }
        });

        Self {
            writer: Arc::new(Mutex::new(writer)),
            tags: TagAllocator::new(),
            inflight,
            conn_id,
        }
    }

    /// The monotonic connection id attached to this client.
    pub fn conn_id(&self) -> u64 {
        self.conn_id
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

        let mt_name = msg_type.name();
        let conn_id = self.conn_id;
        tracing::trace!(conn_id, tag, msg_type = mt_name, "tcp rpc send");

        let (tx, rx) = oneshot::channel();
        self.inflight.insert(tag, tx);

        // Send on TCP (serialized via Mutex)
        {
            let mut writer = self.writer.lock().await;
            if let Err(e) = framing::write_message(&mut *writer, &fc).await {
                self.inflight.remove(&tag);
                tracing::debug!(conn_id, tag, msg_type = mt_name, error = %e, "tcp rpc send failed");
                return Err(RpcError::Transport(e.into()));
            }
        }

        // Await response
        let response = tokio::time::timeout(std::time::Duration::from_secs(30), rx)
            .await
            .map_err(|_| {
                self.inflight.remove(&tag);
                tracing::warn!(conn_id, tag, msg_type = mt_name, timeout_secs = 30, "tcp rpc timeout");
                RpcError::from("TCP RPC timeout (30s)")
            })?
            .map_err(|_| {
                tracing::debug!(conn_id, tag, msg_type = mt_name, "tcp rpc channel closed (connection lost)");
                RpcError::from("TCP RPC channel closed (connection lost)")
            })?;

        tracing::trace!(
            conn_id, tag,
            msg_type = mt_name,
            resp = response.msg_type.name(),
            "tcp rpc recv",
        );

        drop(guard);

        // Check for error response — preserve errno
        match &response.msg {
            Msg::Lerror { ecode } => Err(RpcError::NineP { ecode: *ecode }),
            Msg::Error { ename } => Err(RpcError::NinePString { ename: ename.clone() }),
            _ => Ok(response),
        }
    }
}
