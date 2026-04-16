//! Concurrent RPC layer with per-tag inflight dispatch.
//!
//! Each `call()` allocates a tag (with RAII guard), registers a oneshot channel
//! in the inflight map, sends the request, and awaits the matching response.
//! A background task reads all incoming messages and dispatches by tag.

use crate::error::RpcError;
use dashmap::DashMap;
use p9n_proto::classify::{classify, MessageClass};
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::tag::TagAllocator;
use p9n_proto::types::{MsgType, NO_TAG};
use p9n_transport::quic::{datagram, framing};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Semaphore};

pub struct QuicRpcClient {
    conn: quinn::Connection,
    tags: TagAllocator,
    /// In-flight requests: tag -> oneshot sender for the response.
    inflight: Arc<DashMap<u16, oneshot::Sender<Fcall>>>,
    /// Push messages (tag=0xFFFF) forwarded to this channel.
    push_tx: mpsc::Sender<Fcall>,
    /// Monotonic connection id — attached to every log emitted by this client
    /// so requests from before/after a reconnect can be distinguished.
    conn_id: u64,
}

impl QuicRpcClient {
    /// Create a new concurrent RPC client.
    ///
    /// Spawns a background task that reads datagrams and dispatches by tag.
    /// Push messages (tag=NO_TAG) are sent to `push_tx`.
    pub fn new(conn: quinn::Connection, push_tx: mpsc::Sender<Fcall>, conn_id: u64) -> Self {
        let inflight: Arc<DashMap<u16, oneshot::Sender<Fcall>>> = Arc::new(DashMap::new());
        tracing::debug!(conn_id, "QuicRpcClient starting background tasks");

        // Background: read datagrams and dispatch by tag
        let conn2 = conn.clone();
        let inflight2 = inflight.clone();
        let push_tx2 = push_tx.clone();
        tokio::spawn(async move {
            tracing::trace!(conn_id, "QuicRpcClient datagram reader started");
            loop {
                match conn2.read_datagram().await {
                    Ok(data) => {
                        match framing::decode(&data) {
                            Ok(fc) => dispatch_response(&inflight2, &push_tx2, fc, conn_id).await,
                            Err(e) => tracing::debug!(conn_id, error = %e, "datagram decode failed"),
                        }
                    }
                    Err(e) => {
                        tracing::debug!(conn_id, error = %e, "datagram reader exited");
                        break;
                    }
                }
            }
        });

        // Background: accept unidirectional streams (push messages).
        // Limit concurrent stream readers to prevent unbounded task spawning
        // from a misbehaving server.
        let conn3 = conn.clone();
        let push_tx3 = push_tx.clone();
        let stream_limit = Arc::new(Semaphore::new(64));
        tokio::spawn(async move {
            tracing::trace!(conn_id, "QuicRpcClient uni-stream acceptor started");
            loop {
                match conn3.accept_uni().await {
                    Ok(mut recv) => {
                        let tx = push_tx3.clone();
                        let permit = match stream_limit.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => {
                                tracing::debug!(conn_id, "uni-stream acceptor exiting (semaphore closed)");
                                break;
                            }
                        };
                        tokio::spawn(async move {
                            let mut n = 0usize;
                            while let Ok(fc) = framing::read_message(&mut recv).await {
                                n += 1;
                                tracing::trace!(
                                    conn_id, msg_type = fc.msg_type.name(), tag = fc.tag,
                                    "uni-stream push received",
                                );
                                let _ = tx.send(fc).await;
                            }
                            tracing::trace!(conn_id, pushes = n, "uni-stream closed");
                            drop(permit);
                        });
                    }
                    Err(e) => {
                        tracing::debug!(conn_id, error = %e, "uni-stream acceptor exited");
                        break;
                    }
                }
            }
        });

        Self {
            conn,
            tags: TagAllocator::new(),
            inflight,
            push_tx,
            conn_id,
        }
    }

    /// The monotonic connection id attached to this client.
    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }

    /// Send a request and wait for the matching response.
    ///
    /// Tag is automatically allocated and freed (via RAII guard) even on error.
    /// Returns the raw Fcall — caller checks for error responses.
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
        tracing::trace!(conn_id, tag, msg_type = mt_name, "rpc send");

        // Register inflight before sending (avoid race with response)
        let (tx, rx) = oneshot::channel();
        self.inflight.insert(tag, tx);

        // Send via appropriate channel
        if let Err(e) = self.send_request(&fc).await {
            self.inflight.remove(&tag);
            tracing::debug!(conn_id, tag, msg_type = mt_name, error = %e, "rpc send failed");
            return Err(RpcError::Transport(e.into()));
        }

        // Await response (tag guard keeps tag allocated until we're done)
        let response = tokio::time::timeout(std::time::Duration::from_secs(30), rx)
            .await
            .map_err(|_| {
                self.inflight.remove(&tag);
                tracing::warn!(conn_id, tag, msg_type = mt_name, timeout_secs = 30, "rpc timeout");
                RpcError::from("RPC timeout (30s)")
            })?
            .map_err(|_| {
                tracing::debug!(conn_id, tag, msg_type = mt_name, "rpc channel closed (connection lost)");
                RpcError::from("RPC channel closed (connection lost)")
            })?;

        tracing::trace!(
            conn_id, tag,
            msg_type = mt_name,
            resp = response.msg_type.name(),
            "rpc recv",
        );

        // Tag is freed when guard drops (here, at end of scope)
        drop(guard);

        // Check for error response — preserve errno
        match &response.msg {
            Msg::Lerror { ecode } => Err(RpcError::NineP { ecode: *ecode }),
            Msg::Error { ename } => Err(RpcError::NinePString { ename: ename.clone() }),
            _ => Ok(response),
        }
    }

    /// Send a request, routing metadata to datagrams and data to streams.
    async fn send_request(
        &self,
        fc: &Fcall,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let class = classify(fc.msg_type);
        let conn_id = self.conn_id;
        match class {
            MessageClass::Metadata => {
                // Try datagram, fall back to stream if too large
                if !datagram::send_datagram(&self.conn, fc).await? {
                    tracing::trace!(
                        conn_id, tag = fc.tag, msg_type = fc.msg_type.name(),
                        "routing: datagram→stream (too large)",
                    );
                    self.send_on_stream(fc).await?;
                } else {
                    tracing::trace!(
                        conn_id, tag = fc.tag, msg_type = fc.msg_type.name(),
                        "routing: datagram",
                    );
                }
            }
            MessageClass::Data | MessageClass::Push => {
                tracing::trace!(
                    conn_id, tag = fc.tag, msg_type = fc.msg_type.name(),
                    "routing: stream",
                );
                self.send_on_stream(fc).await?;
            }
        }
        Ok(())
    }

    /// Send request on a bidirectional stream; spawn reader for the response.
    async fn send_on_stream(
        &self,
        fc: &Fcall,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut send, mut recv) = self.conn.open_bi().await?;
        framing::write_message(&mut send, fc).await?;
        send.finish()?;

        // Spawn a task to read the response and dispatch it
        let inflight = self.inflight.clone();
        let push_tx = self.push_tx.clone();
        let conn_id = self.conn_id;
        tokio::spawn(async move {
            match framing::read_message(&mut recv).await {
                Ok(response) => dispatch_response(&inflight, &push_tx, response, conn_id).await,
                Err(e) => tracing::debug!(conn_id, error = %e, "stream response read failed"),
            }
        });

        Ok(())
    }

    /// Check whether the QUIC connection is still alive (synchronous, no I/O).
    pub fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none()
    }

    /// Gracefully close the QUIC connection.
    ///
    /// Sends a CONNECTION_CLOSE frame. Background reader tasks (datagram reader,
    /// uni-stream acceptor) will exit on the next iteration when they observe
    /// the connection error.
    pub fn close(&self) {
        self.conn.close(quinn::VarInt::from_u32(0), b"bye");
    }

    /// Get the underlying QUIC connection (for direct operations).
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }
}

/// Route an incoming response to the correct inflight waiter, or push channel.
async fn dispatch_response(
    inflight: &DashMap<u16, oneshot::Sender<Fcall>>,
    push_tx: &mpsc::Sender<Fcall>,
    fc: Fcall,
    conn_id: u64,
) {
    let mt_name = fc.msg_type.name();
    if fc.tag == NO_TAG {
        tracing::trace!(conn_id, msg_type = mt_name, "push received");
        let _ = push_tx.send(fc).await;
    } else if let Some((_, tx)) = inflight.remove(&fc.tag) {
        tracing::trace!(conn_id, tag = fc.tag, msg_type = mt_name, "response dispatched");
        let _ = tx.send(fc);
    } else {
        tracing::warn!(conn_id, tag = fc.tag, msg_type = mt_name, "response for unknown tag");
    }
}
