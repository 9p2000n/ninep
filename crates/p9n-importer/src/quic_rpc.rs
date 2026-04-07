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
use tokio::sync::{mpsc, oneshot};

pub struct QuicRpcClient {
    conn: quinn::Connection,
    tags: TagAllocator,
    /// In-flight requests: tag -> oneshot sender for the response.
    inflight: Arc<DashMap<u16, oneshot::Sender<Fcall>>>,
    /// Push messages (tag=0xFFFF) forwarded to this channel.
    push_tx: mpsc::Sender<Fcall>,
}

impl QuicRpcClient {
    /// Create a new concurrent RPC client.
    ///
    /// Spawns a background task that reads datagrams and dispatches by tag.
    /// Push messages (tag=NO_TAG) are sent to `push_tx`.
    pub fn new(conn: quinn::Connection, push_tx: mpsc::Sender<Fcall>) -> Self {
        let inflight: Arc<DashMap<u16, oneshot::Sender<Fcall>>> = Arc::new(DashMap::new());

        // Background: read datagrams and dispatch by tag
        let conn2 = conn.clone();
        let inflight2 = inflight.clone();
        let push_tx2 = push_tx.clone();
        tokio::spawn(async move {
            loop {
                match conn2.read_datagram().await {
                    Ok(data) => {
                        if let Ok(fc) = framing::decode(&data) {
                            dispatch_response(&inflight2, &push_tx2, fc).await;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Background: accept unidirectional streams (push messages)
        let conn3 = conn.clone();
        let push_tx3 = push_tx.clone();
        tokio::spawn(async move {
            loop {
                match conn3.accept_uni().await {
                    Ok(mut recv) => {
                        let tx = push_tx3.clone();
                        tokio::spawn(async move {
                            while let Ok(fc) = framing::read_message(&mut recv).await {
                                let _ = tx.send(fc).await;
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            conn,
            tags: TagAllocator::new(),
            inflight,
            push_tx,
        }
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

        tracing::trace!("rpc send: tag={tag} type={}", msg_type.name());

        // Register inflight before sending (avoid race with response)
        let (tx, rx) = oneshot::channel();
        self.inflight.insert(tag, tx);

        // Send via appropriate channel
        if let Err(e) = self.send_request(&fc).await {
            self.inflight.remove(&tag);
            return Err(RpcError::Transport(e.into()));
        }

        // Await response (tag guard keeps tag allocated until we're done)
        let response = tokio::time::timeout(std::time::Duration::from_secs(30), rx)
            .await
            .map_err(|_| {
                self.inflight.remove(&tag);
                tracing::debug!("rpc timeout: tag={tag} type={}", msg_type.name());
                RpcError::from("RPC timeout (30s)")
            })?
            .map_err(|_| {
                tracing::debug!("rpc channel closed: tag={tag} type={}", msg_type.name());
                RpcError::from("RPC channel closed (connection lost)")
            })?;

        tracing::trace!(
            "rpc recv: tag={tag} type={} resp={}",
            msg_type.name(),
            response.msg_type.name(),
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
        match class {
            MessageClass::Metadata => {
                // Try datagram, fall back to stream if too large
                if !datagram::send_datagram(&self.conn, fc).await? {
                    tracing::trace!("routing: tag={} type={} datagram→stream (too large)", fc.tag, fc.msg_type.name());
                    self.send_on_stream(fc).await?;
                } else {
                    tracing::trace!("routing: tag={} type={} via datagram", fc.tag, fc.msg_type.name());
                }
            }
            MessageClass::Data | MessageClass::Push => {
                tracing::trace!("routing: tag={} type={} via stream", fc.tag, fc.msg_type.name());
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
        tokio::spawn(async move {
            if let Ok(response) = framing::read_message(&mut recv).await {
                dispatch_response(&inflight, &push_tx, response).await;
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
) {
    if fc.tag == NO_TAG {
        tracing::trace!("push received: type={}", fc.msg_type.name());
        let _ = push_tx.send(fc).await;
    } else if let Some((_, tx)) = inflight.remove(&fc.tag) {
        tracing::trace!("response dispatched: tag={} type={}", fc.tag, fc.msg_type.name());
        let _ = tx.send(fc);
    } else {
        tracing::warn!("response for unknown tag {}", fc.tag);
    }
}
