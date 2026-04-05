//! QuicTransport: the main transport implementation.

use super::{datagram, framing, streams};
use crate::error::TransportError;
use p9n_proto::classify::{classify, MessageClass};
use p9n_proto::fcall::Fcall;
use p9n_proto::types::NO_TAG;
use dashmap::DashMap;
use quinn::Connection;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// QUIC transport for 9P2000.N with automatic datagram/stream routing.
pub struct QuicTransport {
    conn: Connection,
    /// Channel for receiving push messages from the background task.
    push_rx: mpsc::Receiver<Fcall>,
    /// Tag-based inflight map for datagram responses.
    dgram_inflight: Arc<DashMap<u16, oneshot::Sender<Fcall>>>,
}

impl QuicTransport {
    /// Create a new transport wrapping a QUIC connection.
    /// Spawns background tasks for receiving datagrams and push messages.
    pub fn new(conn: Connection) -> Self {
        let (push_tx, push_rx) = mpsc::channel(64);
        let dgram_inflight: Arc<DashMap<u16, oneshot::Sender<Fcall>>> = Arc::new(DashMap::new());

        // Background task: receive datagrams and dispatch by tag
        let conn2 = conn.clone();
        let inflight = dgram_inflight.clone();
        let push_tx2 = push_tx.clone();
        tokio::spawn(async move {
            loop {
                match datagram::recv_datagram(&conn2).await {
                    Ok(fc) => {
                        if fc.tag == NO_TAG {
                            let _ = push_tx2.send(fc).await;
                        } else if let Some((_, tx)) = inflight.remove(&fc.tag) {
                            let _ = tx.send(fc);
                        } else {
                            tracing::debug!("datagram for unknown tag {}", fc.tag);
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Background task: accept and read push streams
        let conn3 = conn.clone();
        tokio::spawn(async move {
            loop {
                match streams::accept_push_stream(&conn3).await {
                    Ok(mut recv) => {
                        let tx = push_tx.clone();
                        tokio::spawn(async move {
                            loop {
                                match framing::read_message(&mut recv).await {
                                    Ok(fc) => {
                                        if tx.send(fc).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            conn,
            push_rx,
            dgram_inflight,
        }
    }

    /// Send an Fcall, automatically routing via datagram or stream.
    pub async fn send(&self, fc: &Fcall) -> Result<(), TransportError> {
        let class = classify(fc.msg_type);
        match class {
            MessageClass::Metadata => {
                if !datagram::send_datagram(&self.conn, fc).await? {
                    let (mut send, _recv) = self.conn.open_bi().await?;
                    framing::write_message(&mut send, fc).await?;
                    send.finish()?;
                }
            }
            MessageClass::Data | MessageClass::Push => {
                let (mut send, _recv) = self.conn.open_bi().await?;
                framing::write_message(&mut send, fc).await?;
                send.finish()?;
            }
        }
        Ok(())
    }

    /// Send and receive a response (RPC pattern).
    ///
    /// Metadata: sent via datagram with tag-based response matching.
    /// Data: sent via bidirectional stream.
    pub async fn rpc(&self, fc: &Fcall) -> Result<Fcall, TransportError> {
        let class = classify(fc.msg_type);
        match class {
            MessageClass::Data => streams::stream_rpc(&self.conn, fc).await,
            MessageClass::Metadata => {
                if datagram::send_datagram(&self.conn, fc).await? {
                    // Register inflight and wait for tag-matched response
                    let (tx, rx) = oneshot::channel();
                    self.dgram_inflight.insert(fc.tag, tx);

                    let response = tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        rx,
                    )
                    .await
                    .map_err(|_| {
                        self.dgram_inflight.remove(&fc.tag);
                        TransportError::Timeout
                    })?
                    .map_err(|_| TransportError::Closed)?;

                    Ok(response)
                } else {
                    streams::stream_rpc(&self.conn, fc).await
                }
            }
            MessageClass::Push => {
                Err(TransportError::Other("cannot RPC a push message".into()))
            }
        }
    }

    /// Receive the next push message.
    pub async fn recv_push(&mut self) -> Result<Fcall, TransportError> {
        self.push_rx.recv().await.ok_or(TransportError::Closed)
    }

    /// Accept a new bidirectional stream (server-side).
    pub async fn accept_bi(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), TransportError> {
        let (send, recv) = self.conn.accept_bi().await?;
        Ok((send, recv))
    }

    /// Open a unidirectional stream (server-side: for push messages).
    pub async fn open_push_stream(&self) -> Result<quinn::SendStream, TransportError> {
        let send = self.conn.open_uni().await?;
        Ok(send)
    }

    /// Get the underlying QUIC connection.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Close the transport.
    pub fn close(&self) {
        self.conn.close(quinn::VarInt::from_u32(0), b"bye");
    }

    /// Get the negotiated max datagram size.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }
}
