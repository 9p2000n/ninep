//! Server push: delivers unsolicited messages (Rnotify, Rleasebreak, etc.) to clients.

use crate::watch_manager::WatchEvent;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::{MsgType, NO_TAG};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::{mpsc, oneshot};

/// Error returned by `QuicPushSender::bind_persistent`.
#[derive(Debug)]
pub enum BindError {
    AlreadyBound,
    NotSupported,
    Io(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyBound => f.write_str("push stream already bound"),
            Self::NotSupported => f.write_str("push stream binding not supported on this transport"),
            Self::Io(e) => write!(f, "push stream bind I/O error: {e}"),
        }
    }
}

impl std::error::Error for BindError {}

/// Oneshot responder returned to a Tquicstream handler after the run loop
/// has attempted the bind. Carries either the server-assigned alias or a
/// `BindError`.
pub type BindResponder = oneshot::Sender<Result<u64, BindError>>;

/// Channel the Tquicstream handler uses to request a persistent push
/// stream bind from the connection run loop. The run loop is the only
/// component that may touch the pusher's internal state, so all bind
/// requests funnel through here.
pub type BindTx = mpsc::Sender<BindResponder>;
pub type BindRx = mpsc::Receiver<BindResponder>;

/// Trait for sending server-initiated push messages to a connected client.
pub trait PushSender: Send + Sync {
    fn send_push(
        &self,
        fc: Fcall,
    ) -> impl std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
           + Send;
}

/// Build an Rnotify Fcall from a watch event.
pub fn notify_fcall(event: WatchEvent) -> Fcall {
    Fcall {
        size: 0,
        msg_type: MsgType::Rnotify,
        tag: NO_TAG,
        msg: Msg::Notify {
            watch_id: event.watch_id,
            event: event.event_mask,
            name: event.name,
            qid: event.qid,
        },
    }
}

/// QUIC push sender with optional persistent-stream binding.
///
/// In legacy mode (no Tquicstream bind), every push opens a fresh
/// unidirectional stream — one stream per message. After a successful
/// `bind_persistent()`, pushes flow through a single long-lived uni-stream.
/// If a write on the persistent stream fails, the sender clears the slot
/// and the current push falls through to the ephemeral path; subsequent
/// pushes remain on the ephemeral path for the rest of the connection.
pub struct QuicPushSender {
    conn: quinn::Connection,
    persistent: Mutex<Option<quinn::SendStream>>,
}

impl QuicPushSender {
    pub fn new(conn: quinn::Connection) -> Self {
        Self {
            conn,
            persistent: Mutex::new(None),
        }
    }

    /// Open a persistent unidirectional stream for push messages and
    /// return its server-assigned alias (derived from the quinn StreamId).
    pub async fn bind_persistent(&self) -> Result<u64, BindError> {
        let mut slot = self.persistent.lock().await;
        if slot.is_some() {
            return Err(BindError::AlreadyBound);
        }
        let send = self
            .conn
            .open_uni()
            .await
            .map_err(|e| BindError::Io(Box::new(e)))?;
        let alias = u64::from(send.id());
        *slot = Some(send);
        Ok(alias)
    }
}

impl PushSender for QuicPushSender {
    async fn send_push(
        &self,
        fc: Fcall,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Try the persistent stream first. If the write fails, drop it
        // and fall through to the legacy ephemeral path. We deliberately
        // do not try to reopen a replacement persistent stream — a write
        // failure almost always signals broader connection trouble and a
        // retry loop would only make things worse.
        {
            let mut slot = self.persistent.lock().await;
            if let Some(stream) = slot.as_mut() {
                match p9n_transport::quic::framing::write_message(stream, &fc).await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        tracing::warn!(
                            "persistent push stream errored, falling back to ephemeral: {e}"
                        );
                        *slot = None;
                    }
                }
            }
        }
        let mut send = self.conn.open_uni().await?;
        p9n_transport::quic::framing::write_message(&mut send, &fc).await?;
        send.finish()?;
        Ok(())
    }
}

/// Build an Rleasebreak Fcall.
pub fn leasebreak_fcall(lease_id: u64, new_type: u8) -> Fcall {
    Fcall {
        size: 0,
        msg_type: MsgType::Rleasebreak,
        tag: NO_TAG,
        msg: Msg::Leasebreak {
            lease_id,
            new_type,
        },
    }
}

/// TCP push sender: delivers push messages on the shared TCP stream.
pub struct TcpPushSender<W> {
    writer: Arc<Mutex<W>>,
}

impl<W> TcpPushSender<W> {
    pub fn new(writer: Arc<Mutex<W>>) -> Self {
        Self { writer }
    }
}

impl<W: tokio::io::AsyncWrite + Unpin + Send + 'static> PushSender for TcpPushSender<W> {
    async fn send_push(
        &self,
        fc: Fcall,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut writer = self.writer.lock().await;
        p9n_transport::framing::write_message(&mut *writer, &fc).await?;
        Ok(())
    }
}

/// RDMA push sender: delivers push messages via RDMA Send with tag=NO_TAG.
#[cfg(feature = "rdma")]
pub struct RdmaPushSender {
    transport: Arc<p9n_transport::rdma::RdmaTransport>,
}

#[cfg(feature = "rdma")]
impl RdmaPushSender {
    pub fn new(transport: Arc<p9n_transport::rdma::RdmaTransport>) -> Self {
        Self { transport }
    }
}

#[cfg(feature = "rdma")]
impl PushSender for RdmaPushSender {
    async fn send_push(
        &self,
        fc: Fcall,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.transport.send(&fc).await?;
        Ok(())
    }
}
