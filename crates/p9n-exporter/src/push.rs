//! Server push: delivers unsolicited messages (Rnotify, Rleasebreak, etc.) to clients.

use crate::watch_manager::WatchEvent;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::{MsgType, NO_TAG};
use std::sync::Arc;
use tokio::sync::Mutex;

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

/// QUIC push sender: delivers push messages on unidirectional streams.
pub struct QuicPushSender {
    conn: quinn::Connection,
}

impl QuicPushSender {
    pub fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }
}

impl PushSender for QuicPushSender {
    async fn send_push(
        &self,
        fc: Fcall,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
