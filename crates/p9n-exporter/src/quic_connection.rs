use crate::handlers;
use crate::lease_manager;
use crate::push::{self, PushSender, QuicPushSender};
use crate::session::Session;
use crate::shared::SharedCtx;
use crate::watch_manager::WatchEvent;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::{MsgType, SESSION_FIDS, SESSION_WATCHES};
use p9n_transport::quic::framing;
use crate::util::map_io_error;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct QuicConnectionHandler {
    conn: quinn::Connection,
    ctx: Arc<SharedCtx>,
    session: Arc<Session>,
    watch_rx: mpsc::Receiver<WatchEvent>,
    watch_tx: mpsc::Sender<WatchEvent>,
    push_rx: mpsc::Receiver<Fcall>,
    push_tx: mpsc::Sender<Fcall>,
    pusher: QuicPushSender,
}

impl QuicConnectionHandler {
    pub fn new(conn: quinn::Connection, ctx: Arc<SharedCtx>) -> Self {
        let (watch_tx, watch_rx) = mpsc::channel(256);
        let (push_tx, push_rx) = mpsc::channel(64);
        let spiffe_id = extract_spiffe_id_from_conn(&conn);

        if let Some(ref id) = spiffe_id {
            tracing::info!("peer authenticated: {id}");
        }

        let conn_id = lease_manager::next_conn_id();
        let mut session = Session::new(conn_id);
        session.spiffe_id = spiffe_id;
        let pusher = QuicPushSender::new(conn.clone());

        Self {
            conn,
            ctx,
            session: Arc::new(session),
            watch_rx,
            watch_tx,
            push_rx,
            push_tx,
            pusher,
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            tokio::select! {
                result = self.conn.accept_bi() => {
                    match result {
                        Ok((send, recv)) => {
                            let ctx = self.ctx.clone();
                            let session = self.session.clone();
                            let watch_tx = self.watch_tx.clone();
                            let push_tx = self.push_tx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_stream(ctx, session, watch_tx, push_tx, send, recv).await {
                                    tracing::debug!("stream error: {e}");
                                }
                            });
                        }
                        Err(e) => { tracing::debug!("connection closed: {e}"); break; }
                    }
                }
                result = self.conn.read_datagram() => {
                    match result {
                        Ok(data) => {
                            let ctx = self.ctx.clone();
                            let session = self.session.clone();
                            let watch_tx = self.watch_tx.clone();
                            let push_tx = self.push_tx.clone();
                            let conn = self.conn.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_datagram(ctx, session, watch_tx, push_tx, conn, data).await {
                                    tracing::debug!("datagram error: {e}");
                                }
                            });
                        }
                        Err(e) => { tracing::debug!("datagram error: {e}"); break; }
                    }
                }
                Some(event) = self.watch_rx.recv() => {
                    if let Err(e) = self.pusher.send_push(push::notify_fcall(event)).await {
                        tracing::debug!("push notify error: {e}");
                    }
                }
                Some(fc) = self.push_rx.recv() => {
                    if let Err(e) = self.pusher.send_push(fc).await {
                        tracing::debug!("push error: {e}");
                    }
                }
            }
        }
        self.cleanup();
        Ok(())
    }

    fn cleanup(&self) {
        if let Some(key) = self.session.get_session_key() {
            let mut flags = 0u32;
            if !self.session.fids.is_empty() {
                flags |= SESSION_FIDS;
            }
            let wids = self.session.watch_id_list();
            if !wids.is_empty() {
                flags |= SESSION_WATCHES;
            }
            self.ctx
                .session_store
                .save(key, self.session.spiffe_id.clone(), flags);
        }
        for wid in self.session.watch_id_list() {
            let _ = self.ctx.watch_mgr.remove_watch(wid);
        }
        self.ctx.watch_mgr.remove_all_for_sender(&self.watch_tx);
        self.ctx.lease_mgr.remove_by_conn(self.session.conn_id);
        let fid_count = self.session.fids.len();
        self.session.fids.clear();
        if fid_count > 0 {
            tracing::debug!("cleaned up {fid_count} fids on disconnect");
        }
    }
}

/// Handle a single bidirectional QUIC stream with in-flight tracking.
async fn handle_stream(
    ctx: Arc<SharedCtx>,
    session: Arc<Session>,
    watch_tx: mpsc::Sender<WatchEvent>,
    push_tx: mpsc::Sender<Fcall>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let request = framing::read_message(&mut recv).await?;
    let tag = request.tag;

    // Register in-flight (allows Tflush to cancel this request)
    let cancel = session.register_inflight(tag);

    let result = tokio::select! {
        r = handlers::dispatch(&session, &ctx, &watch_tx, &push_tx, request) => r,
        _ = cancel.cancelled() => {
            tracing::debug!("request tag={tag} cancelled by Tflush");
            Err("flushed".into())
        }
    };

    session.deregister_inflight(tag);

    let response = match result {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("handler error: {e}");
            Fcall {
                size: 0,
                msg_type: MsgType::Rlerror,
                tag,
                msg: Msg::Lerror {
                    ecode: map_io_error(&*e),
                },
            }
        }
    };
    framing::write_message(&mut send, &response).await?;
    send.finish()?;
    Ok(())
}

/// Handle a single datagram message.
async fn handle_datagram(
    ctx: Arc<SharedCtx>,
    session: Arc<Session>,
    watch_tx: mpsc::Sender<WatchEvent>,
    push_tx: mpsc::Sender<Fcall>,
    conn: quinn::Connection,
    data: bytes::Bytes,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let request = framing::decode(&data)?;
    let tag = request.tag;
    let result = handlers::dispatch(&session, &ctx, &watch_tx, &push_tx, request).await;
    let response = match result {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("handler error: {e}");
            Fcall {
                size: 0,
                msg_type: MsgType::Rlerror,
                tag,
                msg: Msg::Lerror {
                    ecode: map_io_error(&*e),
                },
            }
        }
    };
    let reply = framing::encode(&response)?;
    conn.send_datagram(reply.into())?;
    Ok(())
}

fn extract_spiffe_id_from_conn(conn: &quinn::Connection) -> Option<String> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().ok()?;
    crate::util::spiffe_id_from_certs(&certs)
}
