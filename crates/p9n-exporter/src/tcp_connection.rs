//! TCP+TLS connection handler for 9P2000.N.
//!
//! Parallel to `quic_connection.rs` but for TCP. Key differences:
//! - No datagram or multi-stream — one serial TCP+TLS stream
//! - Push messages (Rnotify, Rleasebreak) sent on the same stream with tag=NO_TAG
//! - SPIFFE ID extracted from tokio-rustls peer certificates

use crate::backend::Backend;
use crate::handlers;
use crate::lease_manager;
use crate::push::{self, PushSender, TcpPushSender};
use crate::session::Session;
use crate::shared::SharedCtx;
use crate::watch_manager::WatchEvent;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::{MsgType, SESSION_FIDS, SESSION_WATCHES};
use p9n_transport::framing;
use crate::util::map_io_error;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::server::TlsStream;
use tracing::Instrument;

pub struct TcpConnectionHandler<B: Backend> {
    reader: ReadHalf<TlsStream<TcpStream>>,
    writer: Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>,
    ctx: Arc<SharedCtx<B>>,
    session: Arc<Session<B::Handle>>,
    watch_rx: mpsc::Receiver<WatchEvent>,
    watch_tx: mpsc::Sender<WatchEvent>,
    push_rx: mpsc::Receiver<Fcall>,
    push_tx: mpsc::Sender<Fcall>,
    pusher: TcpPushSender<WriteHalf<TlsStream<TcpStream>>>,
    remote: Option<SocketAddr>,
}

impl<B: Backend> TcpConnectionHandler<B> {
    pub fn new(stream: TlsStream<TcpStream>, ctx: Arc<SharedCtx<B>>) -> Self {
        let (watch_tx, watch_rx) = mpsc::channel(256);
        let (push_tx, push_rx) = mpsc::channel(64);

        // Extract SPIFFE ID and remote address before splitting the stream.
        let spiffe_id = extract_spiffe_id_from_tls(&stream);
        let remote = stream.get_ref().0.peer_addr().ok();
        let conn_id = lease_manager::next_conn_id();

        match (&spiffe_id, &remote) {
            (Some(id), Some(addr)) => {
                tracing::info!(conn_id, peer = %id, remote = %addr, "tcp peer authenticated");
            }
            (Some(id), None) => {
                tracing::info!(conn_id, peer = %id, "tcp peer authenticated (remote unknown)");
            }
            (None, Some(addr)) => {
                tracing::info!(conn_id, remote = %addr, "tcp peer connected (anonymous)");
            }
            (None, None) => {
                tracing::info!(conn_id, "tcp peer connected (anonymous, remote unknown)");
            }
        }

        let (reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(writer));
        let pusher = TcpPushSender::new(writer.clone());

        let mut session = Session::new(conn_id, crate::session::TransportKind::Tcp);
        session.spiffe_id = spiffe_id;

        Self {
            reader,
            writer,
            ctx,
            session: Arc::new(session),
            watch_rx,
            watch_tx,
            push_rx,
            push_tx,
            pusher,
            remote,
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let span = tracing::info_span!(
            "tcp_conn",
            conn_id = self.session.conn_id,
            peer = self.session.spiffe_id.as_deref().unwrap_or("anonymous"),
            remote = self.remote.map(|a| a.to_string()).unwrap_or_else(|| "unknown".into()),
        );
        self.run_loop().instrument(span).await
    }

    async fn run_loop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!("tcp connection loop start");
        // Collect push messages into a buffer so that write operations
        // happen outside select!, guaranteeing cancel-safety — a
        // cancelled select! branch can never interrupt a half-written
        // TCP frame.
        let mut pending_pushes: Vec<Fcall> = Vec::new();

        loop {
            // Drain any buffered push messages before waiting for
            // the next event. Writes happen here, outside select!.
            for fc in pending_pushes.drain(..) {
                let mt = fc.msg_type.name();
                let tag = fc.tag;
                if let Err(e) = self.pusher.send_push(fc).await {
                    tracing::debug!(error = %e, msg_type = mt, tag, "tcp push send failed");
                } else {
                    tracing::trace!(msg_type = mt, tag, "tcp push sent");
                }
            }

            tokio::select! {
                // Read next request from TCP stream
                result = framing::read_message(&mut self.reader) => {
                    match result {
                        Ok(request) => {
                            let tag = request.tag;
                            let msg_type = request.msg_type;
                            let mt_name = msg_type.name();
                            tracing::trace!(tag, msg_type = mt_name, "tcp req");
                            let result = handlers::dispatch(
                                &self.session, &self.ctx, &self.watch_tx, &self.push_tx, None, request,
                            ).await;
                            let response = match result {
                                Ok(r) => r,
                                Err(e) => {
                                    tracing::debug!(tag, msg_type = mt_name, error = %e, "handler error");
                                    Fcall {
                                        size: 0,
                                        msg_type: MsgType::Rlerror,
                                        tag,
                                        msg: Msg::Lerror { ecode: map_io_error(&*e) },
                                    }
                                }
                            };
                            tracing::trace!(tag, msg_type = response.msg_type.name(), "tcp resp");
                            let mut writer = self.writer.lock().await;
                            framing::write_message(&mut *writer, &response).await?;
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "tcp read closed");
                            break;
                        }
                    }
                }
                // Buffer watch notifications for cancel-safe sending
                Some(event) = self.watch_rx.recv() => {
                    let wid = event.watch_id;
                    let mask = event.event_mask;
                    tracing::trace!(wid, mask = format_args!("{:#x}", mask), "tcp watch event buffered");
                    pending_pushes.push(push::notify_fcall(event));
                }
                // Buffer lease break / other push messages
                Some(fc) = self.push_rx.recv() => {
                    tracing::trace!(msg_type = fc.msg_type.name(), tag = fc.tag, "tcp push buffered");
                    pending_pushes.push(fc);
                }
            }
        }

        self.cleanup();
        Ok(())
    }

    fn cleanup(&self) {
        let fids_before = self.session.fids.len();
        let watches_before = self.session.watch_id_list().len();
        tracing::info!(
            fids = fids_before,
            watches = watches_before,
            "tcp connection cleanup start",
        );
        let mut session_resumable = false;
        if let Some(key) = self.session.get_session_key() {
            let mut flags = 0u32;
            if !self.session.fids.is_empty() {
                flags |= SESSION_FIDS;
            }
            let wids = self.session.watch_id_list();
            if !wids.is_empty() {
                flags |= SESSION_WATCHES;
            }
            session_resumable = true;
            tracing::debug!(flags = format_args!("{:#x}", flags), "tcp session saved for resume");
            self.ctx
                .session_store
                .save(key, self.session.spiffe_id.clone(), flags);
        }
        for wid in self.session.watch_id_list() {
            let _ = self.ctx.watch_mgr.remove_watch(wid);
        }
        self.ctx.watch_mgr.remove_all_for_sender(&self.watch_tx);
        self.ctx.lease_mgr.remove_by_conn(self.session.conn_id);
        self.session.fids.clear();
        tracing::info!(
            fids_released = fids_before,
            watches_released = watches_before,
            session_resumable,
            "tcp connection cleanup done",
        );
    }
}

/// Extract SPIFFE ID from a tokio-rustls TLS server stream's peer certificate.
fn extract_spiffe_id_from_tls(stream: &TlsStream<TcpStream>) -> Option<String> {
    let (_, server_conn) = stream.get_ref();
    let certs = server_conn.peer_certificates()?;
    crate::util::spiffe_id_from_certs(certs)
}
