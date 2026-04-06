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
use std::sync::Arc;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::server::TlsStream;

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
}

impl<B: Backend> TcpConnectionHandler<B> {
    pub fn new(stream: TlsStream<TcpStream>, ctx: Arc<SharedCtx<B>>) -> Self {
        let (watch_tx, watch_rx) = mpsc::channel(256);
        let (push_tx, push_rx) = mpsc::channel(64);

        // Extract SPIFFE ID from TLS peer certificate
        let spiffe_id = extract_spiffe_id_from_tls(&stream);

        if let Some(ref id) = spiffe_id {
            tracing::info!("tcp peer authenticated: {id}");
        }

        let (reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(writer));
        let pusher = TcpPushSender::new(writer.clone());

        let conn_id = lease_manager::next_conn_id();
        let mut session = Session::new(conn_id);
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
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            tokio::select! {
                // Read next request from TCP stream
                result = framing::read_message(&mut self.reader) => {
                    match result {
                        Ok(request) => {
                            let tag = request.tag;
                            let msg_type = request.msg_type;
                            let result = handlers::dispatch(
                                &self.session, &self.ctx, &self.watch_tx, &self.push_tx, request,
                            ).await;
                            let response = match result {
                                Ok(r) => r,
                                Err(e) => {
                                    tracing::debug!("{} tag={tag}: {e}", msg_type.name());
                                    Fcall {
                                        size: 0,
                                        msg_type: MsgType::Rlerror,
                                        tag,
                                        msg: Msg::Lerror { ecode: map_io_error(&*e) },
                                    }
                                }
                            };
                            let mut writer = self.writer.lock().await;
                            framing::write_message(&mut *writer, &response).await?;
                        }
                        Err(e) => {
                            tracing::debug!("tcp connection closed: {e}");
                            break;
                        }
                    }
                }
                // Send watch notifications on the same TCP stream
                Some(event) = self.watch_rx.recv() => {
                    if let Err(e) = self.pusher.send_push(push::notify_fcall(event)).await {
                        tracing::debug!("tcp push error: {e}");
                    }
                }
                // Send lease break / other push messages on the same TCP stream
                Some(fc) = self.push_rx.recv() => {
                    if let Err(e) = self.pusher.send_push(fc).await {
                        tracing::debug!("tcp push error: {e}");
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
            tracing::debug!("tcp: cleaned up {fid_count} fids on disconnect");
        }
    }
}

/// Extract SPIFFE ID from a tokio-rustls TLS server stream's peer certificate.
fn extract_spiffe_id_from_tls(stream: &TlsStream<TcpStream>) -> Option<String> {
    let (_, server_conn) = stream.get_ref();
    let certs = server_conn.peer_certificates()?;
    crate::util::spiffe_id_from_certs(certs)
}
