use crate::backend::Backend;
use crate::handlers::{self, io::ReadResult};
use crate::lease_manager;
use crate::push::{self, BindResponder, PushSender, QuicPushSender};
use crate::session::Session;
use crate::shared::SharedCtx;
use crate::watch_manager::WatchEvent;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::{MsgType, SESSION_FIDS, SESSION_WATCHES};
use p9n_transport::quic::framing;
use crate::util::map_io_error;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{Instrument, Span};

pub struct QuicConnectionHandler<B: Backend> {
    conn: quinn::Connection,
    ctx: Arc<SharedCtx<B>>,
    session: Arc<Session<B::Handle>>,
    watch_rx: mpsc::Receiver<WatchEvent>,
    watch_tx: mpsc::Sender<WatchEvent>,
    push_rx: mpsc::Receiver<Fcall>,
    push_tx: mpsc::Sender<Fcall>,
    bind_rx: mpsc::Receiver<BindResponder>,
    bind_tx: mpsc::Sender<BindResponder>,
    pusher: QuicPushSender,
}

impl<B: Backend> QuicConnectionHandler<B> {
    pub fn new(conn: quinn::Connection, ctx: Arc<SharedCtx<B>>) -> Self {
        let (watch_tx, watch_rx) = mpsc::channel(256);
        let (push_tx, push_rx) = mpsc::channel(64);
        // Tquicstream bind requests. The bound is 4 because we only ever
        // expect one successful bind per connection; the extra slack covers
        // any transient duplicates.
        let (bind_tx, bind_rx) = mpsc::channel(4);
        let spiffe_id = extract_spiffe_id_from_conn(&conn);
        let conn_id = lease_manager::next_conn_id();
        let remote = conn.remote_address();

        if let Some(ref id) = spiffe_id {
            tracing::info!(conn_id, peer = %id, %remote, "peer authenticated");
        } else {
            tracing::info!(conn_id, %remote, "peer connected (anonymous)");
        }

        let mut session = Session::new(conn_id, crate::session::TransportKind::Quic);
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
            bind_rx,
            bind_tx,
            pusher,
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let span = tracing::info_span!(
            "quic_conn",
            conn_id = self.session.conn_id,
            peer = self.session.spiffe_id.as_deref().unwrap_or("anonymous"),
            remote = %self.conn.remote_address(),
        );
        self.run_loop().instrument(span).await
    }

    async fn run_loop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!("connection loop start");
        loop {
            tokio::select! {
                result = self.conn.accept_bi() => {
                    match result {
                        Ok((send, recv)) => {
                            let ctx = self.ctx.clone();
                            let session = self.session.clone();
                            let watch_tx = self.watch_tx.clone();
                            let push_tx = self.push_tx.clone();
                            let bind_tx = self.bind_tx.clone();
                            tokio::spawn(
                                async move {
                                    if let Err(e) = handle_stream(ctx, session, watch_tx, push_tx, bind_tx, send, recv).await {
                                        tracing::warn!(error = %e, "stream handler error");
                                    }
                                }
                                .instrument(Span::current()),
                            );
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "accept_bi closed");
                            break;
                        }
                    }
                }
                result = self.conn.read_datagram() => {
                    match result {
                        Ok(data) => {
                            let ctx = self.ctx.clone();
                            let session = self.session.clone();
                            let watch_tx = self.watch_tx.clone();
                            let push_tx = self.push_tx.clone();
                            let bind_tx = self.bind_tx.clone();
                            let conn = self.conn.clone();
                            let dlen = data.len();
                            tokio::spawn(
                                async move {
                                    if let Err(e) = handle_datagram(ctx, session, watch_tx, push_tx, bind_tx, conn, data).await {
                                        tracing::warn!(error = %e, dlen, "datagram handler error");
                                    }
                                }
                                .instrument(Span::current()),
                            );
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "datagram read closed");
                            break;
                        }
                    }
                }
                Some(responder) = self.bind_rx.recv() => {
                    // Tquicstream bind: open a persistent uni-stream for
                    // push messages and reply with the assigned alias. The
                    // await is expected to return immediately (quinn does
                    // not block a server-initiated uni-stream opener).
                    let result = self.pusher.bind_persistent().await;
                    match &result {
                        Ok(alias) => tracing::debug!(alias, "persistent push stream bound"),
                        Err(e) => tracing::warn!(error = %e, "persistent push stream bind failed"),
                    }
                    let _ = responder.send(result);
                }
                Some(event) = self.watch_rx.recv() => {
                    let wid = event.watch_id;
                    let mask = event.event_mask;
                    if let Err(e) = self.pusher.send_push(push::notify_fcall(event)).await {
                        tracing::debug!(error = %e, wid, mask = format_args!("{:#x}", mask), "push notify send failed");
                    } else {
                        tracing::trace!(wid, mask = format_args!("{:#x}", mask), "push notify sent");
                    }
                }
                Some(fc) = self.push_rx.recv() => {
                    let mt = fc.msg_type.name();
                    let tag = fc.tag;
                    if let Err(e) = self.pusher.send_push(fc).await {
                        tracing::debug!(error = %e, msg_type = mt, tag, "push forward failed");
                    } else {
                        tracing::trace!(msg_type = mt, tag, "push forwarded");
                    }
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
            "connection cleanup start",
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
            tracing::debug!(flags = format_args!("{:#x}", flags), "session saved for resume");
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
            "connection cleanup done",
        );
    }
}

/// Handle a single bidirectional QUIC stream with in-flight tracking.
async fn handle_stream<B: Backend>(
    ctx: Arc<SharedCtx<B>>,
    session: Arc<Session<B::Handle>>,
    watch_tx: mpsc::Sender<WatchEvent>,
    push_tx: mpsc::Sender<Fcall>,
    bind_tx: mpsc::Sender<BindResponder>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let request = framing::read_message(&mut recv).await?;
    let tag = request.tag;
    let msg_type = request.msg_type;
    let mt_name = msg_type.name();

    tracing::trace!(tag, msg_type = mt_name, "stream req");

    // Register in-flight (allows Tflush to cancel this request)
    let cancel = session.register_inflight(tag);

    // ── Fast path for Tread: bypass marshal, write pre-encoded wire bytes ──
    //
    // This avoids the put_data(extend_from_slice) copy in the normal
    // marshal path.  Permission checks, fid validation, and rate limiting
    // are inlined here to match the dispatch() path.
    if msg_type == MsgType::Tread {
        // Pre-checks (same as dispatch)
        let pre = (|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let sid = session.spiffe_id.as_deref();
            let fid = match &request.msg {
                Msg::Read { fid, .. } => *fid,
                _ => return Err("expected Read".into()),
            };
            if !session.fids.contains(fid) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound, format!("stale fid {fid}"),
                ).into());
            }
            handlers::check_perm(&session, &ctx.access, sid, Some(fid), crate::access::PERM_READ)?;
            Ok(())
        })();

        if let Err(e) = pre {
            session.deregister_inflight(tag);
            tracing::debug!(tag, msg_type = mt_name, error = %e, "pre-check failed");
            let err_fc = Fcall {
                size: 0, msg_type: MsgType::Rlerror, tag,
                msg: Msg::Lerror { ecode: map_io_error(&*e) },
            };
            framing::write_message(&mut send, &err_fc).await?;
            send.finish()?;
            return Ok(());
        }

        // Rate limiting (async)
        handlers::do_rate_limit(&session, &ctx, &request).await;

        let result = tokio::select! {
            r = handlers::io::handle_read(&session, &ctx, request) => r,
            _ = cancel.cancelled() => {
                tracing::debug!(tag, msg_type = mt_name, "request cancelled by Tflush");
                Err("flushed".into())
            }
        };
        session.deregister_inflight(tag);

        match result {
            Ok(ReadResult::Raw(ref wire)) => {
                tracing::trace!(tag, msg_type = "Rread", len = wire.len(), "stream resp");
                framing::write_raw(&mut send, wire).await?;
            }
            Err(e) => {
                tracing::debug!(tag, msg_type = mt_name, error = %e, "handler error");
                let err_fc = Fcall {
                    size: 0, msg_type: MsgType::Rlerror, tag,
                    msg: Msg::Lerror { ecode: map_io_error(&*e) },
                };
                framing::write_message(&mut send, &err_fc).await?;
            }
        }
        send.finish()?;
        return Ok(());
    }

    // ── Normal path for all other message types ──
    let result = tokio::select! {
        r = handlers::dispatch(&session, &ctx, &watch_tx, &push_tx, Some(&bind_tx), request) => r,
        _ = cancel.cancelled() => {
            tracing::debug!(tag, msg_type = mt_name, "request cancelled by Tflush");
            Err("flushed".into())
        }
    };

    session.deregister_inflight(tag);

    let response = match result {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(tag, msg_type = mt_name, error = %e, "handler error");
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
    tracing::trace!(tag, msg_type = response.msg_type.name(), "stream resp");
    framing::write_message(&mut send, &response).await?;
    send.finish()?;
    Ok(())
}

/// Handle a single datagram message.
///
/// Guarantees a response is sent back for every successfully decoded request,
/// even if the handler panics or the response encoding/sending fails.
async fn handle_datagram<B: Backend>(
    ctx: Arc<SharedCtx<B>>,
    session: Arc<Session<B::Handle>>,
    watch_tx: mpsc::Sender<WatchEvent>,
    push_tx: mpsc::Sender<Fcall>,
    bind_tx: mpsc::Sender<BindResponder>,
    conn: quinn::Connection,
    data: bytes::Bytes,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let request = framing::decode(&data)?;
    let tag = request.tag;
    let msg_type = request.msg_type;
    let mt_name = msg_type.name();

    tracing::trace!(tag, msg_type = mt_name, dlen = data.len(), "datagram req");

    // Dispatch in a spawned task to catch handler panics.
    // Without this, a panic kills the task silently and the importer
    // waits until the 30s RPC timeout fires, hanging FUSE operations.
    let dispatch_result = tokio::spawn(
        async move {
            handlers::dispatch(&session, &ctx, &watch_tx, &push_tx, Some(&bind_tx), request).await
        }
        .instrument(Span::current()),
    )
    .await;

    let response = match dispatch_result {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::debug!(tag, msg_type = mt_name, error = %e, "handler error");
            Fcall {
                size: 0,
                msg_type: MsgType::Rlerror,
                tag,
                msg: Msg::Lerror {
                    ecode: map_io_error(&*e),
                },
            }
        }
        Err(e) => {
            tracing::error!(tag, msg_type = mt_name, error = %e, "handler panicked");
            Fcall {
                size: 0,
                msg_type: MsgType::Rlerror,
                tag,
                msg: Msg::Lerror { ecode: 5 }, // EIO
            }
        }
    };

    tracing::trace!(tag, msg_type = response.msg_type.name(), "datagram resp");

    // Send the response.  If encoding or sending fails (e.g. response exceeds
    // the QUIC datagram MTU), fall back to a minimal Rlerror so the importer
    // is not left waiting for a response that never arrives.
    if let Err(e) = send_datagram(&conn, &response) {
        tracing::warn!(tag, msg_type = mt_name, error = %e, "datagram response send failed");
        if !matches!(response.msg, Msg::Lerror { .. }) {
            let err_fc = Fcall {
                size: 0,
                msg_type: MsgType::Rlerror,
                tag,
                msg: Msg::Lerror { ecode: 5 }, // EIO
            };
            if let Err(e2) = send_datagram(&conn, &err_fc) {
                tracing::error!(tag, msg_type = mt_name, error = %e2, "error datagram send failed");
            }
        }
    }
    Ok(())
}

/// Encode and send a single datagram response.
fn send_datagram(
    conn: &quinn::Connection,
    fc: &Fcall,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let reply = framing::encode(fc)?;
    conn.send_datagram(reply.into())?;
    Ok(())
}

fn extract_spiffe_id_from_conn(conn: &quinn::Connection) -> Option<String> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().ok()?;
    crate::util::spiffe_id_from_certs(&certs)
}
