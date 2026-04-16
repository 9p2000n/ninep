//! RDMA connection handler for 9P2000.N.
//!
//! Parallel to `quic_connection.rs` and `tcp_connection.rs` but for RDMA.
//! Messages are received via RDMA Send/Recv verbs, dispatched to handlers,
//! and responses sent back via RDMA Send. Push messages (Rnotify, Rleasebreak)
//! are also sent via RDMA Send with tag=NO_TAG.
//!
//! **Phase 3 optimization**: When a client registers an RDMA token for a fid
//! (via Trdmatoken), Tread and Twrite use one-sided RDMA operations:
//! - Tread: server reads from file → RDMA Write into client buffer → lightweight Rread
//! - Twrite: server RDMA Reads from client buffer → writes to file → Rwrite

use crate::backend::Backend;
use crate::handlers;
use crate::lease_manager;
use crate::push::{self, PushSender, RdmaPushSender};
use crate::session::Session;
use crate::shared::SharedCtx;
use crate::util::{join_err, map_io_error};
use crate::watch_manager::WatchEvent;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::{MsgType, SESSION_FIDS, SESSION_WATCHES};
use p9n_transport::rdma::RdmaTransport;
use p9n_transport::rdma::config::RdmaConnection;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::Instrument;

pub struct RdmaConnectionHandler<B: Backend> {
    transport: Arc<RdmaTransport>,
    ctx: Arc<SharedCtx<B>>,
    session: Arc<Session<B::Handle>>,
    watch_rx: mpsc::Receiver<WatchEvent>,
    watch_tx: mpsc::Sender<WatchEvent>,
    push_rx: mpsc::Receiver<Fcall>,
    push_tx: mpsc::Sender<Fcall>,
    pusher: RdmaPushSender,
    remote: Option<SocketAddr>,
}

impl<B: Backend> RdmaConnectionHandler<B> {
    pub fn new(
        conn: RdmaConnection,
        ctx: Arc<SharedCtx<B>>,
        spiffe_id: Option<String>,
        remote: Option<SocketAddr>,
    ) -> Self {
        let (watch_tx, watch_rx) = mpsc::channel(256);
        let (push_tx, push_rx) = mpsc::channel(64);

        let conn_id = lease_manager::next_conn_id();
        match (&spiffe_id, &remote) {
            (Some(id), Some(addr)) => {
                tracing::info!(conn_id, peer = %id, remote = %addr, "rdma peer authenticated");
            }
            (Some(id), None) => {
                tracing::info!(conn_id, peer = %id, "rdma peer authenticated (remote unknown)");
            }
            (None, Some(addr)) => {
                tracing::info!(conn_id, remote = %addr, "rdma peer connected (anonymous)");
            }
            (None, None) => {
                tracing::info!(conn_id, "rdma peer connected (anonymous, remote unknown)");
            }
        }

        let transport = Arc::new(RdmaTransport::new(conn));
        let pusher = RdmaPushSender::new(transport.clone());

        let mut session = Session::new(conn_id, crate::session::TransportKind::Rdma);
        session.spiffe_id = spiffe_id;

        Self {
            transport,
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
            "rdma_conn",
            conn_id = self.session.conn_id,
            peer = self.session.spiffe_id.as_deref().unwrap_or("anonymous"),
            remote = self.remote.map(|a| a.to_string()).unwrap_or_else(|| "unknown".into()),
        );
        self.run_loop().instrument(span).await
    }

    async fn run_loop(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!("rdma connection loop start");
        loop {
            tokio::select! {
                result = self.transport.recv_push() => {
                    match result {
                        Ok(request) => {
                            let tag = request.tag;
                            let msg_type = request.msg_type;
                            let mt_name = msg_type.name();
                            tracing::trace!(tag, msg_type = mt_name, "rdma req");

                            // Phase 3: intercept Tread/Twrite for RDMA-optimized path.
                            let response = match msg_type {
                                MsgType::Tread => {
                                    self.handle_read_rdma(request).await
                                }
                                MsgType::Twrite => {
                                    self.handle_write_rdma(request).await
                                }
                                _ => {
                                    handlers::dispatch(
                                        &self.session, &self.ctx,
                                        &self.watch_tx, &self.push_tx, None, request,
                                    ).await
                                }
                            };

                            let response = match response {
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
                            tracing::trace!(tag, msg_type = response.msg_type.name(), "rdma resp");
                            if let Err(e) = self.transport.send(&response).await {
                                tracing::warn!(tag, error = %e, "rdma send failed; closing connection");
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "rdma recv closed");
                            break;
                        }
                    }
                }
                Some(event) = self.watch_rx.recv() => {
                    let wid = event.watch_id;
                    let mask = event.event_mask;
                    if let Err(e) = self.pusher.send_push(push::notify_fcall(event)).await {
                        tracing::debug!(error = %e, wid, mask = format_args!("{:#x}", mask), "rdma push notify send failed");
                    } else {
                        tracing::trace!(wid, mask = format_args!("{:#x}", mask), "rdma push notify sent");
                    }
                }
                Some(fc) = self.push_rx.recv() => {
                    let mt = fc.msg_type.name();
                    let tag = fc.tag;
                    if let Err(e) = self.pusher.send_push(fc).await {
                        tracing::debug!(error = %e, msg_type = mt, tag, "rdma push forward failed");
                    } else {
                        tracing::trace!(msg_type = mt, tag, "rdma push forwarded");
                    }
                }
            }
        }

        self.cleanup();
        Ok(())
    }

    /// Handle Tread: if an RDMA token is registered for this fid (direction=READ),
    /// read data from the backend and RDMA Write it directly into the client's
    /// buffer, then return an Rread with empty data. Otherwise, fall back to
    /// the standard handler.
    async fn handle_read_rdma(
        &self,
        fc: Fcall,
    ) -> Result<Fcall, Box<dyn std::error::Error + Send + Sync>> {
        let (fid, offset, count) = match &fc.msg {
            Msg::Read { fid, offset, count } => (*fid, *offset, *count),
            _ => return Err("expected Read message".into()),
        };

        // Check for RDMA token (direction=0 means READ — server RDMA Writes to client).
        let token = self.session.rdma_tokens.get(&fid).map(|t| t.clone());
        let Some(token) = token else {
            // No RDMA token — use standard handler.
            return handlers::dispatch(
                &self.session, &self.ctx, &self.watch_tx, &self.push_tx, None, fc,
            ).await;
        };
        if token.direction != 0 {
            // Token is for WRITE direction, not READ — use standard handler.
            return handlers::dispatch(
                &self.session, &self.ctx, &self.watch_tx, &self.push_tx, None, fc,
            ).await;
        }

        let tag = fc.tag;
        tracing::debug!(
            tag, fid, offset, count,
            token_addr = format_args!("{:#x}", token.addr),
            token_len = token.length,
            "rdma read (RDMA Write path)",
        );

        // Read file data from backend.
        let fid_state = self.session.fids.get(fid)
            .ok_or_else(|| {
                tracing::debug!(fid, "rdma read rejected: unknown fid");
                std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid")
            })?;
        let handle = fid_state.handle.as_ref()
            .ok_or_else(|| {
                tracing::debug!(fid, "rdma read rejected: fid not open");
                std::io::Error::new(std::io::ErrorKind::Other, "fid not open")
            })?
            .clone();
        drop(fid_state);

        let ctx = self.ctx.clone();
        let data = tokio::task::spawn_blocking(move || {
            ctx.backend.read(&handle, offset, count)
        }).await.map_err(join_err)??;

        let data_len = data.len();
        let mut rdma_written = 0usize;

        // RDMA Write the data directly into the client's registered buffer.
        if data_len > 0 && data_len as u32 <= token.length {
            self.transport.rdma_write(&data, token.addr, token.rkey).await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    tracing::warn!(tag, fid, data_len, error = %e, "RDMA Write to client buffer failed");
                    format!("RDMA Write failed: {e}").into()
                })?;
            rdma_written = data_len;
        } else if data_len as u32 > token.length {
            tracing::warn!(
                tag, fid, data_len,
                token_len = token.length,
                "rdma read: data exceeds client buffer; skipping RDMA Write",
            );
        }

        tracing::debug!(tag, fid, data_len, rdma_written, "rdma read result");

        // Send lightweight Rread with empty data — the client reads from
        // its RDMA buffer instead.
        Ok(Fcall {
            size: 0,
            msg_type: MsgType::Rread,
            tag,
            msg: Msg::Rread { data: Vec::new() },
        })
    }

    /// Handle Twrite: if an RDMA token is registered for this fid (direction=WRITE),
    /// RDMA Read the data from the client's buffer, then write to the backend.
    /// Otherwise, fall back to the standard handler.
    async fn handle_write_rdma(
        &self,
        fc: Fcall,
    ) -> Result<Fcall, Box<dyn std::error::Error + Send + Sync>> {
        let (fid, offset, msg_data) = match &fc.msg {
            Msg::Write { fid, offset, data } => (*fid, *offset, data.clone()),
            _ => return Err("expected Write message".into()),
        };

        // Check for RDMA token (direction=1 means WRITE — server RDMA Reads from client).
        let token = self.session.rdma_tokens.get(&fid).map(|t| t.clone());
        let Some(token) = token else {
            return handlers::dispatch(
                &self.session, &self.ctx, &self.watch_tx, &self.push_tx, None, fc,
            ).await;
        };
        if token.direction != 1 {
            return handlers::dispatch(
                &self.session, &self.ctx, &self.watch_tx, &self.push_tx, None, fc,
            ).await;
        }

        let tag = fc.tag;

        // Determine data source: if the Twrite payload is empty, RDMA Read
        // from the client's buffer. If it has data, use it directly (fallback).
        let (data, source) = if msg_data.is_empty() {
            let count = token.length.min(self.session.get_msize()) as usize;
            tracing::debug!(
                tag, fid, offset, count,
                token_addr = format_args!("{:#x}", token.addr),
                token_len = token.length,
                "rdma write (RDMA Read path)",
            );
            let bytes = self.transport.rdma_read(count, token.addr, token.rkey).await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    tracing::warn!(tag, fid, count, error = %e, "RDMA Read from client buffer failed");
                    format!("RDMA Read failed: {e}").into()
                })?;
            (bytes, "rdma_read")
        } else {
            tracing::debug!(
                tag, fid, offset,
                len = msg_data.len(),
                "rdma write (inline payload)",
            );
            (msg_data, "inline")
        };

        let fid_state = self.session.fids.get(fid)
            .ok_or_else(|| {
                tracing::debug!(fid, "rdma write rejected: unknown fid");
                std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid")
            })?;
        let handle = fid_state.handle.as_ref()
            .ok_or_else(|| {
                tracing::debug!(fid, "rdma write rejected: fid not open");
                std::io::Error::new(std::io::ErrorKind::Other, "fid not open")
            })?
            .clone();
        let qid_path = fid_state.qid.path;
        drop(fid_state);

        // Break read leases held by other connections.
        self.ctx.lease_mgr.break_for_write(qid_path, self.session.conn_id);

        let ctx = self.ctx.clone();
        let data_len = data.len();
        let n = tokio::task::spawn_blocking(move || {
            ctx.backend.write(&handle, offset, &data)
        }).await.map_err(join_err)??;

        tracing::debug!(tag, fid, data_len, written = n, source, "rdma write result");

        Ok(Fcall {
            size: 0,
            msg_type: MsgType::Rwrite,
            tag,
            msg: Msg::Rwrite { count: n as u32 },
        })
    }

    fn cleanup(&self) {
        let fids_before = self.session.fids.len();
        let watches_before = self.session.watch_id_list().len();
        let rdma_tokens = self.session.rdma_tokens.len();
        tracing::info!(
            fids = fids_before,
            watches = watches_before,
            rdma_tokens,
            "rdma connection cleanup start",
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
            tracing::debug!(flags = format_args!("{:#x}", flags), "rdma session saved for resume");
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
            "rdma connection cleanup done",
        );
    }
}
