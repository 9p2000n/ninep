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
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct RdmaConnectionHandler<B: Backend> {
    transport: Arc<RdmaTransport>,
    ctx: Arc<SharedCtx<B>>,
    session: Arc<Session<B::Handle>>,
    watch_rx: mpsc::Receiver<WatchEvent>,
    watch_tx: mpsc::Sender<WatchEvent>,
    push_rx: mpsc::Receiver<Fcall>,
    push_tx: mpsc::Sender<Fcall>,
    pusher: RdmaPushSender,
}

impl<B: Backend> RdmaConnectionHandler<B> {
    pub fn new(
        conn: RdmaConnection,
        ctx: Arc<SharedCtx<B>>,
        spiffe_id: Option<String>,
    ) -> Self {
        let (watch_tx, watch_rx) = mpsc::channel(256);
        let (push_tx, push_rx) = mpsc::channel(64);

        if let Some(ref id) = spiffe_id {
            tracing::info!("rdma peer authenticated: {id}");
        }

        let transport = Arc::new(RdmaTransport::new(conn));
        let pusher = RdmaPushSender::new(transport.clone());

        let conn_id = lease_manager::next_conn_id();
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
        }
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            tokio::select! {
                result = self.transport.recv_push() => {
                    match result {
                        Ok(request) => {
                            let tag = request.tag;
                            let msg_type = request.msg_type;
                            tracing::trace!("rdma req: tag={tag} type={}", msg_type.name());

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
                                    tracing::debug!("{} tag={tag}: {e}", msg_type.name());
                                    Fcall {
                                        size: 0,
                                        msg_type: MsgType::Rlerror,
                                        tag,
                                        msg: Msg::Lerror { ecode: map_io_error(&*e) },
                                    }
                                }
                            };
                            tracing::trace!("rdma resp: tag={tag} type={}", response.msg_type.name());
                            if let Err(e) = self.transport.send(&response).await {
                                tracing::debug!("rdma send error: {e}");
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::debug!("rdma connection closed: {e}");
                            break;
                        }
                    }
                }
                Some(event) = self.watch_rx.recv() => {
                    if let Err(e) = self.pusher.send_push(push::notify_fcall(event)).await {
                        tracing::debug!("rdma push error: {e}");
                    }
                }
                Some(fc) = self.push_rx.recv() => {
                    if let Err(e) = self.pusher.send_push(fc).await {
                        tracing::debug!("rdma push error: {e}");
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
        tracing::trace!("rdma read: fid={fid} offset={offset} count={count} (RDMA Write path)");

        // Read file data from backend.
        let fid_state = self.session.fids.get(fid)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
        let handle = fid_state.handle.as_ref()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "fid not open"))?
            .clone();
        drop(fid_state);

        let ctx = self.ctx.clone();
        let data = tokio::task::spawn_blocking(move || {
            ctx.backend.read(&handle, offset, count)
        }).await.map_err(join_err)??;

        let data_len = data.len();

        // RDMA Write the data directly into the client's registered buffer.
        if data_len > 0 && data_len as u32 <= token.length {
            self.transport.rdma_write(&data, token.addr, token.rkey).await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("RDMA Write failed: {e}").into()
                })?;
        }

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
        let data = if msg_data.is_empty() {
            let count = token.length.min(self.session.get_msize()) as usize;
            tracing::trace!("rdma write: fid={fid} offset={offset} count={count} (RDMA Read path)");
            self.transport.rdma_read(count, token.addr, token.rkey).await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("RDMA Read failed: {e}").into()
                })?
        } else {
            tracing::trace!("rdma write: fid={fid} offset={offset} len={} (inline)", msg_data.len());
            msg_data
        };

        let fid_state = self.session.fids.get(fid)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
        let handle = fid_state.handle.as_ref()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "fid not open"))?
            .clone();
        let qid_path = fid_state.qid.path;
        drop(fid_state);

        // Break read leases held by other connections.
        self.ctx.lease_mgr.break_for_write(qid_path, self.session.conn_id);

        let ctx = self.ctx.clone();
        let n = tokio::task::spawn_blocking(move || {
            ctx.backend.write(&handle, offset, &data)
        }).await.map_err(join_err)??;

        Ok(Fcall {
            size: 0,
            msg_type: MsgType::Rwrite,
            tag,
            msg: Msg::Rwrite { count: n as u32 },
        })
    }

    fn cleanup(&self) {
        tracing::debug!(
            "rdma connection cleanup: conn_id={} fids={} watches={}",
            self.session.conn_id,
            self.session.fids.len(),
            self.session.watch_id_list().len(),
        );
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
            tracing::debug!("rdma: cleaned up {fid_count} fids on disconnect");
        }
    }
}
