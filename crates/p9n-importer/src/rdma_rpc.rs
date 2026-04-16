//! RDMA RPC client with tag-based demultiplexing and per-fid RDMA token management.
//!
//! Parallel to `quic_rpc.rs` and `tcp_rpc.rs` but for RDMA. Messages are
//! sent/received via RDMA Send/Recv verbs.
//!
//! **Phase 3**: Supports per-fid RDMA token registration. When a token is
//! active for a fid, Tread responses are expected with empty data (the server
//! RDMA Writes directly into the client's registered buffer), and Twrite
//! sends with empty data (the server RDMA Reads from the client's buffer).

use crate::error::RpcError;
use dashmap::DashMap;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::tag::TagAllocator;
use p9n_proto::types::MsgType;
use p9n_transport::rdma::mr_pool::{LeasedSlot, MrPool};
use p9n_transport::rdma::RdmaTransport;
use p9n_transport::rdma::config::RdmaConnection;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Default size for per-fid RDMA data buffers.
const DATA_SLOT_SIZE: usize = 4 * 1024 * 1024; // 4 MB
/// Number of data slots in the RDMA data pool.
const DATA_POOL_COUNT: usize = 16;

/// RDMA RPC client that wraps `RdmaTransport` with tag allocation,
/// error response detection, and per-fid RDMA token management.
pub struct RdmaRpcClient {
    transport: Arc<RdmaTransport>,
    tags: TagAllocator,
    /// Per-fid RDMA data pool for one-sided operations.
    data_pool: Option<MrPool>,
    /// Per-fid RDMA buffer assignments: fid → leased slot.
    /// The slot's rkey/addr are registered with the server via Trdmatoken.
    fid_buffers: DashMap<u32, LeasedSlot>,
    conn_id: u64,
}

impl RdmaRpcClient {
    /// Create a new RDMA RPC client from an established RDMA connection.
    pub fn new(conn: RdmaConnection, _push_tx: mpsc::Sender<Fcall>, conn_id: u64) -> Self {
        let transport = Arc::new(RdmaTransport::new(conn));

        // Create a dedicated data pool for per-fid RDMA buffers.
        let data_pool = transport
            .create_data_pool(DATA_SLOT_SIZE, DATA_POOL_COUNT)
            .ok();

        tracing::debug!(
            conn_id,
            data_pool_ok = data_pool.is_some(),
            slot_size = DATA_SLOT_SIZE,
            slot_count = DATA_POOL_COUNT,
            "RdmaRpcClient initialized",
        );

        Self {
            transport,
            tags: TagAllocator::new(),
            data_pool,
            fid_buffers: DashMap::new(),
            conn_id,
        }
    }

    /// The monotonic connection id attached to this client.
    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }

    /// Send a request and wait for the matching response.
    ///
    /// For Tread: if an RDMA read token is registered for the fid, the
    /// response data is read from the local RDMA buffer instead of the
    /// Rread payload.
    ///
    /// For Twrite: if an RDMA write token is registered, data is copied
    /// into the local RDMA buffer and the Twrite payload is sent empty.
    pub async fn call(
        &self,
        msg_type: MsgType,
        msg: Msg,
    ) -> Result<Fcall, RpcError> {
        // Phase 3: RDMA-optimized Tread/Twrite.
        match (&msg, msg_type) {
            (Msg::Read { fid, .. }, MsgType::Tread) => {
                if let Some(buf) = self.fid_buffers.get(fid) {
                    return self.rdma_read_call(*fid, msg, &buf).await;
                }
            }
            (Msg::Write { fid, data, .. }, MsgType::Twrite) if !data.is_empty() => {
                if let Some(mut buf) = self.fid_buffers.get_mut(fid) {
                    return self.rdma_write_call(*fid, msg, &mut buf).await;
                }
            }
            _ => {}
        }

        // Standard path.
        self.call_inner(msg_type, msg).await
    }

    /// Standard RPC call (no RDMA optimization).
    async fn call_inner(
        &self,
        msg_type: MsgType,
        msg: Msg,
    ) -> Result<Fcall, RpcError> {
        let guard = self.tags.alloc_guard().ok_or(RpcError::from("tag pool exhausted"))?;
        let tag = guard.tag();

        let fc = Fcall { size: 0, msg_type, tag, msg };
        let mt_name = msg_type.name();
        let conn_id = self.conn_id;
        tracing::trace!(conn_id, tag, msg_type = mt_name, "rdma rpc send");

        let response = self.transport.rpc(&fc).await.map_err(|e| {
            tracing::debug!(conn_id, tag, msg_type = mt_name, error = %e, "rdma rpc failed");
            RpcError::Transport(e.into())
        })?;

        tracing::trace!(
            conn_id, tag,
            msg_type = mt_name,
            resp = response.msg_type.name(),
            "rdma rpc recv",
        );
        drop(guard);

        match &response.msg {
            Msg::Lerror { ecode } => Err(RpcError::NineP { ecode: *ecode }),
            Msg::Error { ename } => Err(RpcError::NinePString { ename: ename.clone() }),
            _ => Ok(response),
        }
    }

    /// RDMA-optimized Tread: send Tread, receive Rread with empty data,
    /// and return the data from the local RDMA buffer (populated by the
    /// server via RDMA Write).
    async fn rdma_read_call(
        &self,
        fid: u32,
        msg: Msg,
        buf: &LeasedSlot,
    ) -> Result<Fcall, RpcError> {
        let (offset, count) = match &msg {
            Msg::Read { offset, count, .. } => (*offset, *count),
            _ => unreachable!(),
        };

        tracing::debug!(
            conn_id = self.conn_id, fid, offset, count,
            "rdma read (RDMA Write path)",
        );

        // Send standard Tread.
        let resp = self.call_inner(MsgType::Tread, msg).await?;

        // The server RDMA Wrote data into our buffer. The Rread response
        // contains empty data but we know how many bytes were transferred
        // from the response. Read from our local buffer.
        match resp.msg {
            Msg::Rread { data } if data.is_empty() => {
                // Data was delivered via RDMA Write into our buffer.
                // We need the count from the server — for RDMA reads, the
                // count is the min of what we asked for and what the file has.
                // Since Rread with empty data means "data is in RDMA buffer",
                // we use the requested count (the server capped it).
                let actual_count = count.min(buf.as_slice().len() as u32);
                let rdma_data = buf.as_slice()[..actual_count as usize].to_vec();
                Ok(Fcall {
                    size: 0,
                    msg_type: MsgType::Rread,
                    tag: resp.tag,
                    msg: Msg::Rread { data: rdma_data },
                })
            }
            _ => {
                // Server returned data inline (fallback). Use as-is.
                Ok(resp)
            }
        }
    }

    /// RDMA-optimized Twrite: copy data into local RDMA buffer, send Twrite
    /// with empty data. The server RDMA Reads from our buffer.
    async fn rdma_write_call(
        &self,
        fid: u32,
        msg: Msg,
        _buf: &mut LeasedSlot,
    ) -> Result<Fcall, RpcError> {
        let (offset, data) = match msg {
            Msg::Write { offset, data, .. } => (offset, data),
            _ => unreachable!(),
        };

        tracing::debug!(
            conn_id = self.conn_id, fid, offset,
            len = data.len(),
            "rdma write (RDMA Read path)",
        );

        // Copy data into the RDMA buffer so the server can RDMA Read it.
        if let Some(mut buf_ref) = self.fid_buffers.get_mut(&fid) {
            let len = data.len().min(buf_ref.len());
            buf_ref.as_mut_slice()[..len].copy_from_slice(&data[..len]);
        }

        // Send Twrite with empty data — server will RDMA Read.
        self.call_inner(MsgType::Twrite, Msg::Write {
            fid,
            offset,
            data: Vec::new(),
        }).await
    }

    /// Register an RDMA token for a fid.
    ///
    /// Allocates a buffer from the data pool and sends Trdmatoken to the
    /// server with the buffer's rkey/addr/length.
    pub async fn register_rdma_token(
        &self,
        fid: u32,
        direction: u8,
    ) -> Result<(), RpcError> {
        let pool = match &self.data_pool {
            Some(p) => p,
            None => return Ok(()), // No data pool — silently skip.
        };

        let slot = pool.checkout()
            .ok_or_else(|| RpcError::from("RDMA data pool exhausted"))?;

        let rkey = pool.rkey();
        let addr = slot.addr();
        let length = slot.len() as u32;

        tracing::debug!(
            conn_id = self.conn_id, fid, direction, rkey,
            addr = format_args!("{:#x}", addr), length,
            "registering RDMA token",
        );

        let leased = slot.leak();

        // Send Trdmatoken to the server.
        let resp = self.call_inner(MsgType::Trdmatoken, Msg::Rdmatoken {
            fid,
            direction,
            rkey,
            addr,
            length,
        }).await?;

        match resp.msg {
            Msg::Rrdmatoken { .. } => {
                // Token accepted. Store the buffer mapping.
                self.fid_buffers.insert(fid, leased);
                tracing::info!(
                    conn_id = self.conn_id, fid, direction,
                    active_tokens = self.fid_buffers.len(),
                    "RDMA token registered",
                );
                Ok(())
            }
            _ => {
                // Token rejected. Return the slot.
                leased.return_to_pool();
                tracing::warn!(conn_id = self.conn_id, fid, "RDMA token registration rejected");
                Err(RpcError::from("unexpected Rrdmatoken response"))
            }
        }
    }

    /// Deregister the RDMA token for a fid, returning the buffer to the pool.
    pub fn deregister_rdma_token(&self, fid: u32) {
        if let Some((_, leased)) = self.fid_buffers.remove(&fid) {
            leased.return_to_pool();
            tracing::debug!(
                conn_id = self.conn_id, fid,
                active_tokens = self.fid_buffers.len(),
                "RDMA token deregistered",
            );
        }
    }

    /// Check whether the RDMA connection is still alive.
    pub fn is_alive(&self) -> bool {
        self.transport.is_alive()
    }

    /// Close the RDMA connection.
    pub fn close(&self) {
        self.transport.close();
    }
}
