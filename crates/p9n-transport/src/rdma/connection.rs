//! RDMA transport: Send/Recv based message passing over InfiniBand/RoCE.
//!
//! Phase 1 uses two-sided RDMA Send/Recv for all messages (metadata, data, push).
//! This is functionally equivalent to TCP but over RDMA fabric.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{trace, warn};

use super::config::RdmaConnection;
use super::ffi;
use super::mr_pool::MrPool;
use super::verbs::{AsyncCompletionQueue, CompletionQueue, QueuePair};
use crate::error::TransportError;
use crate::framing;
use p9n_proto::fcall::Fcall;
use p9n_proto::types::NO_TAG;

/// RDMA transport for 9P2000.N.
///
/// All messages flow through RDMA Send/Recv work requests.
/// A background task polls the receive CQ and dispatches responses
/// by tag (same pattern as QUIC datagram and TCP reader tasks).
pub struct RdmaTransport {
    qp: Arc<QueuePair>,
    pd: Arc<super::verbs::ProtectionDomain>,
    send_pool: MrPool,
    send_cq: Arc<CompletionQueue>,
    push_rx: Mutex<mpsc::Receiver<Fcall>>,
    inflight: Arc<DashMap<u16, oneshot::Sender<Fcall>>>,
    alive: Arc<std::sync::atomic::AtomicBool>,
}

impl RdmaTransport {
    /// Create a new RDMA transport from an established connection.
    ///
    /// Spawns a background task that polls the receive CQ and dispatches
    /// incoming messages by tag to waiting RPC callers or the push channel.
    pub fn new(conn: RdmaConnection) -> Self {
        let inflight: Arc<DashMap<u16, oneshot::Sender<Fcall>>> = Arc::new(DashMap::new());
        let (push_tx, push_rx) = mpsc::channel(64);
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));

        // Spawn background receive CQ poller.
        let recv_cq = conn.recv_cq.clone();
        let qp = conn.qp.clone();
        let pd = conn.pd.clone();
        let recv_pool = conn.recv_pool;
        let inflight_bg = inflight.clone();
        let alive_bg = alive.clone();

        tokio::spawn(async move {
            if let Err(e) = recv_loop(
                recv_cq, qp, recv_pool, inflight_bg, push_tx, alive_bg,
            )
            .await
            {
                warn!("RDMA recv loop exited: {e}");
            }
        });

        Self {
            qp: conn.qp,
            pd,
            send_pool: conn.send_pool,
            send_cq: conn.send_cq,
            push_rx: Mutex::new(push_rx),
            inflight,
            alive,
        }
    }

    /// Send a 9P message (fire-and-forget).
    ///
    /// Checks out a slot from the send pool, copies the encoded message,
    /// posts RDMA Send, waits for CQ completion, then the slot is returned
    /// to the pool automatically (via Drop). Supports concurrent sends since
    /// each caller gets its own slot.
    pub async fn send(&self, fc: &Fcall) -> Result<(), TransportError> {
        let encoded = framing::encode(fc)?;
        let mut slot = self.send_pool.checkout_async().await?;
        slot.write_data(&encoded)?;
        slot.post_send(&self.qp, encoded.len())?;
        // Wait for send completion.
        self.poll_send_cq().await?;
        // Slot is returned to pool on drop here.
        Ok(())
    }

    /// Send a 9P message and wait for the tag-matched response.
    pub async fn rpc(&self, fc: &Fcall) -> Result<Fcall, TransportError> {
        let (tx, rx) = oneshot::channel();
        self.inflight.insert(fc.tag, tx);

        if let Err(e) = self.send(fc).await {
            self.inflight.remove(&fc.tag);
            return Err(e);
        }

        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_)) => {
                self.inflight.remove(&fc.tag);
                Err(TransportError::Closed)
            }
            Err(_) => {
                self.inflight.remove(&fc.tag);
                Err(TransportError::Timeout)
            }
        }
    }

    /// Receive the next message from the push/request channel.
    ///
    /// On the client side, this receives push messages (Rnotify, Rleasebreak).
    /// On the server side, this receives ALL incoming messages (requests).
    pub async fn recv_push(&self) -> Result<Fcall, TransportError> {
        let mut rx = self.push_rx.lock().await;
        rx.recv().await.ok_or(TransportError::Closed)
    }

    /// Create a new MR pool sharing the same protection domain as this transport.
    ///
    /// Used by the importer to allocate per-fid RDMA buffers for one-sided
    /// operations (Phase 3). The returned pool's rkey is valid for the
    /// remote peer to RDMA Write/Read.
    pub fn create_data_pool(
        &self,
        slot_size: usize,
        count: usize,
    ) -> Result<MrPool, TransportError> {
        MrPool::new(&self.pd, slot_size, count)
    }

    /// Check if the transport is still alive.
    pub fn is_alive(&self) -> bool {
        self.alive.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Close the RDMA connection.
    pub fn close(&self) {
        self.alive
            .store(false, std::sync::atomic::Ordering::Release);
        self.qp.to_error();
    }

    /// Perform an RDMA Write: push local data into the remote peer's buffer.
    ///
    /// Checks out a slot from the send pool, copies `data` into it,
    /// posts an RDMA Write work request, and waits for completion.
    pub async fn rdma_write(
        &self,
        data: &[u8],
        remote_addr: u64,
        remote_rkey: u32,
    ) -> Result<(), TransportError> {
        let mut slot = self.send_pool.checkout_async().await?;
        slot.write_data(data)?;
        slot.post_rdma_write(&self.qp, data.len(), remote_addr, remote_rkey)?;
        self.poll_send_cq().await
    }

    /// Perform an RDMA Read: pull `len` bytes from the remote peer's buffer.
    ///
    /// Checks out a slot from the send pool, posts an RDMA Read work request,
    /// waits for completion, and returns the data.
    pub async fn rdma_read(
        &self,
        len: usize,
        remote_addr: u64,
        remote_rkey: u32,
    ) -> Result<Vec<u8>, TransportError> {
        let slot = self.send_pool.checkout_async().await?;
        slot.post_rdma_read(&self.qp, len, remote_addr, remote_rkey)?;
        self.poll_send_cq().await?;
        Ok(slot.as_slice()[..len].to_vec())
    }

    /// Poll the send CQ for completion of the most recent send.
    async fn poll_send_cq(&self) -> Result<(), TransportError> {
        // Busy-poll send CQ (send completions are fast, typically < 1µs).
        // We don't use AsyncFd here since send completions are near-instant
        // for connected RC QPs.
        let mut wc = [ffi::ibv_wc::default()];
        for _ in 0..1000 {
            let n = self.send_cq.poll(&mut wc);
            if n > 0 {
                if wc[0].status != ffi::IBV_WC_SUCCESS {
                    return Err(TransportError::Rdma(format!(
                        "send WC error: status={}",
                        wc[0].status
                    )));
                }
                return Ok(());
            }
            if n < 0 {
                return Err(TransportError::Rdma("send CQ poll failed".into()));
            }
            tokio::task::yield_now().await;
        }
        Err(TransportError::Timeout)
    }
}

/// Background receive CQ polling loop.
///
/// Polls the recv CQ via `AsyncFd`, decodes incoming Fcall messages,
/// and dispatches them:
/// - tag=NO_TAG → push channel (Rnotify, Rleasebreak, etc.)
/// - other tags → inflight DashMap (RPC response matching)
///
/// After consuming a recv buffer slot, checks out a fresh slot from the
/// recv pool and reposts it to keep the receive queue saturated.
async fn recv_loop(
    recv_cq: Arc<CompletionQueue>,
    qp: Arc<QueuePair>,
    recv_pool: MrPool,
    inflight: Arc<DashMap<u16, oneshot::Sender<Fcall>>>,
    push_tx: mpsc::Sender<Fcall>,
    alive: Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), TransportError> {
    let async_cq = AsyncCompletionQueue::new(recv_cq)?;
    let mut wc_buf = Vec::with_capacity(16);

    while alive.load(std::sync::atomic::Ordering::Acquire) {
        async_cq.poll(&mut wc_buf).await?;

        for wc in &wc_buf {
            if wc.status != ffi::IBV_WC_SUCCESS {
                warn!(wr_id = wc.wr_id, status = wc.status, "recv WC error");
                // Return the slot to the pool and repost a new one.
                repost_recv_slot(&recv_pool, &qp, wc.wr_id as u32);
                continue;
            }

            let slot_idx = wc.wr_id as u32;
            let byte_len = wc.byte_len as usize;

            // Access the slot's memory directly from the pool's backing buffer.
            let data = unsafe {
                let base = recv_pool.slot_addr(slot_idx);
                std::slice::from_raw_parts(base as *const u8, byte_len)
            };

            let fc = match framing::decode(data) {
                Ok(fc) => fc,
                Err(e) => {
                    warn!("failed to decode RDMA message: {e}");
                    repost_recv_slot(&recv_pool, &qp, slot_idx);
                    continue;
                }
            };

            trace!(tag = fc.tag, msg_type = ?fc.msg_type, "RDMA recv");

            // Dispatch by tag.
            if fc.tag == NO_TAG {
                let _ = push_tx.try_send(fc);
            } else if let Some((_, tx)) = inflight.remove(&fc.tag) {
                let _ = tx.send(fc);
            } else {
                let _ = push_tx.try_send(fc);
            }

            // Return this slot to the pool and post a fresh recv buffer.
            repost_recv_slot(&recv_pool, &qp, slot_idx);
        }
    }

    Ok(())
}

/// Return a slot to the recv pool and post a fresh slot to the receive queue.
fn repost_recv_slot(pool: &MrPool, qp: &QueuePair, consumed_idx: u32) {
    // Return the consumed slot to the pool.
    pool.return_slot(consumed_idx);

    // Check out a fresh slot and post it.
    if let Some(slot) = pool.checkout() {
        if let Err(e) = slot.post_recv(qp) {
            warn!("failed to repost recv buffer: {e}");
            // Slot returns to pool on drop.
            return;
        }
        slot.leak(); // Leased to QP until next completion.
    } else {
        warn!("recv pool exhausted, cannot repost buffer");
    }
}
