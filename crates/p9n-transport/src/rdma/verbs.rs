//! Safe RAII wrappers around libibverbs.
//!
//! All unsafe FFI calls are isolated in this module. Higher-level code
//! uses these wrappers without touching raw pointers directly.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tracing::debug;

use super::ffi;
use crate::error::TransportError;

// ── Device & Context ──────────────────────────────────────────────

/// RAII wrapper around `ibv_context` (opened RDMA device).
pub struct RdmaContext {
    ctx: *mut ffi::ibv_context,
}

unsafe impl Send for RdmaContext {}
unsafe impl Sync for RdmaContext {}

impl RdmaContext {
    /// Open the first available RDMA device, or a named one.
    pub fn open(device_name: Option<&str>) -> Result<Self, TransportError> {
        unsafe {
            let mut num_devices: i32 = 0;
            let dev_list = ffi::ibv_get_device_list(&mut num_devices);
            if dev_list.is_null() || num_devices == 0 {
                return Err(TransportError::Rdma("no RDMA devices found".into()));
            }

            let mut chosen: *mut ffi::ibv_device = ptr::null_mut();
            for i in 0..num_devices as isize {
                let dev = *dev_list.offset(i);
                if dev.is_null() {
                    continue;
                }
                if let Some(name) = device_name {
                    let dev_name = std::ffi::CStr::from_ptr(ffi::ibv_get_device_name(dev));
                    if dev_name.to_string_lossy() == name {
                        chosen = dev;
                        break;
                    }
                } else {
                    chosen = dev;
                    break;
                }
            }

            if chosen.is_null() {
                ffi::ibv_free_device_list(dev_list);
                return Err(TransportError::Rdma(format!(
                    "RDMA device {:?} not found",
                    device_name
                )));
            }

            let ctx = ffi::ibv_open_device(chosen);
            ffi::ibv_free_device_list(dev_list);

            if ctx.is_null() {
                return Err(TransportError::Rdma("ibv_open_device failed".into()));
            }

            debug!("opened RDMA device");
            Ok(Self { ctx })
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::ibv_context {
        self.ctx
    }

    /// Query GID at the given port and index.
    pub fn query_gid(&self, port: u8, index: i32) -> Result<ffi::ibv_gid, TransportError> {
        unsafe {
            let mut gid = ffi::ibv_gid::default();
            let rc = ffi::ibv_query_gid(self.ctx, port, index, &mut gid);
            if rc != 0 {
                return Err(TransportError::Rdma(format!(
                    "ibv_query_gid failed: {}",
                    io::Error::from_raw_os_error(-rc)
                )));
            }
            Ok(gid)
        }
    }

    /// Query port attributes.
    pub fn query_port(&self, port: u8) -> Result<ffi::ibv_port_attr, TransportError> {
        unsafe {
            let mut attr: ffi::ibv_port_attr = std::mem::zeroed();
            let rc = ffi::ibv_query_port(self.ctx, port, &mut attr);
            if rc != 0 {
                return Err(TransportError::Rdma(format!(
                    "ibv_query_port failed: {}",
                    io::Error::from_raw_os_error(-rc)
                )));
            }
            Ok(attr)
        }
    }
}

impl Drop for RdmaContext {
    fn drop(&mut self) {
        unsafe {
            if !self.ctx.is_null() {
                ffi::ibv_close_device(self.ctx);
            }
        }
    }
}

// ── Protection Domain ─────────────────────────────────────────────

/// RAII wrapper around `ibv_pd`.
pub struct ProtectionDomain {
    pd: *mut ffi::ibv_pd,
    _ctx: Arc<RdmaContext>,
}

unsafe impl Send for ProtectionDomain {}
unsafe impl Sync for ProtectionDomain {}

impl ProtectionDomain {
    pub fn new(ctx: Arc<RdmaContext>) -> Result<Self, TransportError> {
        unsafe {
            let pd = ffi::ibv_alloc_pd(ctx.as_ptr());
            if pd.is_null() {
                return Err(TransportError::Rdma("ibv_alloc_pd failed".into()));
            }
            Ok(Self { pd, _ctx: ctx })
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::ibv_pd {
        self.pd
    }
}

impl Drop for ProtectionDomain {
    fn drop(&mut self) {
        unsafe {
            if !self.pd.is_null() {
                ffi::ibv_dealloc_pd(self.pd);
            }
        }
    }
}

// ── Completion Channel ────────────────────────────────────────────

/// RAII wrapper around `ibv_comp_channel` (fd for epoll-based CQ notification).
pub struct CompletionChannel {
    channel: *mut ffi::ibv_comp_channel,
    _ctx: Arc<RdmaContext>,
}

unsafe impl Send for CompletionChannel {}
unsafe impl Sync for CompletionChannel {}

impl CompletionChannel {
    pub fn new(ctx: Arc<RdmaContext>) -> Result<Self, TransportError> {
        unsafe {
            let channel = ffi::ibv_create_comp_channel(ctx.as_ptr());
            if channel.is_null() {
                return Err(TransportError::Rdma(
                    "ibv_create_comp_channel failed".into(),
                ));
            }
            // Set non-blocking for tokio AsyncFd compatibility.
            let fd = (*channel).fd;
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            Ok(Self {
                channel,
                _ctx: ctx,
            })
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::ibv_comp_channel {
        self.channel
    }
}

impl AsRawFd for CompletionChannel {
    fn as_raw_fd(&self) -> RawFd {
        unsafe { (*self.channel).fd }
    }
}

impl Drop for CompletionChannel {
    fn drop(&mut self) {
        unsafe {
            if !self.channel.is_null() {
                ffi::ibv_destroy_comp_channel(self.channel);
            }
        }
    }
}

// ── Completion Queue ──────────────────────────────────────────────

/// RAII wrapper around `ibv_cq`.
pub struct CompletionQueue {
    cq: *mut ffi::ibv_cq,
    channel: Arc<CompletionChannel>,
}

unsafe impl Send for CompletionQueue {}
unsafe impl Sync for CompletionQueue {}

impl CompletionQueue {
    /// Create a CQ with the given capacity, attached to a completion channel.
    pub fn new(
        ctx: &RdmaContext,
        cqe: i32,
        channel: Arc<CompletionChannel>,
    ) -> Result<Self, TransportError> {
        unsafe {
            let cq =
                ffi::ibv_create_cq(ctx.as_ptr(), cqe, ptr::null_mut(), channel.as_ptr(), 0);
            if cq.is_null() {
                return Err(TransportError::Rdma("ibv_create_cq failed".into()));
            }
            // Arm the CQ for the first notification.
            let rc = ffi::ibv_req_notify_cq(cq, 0);
            if rc != 0 {
                ffi::ibv_destroy_cq(cq);
                return Err(TransportError::Rdma("ibv_req_notify_cq failed".into()));
            }
            Ok(Self { cq, channel })
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::ibv_cq {
        self.cq
    }

    /// Poll up to `max_entries` completions synchronously.
    pub fn poll(&self, wc_buf: &mut [ffi::ibv_wc]) -> i32 {
        unsafe { ffi::ibv_poll_cq(self.cq, wc_buf.len() as i32, wc_buf.as_mut_ptr()) }
    }

    /// Re-arm CQ notification (must call after draining completions).
    pub fn req_notify(&self) -> Result<(), TransportError> {
        unsafe {
            let rc = ffi::ibv_req_notify_cq(self.cq, 0);
            if rc != 0 {
                return Err(TransportError::Rdma("ibv_req_notify_cq failed".into()));
            }
            Ok(())
        }
    }

    /// Acknowledge completion events from the channel.
    pub fn ack_events(&self, nevents: u32) {
        unsafe {
            ffi::ibv_ack_cq_events(self.cq, nevents);
        }
    }

    pub fn channel(&self) -> &CompletionChannel {
        &self.channel
    }
}

impl Drop for CompletionQueue {
    fn drop(&mut self) {
        unsafe {
            if !self.cq.is_null() {
                ffi::ibv_destroy_cq(self.cq);
            }
        }
    }
}

// ── Queue Pair ────────────────────────────────────────────────────

/// RDMA QP parameters exchanged between peers during connection bootstrap.
#[derive(Debug, Clone, Copy)]
pub struct QpEndpoint {
    pub qp_num: u32,
    pub lid: u16,
    pub gid: [u8; 16],
    pub psn: u32,
}

/// RAII wrapper around `ibv_qp` (Reliable Connected).
pub struct QueuePair {
    qp: *mut ffi::ibv_qp,
    _pd: Arc<ProtectionDomain>,
}

unsafe impl Send for QueuePair {}
unsafe impl Sync for QueuePair {}

impl QueuePair {
    /// Create an RC (Reliable Connected) queue pair.
    pub fn new(
        pd: Arc<ProtectionDomain>,
        send_cq: &CompletionQueue,
        recv_cq: &CompletionQueue,
        max_send_wr: u32,
        max_recv_wr: u32,
        max_send_sge: u32,
        max_recv_sge: u32,
    ) -> Result<Self, TransportError> {
        unsafe {
            let mut init_attr: ffi::ibv_qp_init_attr = std::mem::zeroed();
            init_attr.qp_type = ffi::IBV_QPT_RC;
            init_attr.send_cq = send_cq.as_ptr();
            init_attr.recv_cq = recv_cq.as_ptr();
            init_attr.cap.max_send_wr = max_send_wr;
            init_attr.cap.max_recv_wr = max_recv_wr;
            init_attr.cap.max_send_sge = max_send_sge;
            init_attr.cap.max_recv_sge = max_recv_sge;
            init_attr.sq_sig_all = 1;

            let qp = ffi::ibv_create_qp(pd.as_ptr(), &mut init_attr);
            if qp.is_null() {
                return Err(TransportError::Rdma("ibv_create_qp failed".into()));
            }
            Ok(Self { qp, _pd: pd })
        }
    }

    pub fn as_ptr(&self) -> *mut ffi::ibv_qp {
        self.qp
    }

    pub fn qp_num(&self) -> u32 {
        unsafe { (*self.qp).qp_num }
    }

    /// Transition QP: RESET → INIT.
    pub fn to_init(&self, port: u8) -> Result<(), TransportError> {
        unsafe {
            let mut attr: ffi::ibv_qp_attr = std::mem::zeroed();
            attr.qp_state = ffi::IBV_QPS_INIT;
            attr.port_num = port;
            attr.pkey_index = 0;
            attr.qp_access_flags =
                ffi::IBV_ACCESS_LOCAL_WRITE | ffi::IBV_ACCESS_REMOTE_READ | ffi::IBV_ACCESS_REMOTE_WRITE;

            let mask = ffi::IBV_QP_STATE
                | ffi::IBV_QP_PKEY_INDEX
                | ffi::IBV_QP_PORT
                | ffi::IBV_QP_ACCESS_FLAGS;

            let rc = ffi::ibv_modify_qp(self.qp, &mut attr, mask);
            if rc != 0 {
                return Err(TransportError::Rdma(format!(
                    "QP to INIT failed: {}",
                    io::Error::from_raw_os_error(-rc)
                )));
            }
            Ok(())
        }
    }

    /// Transition QP: INIT → RTR (Ready To Receive).
    pub fn to_rtr(
        &self,
        remote: &QpEndpoint,
        port: u8,
        gid_index: u8,
    ) -> Result<(), TransportError> {
        unsafe {
            let mut attr: ffi::ibv_qp_attr = std::mem::zeroed();
            attr.qp_state = ffi::IBV_QPS_RTR;
            attr.path_mtu = ffi::IBV_MTU_1024;
            attr.dest_qp_num = remote.qp_num;
            attr.rq_psn = remote.psn;
            attr.max_dest_rd_atomic = 1;
            attr.min_rnr_timer = 12;

            attr.ah_attr.dlid = remote.lid;
            attr.ah_attr.sl = 0;
            attr.ah_attr.src_path_bits = 0;
            attr.ah_attr.port_num = port;

            // Use GRH for RoCE / cross-subnet IB.
            attr.ah_attr.is_global = 1;
            let mut gid = ffi::ibv_gid::default();
            gid.raw = remote.gid;
            attr.ah_attr.grh.dgid = gid;
            attr.ah_attr.grh.sgid_index = gid_index;
            attr.ah_attr.grh.flow_label = 0;
            attr.ah_attr.grh.hop_limit = 64;
            attr.ah_attr.grh.traffic_class = 0;

            let mask = ffi::IBV_QP_STATE
                | ffi::IBV_QP_AV
                | ffi::IBV_QP_PATH_MTU
                | ffi::IBV_QP_DEST_QPN
                | ffi::IBV_QP_RQ_PSN
                | ffi::IBV_QP_MAX_DEST_RD_ATOMIC
                | ffi::IBV_QP_MIN_RNR_TIMER;

            let rc = ffi::ibv_modify_qp(self.qp, &mut attr, mask);
            if rc != 0 {
                return Err(TransportError::Rdma(format!(
                    "QP to RTR failed: {}",
                    io::Error::from_raw_os_error(-rc)
                )));
            }
            Ok(())
        }
    }

    /// Transition QP: RTR → RTS (Ready To Send).
    pub fn to_rts(&self, local_psn: u32) -> Result<(), TransportError> {
        unsafe {
            let mut attr: ffi::ibv_qp_attr = std::mem::zeroed();
            attr.qp_state = ffi::IBV_QPS_RTS;
            attr.sq_psn = local_psn;
            attr.timeout = 14;
            attr.retry_cnt = 7;
            attr.rnr_retry = 7;
            attr.max_rd_atomic = 1;

            let mask = ffi::IBV_QP_STATE
                | ffi::IBV_QP_SQ_PSN
                | ffi::IBV_QP_TIMEOUT
                | ffi::IBV_QP_RETRY_CNT
                | ffi::IBV_QP_RNR_RETRY
                | ffi::IBV_QP_MAX_QP_RD_ATOMIC;

            let rc = ffi::ibv_modify_qp(self.qp, &mut attr, mask);
            if rc != 0 {
                return Err(TransportError::Rdma(format!(
                    "QP to RTS failed: {}",
                    io::Error::from_raw_os_error(-rc)
                )));
            }
            Ok(())
        }
    }

    /// Transition QP to ERROR state (used on close).
    pub fn to_error(&self) {
        unsafe {
            let mut attr: ffi::ibv_qp_attr = std::mem::zeroed();
            attr.qp_state = ffi::IBV_QPS_ERR;
            let _ = ffi::ibv_modify_qp(self.qp, &mut attr, ffi::IBV_QP_STATE);
        }
    }

}

impl Drop for QueuePair {
    fn drop(&mut self) {
        unsafe {
            if !self.qp.is_null() {
                ffi::ibv_destroy_qp(self.qp);
            }
        }
    }
}

// ── Async Completion Queue ────────────────────────────────────────

/// Async wrapper around a CQ + completion channel, suitable for tokio.
///
/// Uses `AsyncFd` on the completion channel's fd to integrate with
/// tokio's epoll reactor. Zero CPU consumption while waiting.
pub struct AsyncCompletionQueue {
    cq: Arc<CompletionQueue>,
    async_fd: AsyncFd<RawFd>,
}

impl AsyncCompletionQueue {
    pub fn new(cq: Arc<CompletionQueue>) -> Result<Self, TransportError> {
        let fd = cq.channel().as_raw_fd();
        let async_fd =
            AsyncFd::new(fd).map_err(|e| TransportError::Rdma(format!("AsyncFd: {e}")))?;
        Ok(Self { cq, async_fd })
    }

    /// Wait for and return completed work requests.
    ///
    /// This integrates with tokio's event loop: the task sleeps on
    /// epoll until the completion channel fd becomes readable, then
    /// drains all pending completions from the CQ.
    pub async fn poll(&self, wc_buf: &mut Vec<ffi::ibv_wc>) -> Result<(), TransportError> {
        loop {
            let mut guard = self.async_fd.readable().await.map_err(|e| {
                TransportError::Rdma(format!("AsyncFd readable: {e}"))
            })?;

            // Acknowledge the completion event from the channel.
            unsafe {
                let mut ev_cq: *mut ffi::ibv_cq = ptr::null_mut();
                let mut ev_ctx: *mut std::ffi::c_void = ptr::null_mut();
                let rc = ffi::ibv_get_cq_event(
                    self.cq.channel().as_ptr(),
                    &mut ev_cq,
                    &mut ev_ctx,
                );
                if rc != 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    return Err(TransportError::Rdma(format!(
                        "ibv_get_cq_event failed: {err}"
                    )));
                }
                self.cq.ack_events(1);
            }

            // Re-arm the CQ for the next notification.
            self.cq.req_notify()?;

            // Drain all completions.
            let batch_size = wc_buf.capacity().max(16);
            wc_buf.clear();
            wc_buf.resize(batch_size, ffi::ibv_wc::default());

            let n = self.cq.poll(wc_buf);
            if n < 0 {
                return Err(TransportError::Rdma("ibv_poll_cq failed".into()));
            }
            if n > 0 {
                wc_buf.truncate(n as usize);
                return Ok(());
            }

            // Spurious wakeup — no completions; clear and loop.
            wc_buf.clear();
            guard.clear_ready();
        }
    }
}
