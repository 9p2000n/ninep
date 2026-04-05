//! Client-side fid allocator with RAII guard for automatic clunk on error.

use crate::rpc_client::RpcClient;
use p9n_proto::fcall::Msg;
use p9n_proto::types::MsgType;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Monotonically increasing fid allocator.
///
/// Fid 0 is reserved for the root. The counter wraps at u32::MAX - 2
/// (avoiding NO_FID=0xFFFFFFFF and PREV_FID=0xFFFFFFFE).
pub struct FidPool {
    next: AtomicU32,
}

impl FidPool {
    pub fn new() -> Self {
        Self {
            next: AtomicU32::new(1),
        }
    }

    pub fn alloc(&self) -> u32 {
        loop {
            let fid = self.next.fetch_add(1, Ordering::Relaxed);
            // Skip reserved values
            if fid != 0xFFFFFFFF && fid != 0xFFFFFFFE {
                return fid;
            }
            // Wrap around (extremely unlikely in practice)
            self.next.store(1, Ordering::Relaxed);
        }
    }
}

/// RAII guard that automatically clunks a fid if not consumed.
///
/// Use in FUSE operations to ensure fids are cleaned up on error paths:
/// ```ignore
/// let guard = FidGuard::new(fid_pool.alloc(), rpc.clone());
/// // ... do walk, getattr, etc. If any fails, guard drops and clunks.
/// guard.consume(); // success: fid is kept alive
/// ```
pub struct FidGuard {
    fid: u32,
    rpc: Arc<RpcClient>,
    consumed: bool,
}

impl FidGuard {
    pub fn new(fid: u32, rpc: Arc<RpcClient>) -> Self {
        Self {
            fid,
            rpc,
            consumed: false,
        }
    }

    pub fn fid(&self) -> u32 {
        self.fid
    }

    /// Consume the guard without clunking. The fid is now the caller's responsibility.
    pub fn consume(mut self) -> u32 {
        self.consumed = true;
        self.fid
    }
}

impl Drop for FidGuard {
    fn drop(&mut self) {
        if !self.consumed {
            let fid = self.fid;
            let rpc = self.rpc.clone();
            // Spawn a background task to send Tclunk — can't block in drop.
            tokio::spawn(async move {
                let _ = rpc
                    .call(MsgType::Tclunk, Msg::Clunk { fid })
                    .await;
            });
        }
    }
}
