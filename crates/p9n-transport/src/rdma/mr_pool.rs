//! Pre-registered memory region pool for RDMA.
//!
//! Each `ibv_reg_mr` / `ibv_dereg_mr` costs ~1µs due to kernel page pinning.
//! This pool eliminates per-message registration by pre-allocating a large
//! contiguous buffer, registering it once as a single MR, and handing out
//! fixed-size slots via a lock-free queue.
//!
//! Slots are returned to the pool automatically when the `MrSlot` guard drops.

use std::sync::Arc;

use crate::error::TransportError;
use super::ffi;
use super::verbs::ProtectionDomain;

/// A pool of pre-registered memory slots backed by a single large MR.
///
/// Thread-safe: checkout and return are lock-free (atomic crossbeam queue).
pub struct MrPool {
    inner: Arc<MrPoolInner>,
}

struct MrPoolInner {
    /// Raw pointer to the single registered MR covering the entire buffer.
    mr: *mut ffi::ibv_mr,
    /// Base pointer of the allocated buffer.
    buf: *mut u8,
    /// Total buffer size.
    buf_len: usize,
    /// Size of each slot.
    slot_size: usize,
    /// Total number of slots.
    slot_count: usize,
    /// Lock-free queue of available slot indices.
    free: crossbeam_queue::ArrayQueue<u32>,
    /// lkey for all slots (same MR).
    lkey: u32,
    /// rkey for remote access (same MR).
    rkey: u32,
}

// SAFETY: The buffer and MR are pinned for the lifetime of the pool.
// Slots are exclusively owned while checked out.
unsafe impl Send for MrPoolInner {}
unsafe impl Sync for MrPoolInner {}

impl MrPool {
    /// Create a new MR pool with `count` slots of `slot_size` bytes each.
    ///
    /// Allocates one contiguous buffer of `count * slot_size` bytes,
    /// page-aligned, and registers it as a single MR.
    pub fn new(
        pd: &ProtectionDomain,
        slot_size: usize,
        count: usize,
    ) -> Result<Self, TransportError> {
        let total = slot_size * count;
        let layout = std::alloc::Layout::from_size_align(total, 4096)
            .map_err(|e| TransportError::Rdma(format!("pool layout: {e}")))?;

        unsafe {
            let buf = std::alloc::alloc_zeroed(layout);
            if buf.is_null() {
                return Err(TransportError::Rdma("pool alloc failed".into()));
            }

            let access = ffi::IBV_ACCESS_LOCAL_WRITE
                | ffi::IBV_ACCESS_REMOTE_READ
                | ffi::IBV_ACCESS_REMOTE_WRITE;

            let mr = ffi::ibv_reg_mr(pd.as_ptr(), buf as *mut _, total, access);
            if mr.is_null() {
                std::alloc::dealloc(buf, layout);
                return Err(TransportError::Rdma("pool ibv_reg_mr failed".into()));
            }

            let free = crossbeam_queue::ArrayQueue::new(count);
            for i in 0..count {
                let _ = free.push(i as u32);
            }

            let lkey = (*mr).lkey;
            let rkey = (*mr).rkey;

            Ok(Self {
                inner: Arc::new(MrPoolInner {
                    mr,
                    buf,
                    buf_len: total,
                    slot_size,
                    slot_count: count,
                    free,
                    lkey,
                    rkey,
                }),
            })
        }
    }

    /// Check out a slot from the pool.
    ///
    /// Returns `None` if all slots are currently in use.
    /// The slot is automatically returned when `MrSlot` drops.
    pub fn checkout(&self) -> Option<MrSlot> {
        let idx = self.inner.free.pop()?;
        Some(MrSlot {
            pool: self.inner.clone(),
            idx,
        })
    }

    /// Check out a slot, blocking until one is available.
    ///
    /// Yields to the tokio scheduler between retries (up to 10ms total).
    pub async fn checkout_async(&self) -> Result<MrSlot, TransportError> {
        for _ in 0..100 {
            if let Some(slot) = self.checkout() {
                return Ok(slot);
            }
            tokio::task::yield_now().await;
        }
        Err(TransportError::Rdma("MR pool exhausted".into()))
    }

    /// Number of slots currently available.
    pub fn available(&self) -> usize {
        self.inner.free.len()
    }

    /// Total number of slots in the pool.
    pub fn capacity(&self) -> usize {
        self.inner.slot_count
    }

    /// Size of each slot in bytes.
    pub fn slot_size(&self) -> usize {
        self.inner.slot_size
    }

    /// The lkey for this pool's MR (same for all slots).
    pub fn lkey(&self) -> u32 {
        self.inner.lkey
    }

    /// The rkey for this pool's MR — given to the remote peer for
    /// RDMA Read/Write access.
    pub fn rkey(&self) -> u32 {
        self.inner.rkey
    }

    /// Base address of the pool's buffer. Combined with slot index and
    /// slot_size, this lets the remote peer calculate per-slot addresses.
    pub fn base_addr(&self) -> u64 {
        self.inner.buf as u64
    }

    /// Get the raw address of a slot by index.
    ///
    /// # Safety
    /// The caller must ensure `idx` is a valid slot index and the memory
    /// is not being concurrently written.
    pub unsafe fn slot_addr(&self, idx: u32) -> u64 {
        let offset = idx as usize * self.inner.slot_size;
        self.inner.buf.add(offset) as u64
    }

    /// Return a leased slot to the pool by index.
    ///
    /// Used by the recv loop to return consumed buffers identified by wr_id.
    pub fn return_slot(&self, idx: u32) {
        let _ = self.inner.free.push(idx);
    }
}

impl Drop for MrPoolInner {
    fn drop(&mut self) {
        unsafe {
            if !self.mr.is_null() {
                ffi::ibv_dereg_mr(self.mr);
            }
            if !self.buf.is_null() {
                let layout =
                    std::alloc::Layout::from_size_align_unchecked(self.buf_len, 4096);
                std::alloc::dealloc(self.buf, layout);
            }
        }
    }
}

/// An exclusively-owned slot from an `MrPool`.
///
/// Provides access to a `slot_size`-byte region of pre-registered memory.
/// Automatically returned to the pool on drop.
pub struct MrSlot {
    pool: Arc<MrPoolInner>,
    idx: u32,
}

impl MrSlot {
    /// RDMA virtual address of this slot.
    pub fn addr(&self) -> u64 {
        let offset = self.idx as usize * self.pool.slot_size;
        unsafe { self.pool.buf.add(offset) as u64 }
    }

    /// lkey for posting work requests.
    pub fn lkey(&self) -> u32 {
        self.pool.lkey
    }

    /// Slot size in bytes.
    pub fn len(&self) -> usize {
        self.pool.slot_size
    }

    /// Slot index (used as wr_id for identifying completions).
    pub fn index(&self) -> u32 {
        self.idx
    }

    /// Get a mutable slice for writing data into this slot.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let offset = self.idx as usize * self.pool.slot_size;
        unsafe {
            std::slice::from_raw_parts_mut(
                self.pool.buf.add(offset),
                self.pool.slot_size,
            )
        }
    }

    /// Get a slice for reading data from this slot.
    pub fn as_slice(&self) -> &[u8] {
        let offset = self.idx as usize * self.pool.slot_size;
        unsafe {
            std::slice::from_raw_parts(
                self.pool.buf.add(offset),
                self.pool.slot_size,
            )
        }
    }

    /// Copy data into this slot. Returns error if data exceeds slot size.
    pub fn write_data(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if data.len() > self.pool.slot_size {
            return Err(TransportError::Rdma(format!(
                "data too large for slot: {} > {}",
                data.len(),
                self.pool.slot_size
            )));
        }
        self.as_mut_slice()[..data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Post this slot as a send work request.
    ///
    /// Uses the pool's lkey and the slot's address directly.
    pub fn post_send(
        &self,
        qp: &super::verbs::QueuePair,
        len: usize,
    ) -> Result<(), TransportError> {
        unsafe {
            let mut sge = ffi::ibv_sge {
                addr: self.addr(),
                length: len as u32,
                lkey: self.lkey(),
            };

            let mut wr: ffi::ibv_send_wr = std::mem::zeroed();
            wr.wr_id = self.idx as u64;
            wr.sg_list = &mut sge;
            wr.num_sge = 1;
            wr.opcode = ffi::IBV_WR_SEND;
            wr.send_flags = ffi::IBV_SEND_SIGNALED;

            let mut bad_wr: *mut ffi::ibv_send_wr = std::ptr::null_mut();
            let rc = ffi::ibv_post_send(qp.as_ptr(), &mut wr, &mut bad_wr);
            if rc != 0 {
                return Err(TransportError::Rdma(format!(
                    "ibv_post_send failed: {}",
                    std::io::Error::from_raw_os_error(-rc)
                )));
            }
            Ok(())
        }
    }

    /// Post this slot as a receive work request.
    pub fn post_recv(
        &self,
        qp: &super::verbs::QueuePair,
    ) -> Result<(), TransportError> {
        unsafe {
            let mut sge = ffi::ibv_sge {
                addr: self.addr(),
                length: self.pool.slot_size as u32,
                lkey: self.lkey(),
            };

            let mut wr: ffi::ibv_recv_wr = std::mem::zeroed();
            wr.wr_id = self.idx as u64;
            wr.sg_list = &mut sge;
            wr.num_sge = 1;

            let mut bad_wr: *mut ffi::ibv_recv_wr = std::ptr::null_mut();
            let rc = ffi::ibv_post_recv(qp.as_ptr(), &mut wr, &mut bad_wr);
            if rc != 0 {
                return Err(TransportError::Rdma(format!(
                    "ibv_post_recv failed: {}",
                    std::io::Error::from_raw_os_error(-rc)
                )));
            }
            Ok(())
        }
    }

    /// Post an RDMA Write: push `len` bytes from this local slot into the
    /// remote peer's memory at (`remote_addr`, `remote_rkey`).
    ///
    /// The caller must ensure the remote buffer was registered with
    /// `IBV_ACCESS_REMOTE_WRITE` and the remote rkey/addr were obtained
    /// via Trdmatoken exchange.
    pub fn post_rdma_write(
        &self,
        qp: &super::verbs::QueuePair,
        len: usize,
        remote_addr: u64,
        remote_rkey: u32,
    ) -> Result<(), TransportError> {
        unsafe {
            let mut sge = ffi::ibv_sge {
                addr: self.addr(),
                length: len as u32,
                lkey: self.lkey(),
            };

            let mut wr: ffi::ibv_send_wr = std::mem::zeroed();
            wr.wr_id = self.idx as u64;
            wr.sg_list = &mut sge;
            wr.num_sge = 1;
            wr.opcode = ffi::IBV_WR_RDMA_WRITE;
            wr.send_flags = ffi::IBV_SEND_SIGNALED;
            wr.wr_rdma_remote_addr = remote_addr;
            wr.wr_rdma_rkey = remote_rkey;

            let mut bad_wr: *mut ffi::ibv_send_wr = std::ptr::null_mut();
            let rc = ffi::ibv_post_send(qp.as_ptr(), &mut wr, &mut bad_wr);
            if rc != 0 {
                return Err(TransportError::Rdma(format!(
                    "ibv_post_send (RDMA_WRITE) failed: {}",
                    std::io::Error::from_raw_os_error(-rc)
                )));
            }
            Ok(())
        }
    }

    /// Post an RDMA Read: pull `len` bytes from the remote peer's memory at
    /// (`remote_addr`, `remote_rkey`) into this local slot.
    ///
    /// The caller must ensure the remote buffer was registered with
    /// `IBV_ACCESS_REMOTE_READ`.
    pub fn post_rdma_read(
        &self,
        qp: &super::verbs::QueuePair,
        len: usize,
        remote_addr: u64,
        remote_rkey: u32,
    ) -> Result<(), TransportError> {
        unsafe {
            let mut sge = ffi::ibv_sge {
                addr: self.addr(),
                length: len as u32,
                lkey: self.lkey(),
            };

            let mut wr: ffi::ibv_send_wr = std::mem::zeroed();
            wr.wr_id = self.idx as u64;
            wr.sg_list = &mut sge;
            wr.num_sge = 1;
            wr.opcode = ffi::IBV_WR_RDMA_READ;
            wr.send_flags = ffi::IBV_SEND_SIGNALED;
            wr.wr_rdma_remote_addr = remote_addr;
            wr.wr_rdma_rkey = remote_rkey;

            let mut bad_wr: *mut ffi::ibv_send_wr = std::ptr::null_mut();
            let rc = ffi::ibv_post_send(qp.as_ptr(), &mut wr, &mut bad_wr);
            if rc != 0 {
                return Err(TransportError::Rdma(format!(
                    "ibv_post_send (RDMA_READ) failed: {}",
                    std::io::Error::from_raw_os_error(-rc)
                )));
            }
            Ok(())
        }
    }

    /// Consume the slot without returning it to the pool.
    ///
    /// Used when the slot is transferred to a long-lived owner (e.g., recv
    /// buffer that will be manually returned after CQ completion).
    pub fn leak(self) -> LeasedSlot {
        let slot = LeasedSlot {
            pool: self.pool.clone(),
            idx: self.idx,
        };
        std::mem::forget(self);
        slot
    }
}

impl Drop for MrSlot {
    fn drop(&mut self) {
        let _ = self.pool.free.push(self.idx);
    }
}

/// A slot that has been leased out (no auto-return on drop).
///
/// Must be explicitly returned via `return_to_pool()`.
pub struct LeasedSlot {
    pool: Arc<MrPoolInner>,
    idx: u32,
}

impl LeasedSlot {
    pub fn addr(&self) -> u64 {
        let offset = self.idx as usize * self.pool.slot_size;
        unsafe { self.pool.buf.add(offset) as u64 }
    }

    pub fn index(&self) -> u32 {
        self.idx
    }

    /// Slot size in bytes.
    pub fn len(&self) -> usize {
        self.pool.slot_size
    }

    /// Read data from this slot.
    pub fn as_slice(&self) -> &[u8] {
        let offset = self.idx as usize * self.pool.slot_size;
        unsafe {
            std::slice::from_raw_parts(
                self.pool.buf.add(offset),
                self.pool.slot_size,
            )
        }
    }

    /// Get a mutable slice for writing data into this slot.
    ///
    /// # Safety (internal)
    /// The slot is exclusively owned by this `LeasedSlot`, so mutable
    /// access is safe as long as no RDMA work request is in flight
    /// referencing this buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let offset = self.idx as usize * self.pool.slot_size;
        unsafe {
            std::slice::from_raw_parts_mut(
                self.pool.buf.add(offset),
                self.pool.slot_size,
            )
        }
    }

    /// Return the slot to the pool.
    pub fn return_to_pool(self) {
        let _ = self.pool.free.push(self.idx);
    }
}
