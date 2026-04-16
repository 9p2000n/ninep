use crate::fid_table::FidTable;
use dashmap::DashMap;
use p9n_proto::caps::CapSet;
use std::collections::HashSet;
use std::os::unix::io::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use parking_lot::Mutex;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Which transport accepted this connection. Determines whether transport-
/// specific features (Tquicstream, Trdmatoken) are applicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Quic,
    Tcp,
    Rdma,
}

/// A successful Tquicstream binding. Only one per session is allowed in P0.
/// See docs/QUICSTREAM.md for the full design.
#[derive(Debug, Clone, Copy)]
pub struct QuicBinding {
    /// Server-assigned alias (derived from the quinn `StreamId`).
    pub alias: u64,
    /// 0=control, 1=data, 2=push, 3=bulk. P0 only accepts 2.
    pub stream_type: u8,
}

/// Active capability token granted via Tcapgrant/Tcapuse.
#[derive(Debug, Clone)]
pub struct CapToken {
    pub rights: u64,
    pub depth: u16,
    pub expiry: u64,
}

// ── Rate limiting ──

/// Token bucket rate limiter.
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate: f64) -> Self {
        Self {
            tokens: rate, // start full (one second's worth)
            capacity: rate,
            rate,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
    }

    /// Try to consume `cost` tokens. Returns wait duration if insufficient.
    fn try_consume(&mut self, cost: f64) -> Option<Duration> {
        self.refill();
        if self.tokens >= cost {
            self.tokens -= cost;
            None
        } else {
            let deficit = cost - self.tokens;
            self.tokens = 0.0;
            Some(Duration::from_secs_f64(deficit / self.rate))
        }
    }
}

/// Per-fid rate limiter with independent IOPS and BPS token buckets.
pub struct RateLimiter {
    iops: Option<Mutex<TokenBucket>>,
    bps: Option<Mutex<TokenBucket>>,
}

impl RateLimiter {
    pub fn new(iops: u32, bps: u64) -> Self {
        Self {
            iops: if iops > 0 {
                Some(Mutex::new(TokenBucket::new(iops as f64)))
            } else {
                None
            },
            bps: if bps > 0 {
                Some(Mutex::new(TokenBucket::new(bps as f64)))
            } else {
                None
            },
        }
    }

    /// Wait until both IOPS and BPS budgets allow the operation.
    ///
    /// Uses `parking_lot::Mutex` (not tokio) because the critical section
    /// is a trivial O(1) arithmetic operation that completes in nanoseconds
    /// and the lock is never held across an `.await` point.
    pub async fn acquire(&self, ops: u32, bytes: u64) {
        if let Some(ref iops) = self.iops {
            let wait = iops.lock().try_consume(ops as f64);
            if let Some(d) = wait {
                tokio::time::sleep(d).await;
            }
        }
        if let Some(ref bps) = self.bps {
            let wait = bps.lock().try_consume(bytes as f64);
            if let Some(d) = wait {
                tokio::time::sleep(d).await;
            }
        }
    }
}

/// State for an active streaming I/O session opened via Tstreamopen.
///
/// The handle is cloned from the fid's `Arc<H>` at stream-open time, so
/// subsequent `Tstreamdata` and `Tstreamclose` operations access it directly
/// without a fid table lookup.
pub struct StreamState<H: Send + Sync + 'static> {
    /// Cached handle cloned from the fid's open handle.
    pub handle: Arc<H>,
    /// The fid this stream is associated with (for debugging/cleanup).
    pub fid: u32,
    /// Direction: 0 = read, 1 = write.
    pub direction: u8,
    /// Current file offset, advanced on each Tstreamdata.
    pub offset: Mutex<u64>,
}

pub struct Session<H: Send + Sync + 'static = OwnedFd> {
    pub version: Mutex<Option<String>>,
    pub msize: AtomicU32,
    pub caps: Mutex<CapSet>,
    pub spiffe_id: Option<String>,
    pub session_key: Mutex<Option<[u8; 16]>>,
    pub conn_id: u64,
    pub transport_kind: TransportKind,
    pub fids: FidTable<H>,
    pub watch_ids: Mutex<HashSet<u32>>,
    authenticated: AtomicBool,
    spiffe_verified: AtomicBool,
    pub active_caps: DashMap<u32, CapToken>,
    /// Active leases: lease_id → (fid, lease_type, expiry_instant, duration_secs)
    pub active_leases: DashMap<u64, (u32, u8, std::time::Instant, u32)>,
    /// Active streams: stream_id → StreamState. Used by streaming I/O.
    pub active_streams: DashMap<u32, StreamState<H>>,
    /// Per-fid rate limiters. Only populated when rate limiting is enabled.
    pub rate_limits: DashMap<u32, RateLimiter>,
    /// In-flight requests: tag → CancellationToken. Used by Tflush.
    pub inflight: DashMap<u16, CancellationToken>,
    /// Per-fid RDMA tokens: fid → RdmaToken. Registered via Trdmatoken.
    /// When present, Tread/Twrite use one-sided RDMA Read/Write instead
    /// of copying data through the message payload.
    pub rdma_tokens: DashMap<u32, RdmaToken>,
    /// Persistent QUIC push stream binding set via Tquicstream(push).
    /// At most one binding per session — a rebind attempt while `Some`
    /// must return EBUSY. See docs/QUICSTREAM.md.
    pub quic_push_binding: Mutex<Option<QuicBinding>>,
}

/// An RDMA token registered by the client for a specific fid.
///
/// Holds the remote memory registration info so the server can
/// RDMA Write (for reads) or RDMA Read (for writes) directly
/// to/from the client's buffer.
#[derive(Debug, Clone)]
pub struct RdmaToken {
    /// 0 = READ (server will RDMA Write data into client buffer),
    /// 1 = WRITE (server will RDMA Read data from client buffer).
    pub direction: u8,
    /// Remote key for the client's registered memory region.
    pub rkey: u32,
    /// Remote virtual address of the client's buffer.
    pub addr: u64,
    /// Size of the client's registered buffer.
    pub length: u32,
}

impl<H: Send + Sync + 'static> Session<H> {
    pub fn new(conn_id: u64, transport_kind: TransportKind) -> Self {
        Self {
            version: Mutex::new(None),
            msize: AtomicU32::new(8192),
            caps: Mutex::new(CapSet::new()),
            spiffe_id: None,
            session_key: Mutex::new(None),
            conn_id,
            transport_kind,
            fids: FidTable::new(),
            watch_ids: Mutex::new(HashSet::new()),
            authenticated: AtomicBool::new(true),
            spiffe_verified: AtomicBool::new(false),
            active_caps: DashMap::new(),
            active_leases: DashMap::new(),
            active_streams: DashMap::new(),
            rate_limits: DashMap::new(),
            inflight: DashMap::new(),
            rdma_tokens: DashMap::new(),
            quic_push_binding: Mutex::new(None),
        }
    }

    pub fn reset(&self) {
        self.fids.clear();
        self.watch_ids.lock().clear();
        *self.caps.lock() = CapSet::new();
        *self.session_key.lock() = None;
        self.active_caps.clear();
        self.active_leases.clear();
        self.active_streams.clear();
        self.rate_limits.clear();
        self.rdma_tokens.clear();
        *self.quic_push_binding.lock() = None;
        self.spiffe_verified.store(false, Ordering::Relaxed);
        // Cancel all in-flight requests
        for entry in self.inflight.iter() {
            entry.value().cancel();
        }
        self.inflight.clear();
    }

    pub fn get_version(&self) -> Option<String> { self.version.lock().clone() }
    pub fn set_version(&self, v: String) { *self.version.lock() = Some(v); }
    pub fn get_msize(&self) -> u32 { self.msize.load(Ordering::Relaxed) }
    pub fn set_msize(&self, v: u32) { self.msize.store(v, Ordering::Relaxed); }
    pub fn set_caps(&self, c: CapSet) { *self.caps.lock() = c; }
    pub fn has_cap(&self, cap: &str) -> bool { self.caps.lock().has(cap) }
    pub fn get_session_key(&self) -> Option<[u8; 16]> { *self.session_key.lock() }
    pub fn set_session_key(&self, k: [u8; 16]) { *self.session_key.lock() = Some(k); }
    pub fn add_watch_id(&self, id: u32) { self.watch_ids.lock().insert(id); }
    pub fn remove_watch_id(&self, id: u32) { self.watch_ids.lock().remove(&id); }
    pub fn watch_id_list(&self) -> Vec<u32> { self.watch_ids.lock().iter().copied().collect() }
    pub fn is_authenticated(&self) -> bool { self.authenticated.load(Ordering::Relaxed) }
    pub fn set_authenticated(&self, v: bool) { self.authenticated.store(v, Ordering::Relaxed); }
    pub fn is_spiffe_verified(&self) -> bool { self.spiffe_verified.load(Ordering::Relaxed) }
    pub fn set_spiffe_verified(&self, v: bool) { self.spiffe_verified.store(v, Ordering::Relaxed); }

    pub fn check_cap(&self, fid: u32, required: u32) -> bool {
        if let Some(cap) = self.active_caps.get(&fid) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now < cap.expiry && (cap.rights as u32) & required == required {
                return true;
            }
        }
        false
    }

    /// Register an in-flight request. Returns a CancellationToken for the handler to check.
    pub fn register_inflight(&self, tag: u16) -> CancellationToken {
        let token = CancellationToken::new();
        self.inflight.insert(tag, token.clone());
        token
    }

    /// Deregister an in-flight request (normal completion).
    pub fn deregister_inflight(&self, tag: u16) {
        self.inflight.remove(&tag);
    }

    /// Cancel an in-flight request (called by Tflush handler).
    pub fn cancel_inflight(&self, tag: u16) -> bool {
        if let Some((_, token)) = self.inflight.remove(&tag) {
            token.cancel();
            true
        } else {
            false
        }
    }
}
