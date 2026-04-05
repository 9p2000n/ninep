//! Capability set management with bitmask fast path.

use crate::types::*;
use std::collections::HashMap;

/// Bit index for known capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CapBit {
    Tls = 0, Auth, Caps, Audit, Compound, Largemsg, Compress, Zerocopy,
    Copy, Alloc, Mmap, Watch, Acl, Snapshot, Xattr2, Lease, Session,
    Consistency, Topology, Trace, Health, Stats, Quota, Ratelimit,
    Async, Pipe, Search, Hash, Spiffe,
    Quic, QuicMulti, Rdma, Cxl,
}

fn build_table() -> HashMap<&'static str, CapBit> {
    use CapBit::*;
    HashMap::from([
        (CAP_TLS, Tls), (CAP_AUTH, Auth), (CAP_SPIFFE, Spiffe),
        (CAP_COMPOUND, Compound), (CAP_LARGEMSG, Largemsg),
        (CAP_COMPRESS, Compress), (CAP_COPY, Copy), (CAP_ALLOC, Alloc),
        (CAP_WATCH, Watch), (CAP_ACL, Acl), (CAP_SNAPSHOT, Snapshot),
        (CAP_XATTR2, Xattr2), (CAP_LEASE, Lease), (CAP_SESSION, Session),
        (CAP_CONSISTENCY, Consistency), (CAP_TOPOLOGY, Topology),
        (CAP_TRACE, Trace), (CAP_HEALTH, Health), (CAP_STATS, Stats),
        (CAP_QUOTA, Quota), (CAP_RATELIMIT, Ratelimit),
        (CAP_ASYNC, Async), (CAP_PIPE, Pipe),
        (CAP_SEARCH, Search), (CAP_HASH, Hash),
        (CAP_QUIC, Quic), (CAP_QUIC_MULTI, QuicMulti), (CAP_RDMA, Rdma), (CAP_CXL, Cxl),
    ])
}

/// Resolve a capability string to its bit index.
pub fn cap_to_bit(cap: &str) -> Option<CapBit> {
    build_table().get(cap).copied()
}

/// A set of negotiated capabilities.
#[derive(Debug, Clone, Default)]
pub struct CapSet {
    bits: u64,
    caps: Vec<String>,
}

impl CapSet {
    pub fn new() -> Self { Self::default() }

    /// Add a capability. Duplicates are ignored.
    pub fn add(&mut self, cap: &str) {
        if self.caps.iter().any(|c| c == cap) { return; }
        self.caps.push(cap.to_string());
        if let Some(b) = cap_to_bit(cap) {
            self.bits |= 1u64 << (b as u64);
        }
    }

    /// Check if a capability is present.
    pub fn has(&self, cap: &str) -> bool {
        if let Some(b) = cap_to_bit(cap) {
            return self.bits & (1u64 << (b as u64)) != 0;
        }
        self.caps.iter().any(|c| c == cap)
    }

    /// Check by bit index.
    pub fn has_bit(&self, bit: CapBit) -> bool {
        self.bits & (1u64 << (bit as u64)) != 0
    }

    pub fn caps(&self) -> &[String] { &self.caps }
    pub fn count(&self) -> usize { self.caps.len() }
}

/// Intersect two capability sets.
pub fn intersect(client: &CapSet, server: &CapSet) -> CapSet {
    let mut result = CapSet::new();
    for c in &client.caps {
        if server.has(c) {
            result.add(c);
        }
    }
    result
}
