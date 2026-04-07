//! Client-side lease tracking for cache coherence.
//!
//! Maps between file handles (fh), server lease IDs, and inodes so that:
//! - `getattr` can skip TTL checks while a lease is held
//! - `release` can send Tleaseack to the server
//! - `push_receiver` can invalidate caches on Rleasebreak

use dashmap::DashMap;

pub struct LeaseMap {
    /// fh (open fid) → lease_id. Used by release() to find which lease to ack.
    fh_to_lease: DashMap<u32, u64>,
    /// lease_id → ino. Used by push_receiver to find which inode to invalidate.
    lease_to_ino: DashMap<u64, u64>,
    /// ino → active lease count. Used by getattr to decide whether to skip TTL.
    ino_lease_count: DashMap<u64, u32>,
}

impl LeaseMap {
    pub fn new() -> Self {
        Self {
            fh_to_lease: DashMap::new(),
            lease_to_ino: DashMap::new(),
            ino_lease_count: DashMap::new(),
        }
    }

    /// Record a newly granted lease.
    pub fn grant(&self, fh: u32, lease_id: u64, ino: u64) {
        tracing::debug!("lease grant: fh={fh} lid={lease_id} ino={ino}");
        self.fh_to_lease.insert(fh, lease_id);
        self.lease_to_ino.insert(lease_id, ino);
        self.ino_lease_count
            .entry(ino)
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    /// Release the lease associated with a file handle (on close).
    /// Returns the lease_id if the lease was still active (not already broken).
    pub fn release_by_fh(&self, fh: u32) -> Option<u64> {
        let (_, lease_id) = self.fh_to_lease.remove(&fh)?;
        // If lease_to_ino still has this lease, it hasn't been broken yet.
        if let Some((_, ino)) = self.lease_to_ino.remove(&lease_id) {
            tracing::debug!("lease release: fh={fh} lid={lease_id} ino={ino}");
            self.decrement_ino(ino);
            Some(lease_id)
        } else {
            tracing::debug!("lease release: fh={fh} lid={lease_id} — already broken");
            None
        }
    }

    /// Handle a server-initiated lease break. Returns the inode to invalidate.
    pub fn break_lease(&self, lease_id: u64) -> Option<u64> {
        let (_, ino) = self.lease_to_ino.remove(&lease_id)?;
        tracing::debug!("lease break: lid={lease_id} ino={ino}");
        self.decrement_ino(ino);
        Some(ino)
    }

    /// Check whether an inode has any active lease.
    pub fn has_lease(&self, ino: u64) -> bool {
        self.ino_lease_count
            .get(&ino)
            .map(|c| *c > 0)
            .unwrap_or(false)
    }

    /// Remove and return all active leases. Used during graceful shutdown
    /// to send Tleaseack for every outstanding lease.
    pub fn drain_all(&self) -> Vec<(u32, u64)> {
        let entries: Vec<(u32, u64)> = self
            .fh_to_lease
            .iter()
            .map(|r| (*r.key(), *r.value()))
            .collect();
        self.fh_to_lease.clear();
        self.lease_to_ino.clear();
        self.ino_lease_count.clear();
        entries
    }

    fn decrement_ino(&self, ino: u64) {
        if let Some(mut entry) = self.ino_lease_count.get_mut(&ino) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                drop(entry);
                self.ino_lease_count.remove(&ino);
            }
        }
    }
}
