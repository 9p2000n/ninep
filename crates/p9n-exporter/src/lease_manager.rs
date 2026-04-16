//! Global lease manager: tracks active leases across all connections and
//! sends Rleasebreak push messages when a conflicting write occurs.
//!
//! Lease conflict rules:
//! - Multiple READ leases from different connections can coexist.
//! - A WRITE lease is exclusive: only one connection may hold it.
//! - Requesting WRITE when another connection holds READ: the READ leases are
//!   broken (Rleasebreak pushed) and the WRITE is granted.
//! - Requesting WRITE when another connection holds WRITE: rejected (EAGAIN).
//! - Requesting READ when another connection holds WRITE: rejected (EAGAIN).
//! - Same-connection leases never conflict with each other.

use dashmap::DashMap;
use p9n_proto::fcall::Fcall;
use p9n_proto::types;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

/// Snapshot of lease manager state, suitable for periodic logging.
#[derive(Debug, Clone, Copy)]
pub struct LeaseStats {
    pub leases: usize,
    pub qid_paths: usize,
    pub read_leases: usize,
    pub write_leases: usize,
    pub breaks_attempted: u64,
    pub break_pushes_dropped: u64,
}

/// Atomic counters for the lease subsystem. Kept separate from `LeaseManager`
/// so that mutation (recording events) is decoupled from observation
/// (`snapshot()` for logging / metrics export).
#[derive(Default)]
struct LeaseCounters {
    breaks_attempted: AtomicU64,
    break_pushes_dropped: AtomicU64,
}

impl LeaseCounters {
    fn record_break_attempt(&self) {
        self.breaks_attempted.fetch_add(1, Ordering::Relaxed);
    }
    fn record_break_dropped(&self) {
        self.break_pushes_dropped.fetch_add(1, Ordering::Relaxed);
    }
    fn breaks(&self) -> u64 {
        self.breaks_attempted.load(Ordering::Relaxed)
    }
    fn drops(&self) -> u64 {
        self.break_pushes_dropped.load(Ordering::Relaxed)
    }
}

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a unique connection identifier.
pub fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

struct LeaseEntry {
    qid_path: u64,
    lease_type: u8,
    conn_id: u64,
    push_tx: mpsc::Sender<Fcall>,
}

/// Result of a lease grant attempt.
pub enum GrantResult {
    /// Lease can be granted (conflicting READ leases, if any, have been broken).
    Granted,
    /// Another connection holds a conflicting lease — return EAGAIN.
    Conflict,
}

/// Server-wide lease registry shared across all connections.
pub struct LeaseManager {
    /// lease_id → entry
    leases: DashMap<u64, LeaseEntry>,
    /// qid_path → list of lease_ids on that inode
    path_leases: DashMap<u64, Vec<u64>>,
    counters: LeaseCounters,
}

impl LeaseManager {
    pub fn new() -> Self {
        Self {
            leases: DashMap::new(),
            path_leases: DashMap::new(),
            counters: LeaseCounters::default(),
        }
    }

    /// Snapshot the current state of the lease manager (for periodic logging).
    pub fn stats(&self) -> LeaseStats {
        let mut read = 0usize;
        let mut write = 0usize;
        for e in self.leases.iter() {
            match e.value().lease_type {
                types::LEASE_READ => read += 1,
                types::LEASE_WRITE => write += 1,
                _ => {}
            }
        }
        LeaseStats {
            leases: self.leases.len(),
            qid_paths: self.path_leases.len(),
            read_leases: read,
            write_leases: write,
            breaks_attempted: self.counters.breaks(),
            break_pushes_dropped: self.counters.drops(),
        }
    }

    /// Check whether `lease_type` can be granted on `qid_path` for `conn_id`.
    ///
    /// If the request is WRITE and other connections hold READ leases, those
    /// leases are broken (Rleasebreak pushed) and `Granted` is returned.
    /// If a conflicting WRITE lease from another connection exists, `Conflict`
    /// is returned.
    pub fn try_grant(
        &self,
        qid_path: u64,
        lease_type: u8,
        conn_id: u64,
    ) -> GrantResult {
        tracing::trace!(qid_path, lease_type, conn_id, "lease try_grant");
        let lease_ids = match self.path_leases.get(&qid_path) {
            Some(ids) => ids.clone(),
            None => {
                tracing::trace!(qid_path, lease_type, conn_id, "lease granted: no existing leases on path");
                return GrantResult::Granted;
            }
        };

        for lid in &lease_ids {
            let entry = match self.leases.get(lid) {
                Some(e) => e,
                None => continue,
            };
            if entry.conn_id == conn_id {
                continue; // same connection — no conflict
            }

            match (lease_type, entry.lease_type) {
                // READ vs READ: coexist
                (types::LEASE_READ, types::LEASE_READ) => {}

                // READ vs (other's) WRITE: conflict
                (types::LEASE_READ, types::LEASE_WRITE) => {
                    tracing::debug!(
                        qid_path,
                        conn_id,
                        holder_lid = lid,
                        holder_conn = entry.conn_id,
                        "lease conflict: READ requested but other connection holds WRITE",
                    );
                    return GrantResult::Conflict;
                }

                // WRITE vs (other's) WRITE: conflict
                (types::LEASE_WRITE, types::LEASE_WRITE) => {
                    tracing::debug!(
                        qid_path,
                        conn_id,
                        holder_lid = lid,
                        holder_conn = entry.conn_id,
                        "lease conflict: WRITE requested but other connection holds WRITE",
                    );
                    return GrantResult::Conflict;
                }

                // WRITE vs (other's) READ: break their READs, then grant
                (types::LEASE_WRITE, types::LEASE_READ) => {
                    // Will be broken below after the conflict scan completes.
                }

                _ => {}
            }
        }

        // If requesting WRITE, break all READ leases from other connections.
        if lease_type == types::LEASE_WRITE {
            let mut broken = 0usize;
            for lid in &lease_ids {
                if let Some(entry) = self.leases.get(lid) {
                    if entry.conn_id != conn_id && entry.lease_type == types::LEASE_READ {
                        self.counters.record_break_attempt();
                        broken += 1;
                        tracing::info!(
                            broken_lid = lid,
                            holder_conn = entry.conn_id,
                            writer_conn = conn_id,
                            qid_path,
                            "lease break: WRITE supersedes READ",
                        );
                        let fc = crate::push::leasebreak_fcall(*lid, 0);
                        if let Err(e) = entry.push_tx.try_send(fc) {
                            self.counters.record_break_dropped();
                            tracing::warn!(
                                broken_lid = lid,
                                holder_conn = entry.conn_id,
                                error = %e,
                                "lease break notification dropped (channel full or closed)",
                            );
                        }
                    }
                }
            }
            tracing::debug!(qid_path, conn_id, broken, "lease granted: WRITE after breaking READs");
        } else {
            tracing::trace!(qid_path, conn_id, lease_type, "lease granted: compatible with existing");
        }

        GrantResult::Granted
    }

    /// Register a newly granted lease.
    pub fn register(
        &self,
        lease_id: u64,
        qid_path: u64,
        lease_type: u8,
        conn_id: u64,
        push_tx: mpsc::Sender<Fcall>,
    ) {
        self.leases.insert(
            lease_id,
            LeaseEntry {
                qid_path,
                lease_type,
                conn_id,
                push_tx,
            },
        );
        self.path_leases
            .entry(qid_path)
            .or_default()
            .push(lease_id);
        tracing::debug!(
            lease_id,
            qid_path,
            lease_type,
            conn_id,
            total_leases = self.leases.len(),
            "lease registered",
        );
    }

    /// Break all leases on `qid_path` held by connections other than
    /// `writer_conn_id`.  Sends an Rleasebreak push to each affected
    /// connection (non-blocking `try_send`).
    pub fn break_for_write(&self, qid_path: u64, writer_conn_id: u64) {
        let lease_ids = match self.path_leases.get(&qid_path) {
            Some(ids) => ids.clone(),
            None => return,
        };

        let mut broken = 0usize;
        let mut dropped = 0usize;
        for lid in &lease_ids {
            if let Some(entry) = self.leases.get(lid) {
                if entry.conn_id == writer_conn_id {
                    continue;
                }
                self.counters.record_break_attempt();
                broken += 1;
                tracing::info!(
                    broken_lid = lid,
                    qid_path,
                    holder_conn = entry.conn_id,
                    writer_conn = writer_conn_id,
                    holder_lease_type = entry.lease_type,
                    "lease break_for_write: notifying holder",
                );
                let fc = crate::push::leasebreak_fcall(*lid, 0);
                if let Err(e) = entry.push_tx.try_send(fc) {
                    self.counters.record_break_dropped();
                    dropped += 1;
                    tracing::warn!(
                        broken_lid = lid,
                        holder_conn = entry.conn_id,
                        error = %e,
                        "lease break_for_write notification dropped (channel full or closed)",
                    );
                }
            }
        }
        if broken > 0 || dropped > 0 {
            tracing::debug!(
                qid_path,
                writer_conn = writer_conn_id,
                broken,
                dropped,
                "lease break_for_write summary",
            );
        }
    }

    /// Remove a lease after the client acknowledges the break (Tleaseack).
    pub fn acknowledge(&self, lease_id: u64) {
        if let Some((_, entry)) = self.leases.remove(&lease_id) {
            if let Some(mut ids) = self.path_leases.get_mut(&entry.qid_path) {
                ids.retain(|&id| id != lease_id);
            }
            tracing::trace!(
                lease_id,
                qid_path = entry.qid_path,
                conn_id = entry.conn_id,
                total_leases = self.leases.len(),
                "lease acknowledged and removed",
            );
        } else {
            tracing::trace!(lease_id, "lease acknowledge: lease not found (already removed)");
        }
    }

    /// Remove all leases belonging to a connection (cleanup on disconnect).
    pub fn remove_by_conn(&self, conn_id: u64) {
        let to_remove: Vec<u64> = self
            .leases
            .iter()
            .filter(|e| e.conn_id == conn_id)
            .map(|e| *e.key())
            .collect();
        let n = to_remove.len();
        for lid in to_remove {
            self.acknowledge(lid);
        }
        tracing::debug!(
            conn_id,
            removed = n,
            total_leases = self.leases.len(),
            "lease remove_by_conn",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_zero() {
        let c = LeaseCounters::default();
        assert_eq!(c.breaks(), 0);
        assert_eq!(c.drops(), 0);
    }

    #[test]
    fn counters_record_is_independent_of_logging() {
        let c = LeaseCounters::default();
        c.record_break_attempt();
        c.record_break_attempt();
        c.record_break_dropped();
        assert_eq!(c.breaks(), 2);
        assert_eq!(c.drops(), 1);
    }
}
