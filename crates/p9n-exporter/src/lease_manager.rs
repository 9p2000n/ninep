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
}

impl LeaseManager {
    pub fn new() -> Self {
        Self {
            leases: DashMap::new(),
            path_leases: DashMap::new(),
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
        tracing::trace!("lease try_grant: qid_path={qid_path} type={lease_type} conn={conn_id}");
        let lease_ids = match self.path_leases.get(&qid_path) {
            Some(ids) => ids.clone(),
            None => return GrantResult::Granted, // no existing leases
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
                    return GrantResult::Conflict;
                }

                // WRITE vs (other's) WRITE: conflict
                (types::LEASE_WRITE, types::LEASE_WRITE) => {
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
            for lid in &lease_ids {
                if let Some(entry) = self.leases.get(lid) {
                    if entry.conn_id != conn_id && entry.lease_type == types::LEASE_READ {
                        tracing::debug!("lease break: lid={lid} conn={} (write requested by conn={conn_id})", entry.conn_id);
                        let fc = crate::push::leasebreak_fcall(*lid, 0);
                        if let Err(e) = entry.push_tx.try_send(fc) {
                            tracing::warn!(
                                "lease break notification dropped: lid={lid} conn={}: {e}",
                                entry.conn_id,
                            );
                        }
                    }
                }
            }
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
        tracing::trace!("lease register: lid={lease_id} qid_path={qid_path} type={lease_type} conn={conn_id}");
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
    }

    /// Break all leases on `qid_path` held by connections other than
    /// `writer_conn_id`.  Sends an Rleasebreak push to each affected
    /// connection (non-blocking `try_send`).
    pub fn break_for_write(&self, qid_path: u64, writer_conn_id: u64) {
        let lease_ids = match self.path_leases.get(&qid_path) {
            Some(ids) => ids.clone(),
            None => return,
        };

        for lid in lease_ids {
            if let Some(entry) = self.leases.get(&lid) {
                if entry.conn_id == writer_conn_id {
                    continue;
                }
                tracing::debug!(
                    "lease break_for_write: lid={lid} qid_path={qid_path} holder_conn={} writer_conn={writer_conn_id}",
                    entry.conn_id,
                );
                let fc = crate::push::leasebreak_fcall(lid, 0);
                if let Err(e) = entry.push_tx.try_send(fc) {
                    tracing::warn!(
                        "lease break_for_write notification dropped: lid={lid} conn={}: {e}",
                        entry.conn_id,
                    );
                }
            }
        }
    }

    /// Remove a lease after the client acknowledges the break (Tleaseack).
    pub fn acknowledge(&self, lease_id: u64) {
        tracing::trace!("lease acknowledge: lid={lease_id}");
        if let Some((_, entry)) = self.leases.remove(&lease_id) {
            if let Some(mut ids) = self.path_leases.get_mut(&entry.qid_path) {
                ids.retain(|&id| id != lease_id);
            }
        }
    }

    /// Remove all leases belonging to a connection (cleanup on disconnect).
    pub fn remove_by_conn(&self, conn_id: u64) {
        tracing::debug!("lease remove_by_conn: conn={conn_id}");
        let to_remove: Vec<u64> = self
            .leases
            .iter()
            .filter(|e| e.conn_id == conn_id)
            .map(|e| *e.key())
            .collect();
        for lid in to_remove {
            self.acknowledge(lid);
        }
    }
}
