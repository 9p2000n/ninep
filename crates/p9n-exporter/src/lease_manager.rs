//! Global lease manager: tracks active leases across all connections and
//! sends Rleasebreak push messages when a conflicting write occurs.

use dashmap::DashMap;
use p9n_proto::fcall::Fcall;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a unique connection identifier.
pub fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

struct LeaseEntry {
    qid_path: u64,
    #[allow(dead_code)] // used for future read-vs-write lease differentiation
    lease_type: u8,
    conn_id: u64,
    push_tx: mpsc::Sender<Fcall>,
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
                let fc = crate::push::leasebreak_fcall(lid, 0);
                // Best-effort: if the receiver is full or gone, skip.
                let _ = entry.push_tx.try_send(fc);
            }
        }
    }

    /// Remove a lease after the client acknowledges the break (Tleaseack).
    pub fn acknowledge(&self, lease_id: u64) {
        if let Some((_, entry)) = self.leases.remove(&lease_id) {
            if let Some(mut ids) = self.path_leases.get_mut(&entry.qid_path) {
                ids.retain(|&id| id != lease_id);
            }
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
        for lid in to_remove {
            self.acknowledge(lid);
        }
    }
}
