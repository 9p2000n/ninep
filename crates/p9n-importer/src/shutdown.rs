//! Graceful shutdown handle for the importer.
//!
//! `ShutdownHandle` holds `Arc` references to shared state that outlives
//! the `P9Filesystem` (which is consumed by fuse3 on mount). After the FUSE
//! mount is torn down, `run()` drives an ordered cleanup sequence:
//!
//! 1. Release all leases (Tleaseack)
//! 2. Clunk all fids (Tclunk)
//! 3. Close the transport connection

use crate::fuse::compound::{encode_subop, send_compound};
use crate::fuse::inode_map::InodeMap;
use crate::fuse::lease_map::LeaseMap;
use crate::rpc_client::RpcClient;
use p9n_proto::fcall::Msg;
use p9n_proto::types::MsgType;
use std::sync::Arc;

pub struct ShutdownHandle {
    rpc: Arc<RpcClient>,
    leases: Arc<LeaseMap>,
    inodes: Arc<InodeMap>,
}

impl ShutdownHandle {
    pub fn new(
        rpc: Arc<RpcClient>,
        leases: Arc<LeaseMap>,
        inodes: Arc<InodeMap>,
    ) -> Self {
        Self { rpc, leases, inodes }
    }

    /// Run the ordered shutdown sequence.
    ///
    /// Must be called AFTER the FUSE mount has been torn down so that no new
    /// FUSE operations can create additional fids or leases.
    pub async fn run(&self) {
        let conn_id = self.rpc.conn_id();
        tracing::info!(conn_id, "shutdown sequence starting");
        self.release_all_leases().await;
        self.clunk_all_fids().await;
        self.rpc.close().await;
        tracing::info!(conn_id, "shutdown sequence complete");
    }

    /// Send Tleaseack for every outstanding lease.
    ///
    /// Batches all acks into a single Tcompound when possible (1 round-trip).
    /// Falls back to individual RPCs if compound encoding fails.
    async fn release_all_leases(&self) {
        let conn_id = self.rpc.conn_id();
        let leases = self.leases.drain_all();
        let n = leases.len();
        if n == 0 {
            tracing::debug!(conn_id, "shutdown: no outstanding leases");
            return;
        }
        tracing::info!(conn_id, leases = n, "shutdown: releasing leases");

        // Try compound batch
        let ops: Vec<_> = leases
            .iter()
            .filter_map(|(_, lease_id)| {
                encode_subop(MsgType::Tleaseack, &Msg::Leaseack { lease_id: *lease_id }).ok()
            })
            .collect();
        if ops.len() == n {
            tracing::debug!(conn_id, ops = n, "shutdown: leaseack via compound batch");
            if let Err(e) = send_compound(&self.rpc, ops).await {
                tracing::debug!(conn_id, error = %e, "compound leaseack failed; ignoring");
            }
            return;
        }

        // Fallback: individual RPCs
        tracing::debug!(conn_id, leases = n, "shutdown: leaseack via per-lease RPCs (encode failed)");
        for (_fh, lease_id) in leases {
            if let Err(e) = self
                .rpc
                .call(MsgType::Tleaseack, Msg::Leaseack { lease_id })
                .await
            {
                tracing::debug!(conn_id, lease_id, error = %e, "leaseack failed");
            }
        }
    }

    /// Send Tclunk for every allocated fid.
    ///
    /// Batches all clunks into a single Tcompound when possible (1 round-trip
    /// instead of N). Falls back to individual RPCs if compound encoding fails.
    async fn clunk_all_fids(&self) {
        let conn_id = self.rpc.conn_id();
        let fids = self.inodes.drain_fids();
        let n = fids.len();
        if n == 0 {
            tracing::debug!(conn_id, "shutdown: no fids to clunk");
            return;
        }
        tracing::info!(conn_id, fids = n, "shutdown: clunking fids");

        // Try compound batch
        let ops: Vec<_> = fids
            .iter()
            .filter_map(|fid| encode_subop(MsgType::Tclunk, &Msg::Clunk { fid: *fid }).ok())
            .collect();
        if ops.len() == n {
            tracing::debug!(conn_id, ops = n, "shutdown: clunk via compound batch");
            if let Err(e) = send_compound(&self.rpc, ops).await {
                tracing::debug!(conn_id, error = %e, "compound clunk failed; ignoring");
            }
            return;
        }

        // Fallback: individual RPCs
        tracing::debug!(conn_id, fids = n, "shutdown: clunk via per-fid RPCs (encode failed)");
        for fid in fids {
            if let Err(e) = self
                .rpc
                .call(MsgType::Tclunk, Msg::Clunk { fid })
                .await
            {
                tracing::debug!(conn_id, fid, error = %e, "clunk failed");
            }
        }
    }
}
