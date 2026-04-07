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
        self.release_all_leases().await;
        self.clunk_all_fids().await;
        self.rpc.close().await;
    }

    /// Send Tleaseack for every outstanding lease.
    ///
    /// Batches all acks into a single Tcompound when possible (1 round-trip).
    /// Falls back to individual RPCs if compound encoding fails.
    async fn release_all_leases(&self) {
        let leases = self.leases.drain_all();
        if leases.is_empty() {
            return;
        }
        tracing::info!("releasing {} lease(s)...", leases.len());

        // Try compound batch
        let ops: Vec<_> = leases
            .iter()
            .filter_map(|(_, lease_id)| {
                encode_subop(MsgType::Tleaseack, &Msg::Leaseack { lease_id: *lease_id }).ok()
            })
            .collect();
        if ops.len() == leases.len() {
            if let Err(e) = send_compound(&self.rpc, ops).await {
                tracing::debug!("compound leaseack failed, ignoring: {e}");
            }
            return;
        }

        // Fallback: individual RPCs
        for (_fh, lease_id) in leases {
            if let Err(e) = self
                .rpc
                .call(MsgType::Tleaseack, Msg::Leaseack { lease_id })
                .await
            {
                tracing::debug!("leaseack lease={lease_id}: {e}");
            }
        }
    }

    /// Send Tclunk for every allocated fid.
    ///
    /// Batches all clunks into a single Tcompound when possible (1 round-trip
    /// instead of N). Falls back to individual RPCs if compound encoding fails.
    async fn clunk_all_fids(&self) {
        let fids = self.inodes.drain_fids();
        if fids.is_empty() {
            return;
        }
        tracing::info!("clunking {} fid(s)...", fids.len());

        // Try compound batch
        let ops: Vec<_> = fids
            .iter()
            .filter_map(|fid| encode_subop(MsgType::Tclunk, &Msg::Clunk { fid: *fid }).ok())
            .collect();
        if ops.len() == fids.len() {
            if let Err(e) = send_compound(&self.rpc, ops).await {
                tracing::debug!("compound clunk failed, ignoring: {e}");
            }
            return;
        }

        // Fallback: individual RPCs
        for fid in fids {
            if let Err(e) = self
                .rpc
                .call(MsgType::Tclunk, Msg::Clunk { fid })
                .await
            {
                tracing::debug!("clunk fid={fid}: {e}");
            }
        }
    }
}
