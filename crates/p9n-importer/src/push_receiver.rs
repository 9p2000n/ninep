//! Receives server push messages and dispatches to cache invalidation.

use crate::fuse::attr_cache::AttrCache;
use crate::fuse::inode_map::InodeMap;
use crate::fuse::lease_map::LeaseMap;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Spawns a background task that reads push messages and invalidates caches.
pub fn spawn_push_handler(
    mut push_rx: mpsc::Receiver<Fcall>,
    inodes: Arc<InodeMap>,
    attrs: Arc<AttrCache>,
    leases: Arc<LeaseMap>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::debug!("push handler task started");
        while let Some(fc) = push_rx.recv().await {
            tracing::trace!("push handler: type={}", fc.msg_type.name());
            match fc.msg {
                Msg::Notify {
                    watch_id: _,
                    event,
                    name: _,
                    qid,
                } => {
                    // Invalidate attr cache for the inode associated with this qid
                    if let Some(ino) = inodes.get_ino_by_qid_path(qid.path) {
                        if event & (WATCH_MODIFY | WATCH_ATTRIB) != 0 {
                            attrs.invalidate(ino);
                            tracing::debug!("cache invalidated: ino={ino} event={event:#x}");
                        }
                        if event & (WATCH_CREATE | WATCH_REMOVE | WATCH_RENAME) != 0 {
                            // Parent directory changed — invalidate its attr too
                            attrs.invalidate(ino);
                            tracing::debug!(
                                "dir cache invalidated: ino={ino} event={event:#x}"
                            );
                        }
                    }
                }
                Msg::Leasebreak {
                    lease_id,
                    new_type,
                } => {
                    // Server broke (or downgraded) the lease — invalidate cached
                    // attrs for that inode.  We always invalidate regardless of
                    // new_type: a full revocation (new_type=0) means the data may
                    // have changed; a downgrade (new_type>0) means the exclusivity
                    // guarantee is lost, so the cache must be re-validated.
                    if let Some(ino) = leases.break_lease(lease_id) {
                        attrs.invalidate(ino);
                        tracing::info!(
                            "lease break: lease_id={lease_id} ino={ino} new_type={new_type} — cache invalidated"
                        );
                    } else {
                        tracing::debug!(
                            "lease break: lease_id={lease_id} — no mapping (already released?)"
                        );
                    }
                }
                _ => {
                    tracing::debug!("unhandled push: {:?}", fc.msg_type);
                }
            }
        }
    })
}
