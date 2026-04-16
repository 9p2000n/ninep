//! Receives server push messages and dispatches to cache invalidation.

use crate::fuse::attr_cache::AttrCache;
use crate::fuse::inode_map::InodeMap;
use crate::fuse::lease_map::LeaseMap;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// Heartbeat interval for the push handler — even when no pushes arrive,
/// emit a debug log so operators can see the task is alive.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// Spawns a background task that reads push messages and invalidates caches.
pub fn spawn_push_handler(
    mut push_rx: mpsc::Receiver<Fcall>,
    inodes: Arc<InodeMap>,
    attrs: Arc<AttrCache>,
    leases: Arc<LeaseMap>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(
            heartbeat_secs = HEARTBEAT_INTERVAL.as_secs(),
            "push handler task started",
        );
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        // Skip the immediate first tick so the first heartbeat fires after
        // a real interval, not at startup.
        heartbeat.tick().await;
        let mut total: u64 = 0;
        let mut notifies: u64 = 0;
        let mut lease_breaks: u64 = 0;
        let mut unhandled: u64 = 0;
        let mut cache_invalidations: u64 = 0;
        let mut last_event_at: Option<Instant> = None;
        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    let idle_for = last_event_at.map(|t| t.elapsed().as_secs()).unwrap_or(u64::MAX);
                    tracing::debug!(
                        total,
                        notifies,
                        lease_breaks,
                        unhandled,
                        cache_invalidations,
                        idle_for_secs = idle_for,
                        "push handler heartbeat",
                    );
                }
                maybe = push_rx.recv() => {
                    let Some(fc) = maybe else {
                        tracing::info!(
                            total, notifies, lease_breaks, unhandled, cache_invalidations,
                            "push handler exiting (channel closed)",
                        );
                        break;
                    };
                    total += 1;
                    last_event_at = Some(Instant::now());
                    let mt_name = fc.msg_type.name();
                    tracing::trace!(msg_type = mt_name, "push received");
                    match fc.msg {
                        Msg::Notify {
                            watch_id,
                            event,
                            name,
                            qid,
                        } => {
                            notifies += 1;
                            // Invalidate attr cache for the inode associated with this qid
                            if let Some(ino) = inodes.get_ino_by_qid_path(qid.path) {
                                if event & (WATCH_MODIFY | WATCH_ATTRIB) != 0 {
                                    attrs.invalidate(ino);
                                    cache_invalidations += 1;
                                    tracing::debug!(
                                        watch_id, ino, name = %name,
                                        event = format_args!("{:#x}", event),
                                        "attr cache invalidated (modify/attrib)",
                                    );
                                }
                                if event & (WATCH_CREATE | WATCH_REMOVE | WATCH_RENAME) != 0 {
                                    // Parent directory changed — invalidate its attr too
                                    attrs.invalidate(ino);
                                    cache_invalidations += 1;
                                    tracing::debug!(
                                        watch_id, ino, name = %name,
                                        event = format_args!("{:#x}", event),
                                        "dir cache invalidated (create/remove/rename)",
                                    );
                                }
                            } else {
                                tracing::trace!(
                                    watch_id, qid_path = qid.path, name = %name,
                                    event = format_args!("{:#x}", event),
                                    "notify: no inode mapping for qid_path",
                                );
                            }
                        }
                        Msg::Leasebreak {
                            lease_id,
                            new_type,
                        } => {
                            lease_breaks += 1;
                            // Server broke (or downgraded) the lease — invalidate cached
                            // attrs for that inode.  We always invalidate regardless of
                            // new_type: a full revocation (new_type=0) means the data may
                            // have changed; a downgrade (new_type>0) means the exclusivity
                            // guarantee is lost, so the cache must be re-validated.
                            if let Some(ino) = leases.break_lease(lease_id) {
                                attrs.invalidate(ino);
                                cache_invalidations += 1;
                                tracing::info!(
                                    lease_id, ino, new_type,
                                    "lease break: cache invalidated",
                                );
                            } else {
                                tracing::debug!(
                                    lease_id, new_type,
                                    "lease break: no mapping (already released?)",
                                );
                            }
                        }
                        _ => {
                            unhandled += 1;
                            tracing::debug!(msg_type = mt_name, "unhandled push type");
                        }
                    }
                }
            }
        }
    })
}
