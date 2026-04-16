//! Global inotify watch manager using the `notify` crate.
//!
//! Uses DashMap for lock-free event dispatch to avoid blocking the
//! notify OS watcher thread. Only the underlying `RecommendedWatcher`
//! is protected by a Mutex (locked only during watch/unwatch calls).

use dashmap::DashMap;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use p9n_proto::types::*;
use p9n_proto::wire::Qid;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::Mutex;
use tokio::sync::mpsc;

/// Counters shared between the manager and the OS-watcher callback.
/// Mutation (record_*) is kept separate from observation (`snapshot()`) so
/// log sites never call `fetch_add` directly.
#[derive(Default)]
struct WatchCounters {
    events_dispatched: AtomicU64,
    events_dropped: AtomicU64,
    events_ignored: AtomicU64,
}

impl WatchCounters {
    fn record_dispatched(&self) {
        self.events_dispatched.fetch_add(1, Ordering::Relaxed);
    }
    fn record_dropped(&self) {
        self.events_dropped.fetch_add(1, Ordering::Relaxed);
    }
    fn record_ignored(&self) {
        self.events_ignored.fetch_add(1, Ordering::Relaxed);
    }
    /// Snapshot `(dispatched, dropped, ignored)` for periodic logging.
    fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.events_dispatched.load(Ordering::Relaxed),
            self.events_dropped.load(Ordering::Relaxed),
            self.events_ignored.load(Ordering::Relaxed),
        )
    }
}

/// Snapshot of watch manager state for periodic logging.
#[derive(Debug, Clone, Copy)]
pub struct WatchStats {
    pub watches: usize,
    pub watched_paths: usize,
    pub events_dispatched: u64,
    pub events_dropped: u64,
    pub events_ignored: u64,
}

/// A watch event ready to be sent as Rnotify to a client.
#[derive(Debug, Clone)]
pub struct WatchEvent {
    pub watch_id: u32,
    pub event_mask: u32,
    pub name: String,
    pub qid: Qid,
}

/// Per-connection watch registration.
struct WatchRegistration {
    watch_id: u32,
    mask: u32,
    tx: mpsc::Sender<WatchEvent>,
}

/// Global inotify manager shared across all connections.
///
/// Event dispatch uses DashMap (per-shard read lock) so the notify OS thread
/// never blocks on handler registrations.
pub struct WatchManager {
    /// path -> registrations (DashMap: per-shard lock, no global lock)
    path_watches: Arc<DashMap<PathBuf, Vec<WatchRegistration>>>,
    /// watch_id -> path (DashMap: per-shard lock)
    id_to_path: DashMap<u32, PathBuf>,
    /// Monotonic watch ID counter.
    next_id: AtomicU32,
    /// The underlying OS watcher (locked only for watch/unwatch calls).
    watcher: Mutex<RecommendedWatcher>,
    /// Counters shared with the dispatch path.
    counters: Arc<WatchCounters>,
}

impl WatchManager {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path_watches: Arc<DashMap<PathBuf, Vec<WatchRegistration>>> =
            Arc::new(DashMap::new());
        let counters = Arc::new(WatchCounters::default());

        let pw_clone = path_watches.clone();
        let cnt_clone = counters.clone();
        let watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => dispatch_event(&pw_clone, &cnt_clone, &event),
                Err(e) => tracing::warn!(error = %e, "notify watcher reported error"),
            }
        })?;

        Ok(Self {
            path_watches,
            id_to_path: DashMap::new(),
            next_id: AtomicU32::new(1),
            watcher: Mutex::new(watcher),
            counters,
        })
    }

    /// Snapshot the current state of the watch manager (for periodic logging).
    pub fn stats(&self) -> WatchStats {
        let watches: usize = self.path_watches.iter().map(|e| e.value().len()).sum();
        let (events_dispatched, events_dropped, events_ignored) = self.counters.snapshot();
        WatchStats {
            watches,
            watched_paths: self.path_watches.len(),
            events_dispatched,
            events_dropped,
            events_ignored,
        }
    }

    /// Register a watch on a path for a connection. Returns the watch_id.
    pub fn add_watch(
        &self,
        path: &Path,
        mask: u32,
        flags: u32,
        tx: mpsc::Sender<WatchEvent>,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let watch_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

        let is_new_path = !self.path_watches.contains_key(&canonical);

        self.path_watches
            .entry(canonical.clone())
            .or_default()
            .push(WatchRegistration {
                watch_id,
                mask,
                tx,
            });

        self.id_to_path.insert(watch_id, canonical.clone());

        if is_new_path {
            let recursive = (flags & WATCH_RECURSIVE) != 0;
            let mode = if recursive {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            };
            // Only lock the OS watcher for the actual watch syscall
            let mut watcher = self.watcher.lock();
            if let Err(e) = watcher.watch(&canonical, mode) {
                tracing::warn!(
                    watch_id,
                    path = %canonical.display(),
                    recursive,
                    error = %e,
                    "OS watch syscall failed; rolling back registration",
                );
                // Cleanup on failure
                if let Some(mut regs) = self.path_watches.get_mut(&canonical) {
                    regs.retain(|r| r.watch_id != watch_id);
                    if regs.is_empty() {
                        drop(regs);
                        self.path_watches.remove(&canonical);
                    }
                }
                self.id_to_path.remove(&watch_id);
                return Err(Box::new(e));
            }
        }

        tracing::info!(
            watch_id,
            path = %canonical.display(),
            mask = format_args!("{:#x}", mask),
            flags = format_args!("{:#x}", flags),
            new_path = is_new_path,
            total_paths = self.path_watches.len(),
            "watch added",
        );
        Ok(watch_id)
    }

    /// Remove a watch by ID.
    pub fn remove_watch(
        &self,
        watch_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = match self.id_to_path.remove(&watch_id) {
            Some((_, p)) => p,
            None => {
                tracing::trace!(watch_id, "watch remove: not found (already removed)");
                return Ok(());
            }
        };

        let should_unwatch = if let Some(mut regs) = self.path_watches.get_mut(&path) {
            regs.retain(|r| r.watch_id != watch_id);
            regs.is_empty()
        } else {
            false
        };

        if should_unwatch {
            self.path_watches.remove(&path);
            let mut watcher = self.watcher.lock();
            let _ = watcher.unwatch(&path);
        }

        tracing::info!(
            watch_id,
            path = %path.display(),
            os_unwatched = should_unwatch,
            total_paths = self.path_watches.len(),
            "watch removed",
        );
        Ok(())
    }

    /// Remove all watches associated with a given sender (connection cleanup).
    pub fn remove_all_for_sender(&self, tx: &mpsc::Sender<WatchEvent>) {
        // Collect watch_ids to remove
        let mut to_remove = Vec::new();
        for entry in self.path_watches.iter() {
            for reg in entry.value() {
                if reg.tx.same_channel(tx) {
                    to_remove.push(reg.watch_id);
                }
            }
        }

        let n = to_remove.len();
        for watch_id in to_remove {
            let _ = self.remove_watch(watch_id);
        }
        if n > 0 {
            tracing::debug!(removed = n, "watch remove_all_for_sender (connection cleanup)");
        }
    }
}

fn map_event_kind(kind: &EventKind) -> u32 {
    match kind {
        EventKind::Create(_) => WATCH_CREATE,
        EventKind::Remove(_) => WATCH_REMOVE,
        EventKind::Modify(modify) => match modify {
            notify::event::ModifyKind::Data(_) => WATCH_MODIFY,
            notify::event::ModifyKind::Metadata(_) => WATCH_ATTRIB,
            notify::event::ModifyKind::Name(_) => WATCH_RENAME,
            _ => WATCH_MODIFY,
        },
        EventKind::Access(_) => 0,
        EventKind::Other => 0,
        _ => 0,
    }
}

fn qid_for_path(path: &Path) -> Qid {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let qtype = if meta.is_dir() {
                QT_DIR
            } else if meta.file_type().is_symlink() {
                QT_SYMLINK
            } else {
                QT_FILE
            };
            Qid {
                qtype,
                version: meta.mtime() as u32,
                path: meta.ino(),
            }
        }
        Err(_) => Qid {
            qtype: QT_FILE,
            version: 0,
            path: 0,
        },
    }
}

/// Dispatch a notify event to all registered watchers.
/// Uses DashMap read access — does NOT block add_watch/remove_watch on other shards.
fn dispatch_event(
    path_watches: &DashMap<PathBuf, Vec<WatchRegistration>>,
    counters: &WatchCounters,
    event: &Event,
) {
    let event_mask = map_event_kind(&event.kind);
    if event_mask == 0 {
        counters.record_ignored();
        return;
    }

    for event_path in &event.paths {
        let candidates = [
            event_path.clone(),
            event_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_default(),
        ];

        for candidate in &candidates {
            if let Some(regs) = path_watches.get(candidate) {
                let name = event_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let qid = qid_for_path(event_path);

                for reg in regs.value() {
                    if reg.mask & event_mask != 0 {
                        let watch_event = WatchEvent {
                            watch_id: reg.watch_id,
                            event_mask,
                            name: name.clone(),
                            qid: qid.clone(),
                        };
                        match reg.tx.try_send(watch_event) {
                            Ok(()) => {
                                counters.record_dispatched();
                                tracing::trace!(
                                    wid = reg.watch_id,
                                    mask = format_args!("{:#x}", event_mask),
                                    name = %name,
                                    "watch event dispatched",
                                );
                            }
                            Err(e) => {
                                counters.record_dropped();
                                tracing::warn!(
                                    wid = reg.watch_id,
                                    mask = format_args!("{:#x}", event_mask),
                                    name = %name,
                                    error = %e,
                                    "watch event dropped (channel full or closed)",
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_default_and_snapshot() {
        let c = WatchCounters::default();
        assert_eq!(c.snapshot(), (0, 0, 0));
    }

    #[test]
    fn counters_record_each_type_independently() {
        let c = WatchCounters::default();
        c.record_dispatched();
        c.record_dispatched();
        c.record_dropped();
        c.record_ignored();
        c.record_ignored();
        c.record_ignored();
        assert_eq!(c.snapshot(), (2, 1, 3));
    }
}
