//! Directory entry cache for FUSE readdir.
//!
//! Cached entries are the full listing from offset 0. A non-zero readdir
//! offset serves from the same cached vec by skipping entries whose index
//! is less than or equal to the requested offset.

use fuse3::raw::prelude::DirectoryEntry;
use lru::LruCache;
use std::num::NonZeroUsize;
use parking_lot::Mutex;
use std::time::{Duration, Instant};

pub struct DirCache {
    cache: Mutex<LruCache<u64, (Vec<DirectoryEntry>, Instant)>>,
    ttl: Duration,
}

impl DirCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(capacity).unwrap())),
            ttl,
        }
    }

    /// Look up cached entries for `ino`. Returns entries whose 1-based
    /// index is strictly greater than `offset` (the offset a FUSE readdir
    /// call has already consumed).
    pub fn get(&self, ino: u64, offset: i64) -> Option<Vec<DirectoryEntry>> {
        let mut cache = self.cache.lock();
        let (entries, time) = cache.get(&ino)?;
        if time.elapsed() >= self.ttl {
            cache.pop(&ino);
            return None;
        }
        if offset == 0 {
            return Some(entries.clone());
        }
        Some(entries.iter().filter(|e| e.offset > offset).cloned().collect())
    }

    /// Store the full entry list for `ino`. Call only with the entries
    /// starting from offset 0 — partial listings are not cached.
    pub fn put(&self, ino: u64, entries: Vec<DirectoryEntry>) {
        self.cache.lock().put(ino, (entries, Instant::now()));
    }

    pub fn invalidate(&self, ino: u64) {
        self.cache.lock().pop(&ino);
    }
}
