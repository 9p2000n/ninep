//! Attribute cache with TTL and lease-aware lookup.
//!
//! When an inode has an active server lease, `get_leased()` returns the cached
//! value regardless of TTL — the lease guarantees the server will push an
//! Rleasebreak before anyone else modifies the file.

use lru::LruCache;
use p9n_proto::wire::Stat;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct AttrCache {
    cache: Mutex<LruCache<u64, (Stat, Instant)>>,
    ttl: Duration,
}

impl AttrCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(capacity).unwrap())),
            ttl,
        }
    }

    /// Get a cached stat if it exists and hasn't expired.
    pub fn get(&self, ino: u64) -> Option<Stat> {
        let mut cache = self.cache.lock().unwrap();
        if let Some((stat, time)) = cache.get(&ino) {
            if time.elapsed() < self.ttl {
                return Some(stat.clone());
            }
            cache.pop(&ino);
        }
        None
    }

    /// Get a cached stat regardless of TTL expiry. Used when the inode has an
    /// active server lease — the lease guarantees coherence via Rleasebreak push.
    pub fn get_leased(&self, ino: u64) -> Option<Stat> {
        let cache = self.cache.lock().unwrap();
        cache.peek(&ino).map(|(stat, _)| stat.clone())
    }

    pub fn put(&self, ino: u64, stat: Stat) {
        tracing::trace!("attr_cache put: ino={ino} size={}", stat.size);
        let mut cache = self.cache.lock().unwrap();
        cache.put(ino, (stat, Instant::now()));
    }

    pub fn invalidate(&self, ino: u64) {
        tracing::trace!("attr_cache invalidate: ino={ino}");
        let mut cache = self.cache.lock().unwrap();
        cache.pop(&ino);
    }
}
