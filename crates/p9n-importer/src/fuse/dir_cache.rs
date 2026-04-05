//! Directory entry cache.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct CachedDirEntry {
    pub ino: u64,
    pub name: String,
    pub dtype: u32,
}

pub struct DirCache {
    cache: Mutex<LruCache<u64, (Vec<CachedDirEntry>, Instant)>>,
    ttl: Duration,
}

impl DirCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(capacity).unwrap())),
            ttl,
        }
    }

    pub fn get(&self, ino: u64) -> Option<Vec<CachedDirEntry>> {
        let mut cache = self.cache.lock().unwrap();
        if let Some((entries, time)) = cache.get(&ino) {
            if time.elapsed() < self.ttl {
                return Some(entries.clone());
            }
            cache.pop(&ino);
        }
        None
    }

    pub fn put(&self, ino: u64, entries: Vec<CachedDirEntry>) {
        let mut cache = self.cache.lock().unwrap();
        cache.put(ino, (entries, Instant::now()));
    }

    pub fn invalidate(&self, ino: u64) {
        let mut cache = self.cache.lock().unwrap();
        cache.pop(&ino);
    }
}
