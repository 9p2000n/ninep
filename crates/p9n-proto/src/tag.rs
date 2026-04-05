//! Tag allocation for concurrent 9P requests with RAII lifecycle.

use crate::types::NO_TAG;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Concurrent tag allocator using a 1024-bit bitmap.
/// Tags 0..1023 are available; NO_TAG (0xFFFF) is reserved.
pub struct TagAllocator {
    bitmap: Arc<[AtomicU64; 16]>,
}

impl TagAllocator {
    pub fn new() -> Self {
        Self {
            bitmap: Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
        }
    }

    /// Allocate a tag with RAII guard. Tag is freed when guard is dropped.
    pub fn alloc_guard(&self) -> Option<TagGuard> {
        let tag = self.alloc_raw()?;
        Some(TagGuard {
            tag,
            bitmap: self.bitmap.clone(),
            consumed: false,
        })
    }

    /// Allocate a free tag (raw, caller must free manually).
    pub fn alloc_raw(&self) -> Option<u16> {
        for (chunk_idx, chunk) in self.bitmap.iter().enumerate() {
            let mut current = chunk.load(Ordering::Relaxed);
            loop {
                if current == u64::MAX {
                    break;
                }
                let bit = (!current).trailing_zeros() as u64;
                let new = current | (1u64 << bit);
                match chunk.compare_exchange_weak(current, new, Ordering::AcqRel, Ordering::Relaxed)
                {
                    Ok(_) => {
                        let tag = (chunk_idx as u16) * 64 + bit as u16;
                        if tag == NO_TAG {
                            free_tag(&self.bitmap, tag);
                            continue;
                        }
                        return Some(tag);
                    }
                    Err(actual) => current = actual,
                }
            }
        }
        None
    }

    /// Release a tag back to the pool.
    pub fn free(&self, tag: u16) {
        free_tag(&self.bitmap, tag);
    }
}

impl Default for TagAllocator {
    fn default() -> Self {
        Self::new()
    }
}

fn free_tag(bitmap: &[AtomicU64; 16], tag: u16) {
    let chunk_idx = (tag / 64) as usize;
    let bit = (tag % 64) as u64;
    if chunk_idx < bitmap.len() {
        bitmap[chunk_idx].fetch_and(!(1u64 << bit), Ordering::Release);
    }
}

/// RAII guard for a tag. Automatically frees the tag on drop.
///
/// Call `consume()` to take ownership of the tag value without freeing it
/// (used when transferring the tag to a response handler).
pub struct TagGuard {
    tag: u16,
    bitmap: Arc<[AtomicU64; 16]>,
    consumed: bool,
}

impl TagGuard {
    /// Get the tag value.
    pub fn tag(&self) -> u16 {
        self.tag
    }

    /// Consume the guard without freeing the tag.
    /// Returns the raw tag value. Caller takes responsibility for freeing.
    pub fn consume(mut self) -> u16 {
        self.consumed = true;
        self.tag
    }
}

impl Drop for TagGuard {
    fn drop(&mut self) {
        if !self.consumed {
            free_tag(&self.bitmap, self.tag);
        }
    }
}
