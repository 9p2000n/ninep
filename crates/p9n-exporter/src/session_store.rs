//! Per-identity session store for 9P session resumption.
//!
//! Sessions are partitioned by SPIFFE ID so different identities cannot
//! interfere with each other's sessions, even if keys collide.

use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Saved session state for resumption.
pub struct SavedSession {
    /// Which state was preserved.
    pub flags: u32,
    /// When this session was saved (for expiry).
    pub saved_at: Instant,
}

/// Server-wide session store, partitioned by SPIFFE ID.
///
/// Structure: `spiffe_id → (session_key → SavedSession)`
///
/// This ensures:
/// - Different SPIFFE identities cannot access each other's sessions
/// - Key collisions only affect the same identity (same workload replicas)
/// - Resume validation is O(1) without scanning
pub struct SessionStore {
    /// Outer map: SPIFFE ID (or "" for anonymous) → inner map of sessions.
    store: DashMap<String, DashMap<[u8; 16], SavedSession>>,
    /// Maximum time a saved session can be resumed.
    ttl: Duration,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            store: DashMap::new(),
            ttl,
        }
    }

    /// Save session state for potential future resumption.
    pub fn save(&self, key: [u8; 16], spiffe_id: Option<String>, flags: u32) {
        let id = spiffe_id.unwrap_or_default();
        self.store
            .entry(id)
            .or_default()
            .insert(key, SavedSession {
                flags,
                saved_at: Instant::now(),
            });
        tracing::debug!("session saved, flags={flags:#x}");
    }

    /// Attempt to resume a session by key and SPIFFE identity.
    ///
    /// The session is consumed on successful resume (one-time use).
    pub fn resume(&self, key: &[u8; 16], peer_spiffe_id: &Option<String>) -> Option<u32> {
        let id = peer_spiffe_id.as_deref().unwrap_or("");

        let inner = self.store.get(id)?;
        let entry = inner.remove(key)?;
        let saved = entry.1;

        // Check TTL
        if saved.saved_at.elapsed() > self.ttl {
            tracing::debug!("session expired");
            return None;
        }

        tracing::info!("session resumed, flags={:#x}", saved.flags);
        Some(saved.flags)
    }

    /// Remove expired sessions across all identities.
    pub fn gc(&self) {
        for entry in self.store.iter() {
            entry.value().retain(|_, v| v.saved_at.elapsed() <= self.ttl);
        }
        // Remove empty identity buckets
        self.store.retain(|_, v| !v.is_empty());
    }
}
