//! Dynamic TLS certificate resolver for SVID auto-rotation.
//!
//! Implements `rustls::server::ResolvesServerCert` backed by an
//! `Arc<RwLock<>>` that is updated when SVIDs rotate.

use super::SpiffeIdentity;
use crate::error::AuthError;
use parking_lot::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Snapshot of cert resolver state for periodic logging.
#[derive(Debug, Clone)]
pub struct CertStats {
    pub reloads: u64,
    pub reload_failures: u64,
    pub last_reload_age: Option<Duration>,
}

/// Atomic counters for cert reload activity. Record methods are the only
/// allowed mutators; `snapshot()` is the only read path.
struct CertCounters {
    reloads: AtomicU64,
    reload_failures: AtomicU64,
    /// Nanoseconds since `created_at` at the most recent successful reload,
    /// or 0 if none yet.
    last_reload_nanos: AtomicU64,
    /// Reference instant for `last_reload_nanos`.
    created_at: Instant,
}

impl CertCounters {
    fn new() -> Self {
        Self {
            reloads: AtomicU64::new(0),
            reload_failures: AtomicU64::new(0),
            last_reload_nanos: AtomicU64::new(0),
            created_at: Instant::now(),
        }
    }

    fn record_success(&self) -> u64 {
        self.last_reload_nanos
            .store(self.created_at.elapsed().as_nanos() as u64, Ordering::Relaxed);
        self.reloads.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn record_failure(&self) -> u64 {
        self.reload_failures.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn snapshot(&self) -> CertStats {
        let last_nanos = self.last_reload_nanos.load(Ordering::Relaxed);
        let last_reload_age = if last_nanos == 0 {
            None
        } else {
            self.created_at
                .elapsed()
                .checked_sub(Duration::from_nanos(last_nanos))
        };
        CertStats {
            reloads: self.reloads.load(Ordering::Relaxed),
            reload_failures: self.reload_failures.load(Ordering::Relaxed),
            last_reload_age,
        }
    }
}

/// A certificate resolver that hot-swaps when SVIDs rotate.
pub struct SpiffeCertResolver {
    current: Arc<RwLock<Arc<CertifiedKey>>>,
    counters: Arc<CertCounters>,
}

impl SpiffeCertResolver {
    /// Create from an initial identity.
    pub fn new(identity: &SpiffeIdentity) -> Result<Self, AuthError> {
        let key = build_certified_key(identity)?;
        tracing::info!(
            spiffe_id = %identity.spiffe_id,
            chain_len = identity.cert_chain.len(),
            "cert resolver initialized",
        );
        Ok(Self {
            current: Arc::new(RwLock::new(Arc::new(key))),
            counters: Arc::new(CertCounters::new()),
        })
    }

    /// Snapshot resolver counters (for periodic logging).
    pub fn stats(&self) -> CertStats {
        self.counters.snapshot()
    }

    /// Manually update the certificate.
    pub fn update(&self, identity: &SpiffeIdentity) -> Result<(), AuthError> {
        let key = build_certified_key(identity)?;
        let mut guard = self.current.write();
        *guard = Arc::new(key);
        drop(guard);
        let reloads = self.counters.record_success();
        tracing::info!(
            spiffe_id = %identity.spiffe_id,
            chain_len = identity.cert_chain.len(),
            reloads,
            "TLS certificate updated (manual)",
        );
        Ok(())
    }

    /// Spawn a background task that watches for SVID updates and auto-reloads.
    pub fn spawn_updater(
        &self,
        mut rx: watch::Receiver<Arc<SpiffeIdentity>>,
    ) -> tokio::task::JoinHandle<()> {
        let current = self.current.clone();
        let counters = self.counters.clone();
        tokio::spawn(async move {
            tracing::debug!("cert resolver updater started");
            while rx.changed().await.is_ok() {
                let identity = rx.borrow().clone();
                match build_certified_key(&identity) {
                    Ok(key) => {
                        let mut guard = current.write();
                        *guard = Arc::new(key);
                        drop(guard);
                        let reloads = counters.record_success();
                        tracing::info!(
                            spiffe_id = %identity.spiffe_id,
                            chain_len = identity.cert_chain.len(),
                            reloads,
                            "TLS cert hot-reloaded",
                        );
                    }
                    Err(e) => {
                        let failures = counters.record_failure();
                        tracing::warn!(
                            spiffe_id = %identity.spiffe_id,
                            error = %e,
                            failures,
                            "TLS cert reload failed",
                        );
                    }
                }
            }
            tracing::info!("cert resolver updater exited (channel closed)");
        })
    }
}

impl fmt::Debug for SpiffeCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpiffeCertResolver").finish()
    }
}

impl ResolvesServerCert for SpiffeCertResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let guard = self.current.read();
        Some(Arc::clone(&guard))
    }
}

/// Build a `CertifiedKey` from a `SpiffeIdentity`.
fn build_certified_key(identity: &SpiffeIdentity) -> Result<CertifiedKey, AuthError> {
    let certs: Vec<CertificateDer<'static>> = identity
        .cert_chain
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.private_key.clone()));

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| AuthError::Tls(format!("signing key: {e}")))?;

    Ok(CertifiedKey::new(certs, signing_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_initial_state() {
        let c = CertCounters::new();
        let snap = c.snapshot();
        assert_eq!(snap.reloads, 0);
        assert_eq!(snap.reload_failures, 0);
        assert!(snap.last_reload_age.is_none());
    }

    #[test]
    fn counters_record_tracks_totals_and_age() {
        let c = CertCounters::new();
        assert_eq!(c.record_success(), 1);
        assert_eq!(c.record_success(), 2);
        assert_eq!(c.record_failure(), 1);
        let snap = c.snapshot();
        assert_eq!(snap.reloads, 2);
        assert_eq!(snap.reload_failures, 1);
        assert!(snap.last_reload_age.is_some(), "age set after record_success");
    }
}
