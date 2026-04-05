//! Dynamic TLS certificate resolver for SVID auto-rotation.
//!
//! Implements `rustls::server::ResolvesServerCert` backed by an
//! `Arc<RwLock<>>` that is updated when SVIDs rotate.

use super::SpiffeIdentity;
use crate::error::AuthError;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use std::fmt;
use std::sync::{Arc, RwLock};
use tokio::sync::watch;

/// A certificate resolver that hot-swaps when SVIDs rotate.
pub struct SpiffeCertResolver {
    current: Arc<RwLock<Arc<CertifiedKey>>>,
}

impl SpiffeCertResolver {
    /// Create from an initial identity.
    pub fn new(identity: &SpiffeIdentity) -> Result<Self, AuthError> {
        let key = build_certified_key(identity)?;
        Ok(Self {
            current: Arc::new(RwLock::new(Arc::new(key))),
        })
    }

    /// Manually update the certificate.
    pub fn update(&self, identity: &SpiffeIdentity) -> Result<(), AuthError> {
        let key = build_certified_key(identity)?;
        let mut guard = self.current.write().unwrap();
        *guard = Arc::new(key);
        tracing::info!("TLS certificate updated for {}", identity.spiffe_id);
        Ok(())
    }

    /// Spawn a background task that watches for SVID updates and auto-reloads.
    pub fn spawn_updater(
        &self,
        mut rx: watch::Receiver<Arc<SpiffeIdentity>>,
    ) -> tokio::task::JoinHandle<()> {
        let current = self.current.clone();
        tokio::spawn(async move {
            while rx.changed().await.is_ok() {
                let identity = rx.borrow().clone();
                match build_certified_key(&identity) {
                    Ok(key) => {
                        let mut guard = current.write().unwrap();
                        *guard = Arc::new(key);
                        tracing::info!("TLS cert hot-reloaded for {}", identity.spiffe_id);
                    }
                    Err(e) => {
                        tracing::warn!("TLS cert reload failed: {e}");
                    }
                }
            }
            tracing::debug!("cert resolver updater exited");
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
        let guard = self.current.read().unwrap();
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
