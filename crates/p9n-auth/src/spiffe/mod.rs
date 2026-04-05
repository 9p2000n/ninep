//! SPIFFE workload identity support.

pub mod x509_svid;
pub mod trust_bundle;
pub mod tls_config;
pub mod verifier;
pub mod jwt_svid;
pub mod workload_api;
pub mod cert_resolver;
pub mod chain_verifier;

#[cfg(feature = "workload-api")]
pub mod grpc;

use crate::error::AuthError;
use std::sync::Arc;

/// SPIFFE identity: parsed from an X.509-SVID certificate.
#[derive(Debug, Clone)]
pub struct SpiffeIdentity {
    /// Full SPIFFE ID URI (e.g., "spiffe://example.com/workload")
    pub spiffe_id: String,
    /// Trust domain extracted from the SPIFFE ID
    pub trust_domain: String,
    /// DER-encoded certificate chain
    pub cert_chain: Vec<Vec<u8>>,
    /// DER-encoded private key
    pub private_key: Vec<u8>,
}

/// Top-level auth provider that combines X.509-SVID + trust bundles.
///
/// Supports two modes:
/// - **Static**: loads PEM files once, no rotation
/// - **Rotating**: watches files for changes, hot-swaps TLS certs
pub struct SpiffeAuth {
    pub identity: SpiffeIdentity,
    pub trust_store: trust_bundle::TrustBundleStore,
    /// SVID source for rotation support.
    pub source: Option<workload_api::SvidSource>,
    /// Dynamic cert resolver (for rotation-aware TLS).
    pub cert_resolver: Option<Arc<cert_resolver::SpiffeCertResolver>>,
}

impl SpiffeAuth {
    /// Load from PEM files (static, no rotation).
    pub fn from_pem_files(
        cert_path: &str,
        key_path: &str,
        ca_path: &str,
    ) -> Result<Self, AuthError> {
        let identity = x509_svid::load_svid(cert_path, key_path)?;
        let trust_store = trust_bundle::TrustBundleStore::new();
        trust_store.load_pem_file(&identity.trust_domain, ca_path)?;
        Ok(Self {
            identity,
            trust_store,
            source: None,
            cert_resolver: None,
        })
    }

    /// Connect to the SPIFFE Workload API via Unix socket.
    ///
    /// `socket_path` is the path to the SPIRE Agent Unix socket
    /// (e.g., `/run/spire/agent.sock`). The `unix:` or `unix://` prefix
    /// is stripped if present for compatibility with the SPIRE convention.
    #[cfg(feature = "workload-api")]
    pub async fn from_workload_api(socket: &str) -> Result<Self, AuthError> {
        // Strip unix: prefix if present (SPIRE convention).
        let socket_path = socket
            .strip_prefix("unix:")
            .or_else(|| socket.strip_prefix("unix://"))
            .unwrap_or(socket);

        let source = workload_api::SvidSource::workload_api(socket_path).await?;
        let identity = source.identity();
        let trust_store = source.trust_store().unwrap_or_else(trust_bundle::TrustBundleStore::new);

        let resolver = Arc::new(cert_resolver::SpiffeCertResolver::new(&identity)?);

        if let Some(rx) = source.subscribe() {
            resolver.spawn_updater(rx);
        }
        source.spawn_rotation_watcher(0, Some(trust_store.clone()));

        Ok(Self {
            identity,
            trust_store,
            source: Some(source),
            cert_resolver: Some(resolver),
        })
    }

    /// Load from PEM files with SVID rotation support.
    ///
    /// Watches cert/key files for changes and hot-swaps the TLS certificate.
    /// Must be called within a tokio runtime context.
    pub fn from_pem_files_with_rotation(
        cert_path: &str,
        key_path: &str,
        ca_path: &str,
    ) -> Result<Self, AuthError> {
        let source = workload_api::SvidSource::file_watch(cert_path, key_path, ca_path)?;
        let identity = source.identity();
        let trust_store = trust_bundle::TrustBundleStore::new();
        trust_store.load_pem_file(&identity.trust_domain, ca_path)?;

        let resolver = Arc::new(cert_resolver::SpiffeCertResolver::new(&identity)?);

        // Wire up: SVID source -> cert resolver hot-reload
        if let Some(rx) = source.subscribe() {
            resolver.spawn_updater(rx);
        }
        source.spawn_rotation_watcher(30, Some(trust_store.clone())); // poll every 30 seconds

        Ok(Self {
            identity,
            trust_store,
            source: Some(source),
            cert_resolver: Some(resolver),
        })
    }
}
