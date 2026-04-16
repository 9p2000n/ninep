//! SPIFFE Workload API client interface.
//!
//! Provides `SvidSource` — an abstraction over how SVIDs are obtained.
//! Currently supports static files, file-based rotation watching, and
//! (with the `workload-api` feature) gRPC streaming from a SPIRE agent.

use crate::error::AuthError;
use super::{SpiffeIdentity, trust_bundle::TrustBundleStore, x509_svid};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;

/// Source of SPIFFE identities — either static files or a watched source.
pub enum SvidSource {
    /// Static PEM files (no rotation).
    Static {
        identity: SpiffeIdentity,
        trust_store: TrustBundleStore,
    },
    /// File-based watching: polls cert/key files for mtime changes.
    FileWatch {
        cert_path: PathBuf,
        key_path: PathBuf,
        ca_path: PathBuf,
        trust_domain: String,
        tx: watch::Sender<Arc<SpiffeIdentity>>,
        rx: watch::Receiver<Arc<SpiffeIdentity>>,
    },
    /// gRPC Workload API: streams SVIDs from a SPIRE agent via Unix socket.
    #[cfg(feature = "workload-api")]
    WorkloadApi {
        socket_path: String,
        tx: watch::Sender<Arc<SpiffeIdentity>>,
        rx: watch::Receiver<Arc<SpiffeIdentity>>,
        trust_store: TrustBundleStore,
    },
}

impl SvidSource {
    /// Create a static source from PEM files (no rotation).
    pub fn from_files(cert: &str, key: &str, ca: &str) -> Result<Self, AuthError> {
        let identity = x509_svid::load_svid(cert, key)?;
        let trust_store = TrustBundleStore::new();
        trust_store.load_pem_file(&identity.trust_domain, ca)?;
        Ok(Self::Static {
            identity,
            trust_store,
        })
    }

    /// Create a file-watching source that detects SVID rotation via mtime polling.
    pub fn file_watch(cert: &str, key: &str, ca: &str) -> Result<Self, AuthError> {
        let identity = x509_svid::load_svid(cert, key)?;
        let trust_domain = identity.trust_domain.clone();
        let (tx, rx) = watch::channel(Arc::new(identity));
        Ok(Self::FileWatch {
            cert_path: PathBuf::from(cert),
            key_path: PathBuf::from(key),
            ca_path: PathBuf::from(ca),
            trust_domain,
            tx,
            rx,
        })
    }

    /// Connect to the SPIFFE Workload API and fetch the initial SVID.
    #[cfg(feature = "workload-api")]
    pub async fn workload_api(socket_path: &str) -> Result<Self, AuthError> {
        use super::grpc::{client, proto};

        let sender = client::connect(socket_path).await?;
        let mut stream = client::fetch_x509_svid(sender).await?;

        let resp = stream
            .next()
            .await?
            .ok_or_else(|| AuthError::WorkloadApi("empty initial response".into()))?;
        let svid = resp
            .svids
            .into_iter()
            .next()
            .ok_or_else(|| AuthError::WorkloadApi("no SVIDs in response".into()))?;

        let identity = svid_to_identity(&svid)?;
        let trust_store = TrustBundleStore::new();
        let ca_certs = proto::split_der_certs(&svid.bundle_der);
        if !ca_certs.is_empty() {
            trust_store.add(&identity.trust_domain, ca_certs);
        }

        let (tx, rx) = watch::channel(Arc::new(identity));

        Ok(Self::WorkloadApi {
            socket_path: socket_path.to_string(),
            tx,
            rx,
            trust_store,
        })
    }

    /// Get the current identity.
    pub fn identity(&self) -> SpiffeIdentity {
        match self {
            Self::Static { identity, .. } => identity.clone(),
            Self::FileWatch { rx, .. } => (**rx.borrow()).clone(),
            #[cfg(feature = "workload-api")]
            Self::WorkloadApi { rx, .. } => (**rx.borrow()).clone(),
        }
    }

    /// Get the trust store (only for WorkloadApi and Static sources).
    pub fn trust_store(&self) -> Option<TrustBundleStore> {
        match self {
            Self::Static { trust_store, .. } => Some(trust_store.clone()),
            #[cfg(feature = "workload-api")]
            Self::WorkloadApi { trust_store, .. } => Some(trust_store.clone()),
            _ => None,
        }
    }

    /// Get a receiver to observe SVID updates (only for watched sources).
    pub fn subscribe(&self) -> Option<watch::Receiver<Arc<SpiffeIdentity>>> {
        match self {
            Self::FileWatch { rx, .. } => Some(rx.clone()),
            #[cfg(feature = "workload-api")]
            Self::WorkloadApi { rx, .. } => Some(rx.clone()),
            _ => None,
        }
    }

    /// Start a background task that polls for SVID/bundle changes.
    ///
    /// For `FileWatch`: polls cert and CA files by mtime.
    /// For `WorkloadApi`: reconnects to the agent and streams updates.
    /// Returns the JoinHandle (only for watched sources).
    pub fn spawn_rotation_watcher(
        &self,
        interval_secs: u64,
        trust_store: Option<TrustBundleStore>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        match self {
            Self::FileWatch {
                cert_path,
                key_path,
                ca_path,
                trust_domain,
                tx,
                ..
            } => {
                let cert_path = cert_path.clone();
                let key_path = key_path.clone();
                let ca_path = ca_path.clone();
                let trust_domain = trust_domain.clone();
                let tx = tx.clone();
                let interval = std::time::Duration::from_secs(interval_secs);

                Some(tokio::spawn(async move {
                    // All filesystem operations are offloaded to the blocking
                    // pool to avoid stalling the tokio runtime on slow storage.
                    let mut last_cert_modified = {
                        let p = cert_path.clone();
                        tokio::task::spawn_blocking(move || {
                            std::fs::metadata(&p).and_then(|m| m.modified()).ok()
                        }).await.ok().flatten()
                    };
                    let mut last_ca_modified = {
                        let p = ca_path.clone();
                        tokio::task::spawn_blocking(move || {
                            std::fs::metadata(&p).and_then(|m| m.modified()).ok()
                        }).await.ok().flatten()
                    };

                    loop {
                        tokio::time::sleep(interval).await;

                        // Check SVID cert rotation
                        let current_cert_modified = {
                            let p = cert_path.clone();
                            tokio::task::spawn_blocking(move || {
                                std::fs::metadata(&p).and_then(|m| m.modified()).ok()
                            }).await.ok().flatten()
                        };

                        if current_cert_modified != last_cert_modified {
                            tracing::info!("SVID certificate file changed, reloading...");
                            let cp = cert_path.clone();
                            let kp = key_path.clone();
                            match tokio::task::spawn_blocking(move || {
                                x509_svid::load_svid(
                                    cp.to_str().unwrap_or(""),
                                    kp.to_str().unwrap_or(""),
                                )
                            }).await {
                                Ok(Ok(new_identity)) => {
                                    tracing::info!(
                                        "SVID rotated: {}",
                                        new_identity.spiffe_id
                                    );
                                    let _ = tx.send(Arc::new(new_identity));
                                }
                                Ok(Err(e)) => {
                                    tracing::warn!("SVID reload failed: {e}");
                                }
                                Err(e) => {
                                    tracing::warn!("SVID reload task panicked: {e}");
                                }
                            }
                            last_cert_modified = current_cert_modified;
                        }

                        // Check CA bundle rotation
                        if let Some(ref store) = trust_store {
                            let current_ca_modified = {
                                let p = ca_path.clone();
                                tokio::task::spawn_blocking(move || {
                                    std::fs::metadata(&p).and_then(|m| m.modified()).ok()
                                }).await.ok().flatten()
                            };

                            if current_ca_modified != last_ca_modified {
                                tracing::info!("CA bundle file changed, reloading...");
                                let s = store.clone();
                                let td = trust_domain.clone();
                                let p = ca_path.clone();
                                match tokio::task::spawn_blocking(move || {
                                    s.load_pem_file(&td, p.to_str().unwrap_or(""))
                                }).await {
                                    Ok(Ok(())) => {
                                        tracing::info!(
                                            "CA bundle reloaded for domain: {trust_domain}"
                                        );
                                    }
                                    Ok(Err(e)) => {
                                        tracing::warn!("CA bundle reload failed: {e}");
                                    }
                                    Err(e) => {
                                        tracing::warn!("CA bundle reload task panicked: {e}");
                                    }
                                }
                                last_ca_modified = current_ca_modified;
                            }
                        }
                    }
                }))
            }
            #[cfg(feature = "workload-api")]
            Self::WorkloadApi {
                socket_path,
                tx,
                trust_store: src_trust_store,
                ..
            } => {
                let socket_path = socket_path.clone();
                let tx = tx.clone();
                let store = trust_store
                    .clone()
                    .unwrap_or_else(|| src_trust_store.clone());

                Some(tokio::spawn(async move {
                    workload_api_watch_loop(&socket_path, &tx, &store).await;
                }))
            }
            _ => None,
        }
    }
}

#[cfg(feature = "workload-api")]
fn svid_to_identity(
    svid: &super::grpc::proto::X509Svid,
) -> Result<SpiffeIdentity, AuthError> {
    let cert_chain = super::grpc::proto::split_der_certs(&svid.cert_chain_der);
    if cert_chain.is_empty() {
        return Err(AuthError::WorkloadApi("empty certificate chain".into()));
    }
    let trust_domain = x509_svid::extract_trust_domain(&svid.spiffe_id)?;
    Ok(SpiffeIdentity {
        spiffe_id: svid.spiffe_id.clone(),
        trust_domain,
        cert_chain,
        private_key: svid.private_key_der.clone(),
    })
}

/// Background loop: connect to the Workload API, stream SVIDs, and reconnect
/// on failure with exponential backoff (5s → 60s cap).
#[cfg(feature = "workload-api")]
async fn workload_api_watch_loop(
    socket_path: &str,
    tx: &watch::Sender<Arc<SpiffeIdentity>>,
    trust_store: &TrustBundleStore,
) {
    use super::grpc::{client, proto};
    use std::time::Duration;

    let mut backoff = Duration::from_secs(5);
    let max_backoff = Duration::from_secs(60);

    loop {
        match client::connect(socket_path).await {
            Ok(sender) => match client::fetch_x509_svid(sender).await {
                Ok(mut stream) => {
                    backoff = Duration::from_secs(5); // reset on success
                    loop {
                        match stream.next().await {
                            Ok(Some(resp)) => {
                                if let Some(svid) = resp.svids.into_iter().next() {
                                    match svid_to_identity(&svid) {
                                        Ok(identity) => {
                                            let ca_certs =
                                                proto::split_der_certs(&svid.bundle_der);
                                            if !ca_certs.is_empty() {
                                                trust_store.add(
                                                    &identity.trust_domain,
                                                    ca_certs,
                                                );
                                            }
                                            tracing::info!(
                                                "SVID updated via Workload API: {}",
                                                identity.spiffe_id
                                            );
                                            let _ = tx.send(Arc::new(identity));
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "failed to convert SVID: {e}"
                                            );
                                        }
                                    }
                                }
                            }
                            Ok(None) => {
                                tracing::info!("workload API stream ended, reconnecting...");
                                break;
                            }
                            Err(e) => {
                                tracing::warn!("workload API stream error: {e}");
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("workload API RPC failed: {e}");
                }
            },
            Err(e) => {
                tracing::warn!("workload API connect failed: {e}");
            }
        }
        tracing::debug!("reconnecting in {}s...", backoff.as_secs());
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(max_backoff);
    }
}
