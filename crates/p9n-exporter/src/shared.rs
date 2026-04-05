//! Shared context bundling server-wide state.

use crate::access::AccessControl;
use crate::backend::local::LocalBackend;
use crate::config::ExporterConfig;
use crate::lease_manager::LeaseManager;
use crate::session_store::SessionStore;
use crate::watch_manager::WatchManager;
use p9n_auth::spiffe::trust_bundle::TrustBundleStore;

/// Server-wide state shared across all connections and streams.
pub struct SharedCtx {
    pub backend: LocalBackend,
    pub access: AccessControl,
    pub session_store: SessionStore,
    pub watch_mgr: WatchManager,
    pub lease_mgr: LeaseManager,
    pub trust_store: TrustBundleStore,
    pub server_spiffe_id: String,
    pub server_trust_domain: String,
    pub cap_signing_key: [u8; 32],
    /// Runtime configuration.
    pub config: ExporterConfig,
}
