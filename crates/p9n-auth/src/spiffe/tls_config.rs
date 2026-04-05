//! Build rustls TLS configurations with SPIFFE certificates.

use crate::error::AuthError;
use super::{SpiffeIdentity, trust_bundle::TrustBundleStore, cert_resolver::SpiffeCertResolver};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

fn build_root_store(trust_store: &TrustBundleStore) -> rustls::RootCertStore {
    let mut root_store = rustls::RootCertStore::empty();
    for domain in trust_store.domains() {
        if let Some(cas) = trust_store.get(&domain) {
            for ca_der in cas {
                let _ = root_store.add(CertificateDer::from(ca_der));
            }
        }
    }
    root_store
}

/// Build a rustls ServerConfig with SPIFFE X.509-SVID.
pub fn server_config(
    identity: &SpiffeIdentity,
    trust_store: &TrustBundleStore,
) -> Result<rustls::ServerConfig, AuthError> {
    let certs = identity
        .cert_chain
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect::<Vec<_>>();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.private_key.clone()));

    let root_store = build_root_store(trust_store);

    // Require client authentication (mTLS)
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| AuthError::Tls(format!("client verifier: {e}")))?;

    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| AuthError::Tls(format!("server config: {e}")))?;

    // Enable 0-RTT early data. QUIC requires exactly 0xFFFF_FFFF.
    config.max_early_data_size = 0xFFFF_FFFF;

    Ok(config)
}

/// Build a rustls ClientConfig with SPIFFE X.509-SVID.
///
/// Uses a custom `SpiffeServerVerifier` that validates the server certificate's
/// SPIFFE ID (URI SAN) against the trust bundle, instead of the default WebPKI
/// hostname verification which would require a DNS SAN.
pub fn client_config(
    identity: &SpiffeIdentity,
    trust_store: &TrustBundleStore,
) -> Result<rustls::ClientConfig, AuthError> {
    let certs = identity
        .cert_chain
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect::<Vec<_>>();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.private_key.clone()));

    let crypto_provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

    let verifier = super::server_verifier::SpiffeServerVerifier::new(
        trust_store, crypto_provider,
    );

    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(certs, key)
        .map_err(|e| AuthError::Tls(format!("client config: {e}")))?;

    // Enable TLS 1.3 0-RTT early data with in-memory session ticket storage.
    config.enable_early_data = true;

    Ok(config)
}

/// Build a rustls ServerConfig with a dynamic cert resolver (for SVID rotation).
///
/// Unlike `server_config()`, this uses `with_cert_resolver()` so the certificate
/// can be hot-swapped without rebuilding the config or dropping connections.
pub fn server_config_dynamic(
    resolver: Arc<SpiffeCertResolver>,
    trust_store: &TrustBundleStore,
) -> Result<rustls::ServerConfig, AuthError> {
    let root_store = build_root_store(trust_store);

    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| AuthError::Tls(format!("client verifier: {e}")))?;

    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);

    // Enable 0-RTT early data. QUIC requires exactly 0xFFFF_FFFF.
    config.max_early_data_size = 0xFFFF_FFFF;

    Ok(config)
}
