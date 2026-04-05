//! X.509 certificate chain verification against trust bundles.

use crate::error::AuthError;
use super::trust_bundle::TrustBundleStore;
use super::x509_svid;
use rustls::pki_types::{CertificateDer, UnixTime};

/// Result of a successful X.509 chain verification.
#[derive(Debug)]
pub struct ChainVerifyResult {
    pub spiffe_id: String,
    pub trust_domain: String,
    /// Certificate expiry as nanosecond unix timestamp.
    pub not_after: u64,
}

/// Verify an X.509-SVID certificate against the trust bundle store.
///
/// Validates:
/// 1. Certificate is parseable and contains a SPIFFE ID in SAN
/// 2. Trust domain is present in the trust store
/// 3. Certificate signature chain is valid against the domain's CA certs
/// 4. Certificate is not expired
pub fn verify_x509_svid(
    cert_der: &[u8],
    trust_store: &TrustBundleStore,
) -> Result<ChainVerifyResult, AuthError> {
    // Extract SPIFFE ID and trust domain from the certificate
    let spiffe_id = x509_svid::extract_spiffe_id(cert_der)?;
    let trust_domain = x509_svid::extract_trust_domain(&spiffe_id)?;

    // Get CA certs for this trust domain
    let ca_certs = trust_store
        .get(&trust_domain)
        .ok_or_else(|| AuthError::UntrustedDomain(trust_domain.clone()))?;

    // Build trust anchors from CA certs
    let cert_ders: Vec<CertificateDer<'_>> = ca_certs
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();

    let trust_anchors: Vec<_> = cert_ders
        .iter()
        .filter_map(|der| webpki::anchor_from_trusted_cert(der).ok())
        .map(|ta| ta.to_owned())
        .collect();

    if trust_anchors.is_empty() {
        return Err(AuthError::UntrustedDomain(format!(
            "no valid trust anchors for domain: {trust_domain}"
        )));
    }

    // Parse the end-entity certificate
    let ee_der = CertificateDer::from(cert_der);
    let ee = webpki::EndEntityCert::try_from(&ee_der)
        .map_err(|e| AuthError::UntrustedDomain(format!("cert parse: {e}")))?;

    // Verify the certificate chain + expiry
    let now = UnixTime::now();
    ee.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &trust_anchors,
        &[], // no intermediates (leaf must be directly signed by a CA in bundle)
        now,
        webpki::KeyUsage::client_auth(),
        None, // no revocation checking
        None, // default budget
    )
    .map_err(|e| match e {
        webpki::Error::CertExpired { .. } | webpki::Error::CertNotValidYet { .. } => {
            AuthError::CertificateExpired
        }
        _ => AuthError::UntrustedDomain(format!("chain verification failed: {e}")),
    })?;

    // Extract expiry timestamp
    let not_after = extract_not_after(cert_der);

    Ok(ChainVerifyResult {
        spiffe_id,
        trust_domain,
        not_after,
    })
}

/// Extract not_after as unix timestamp (seconds) from an X.509 certificate.
fn extract_not_after(der: &[u8]) -> u64 {
    x509_parser::parse_x509_certificate(der)
        .map(|(_, cert)| cert.validity().not_after.timestamp() as u64)
        .unwrap_or(0)
}
