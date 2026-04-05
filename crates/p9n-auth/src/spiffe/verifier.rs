//! Custom SPIFFE certificate verifier.

use crate::error::AuthError;
use super::x509_svid;

/// Verify that a DER certificate contains a valid SPIFFE ID
/// and belongs to an expected trust domain.
pub fn verify_spiffe_cert(
    cert_der: &[u8],
    expected_domain: Option<&str>,
) -> Result<String, AuthError> {
    let spiffe_id = x509_svid::extract_spiffe_id(cert_der)?;

    if let Some(domain) = expected_domain {
        let cert_domain = x509_svid::extract_trust_domain(&spiffe_id)?;
        if cert_domain != domain {
            return Err(AuthError::UntrustedDomain(format!(
                "expected domain {domain}, got {cert_domain}"
            )));
        }
    }

    Ok(spiffe_id)
}
