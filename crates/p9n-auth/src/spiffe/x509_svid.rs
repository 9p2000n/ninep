//! X.509-SVID loading and SPIFFE ID extraction.
//! SVID rotation is handled by cert_resolver.rs + workload_api.rs FileWatch.

use crate::error::AuthError;
use super::SpiffeIdentity;
use std::fs;

/// Load an X.509-SVID from PEM cert + key files.
pub fn load_svid(cert_path: &str, key_path: &str) -> Result<SpiffeIdentity, AuthError> {
    let cert_pem = fs::read(cert_path)
        .map_err(|e| AuthError::CertificateLoad(format!("{cert_path}: {e}")))?;
    let key_pem = fs::read(key_path)
        .map_err(|e| AuthError::CertificateLoad(format!("{key_path}: {e}")))?;

    // Parse certificate chain
    let certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .filter_map(|r| r.ok())
        .map(|c| c.to_vec())
        .collect();
    if certs.is_empty() {
        return Err(AuthError::CertificateLoad("no certificates found".into()));
    }

    // Parse private key
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| AuthError::CertificateLoad(format!("key parse: {e}")))?
        .ok_or_else(|| AuthError::CertificateLoad("no private key found".into()))?;

    // Extract SPIFFE ID from the first certificate's SAN URI
    let spiffe_id = extract_spiffe_id(&certs[0])?;
    let trust_domain = extract_trust_domain(&spiffe_id)?;

    Ok(SpiffeIdentity {
        spiffe_id,
        trust_domain,
        cert_chain: certs,
        private_key: key.secret_der().to_vec(),
    })
}

/// Extract the SPIFFE ID from an X.509 certificate's SAN URI extension.
pub fn extract_spiffe_id(der: &[u8]) -> Result<String, AuthError> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| AuthError::InvalidSpiffeId(format!("x509 parse: {e}")))?;

    // Look for Subject Alternative Names
    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = name {
                    if uri.starts_with("spiffe://") {
                        return Ok(uri.to_string());
                    }
                }
            }
        }
    }
    Err(AuthError::InvalidSpiffeId("no spiffe:// URI in SAN".into()))
}

/// Extract trust domain from a SPIFFE ID.
pub fn extract_trust_domain(spiffe_id: &str) -> Result<String, AuthError> {
    let stripped = spiffe_id
        .strip_prefix("spiffe://")
        .ok_or_else(|| AuthError::InvalidSpiffeId(format!("not a SPIFFE URI: {spiffe_id}")))?;
    let domain = stripped
        .split('/')
        .next()
        .ok_or_else(|| AuthError::InvalidSpiffeId(format!("no trust domain: {spiffe_id}")))?;
    Ok(domain.to_string())
}
