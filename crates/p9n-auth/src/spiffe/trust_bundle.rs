//! Trust bundle store: PEM CA chains and JWK Sets keyed by trust domain.
//!
//! Thread-safe via `Arc<RwLock<>>` — cloning shares the underlying store.

use crate::error::AuthError;
use super::jwt_svid::JwkSet;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::fs;

/// Per-domain trust bundle: X.509 CA certs and optional JWT JWK Set.
#[derive(Debug, Clone, Default)]
struct DomainBundle {
    x509_cas: Vec<Vec<u8>>,
    jwt_keys: Option<JwkSet>,
}

/// Stores trust bundles (CA cert chains and JWK Sets) per trust domain.
///
/// Clone is cheap (shares the underlying `Arc`). All methods take `&self`
/// and acquire internal locks as needed.
#[derive(Debug, Clone)]
pub struct TrustBundleStore {
    inner: Arc<RwLock<HashMap<String, DomainBundle>>>,
}

impl Default for TrustBundleStore {
    fn default() -> Self {
        Self { inner: Arc::new(RwLock::new(HashMap::new())) }
    }
}

impl TrustBundleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a PEM CA bundle file for a trust domain.
    pub fn load_pem_file(&self, trust_domain: &str, path: &str) -> Result<(), AuthError> {
        let pem =
            fs::read(path).map_err(|e| AuthError::CertificateLoad(format!("{path}: {e}")))?;
        let certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut &pem[..])
            .filter_map(|r| r.ok())
            .map(|c| c.to_vec())
            .collect();
        if certs.is_empty() {
            return Err(AuthError::CertificateLoad(format!(
                "no CA certs in {path}"
            )));
        }
        let mut bundles = self.inner.write().unwrap();
        let bundle = bundles.entry(trust_domain.to_string()).or_default();
        bundle.x509_cas = certs;
        Ok(())
    }

    /// Add DER-encoded CA certs for a trust domain.
    pub fn add(&self, trust_domain: &str, certs: Vec<Vec<u8>>) {
        let mut bundles = self.inner.write().unwrap();
        let bundle = bundles.entry(trust_domain.to_string()).or_default();
        bundle.x509_cas = certs;
    }

    /// Get the X.509 CA certs for a trust domain (owned clone).
    pub fn get(&self, trust_domain: &str) -> Option<Vec<Vec<u8>>> {
        let bundles = self.inner.read().unwrap();
        bundles.get(trust_domain).map(|b| b.x509_cas.clone())
    }

    /// Check if a trust domain is known.
    pub fn has(&self, trust_domain: &str) -> bool {
        let bundles = self.inner.read().unwrap();
        bundles.contains_key(trust_domain)
    }

    /// Get all trust domains.
    pub fn domains(&self) -> Vec<String> {
        let bundles = self.inner.read().unwrap();
        bundles.keys().cloned().collect()
    }

    /// Set the JWT JWK Set for a trust domain.
    pub fn set_jwt_keys(&self, trust_domain: &str, jwk_set: JwkSet) {
        let mut bundles = self.inner.write().unwrap();
        let bundle = bundles.entry(trust_domain.to_string()).or_default();
        bundle.jwt_keys = Some(jwk_set);
    }

    /// Get the JWT JWK Set for a trust domain (owned clone).
    pub fn get_jwt_keys(&self, trust_domain: &str) -> Option<JwkSet> {
        let bundles = self.inner.read().unwrap();
        bundles.get(trust_domain)?.jwt_keys.clone()
    }

    /// Serialize the JWK Set for a trust domain as JSON bytes.
    pub fn to_jwk_json(&self, trust_domain: &str) -> Option<Vec<u8>> {
        let keys = self.get_jwt_keys(trust_domain)?;
        serde_json::to_vec(&keys).ok()
    }

    /// Serialize all CAs for a trust domain as PEM.
    pub fn to_pem(&self, trust_domain: &str) -> Option<Vec<u8>> {
        let bundles = self.inner.read().unwrap();
        let bundle = bundles.get(trust_domain)?;
        let mut pem = Vec::new();
        for cert_der in &bundle.x509_cas {
            use std::io::Write;
            let b64 = base64_encode(cert_der);
            write!(pem, "-----BEGIN CERTIFICATE-----\n").ok();
            for chunk in b64.as_bytes().chunks(76) {
                pem.extend_from_slice(chunk);
                pem.push(b'\n');
            }
            write!(pem, "-----END CERTIFICATE-----\n").ok();
        }
        Some(pem)
    }
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}
