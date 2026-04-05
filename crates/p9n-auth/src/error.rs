//! Authentication error types.

/// Errors arising from SPIFFE authentication.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Failed to load certificate or key file.
    #[error("certificate load: {0}")]
    CertificateLoad(String),

    /// Malformed SPIFFE ID.
    #[error("invalid SPIFFE ID: {0}")]
    InvalidSpiffeId(String),

    /// Trust domain not present in the bundle store.
    #[error("untrusted domain: {0}")]
    UntrustedDomain(String),

    /// Certificate is past its validity period.
    #[error("certificate expired")]
    CertificateExpired,

    /// TLS / rustls error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// JWT verification failed.
    #[error("JWT error: {0}")]
    Jwt(String),

    /// Workload API error.
    #[error("workload API: {0}")]
    WorkloadApi(String),

    /// Functionality not yet implemented.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl AuthError {
    /// Check if this error represents an expired certificate or token.
    pub fn is_expired(&self) -> bool {
        matches!(self, Self::CertificateExpired)
            || matches!(self, Self::Jwt(msg) if msg.contains("ExpiredSignature"))
    }
}
