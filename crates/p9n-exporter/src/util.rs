//! Shared utilities for exporter handlers.

use std::os::unix::io::{AsRawFd, OwnedFd};

/// Convert a tokio JoinError to a boxed error for handler results.
///
/// If the blocking task panicked, log at warn level so panics don't go
/// unnoticed.  The error still propagates as a normal Err → Rlerror to
/// the client.
pub fn join_err(e: tokio::task::JoinError) -> Box<dyn std::error::Error + Send + Sync> {
    if e.is_panic() {
        tracing::warn!("spawn_blocking task panicked: {e}");
    }
    Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        e.to_string(),
    ))
}

/// Map a dynamic error to a Linux errno code for Rlerror responses.
pub fn map_io_error(e: &(dyn std::error::Error + Send + Sync + 'static)) -> u32 {
    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
        match io_err.raw_os_error() {
            Some(errno) => errno as u32,
            None => match io_err.kind() {
                std::io::ErrorKind::NotFound => 2,          // ENOENT
                std::io::ErrorKind::PermissionDenied => 13,  // EACCES
                std::io::ErrorKind::AlreadyExists => 17,     // EEXIST
                std::io::ErrorKind::InvalidInput => 22,      // EINVAL
                std::io::ErrorKind::WouldBlock => 11,        // EAGAIN
                std::io::ErrorKind::TimedOut => 110,          // ETIMEDOUT
                _ => 5,                                       // EIO
            },
        }
    } else {
        5 // EIO
    }
}

/// Safely borrow a raw fd from an OwnedFd for use in spawn_blocking.
///
/// Returns the raw fd number. The caller MUST ensure the OwnedFd outlives
/// any File/operation created from this fd (use mem::forget on temporary Files).
pub fn borrow_fd(fd: &OwnedFd) -> i32 {
    fd.as_raw_fd()
}

/// Use a raw fd as a temporary std::fs::File without closing it on drop.
///
/// This is the safe wrapper for the `unsafe { File::from_raw_fd() }` + `mem::forget()`
/// pattern used throughout the handlers.
pub fn with_borrowed_file<T>(
    raw_fd: i32,
    f: impl FnOnce(&mut std::fs::File) -> std::io::Result<T>,
) -> std::io::Result<T> {
    let mut file = unsafe { std::os::unix::io::FromRawFd::from_raw_fd(raw_fd) };
    let result = f(&mut file);
    std::mem::forget(file); // don't close the fd
    result
}

/// Extract SPIFFE ID from DER-encoded X.509 certificates.
///
/// Shared between QUIC (quinn peer_identity) and TCP (tokio-rustls peer_certificates).
pub fn spiffe_id_from_certs(certs: &[impl AsRef<[u8]>]) -> Option<String> {
    let first = certs.first()?;
    let (_, cert) = x509_parser::parse_x509_certificate(first.as_ref()).ok()?;
    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = name {
                    if uri.starts_with("spiffe://") {
                        return Some(uri.to_string());
                    }
                }
            }
        }
    }
    None
}
