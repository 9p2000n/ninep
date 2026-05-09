//! SPIFFE authentication provider for 9P2000.N.

pub mod error;
pub mod spiffe;

pub use error::AuthError;
pub use spiffe::SpiffeAuth;
pub use spiffe::SpiffeIdentity;
pub use spiffe::posix_identity::{
    extract_posix_identity, PosixIdentity, MAX_SUPPLEMENTARY_GROUPS,
    P9N_POSIX_IDENTITY_OID, SPIFFE_UID_MAX, SPIFFE_UID_MIN,
};
