//! SPIFFE authentication provider for 9P2000.N.

pub mod error;
pub mod spiffe;

pub use error::AuthError;
pub use spiffe::posix_mapping::{
    BundleEntry, BundlePayload, MappingBundle, PosixIdentity, BUNDLE_KEY_USE, BUNDLE_TYP,
    MAX_BUNDLE_BYTES, MAX_SUPPLEMENTARY_GROUPS, SPIFFE_UID_MAX, SPIFFE_UID_MIN,
};
pub use spiffe::SpiffeAuth;
pub use spiffe::SpiffeIdentity;
