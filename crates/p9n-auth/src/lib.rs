//! SPIFFE authentication provider for 9P2000.N.

pub mod error;
pub mod spiffe;

pub use error::AuthError;
pub use spiffe::SpiffeAuth;
pub use spiffe::SpiffeIdentity;
