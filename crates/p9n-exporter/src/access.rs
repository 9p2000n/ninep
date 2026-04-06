//! Identity-based access control for 9P2000.N.
//!
//! Maps SPIFFE IDs to access policies that control:
//! - Per-user root directory (filesystem namespace isolation)
//! - Read/write/admin permissions
//! - Walk depth limits
//!
//! The default policy allows full access to the export root (single-tenant mode).
//! For multi-tenant deployments, configure explicit policies per SPIFFE ID or
//! trust domain.

use std::collections::HashMap;
use std::path::PathBuf;

/// Permission bits for access control.
pub const PERM_READ: u32 = 0x01;
pub const PERM_WRITE: u32 = 0x02;
pub const PERM_CREATE: u32 = 0x04;
pub const PERM_REMOVE: u32 = 0x08;
pub const PERM_SETATTR: u32 = 0x10;
pub const PERM_ADMIN: u32 = 0x80; // chown, chmod, setacl
pub const PERM_ALL: u32 = 0xFF;

/// Access policy for a specific identity.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Filesystem root for this identity (subdirectory of the export root).
    /// None = use the export root directly.
    pub root: Option<PathBuf>,
    /// Permission bitmask.
    pub permissions: u32,
    /// Maximum walk depth (0 = unlimited).
    pub max_depth: u16,
    /// Map to this uid for file operations (0 = use server process uid).
    pub uid: u32,
    /// Map to this gid for file operations (0 = use server process gid).
    pub gid: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            root: None,
            permissions: PERM_ALL,
            max_depth: 0,
            uid: 0,
            gid: 0,
        }
    }
}

/// Access policy configuration.
///
/// Lookup order:
/// 1. Exact SPIFFE ID match (e.g., "spiffe://example.com/app/worker-1")
/// 2. Trust domain match (e.g., "example.com")
/// 3. Default policy
pub struct AccessControl {
    /// Policies keyed by exact SPIFFE ID.
    by_id: HashMap<String, Policy>,
    /// Policies keyed by trust domain.
    by_domain: HashMap<String, Policy>,
    /// Default policy for unrecognized identities.
    default: Policy,
    /// Export root (used to construct per-user roots).
    export_root: PathBuf,
}

impl AccessControl {
    /// Create with default policy (full access, shared root).
    pub fn new(export_root: PathBuf) -> Self {
        Self {
            by_id: HashMap::new(),
            by_domain: HashMap::new(),
            default: Policy::default(),
            export_root,
        }
    }

    /// Set the default policy.
    pub fn set_default(&mut self, policy: Policy) {
        self.default = policy;
    }

    /// Add a policy for a specific SPIFFE ID.
    pub fn add_id_policy(&mut self, spiffe_id: &str, policy: Policy) {
        self.by_id.insert(spiffe_id.to_string(), policy);
    }

    /// Add a policy for a trust domain (matches all IDs in that domain).
    pub fn add_domain_policy(&mut self, domain: &str, policy: Policy) {
        self.by_domain.insert(domain.to_string(), policy);
    }

    /// Enable per-user directory isolation.
    ///
    /// Creates a policy for the trust domain where each SPIFFE ID gets
    /// a subdirectory named after its workload path component.
    /// E.g., "spiffe://example.com/app/worker" → `{export_root}/app/worker/`
    pub fn enable_isolation(&mut self, domain: &str, permissions: u32) {
        self.add_domain_policy(domain, Policy {
            root: None, // will be computed dynamically in resolve_root()
            permissions,
            max_depth: 0,
            uid: 0,
            gid: 0,
        });
    }

    /// Resolve the policy for a given SPIFFE ID.
    pub fn resolve(&self, spiffe_id: Option<&str>) -> &Policy {
        if let Some(id) = spiffe_id {
            // 1. Exact SPIFFE ID match
            if let Some(policy) = self.by_id.get(id) {
                return policy;
            }
            // 2. Trust domain match
            if let Some(domain) = extract_domain(id) {
                if let Some(policy) = self.by_domain.get(domain) {
                    return policy;
                }
            }
        }
        // 3. Default
        &self.default
    }

    /// Resolve the filesystem root path for a given SPIFFE ID.
    ///
    /// If the policy has an explicit root, use it.
    /// If the policy comes from a domain match, derive from the SPIFFE workload path.
    /// Otherwise, use the export root.
    ///
    /// Note: this only computes the path — it does **not** create the directory.
    /// The caller (attach handler) is responsible for calling `backend.attach()`
    /// which ensures the directory exists.
    pub fn resolve_root(&self, spiffe_id: Option<&str>) -> PathBuf {
        let policy = self.resolve(spiffe_id);

        if let Some(ref root) = policy.root {
            return root.clone();
        }

        // For domain-matched policies: derive per-workload subdirectory
        if let Some(id) = spiffe_id {
            if let Some(domain) = extract_domain(id) {
                if self.by_domain.contains_key(domain) {
                    // "spiffe://example.com/app/worker" → "app/worker"
                    if let Some(workload_path) = extract_workload_path(id) {
                        return self.export_root.join(workload_path);
                    }
                }
            }
        }

        self.export_root.clone()
    }

    /// Check if an operation is permitted.
    pub fn check(&self, spiffe_id: Option<&str>, required: u32) -> Result<(), std::io::Error> {
        let policy = self.resolve(spiffe_id);
        if policy.permissions & required == required {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "access denied: required={required:#x}, have={:#x}",
                    policy.permissions
                ),
            ))
        }
    }

    /// Check walk depth limit.
    pub fn check_depth(&self, spiffe_id: Option<&str>, depth: u16) -> Result<(), std::io::Error> {
        let policy = self.resolve(spiffe_id);
        if policy.max_depth > 0 && depth > policy.max_depth {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("walk depth {depth} exceeds limit {}", policy.max_depth),
            ))
        } else {
            Ok(())
        }
    }

    /// Check if admin operations (chown, chmod) are permitted.
    pub fn check_admin(&self, spiffe_id: Option<&str>) -> Result<(), std::io::Error> {
        self.check(spiffe_id, PERM_ADMIN)
    }

    /// Return the (uid, gid) ownership mapping for a SPIFFE identity.
    ///
    /// Called after lcreate, mkdir, symlink, mknod. The caller should pass
    /// these values to `backend.chown()` if either is non-zero.
    pub fn ownership_for(&self, spiffe_id: Option<&str>) -> (u32, u32) {
        let policy = self.resolve(spiffe_id);
        (policy.uid, policy.gid)
    }
}

/// Extract trust domain from a SPIFFE ID.
/// "spiffe://example.com/app/worker" → "example.com"
fn extract_domain(spiffe_id: &str) -> Option<&str> {
    let rest = spiffe_id.strip_prefix("spiffe://")?;
    rest.split('/').next()
}

/// Extract workload path from a SPIFFE ID.
/// "spiffe://example.com/app/worker" → "app/worker"
fn extract_workload_path(spiffe_id: &str) -> Option<&str> {
    let rest = spiffe_id.strip_prefix("spiffe://")?;
    let slash = rest.find('/')?;
    let path = &rest[slash + 1..];
    if path.is_empty() { None } else { Some(path) }
}
