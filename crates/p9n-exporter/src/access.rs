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
//!
//! # Architectural role
//!
//! Path-level isolation (per-workload root) is the **primary access
//! control boundary** in 9P2000.N. Each workload's session is rooted at
//! a subdirectory derived from its SPIFFE ID; `resolve()` in the backend
//! enforces that no fid can resolve to a path outside that subtree. Two
//! workloads attaching to the same export simply do not see each
//! other's files at the protocol layer.
//!
//! [`p9n_auth::PosixIdentity`] (resolved from the loaded mapping
//! bundle, `docs/POSIX_IDENTITY.md` §3) is layered on top as an
//! **identity label**, not an access mechanism. It drives
//! `chown`-on-create, validates wire `gid` in create messages
//! ([`Self::validate_wire_gid`], §7.6), and constrains
//! `Tsetattr.uid/gid` ([`Self::validate_setattr_owner`], §7.7). It
//! does *not* gate read/write/open syscalls against the peer's uid —
//! the exporter process opens files with its own credentials. This
//! is intentional: the path-level boundary already prevents
//! cross-tenant fid acquisition, so per-syscall fsuid switching
//! would be defense-in-depth rather than a primary control.
//!
//! See `docs/POSIX_IDENTITY.md` §8 for the full architectural model
//! and the operator responsibilities it implies.

use p9n_auth::{PosixIdentity, SPIFFE_UID_MAX, SPIFFE_UID_MIN};
use p9n_proto::types::{P9_SETATTR_GID, P9_SETATTR_UID};
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
        self.add_domain_policy(
            domain,
            Policy {
                root: None, // will be computed dynamically in resolve_root()
                permissions,
                max_depth: 0,
                uid: 0,
                gid: 0,
            },
        );
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
        self.ownership_for_session(spiffe_id, None)
    }

    /// Return the (uid, gid) ownership mapping for a peer, preferring
    /// the bundle-resolved `peer_posix` when present and falling back
    /// to the static `Policy.uid/gid` otherwise.
    ///
    /// See `docs/POSIX_IDENTITY.md` §1.3 / §10 for the design rationale —
    /// when both ends derive their POSIX identity from the same signed
    /// bundle, the client's `getuid()` matches the server's chown target
    /// by construction and `stat` readback no longer mismatches.
    pub fn ownership_for_session(
        &self,
        spiffe_id: Option<&str>,
        peer_posix: Option<&PosixIdentity>,
    ) -> (u32, u32) {
        if let Some(p) = peer_posix {
            return (p.uid, p.gid);
        }
        let policy = self.resolve(spiffe_id);
        (policy.uid, policy.gid)
    }

    /// Validate the wire `gid` field carried in `Tlcreate`/`Tmkdir`/
    /// `Tmknod`/`Tsymlink` against the authoritative gid for the peer.
    ///
    /// See `docs/POSIX_IDENTITY.md` §5.4 and `9P2000.N-protocol.md` §3.6.4
    /// "Wire gid Validation in Create Operations".
    ///
    /// Rules:
    /// - `peer_posix` present → wire MUST equal `peer_posix.gid` else EPERM.
    /// - `peer_posix` absent and `Policy.gid != 0` → wire MUST equal it else EPERM.
    /// - `peer_posix` absent and `Policy.gid == 0` (no explicit mapping
    ///   configured for this peer) → reject with EPERM. Accepting an
    ///   unverifiable wire gid in this state would re-open the trust gap
    ///   the extension was designed to close.
    pub fn validate_wire_gid(
        &self,
        spiffe_id: Option<&str>,
        peer_posix: Option<&PosixIdentity>,
        wire_gid: u32,
    ) -> Result<(), std::io::Error> {
        let auth_gid = match peer_posix {
            Some(p) => p.gid,
            None => {
                let policy = self.resolve(spiffe_id);
                if policy.gid == 0 {
                    return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                }
                policy.gid
            }
        };
        if wire_gid != auth_gid {
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        }
        Ok(())
    }

    /// Validate the uid/gid carried in a Tsetattr request.
    ///
    /// Combines two concerns previously split between this module and the
    /// setattr handler:
    ///
    /// - "Who may change ownership at all?" (the existing `PERM_ADMIN` gate).
    /// - "What target values are admissible?" (the SPIFFE-range check).
    ///
    /// See `docs/POSIX_IDENTITY.md` §5.4 and `9P2000.N-protocol.md` §3.6.4
    /// "Tsetattr Owner Validation".
    ///
    /// Rules when `peer_posix` is in effect:
    /// - `SETATTR_UID` set: allowed if `new_uid == peer_posix.uid` (chown to
    ///   self / no-op) OR the caller has `PERM_ADMIN` and `new_uid` lies in
    ///   `[SPIFFE_UID_MIN, SPIFFE_UID_MAX]`.
    /// - `SETATTR_GID` set: allowed if `new_gid ∈ {peer_posix.gid} ∪
    ///   peer_posix.groups` (chgrp to a group the workload already belongs
    ///   to) OR the caller has `PERM_ADMIN` and `new_gid` lies in the
    ///   SPIFFE range.
    ///
    /// Rules when `peer_posix` is absent: any owner change requires
    /// `PERM_ADMIN`; no range check (preserves backward compatibility for
    /// deployments that haven't adopted the extension).
    ///
    /// Returns `EPERM` on any rule violation.
    pub fn validate_setattr_owner(
        &self,
        spiffe_id: Option<&str>,
        peer_posix: Option<&PosixIdentity>,
        valid: u32,
        new_uid: u32,
        new_gid: u32,
    ) -> Result<(), std::io::Error> {
        let touches_uid = valid & P9_SETATTR_UID != 0;
        let touches_gid = valid & P9_SETATTR_GID != 0;
        if !touches_uid && !touches_gid {
            return Ok(());
        }

        let Some(p) = peer_posix else {
            // Fallback path: require both an explicit Policy mapping and
            // PERM_ADMIN. An unconfigured deployment (default Policy,
            // uid==gid==0) has no authoritative reference for what
            // ownership values are admissible, so silently rubber-stamping
            // a chown via PERM_ADMIN would re-open the trust gap the
            // extension was designed to close. Reject instead.
            let policy = self.resolve(spiffe_id);
            if policy.uid == 0 && policy.gid == 0 {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            return self
                .check_admin(spiffe_id)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EPERM));
        };

        let has_admin = self.check_admin(spiffe_id).is_ok();
        let in_range = |v: u32| (SPIFFE_UID_MIN..=SPIFFE_UID_MAX).contains(&v);

        if touches_uid {
            let self_chown = new_uid == p.uid;
            let admin_chown = has_admin && in_range(new_uid);
            if !(self_chown || admin_chown) {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
        }

        if touches_gid {
            let own_group = new_gid == p.gid || p.groups.contains(&new_gid);
            let admin_chgrp = has_admin && in_range(new_gid);
            if !(own_group || admin_chgrp) {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
        }

        Ok(())
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
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posix(uid: u32, gid: u32) -> PosixIdentity {
        PosixIdentity {
            uid,
            gid,
            groups: Vec::new(),
        }
    }

    #[test]
    fn validate_wire_gid_accepts_match_with_peer_posix() {
        let ac = AccessControl::new(PathBuf::from("/"));
        let p = posix(1_048_577, 1_048_577);
        ac.validate_wire_gid(None, Some(&p), 1_048_577).unwrap();
    }

    #[test]
    fn validate_wire_gid_rejects_mismatch_with_peer_posix() {
        let ac = AccessControl::new(PathBuf::from("/"));
        let p = posix(1_048_577, 1_048_577);
        let err = ac.validate_wire_gid(None, Some(&p), 1_048_578).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn validate_wire_gid_rejects_when_no_authoritative_mapping() {
        // peer_posix absent AND default Policy.gid == 0 → reject with EPERM.
        // Accepting any wire value here would re-open the trust gap that
        // the extension is designed to close (loophole patched 2026-05).
        let ac = AccessControl::new(PathBuf::from("/"));
        let err = ac.validate_wire_gid(None, None, 0).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
        let err = ac.validate_wire_gid(None, None, 12345).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn validate_wire_gid_enforces_static_policy_when_set() {
        let mut ac = AccessControl::new(PathBuf::from("/"));
        ac.set_default(Policy {
            gid: 5000,
            ..Policy::default()
        });
        ac.validate_wire_gid(None, None, 5000).unwrap();
        let err = ac.validate_wire_gid(None, None, 4999).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn validate_wire_gid_peer_posix_wins_over_static_policy() {
        // When both are present, peer_posix is authoritative.
        let mut ac = AccessControl::new(PathBuf::from("/"));
        ac.set_default(Policy {
            gid: 5000,
            ..Policy::default()
        });
        let p = posix(1_048_577, 1_048_577);
        // Wire matches peer_posix but not policy — must succeed.
        ac.validate_wire_gid(None, Some(&p), 1_048_577).unwrap();
        // Wire matches policy but not peer_posix — must fail.
        let err = ac.validate_wire_gid(None, Some(&p), 5000).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    fn posix_with_groups(uid: u32, gid: u32, groups: Vec<u32>) -> PosixIdentity {
        PosixIdentity { uid, gid, groups }
    }

    fn ac_no_admin() -> AccessControl {
        // Default policy strips PERM_ADMIN.
        let mut ac = AccessControl::new(PathBuf::from("/"));
        ac.set_default(Policy {
            permissions: PERM_ALL & !PERM_ADMIN,
            ..Policy::default()
        });
        ac
    }

    fn ac_with_admin() -> AccessControl {
        // Default policy already includes PERM_ADMIN via PERM_ALL.
        AccessControl::new(PathBuf::from("/"))
    }

    #[test]
    fn setattr_no_owner_change_is_noop() {
        // Neither bit set → never errors regardless of values or admin.
        let ac = ac_no_admin();
        ac.validate_setattr_owner(None, None, 0, 12345, 67890)
            .unwrap();
    }

    #[test]
    fn setattr_self_chown_allowed_without_admin() {
        // peer_posix in effect: chown to peer_posix.uid is always OK
        // because it's a no-op semantically.
        let ac = ac_no_admin();
        let p = posix_with_groups(1_048_577, 1_048_577, vec![]);
        ac.validate_setattr_owner(None, Some(&p), P9_SETATTR_UID, 1_048_577, 0)
            .unwrap();
    }

    #[test]
    fn setattr_chown_to_other_workload_requires_admin() {
        let p = posix_with_groups(1_048_577, 1_048_577, vec![]);
        let ac_n = ac_no_admin();
        let err = ac_n
            .validate_setattr_owner(None, Some(&p), P9_SETATTR_UID, 2_097_152, 0)
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
        let ac_a = ac_with_admin();
        ac_a.validate_setattr_owner(None, Some(&p), P9_SETATTR_UID, 2_097_152, 0)
            .unwrap();
    }

    #[test]
    fn setattr_chown_outside_spiffe_range_rejected_even_for_admin() {
        let p = posix_with_groups(1_048_577, 1_048_577, vec![]);
        let ac = ac_with_admin();
        // 500 is below SPIFFE_UID_MIN — closes the range asymmetry.
        let err = ac
            .validate_setattr_owner(None, Some(&p), P9_SETATTR_UID, 500, 0)
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn setattr_chgrp_to_supplementary_group_allowed_without_admin() {
        let p = posix_with_groups(1_048_577, 1_048_577, vec![1_048_577, 2_097_152]);
        let ac = ac_no_admin();
        ac.validate_setattr_owner(None, Some(&p), P9_SETATTR_GID, 0, 2_097_152)
            .unwrap();
    }

    #[test]
    fn setattr_chgrp_to_outside_groups_requires_admin() {
        let p = posix_with_groups(1_048_577, 1_048_577, vec![1_048_577]);
        let ac_n = ac_no_admin();
        let err = ac_n
            .validate_setattr_owner(None, Some(&p), P9_SETATTR_GID, 0, 3_145_728)
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
        let ac_a = ac_with_admin();
        ac_a.validate_setattr_owner(None, Some(&p), P9_SETATTR_GID, 0, 3_145_728)
            .unwrap();
    }

    #[test]
    fn setattr_uid_and_gid_both_must_pass() {
        // When both bits are set, both rules apply.
        let p = posix_with_groups(1_048_577, 1_048_577, vec![]);
        let ac = ac_with_admin();
        // Valid uid (admin), invalid gid (out of range) → EPERM.
        let err = ac
            .validate_setattr_owner(
                None,
                Some(&p),
                P9_SETATTR_UID | P9_SETATTR_GID,
                2_097_152,
                500,
            )
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn setattr_fallback_rejects_unconfigured_deployment() {
        // peer_posix absent AND default Policy (uid==gid==0): admin or not,
        // no authoritative reference exists. Reject (loophole patched 2026-05).
        let p_absent = None;
        let ac_a = ac_with_admin();
        let err = ac_a
            .validate_setattr_owner(None, p_absent, P9_SETATTR_UID, 500, 0)
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn setattr_fallback_with_explicit_policy_uses_perm_admin() {
        // peer_posix absent BUT Policy has an explicit mapping (uid != 0):
        // PERM_ADMIN gates the change, no range constraint applies (legacy
        // deployments that intentionally use non-SPIFFE uids continue to work).
        let p_absent = None;
        let mut ac_n = ac_no_admin();
        ac_n.set_default(Policy {
            uid: 1000,
            gid: 1000,
            permissions: PERM_ALL & !PERM_ADMIN,
            ..Policy::default()
        });
        let err = ac_n
            .validate_setattr_owner(None, p_absent, P9_SETATTR_UID, 500, 0)
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
        let mut ac_a = ac_with_admin();
        ac_a.set_default(Policy {
            uid: 1000,
            gid: 1000,
            ..Policy::default()
        });
        // Non-SPIFFE uid is fine in fallback mode with explicit policy.
        ac_a.validate_setattr_owner(None, p_absent, P9_SETATTR_UID, 500, 0)
            .unwrap();
    }
}
