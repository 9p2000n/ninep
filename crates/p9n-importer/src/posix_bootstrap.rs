//! Privilege-drop bootstrap driven by the importer's POSIX identity.
//!
//! Implements the importer half of `docs/POSIX_IDENTITY.md` §7.1.
//! After resolving `(uid, gid, groups)` for the importer's own SPIFFE
//! ID from the signed mapping bundle, the bootstrap performs the
//! full transition:
//!
//! ```text
//!   setgroups → setresgid → setresuid →
//!     prctl(PR_CAP_AMBIENT_CLEAR_ALL) → capset(0,0,0) →
//!     prctl(PR_SET_NO_NEW_PRIVS)
//! ```
//!
//! before FUSE mounts. After the transition the process holds no
//! capabilities, has no path to regain them (no_new_privs is set), and
//! runs as the bundle-derived `(uid, gid, groups)`. The bootstrap is
//! invoked exactly once at startup, gated behind `--setuid-from-mapping`.

use p9n_auth::spiffe::jwt_svid::JwkSet;
use p9n_auth::{MappingBundle, PosixIdentity};
use std::io;

/// Resolve the importer's POSIX identity from a signed mapping bundle.
///
/// `jws_bytes` is the verbatim JWS-compact bundle as received over
/// `Tfetchbundle(BUNDLE_POSIX_MAPPING)`. `jwk_set` is the local set of
/// candidate verification keys (only those with `use="p9n-mapping"`
/// qualify, enforced inside `MappingBundle::load_and_verify`).
/// `expected_trust_domain` MUST be the importer's own trust domain;
/// a bundle for a different domain is rejected.
///
/// Returns:
/// - `Ok(Some(identity))` on bundle hit.
/// - `Ok(None)` when the bundle is well-formed but lacks an entry for
///   `spiffe_id`. The caller decides whether to fail closed (when
///   `--require-posix-mapping` or `--setuid-from-mapping` is set) or
///   proceed without a derived POSIX identity.
/// - `Err(...)` for any signature, structural, or staleness failure;
///   these are fatal and MUST NOT be silently downgraded to "fall
///   through" — a signed-but-invalid bundle is a security event.
pub fn extract_from_bundle(
    spiffe_id: &str,
    jws_bytes: &[u8],
    jwk_set: &JwkSet,
    expected_trust_domain: &str,
    now: u64,
) -> Result<Option<PosixIdentity>, p9n_auth::AuthError> {
    let bundle = MappingBundle::load_and_verify(jws_bytes, jwk_set, expected_trust_domain, now)?;
    Ok(bundle.lookup_posix(spiffe_id))
}

/// Drop privileges to the SVID-derived `(uid, gid, groups)` and lock down
/// future privilege escalation via `PR_SET_NO_NEW_PRIVS`.
///
/// MUST be called before any privileged operation that the new identity
/// will not be allowed to perform (notably `mount(2)` if the importer is
/// not using the unprivileged `fusermount3` helper).
///
/// The transition order matches §5.1 of the design doc: groups, then gid,
/// then uid (otherwise the kernel rejects the supplementary-group change
/// once we have already become an unprivileged user). After the drop, the
/// process may still hold capabilities — we lock against re-acquisition
/// via `prctl(PR_SET_NO_NEW_PRIVS)`.
pub fn apply_setuid(p: &PosixIdentity) -> io::Result<()> {
    // Sanity: refuse to apply if we're already non-root and the requested
    // uid differs. The kernel would reject the call anyway, but a clear
    // error here gives a better operator experience.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 && euid != p.uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "cannot setuid({}) from euid {} — process must start as root \
                 or with CAP_SETUID/CAP_SETGID",
                p.uid, euid
            ),
        ));
    }

    // setgroups: clear and reset to exactly the supplementary groups in the
    // extension. Pass an empty list as a real `[]` — passing a null pointer
    // is undefined behaviour on glibc.
    let groups: Vec<libc::gid_t> = p.groups.iter().map(|&g| g as libc::gid_t).collect();
    let rc = unsafe { libc::setgroups(groups.len(), groups.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let rc = unsafe {
        libc::setresgid(
            p.gid as libc::gid_t,
            p.gid as libc::gid_t,
            p.gid as libc::gid_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let rc = unsafe {
        libc::setresuid(
            p.uid as libc::uid_t,
            p.uid as libc::uid_t,
            p.uid as libc::uid_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    // ── Explicit capability drop (closes audit finding L-1) ──
    //
    // setresuid from real_uid=0 to non-zero auto-clears the effective,
    // permitted, and ambient capability sets, but it preserves the
    // *inheritable* set. For the documented "start as root" path that's
    // already harmless once PR_SET_NO_NEW_PRIVS is set below (a future
    // exec can't gain caps, so inheritable becomes inert). But for two
    // other startup modes we don't want to assume the kernel did the
    // right thing:
    //
    // 1. File-capability startup: importer launched non-root with file
    //    capabilities (e.g., `setcap cap_setuid,cap_setgid+ep`). The
    //    setresuid above succeeds via CAP_SETUID, but the kernel does
    //    NOT auto-clear permitted/effective when the calling process
    //    wasn't root to begin with — the caps would survive the
    //    transition.
    //
    // 2. Ambient set populated by the launcher (systemd
    //    `AmbientCapabilities=...`). Same residue concern.
    //
    // We therefore explicitly clear the ambient set first
    // (PR_CAP_AMBIENT_CLEAR_ALL) and then capset(0) all three sets.
    // Both are unconditionally permitted operations — dropping caps
    // never requires CAP_SETPCAP.

    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        // EINVAL means PR_CAP_AMBIENT is not supported (Linux < 4.3).
        // The caller almost certainly isn't on such a kernel given
        // the rest of the project's requirements (openat2 needs 5.6+),
        // but treat the error as soft-warn rather than fatal so the
        // bootstrap path stays robust on minimal sandboxes.
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(err);
        }
        tracing::debug!(
            "PR_CAP_AMBIENT not supported by kernel; ambient caps not explicitly cleared"
        );
    }

    // capset(0,0,0) on all three sets via the raw syscall. libc 0.2 does
    // not expose a typed wrapper. _LINUX_CAPABILITY_VERSION_3 takes two
    // 32-bit data slots covering the 64-bit cap mask.
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data: [CapData; 2] = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let post_uid = unsafe { libc::geteuid() };
    let post_gid = unsafe { libc::getegid() };
    if post_uid != p.uid || post_gid != p.gid {
        return Err(io::Error::other(format!(
            "post-setuid identity verification failed: euid={post_uid} egid={post_gid}, \
                 expected uid={} gid={}",
            p.uid, p.gid
        )));
    }

    tracing::info!(
        uid = p.uid,
        gid = p.gid,
        groups = ?p.groups,
        "dropped privileges to SVID-derived POSIX identity"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p9n_auth::{BundleEntry, BundlePayload};

    // ── Same fixed test keypair as p9n_auth::spiffe::posix_mapping tests.
    const TEST_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiVYWvBoz0W8XhaHR\n\
        tkm7T7YeQlWKukKY4jc4OP4q5lehRANCAAS45NzWr0n5A2m2cv202gana0Eicbva\n\
        XxX60iO/d4jQGZ87lXaHPBch/n8BRR4eAmMDb0HoBdJEI3OZdinuLaYW\n\
        -----END PRIVATE KEY-----\n";
    const TEST_PUB_X: &str = "uOTc1q9J-QNptnL9tNoGp2tBInG72l8V-tIjv3eI0Bk";
    const TEST_PUB_Y: &str = "nzuVdoc8FyH-fwFFHh4CYwNvQegF0kQjc5l2Ke4tphY";
    const TEST_KID: &str = "test-key";

    fn jwk_set() -> JwkSet {
        let json = serde_json::json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "kid": TEST_KID,
                "alg": "ES256",
                "use": "p9n-mapping",
                "x": TEST_PUB_X,
                "y": TEST_PUB_Y,
            }]
        });
        JwkSet::from_json(&serde_json::to_vec(&json).unwrap()).unwrap()
    }

    fn sign(payload: &BundlePayload) -> Vec<u8> {
        let key = jsonwebtoken::EncodingKey::from_ec_pem(TEST_PRIVATE_PEM.as_bytes()).unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(TEST_KID.into());
        header.typ = Some("p9n-posix-mapping-bundle".into());
        jsonwebtoken::encode(&header, payload, &key)
            .unwrap()
            .into_bytes()
    }

    fn payload_with(entries: Vec<BundleEntry>) -> BundlePayload {
        BundlePayload {
            version: 1,
            trust_domain: "example.com".into(),
            serial: 1,
            issued_at: 1_000,
            not_after: 1_000_000,
            entries,
        }
    }

    fn alice() -> BundleEntry {
        BundleEntry {
            spiffe_id: "spiffe://example.com/workloads/alice".into(),
            uid: 1_048_577,
            gid: 1_048_577,
            groups: vec![],
            deprecated: false,
            deprecated_since: None,
        }
    }

    #[test]
    fn extract_from_bundle_hit() {
        let payload = payload_with(vec![alice()]);
        let jws = sign(&payload);
        let id = extract_from_bundle(
            "spiffe://example.com/workloads/alice",
            &jws,
            &jwk_set(),
            "example.com",
            500,
        )
        .unwrap()
        .expect("bundle entry exists");
        assert_eq!(id.uid, 1_048_577);
        assert_eq!(id.gid, 1_048_577);
    }

    #[test]
    fn extract_from_bundle_miss_returns_none() {
        let payload = payload_with(vec![alice()]);
        let jws = sign(&payload);
        let result = extract_from_bundle(
            "spiffe://example.com/workloads/bob",
            &jws,
            &jwk_set(),
            "example.com",
            500,
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn extract_from_bundle_expired_errors() {
        let mut payload = payload_with(vec![alice()]);
        payload.not_after = 100;
        let jws = sign(&payload);
        let err = extract_from_bundle(
            "spiffe://example.com/workloads/alice",
            &jws,
            &jwk_set(),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn extract_from_bundle_trust_domain_mismatch_errors() {
        let payload = payload_with(vec![alice()]);
        let jws = sign(&payload);
        let err = extract_from_bundle(
            "spiffe://other.com/workloads/alice",
            &jws,
            &jwk_set(),
            "other.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("trust_domain mismatch"), "{err}");
    }

    #[test]
    fn extract_from_bundle_corrupted_signature_errors() {
        let payload = payload_with(vec![alice()]);
        let mut jws = sign(&payload);
        // Flip a byte deep inside the signature segment.
        let last = jws.len() - 5;
        jws[last] ^= 0x01;
        let err = extract_from_bundle(
            "spiffe://example.com/workloads/alice",
            &jws,
            &jwk_set(),
            "example.com",
            500,
        )
        .unwrap_err();
        // jsonwebtoken surfaces this as a verification failure.
        assert!(
            err.to_string().contains("signature/payload decode")
                || err.to_string().contains("InvalidSignature"),
            "{err}"
        );
    }
}
