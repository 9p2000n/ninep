//! Privilege-drop bootstrap driven by the importer's own SVID.
//!
//! Implements the importer half of `docs/POSIX_IDENTITY.md` §5.1: parse
//! the `p9nPosixIdentity` extension from the local SVID, then
//! (optionally) perform the full transition:
//!
//! ```text
//!   setgroups → setresgid → setresuid →
//!     prctl(PR_CAP_AMBIENT_CLEAR_ALL) → capset(0,0,0) →
//!     prctl(PR_SET_NO_NEW_PRIVS)
//! ```
//!
//! before FUSE mounts. After the transition the process holds no
//! capabilities, has no path to regain them (no_new_privs is set), and
//! runs as the SVID-derived `(uid, gid, groups)`. The bootstrap is
//! invoked exactly once at startup and gated behind an opt-in flag
//! (`--setuid-from-svid`).

use p9n_auth::{PosixIdentity, SpiffeIdentity};
use std::io;

/// Parse the `p9nPosixIdentity` extension from the importer's own SVID.
///
/// Returns `Ok(None)` if the cert has no such extension. Errors propagate
/// up unchanged so the caller can decide whether to fail (when
/// `--require-posix-identity` is set) or fall back.
pub fn extract(identity: &SpiffeIdentity) -> Result<Option<PosixIdentity>, p9n_auth::AuthError> {
    let leaf = identity
        .cert_chain
        .first()
        .ok_or_else(|| p9n_auth::AuthError::CertificateLoad("empty cert chain".into()))?;
    p9n_auth::extract_posix_identity(leaf)
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

    let rc = unsafe { libc::setresgid(p.gid as libc::gid_t, p.gid as libc::gid_t, p.gid as libc::gid_t) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let rc = unsafe { libc::setresuid(p.uid as libc::uid_t, p.uid as libc::uid_t, p.uid as libc::uid_t) };
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
            0, 0, 0,
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
    struct CapHeader { version: u32, pid: i32 }
    #[repr(C)]
    struct CapData { effective: u32, permitted: u32, inheritable: u32 }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

    let header = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let data: [CapData; 2] = [
        CapData { effective: 0, permitted: 0, inheritable: 0 },
        CapData { effective: 0, permitted: 0, inheritable: 0 },
    ];
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const CapHeader,
            data.as_ptr(),
        )
    };
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
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "post-setuid identity verification failed: euid={post_uid} egid={post_gid}, \
                 expected uid={} gid={}",
                p.uid, p.gid
            ),
        ));
    }

    tracing::info!(
        uid = p.uid,
        gid = p.gid,
        groups = ?p.groups,
        "dropped privileges to SVID-derived POSIX identity"
    );
    Ok(())
}
