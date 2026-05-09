//! Server-side state for the signed POSIX mapping bundle.
//!
//! Holds the parsed `MappingBundle` and the original JWS bytes (for
//! Tfetchbundle pass-through), plus the JWK Set used to re-verify on
//! reload. Loaded once at exporter startup. A background poller in
//! `Exporter::run` calls [`PosixMappingState::maybe_reload`] on a
//! cadence to pick up operator-published refreshes; reload is
//! fail-soft — a malformed new bundle leaves the previous one in
//! place.

use p9n_auth::spiffe::jwt_svid::JwkSet;
use p9n_auth::{AuthError, MappingBundle};
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Loaded mapping bundle plus everything needed to re-verify a refreshed
/// version against the same trust anchors.
pub struct PosixMappingState {
    inner: RwLock<Inner>,
    /// Trust domain the bundle is bound to. Constant for the lifetime
    /// of the process (a different trust domain requires a new bundle
    /// authority and would not validate).
    pub trust_domain: String,
    /// JWKs the bundle's signature is verified against. Cloned once
    /// from disk; reload uses the same set.
    pub jwk_set: JwkSet,
    /// Path the bundle JWS is loaded from. Reload (future) re-reads
    /// from this path. `None` for in-memory bundles created in tests.
    pub source_path: Option<PathBuf>,
}

struct Inner {
    bundle: MappingBundle,
    /// Verbatim JWS Compact Serialization bytes — what we ship out
    /// over Tfetchbundle. Re-encoding is forbidden; the wire format
    /// is the original signed artifact.
    raw_jws: Vec<u8>,
    /// File mtime at the last successful load. Compared against the
    /// current mtime in [`PosixMappingState::maybe_reload`] to skip
    /// re-parsing when nothing has changed. `None` for in-memory
    /// bundles built via [`PosixMappingState::from_parts`].
    loaded_mtime: Option<SystemTime>,
}

impl PosixMappingState {
    /// Load + verify a bundle from disk.
    ///
    /// `bundle_path` points to the JWS Compact-form bytes.
    /// `jwk_set_path` points to the JSON JWK Set (typically a slice
    /// of the SPIFFE trust bundle filtered to mapping-authority keys).
    /// `expected_trust_domain` is the validator's configured trust
    /// domain; a bundle whose `trust_domain` differs is rejected.
    pub fn load_from_files(
        bundle_path: &Path,
        jwk_set_path: &Path,
        expected_trust_domain: &str,
    ) -> Result<Self, BundleLoadError> {
        let jwk_bytes = std::fs::read(jwk_set_path).map_err(|e| {
            BundleLoadError::Io(format!("read JWK Set {}: {e}", jwk_set_path.display()))
        })?;
        let jwk_set = JwkSet::from_json(&jwk_bytes)
            .map_err(|e| BundleLoadError::Auth(format!("parse JWK Set: {e}")))?;

        let raw_jws = std::fs::read(bundle_path).map_err(|e| {
            BundleLoadError::Io(format!("read bundle {}: {e}", bundle_path.display()))
        })?;
        let mtime = std::fs::metadata(bundle_path).ok().and_then(|m| m.modified().ok());

        let now = unix_now();
        let bundle =
            MappingBundle::load_and_verify(&raw_jws, &jwk_set, expected_trust_domain, now)
                .map_err(|e| BundleLoadError::Auth(e.to_string()))?;

        Ok(Self {
            inner: RwLock::new(Inner {
                bundle,
                raw_jws,
                loaded_mtime: mtime,
            }),
            trust_domain: expected_trust_domain.to_string(),
            jwk_set,
            source_path: Some(bundle_path.to_path_buf()),
        })
    }

    /// Construct directly from in-memory artifacts. Used by tests and
    /// any future API that delivers the bundle through a non-file
    /// channel.
    pub fn from_parts(
        bundle: MappingBundle,
        raw_jws: Vec<u8>,
        jwk_set: JwkSet,
    ) -> Self {
        let trust_domain = bundle.trust_domain().to_string();
        Self {
            inner: RwLock::new(Inner {
                bundle,
                raw_jws,
                loaded_mtime: None,
            }),
            trust_domain,
            jwk_set,
            source_path: None,
        }
    }

    /// Look up a SPIFFE ID against the *current* bundle and project
    /// to the shared `PosixIdentity` shape.
    pub fn lookup_posix(&self, spiffe_id: &str) -> Option<p9n_auth::PosixIdentity> {
        self.inner.read().bundle.lookup_posix(spiffe_id)
    }

    /// Snapshot the verbatim JWS bytes for forwarding via Tfetchbundle.
    pub fn raw_jws(&self) -> Vec<u8> {
        self.inner.read().raw_jws.clone()
    }

    pub fn serial(&self) -> u64 {
        self.inner.read().bundle.serial()
    }

    pub fn entry_count(&self) -> usize {
        self.inner.read().bundle.entry_count()
    }

    /// Returns true if `now` (Unix seconds) is at or past the bundle's
    /// `not_after`. Callers may treat an expired bundle as fail-closed.
    pub fn is_expired(&self, now: u64) -> bool {
        self.inner.read().bundle.is_expired(now)
    }

    /// Re-read the bundle file, re-verify against the same JWK Set
    /// and trust domain, and atomically swap into place.
    ///
    /// Returns:
    /// - `Ok(true)` when a fresh bundle was loaded.
    /// - `Ok(false)` when the file's mtime is unchanged since the
    ///   last load — no work done.
    /// - `Err(...)` for any I/O or verification failure. The
    ///   previous bundle remains in place; reload is fail-soft so a
    ///   malformed publication does not take the exporter down.
    ///
    /// In-memory bundles (created via [`Self::from_parts`]) have no
    /// `source_path` and reload is a no-op returning `Ok(false)`.
    ///
    /// This call performs blocking file I/O and signature
    /// verification; callers in async contexts should run it inside
    /// `tokio::task::spawn_blocking`.
    pub fn maybe_reload(&self) -> Result<bool, BundleLoadError> {
        let Some(path) = self.source_path.as_ref() else {
            return Ok(false);
        };

        let new_mtime = std::fs::metadata(path)
            .map_err(|e| BundleLoadError::Io(format!("stat {}: {e}", path.display())))?
            .modified()
            .ok();

        // Skip read+verify when the file is byte-identical (mtime
        // unchanged) to the last load.
        {
            let inner = self.inner.read();
            if new_mtime.is_some() && new_mtime == inner.loaded_mtime {
                return Ok(false);
            }
        }

        let raw_jws = std::fs::read(path)
            .map_err(|e| BundleLoadError::Io(format!("read {}: {e}", path.display())))?;
        let now = unix_now();
        let bundle = MappingBundle::load_and_verify(
            &raw_jws,
            &self.jwk_set,
            &self.trust_domain,
            now,
        )
        .map_err(|e| BundleLoadError::Auth(e.to_string()))?;

        // Reject monotonic regressions: if the new bundle's serial is
        // strictly less than the current one, refuse the swap so that a
        // mistaken older publication can't undo a more recent one.
        // Equal serials are tolerated — operators may re-sign without
        // bumping (e.g. to extend not_after).
        let new_serial = bundle.serial();
        let new_not_after = bundle.not_after();
        let new_entries = bundle.entry_count();
        {
            let inner = self.inner.read();
            let cur_serial = inner.bundle.serial();
            if new_serial < cur_serial {
                return Err(BundleLoadError::Auth(format!(
                    "reload rejected: new serial {new_serial} < current {cur_serial}"
                )));
            }
        }

        let mut inner = self.inner.write();
        inner.bundle = bundle;
        inner.raw_jws = raw_jws;
        inner.loaded_mtime = new_mtime;
        drop(inner);

        tracing::info!(
            trust_domain = %self.trust_domain,
            serial = new_serial,
            entries = new_entries,
            not_after = new_not_after,
            "POSIX mapping bundle reloaded",
        );
        Ok(true)
    }
}

impl std::fmt::Debug for PosixMappingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read();
        f.debug_struct("PosixMappingState")
            .field("trust_domain", &self.trust_domain)
            .field("source_path", &self.source_path)
            .field("serial", &inner.bundle.serial())
            .field("entry_count", &inner.bundle.entry_count())
            .field("not_after", &inner.bundle.not_after())
            .finish()
    }
}

/// Failure to load or verify a bundle at startup. Distinguishes I/O
/// problems (missing file, permission denied) from cryptographic /
/// structural rejection so the operator gets actionable diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum BundleLoadError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("auth error: {0}")]
    Auth(String),
}

impl From<AuthError> for BundleLoadError {
    fn from(e: AuthError) -> Self {
        Self::Auth(e.to_string())
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod reload_tests {
    use super::*;
    use p9n_auth::{BundleEntry, BundlePayload};

    // ── Same fixed test ECDSA P-256 keypair as p9n_auth phase-1 tests.
    const TEST_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiVYWvBoz0W8XhaHR\n\
        tkm7T7YeQlWKukKY4jc4OP4q5lehRANCAAS45NzWr0n5A2m2cv202gana0Eicbva\n\
        XxX60iO/d4jQGZ87lXaHPBch/n8BRR4eAmMDb0HoBdJEI3OZdinuLaYW\n\
        -----END PRIVATE KEY-----\n";
    const TEST_PUB_X: &str = "uOTc1q9J-QNptnL9tNoGp2tBInG72l8V-tIjv3eI0Bk";
    const TEST_PUB_Y: &str = "nzuVdoc8FyH-fwFFHh4CYwNvQegF0kQjc5l2Ke4tphY";
    const TEST_KID: &str = "test-key";

    fn write_jwks(dir: &std::path::Path) -> std::path::PathBuf {
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
        let path = dir.join("jwks.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
        path
    }

    fn sign_bundle(payload: &BundlePayload) -> Vec<u8> {
        let key = jsonwebtoken::EncodingKey::from_ec_pem(TEST_PRIVATE_PEM.as_bytes()).unwrap();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(TEST_KID.into());
        header.typ = Some("p9n-posix-mapping-bundle".into());
        jsonwebtoken::encode(&header, payload, &key).unwrap().into_bytes()
    }

    fn payload(serial: u64, alice_uid: u32) -> BundlePayload {
        BundlePayload {
            version: 1,
            trust_domain: "example.com".into(),
            serial,
            issued_at: 1_000,
            not_after: 9_999_999_999,
            entries: vec![BundleEntry {
                spiffe_id: "spiffe://example.com/workloads/alice".into(),
                uid: alice_uid,
                gid: alice_uid,
                groups: vec![],
                deprecated: false,
                deprecated_since: None,
            }],
        }
    }

    /// Touch a path to advance its mtime past the previous load.
    /// stat resolution on Linux is finer than 1 s, but tests on
    /// some CI filesystems can collapse to 1 s — sleep just enough
    /// to guarantee a strictly later mtime.
    fn write_with_distinct_mtime(path: &std::path::Path, bytes: &[u8]) {
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn in_memory_bundle_reload_is_noop() {
        // from_parts has no source_path; maybe_reload returns Ok(false).
        let p = payload(1, 1_048_577);
        let jws = sign_bundle(&p);
        let jwk_json = serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "kid": TEST_KID, "alg": "ES256",
                "use": "p9n-mapping", "x": TEST_PUB_X, "y": TEST_PUB_Y,
            }]
        });
        let jwks =
            JwkSet::from_json(&serde_json::to_vec(&jwk_json).unwrap()).unwrap();
        let bundle =
            MappingBundle::load_and_verify(&jws, &jwks, "example.com", 1_500).unwrap();
        let state = PosixMappingState::from_parts(bundle, jws, jwks);
        assert_eq!(state.maybe_reload().unwrap(), false);
    }

    #[test]
    fn reload_picks_up_new_serial_on_disk_change() {
        let tmp = tempfile::tempdir().unwrap();
        let jwks_path = write_jwks(tmp.path());
        let bundle_path = tmp.path().join("bundle.jws");

        // v1 on disk
        std::fs::write(&bundle_path, sign_bundle(&payload(1, 1_048_577))).unwrap();
        let state = PosixMappingState::load_from_files(
            &bundle_path, &jwks_path, "example.com",
        )
        .unwrap();
        assert_eq!(state.serial(), 1);
        assert_eq!(
            state.lookup_posix("spiffe://example.com/workloads/alice").unwrap().uid,
            1_048_577,
        );

        // No change → no reload.
        assert_eq!(state.maybe_reload().unwrap(), false);
        assert_eq!(state.serial(), 1);

        // v2 on disk (bump serial AND alice's uid)
        write_with_distinct_mtime(&bundle_path, &sign_bundle(&payload(2, 1_048_999)));
        assert_eq!(state.maybe_reload().unwrap(), true);
        assert_eq!(state.serial(), 2);
        assert_eq!(
            state.lookup_posix("spiffe://example.com/workloads/alice").unwrap().uid,
            1_048_999,
        );
    }

    #[test]
    fn reload_keeps_old_bundle_when_new_one_is_corrupt() {
        let tmp = tempfile::tempdir().unwrap();
        let jwks_path = write_jwks(tmp.path());
        let bundle_path = tmp.path().join("bundle.jws");

        std::fs::write(&bundle_path, sign_bundle(&payload(1, 1_048_577))).unwrap();
        let state = PosixMappingState::load_from_files(
            &bundle_path, &jwks_path, "example.com",
        )
        .unwrap();

        // Corrupt the on-disk bundle (truncate signature).
        let mut corrupt = sign_bundle(&payload(2, 1_048_999));
        corrupt.truncate(corrupt.len() - 5);
        write_with_distinct_mtime(&bundle_path, &corrupt);

        let err = state.maybe_reload().unwrap_err();
        assert!(matches!(err, BundleLoadError::Auth(_)), "{err}");

        // Old bundle remains.
        assert_eq!(state.serial(), 1);
        assert_eq!(
            state.lookup_posix("spiffe://example.com/workloads/alice").unwrap().uid,
            1_048_577,
        );
    }

    #[test]
    fn reload_rejects_serial_regression() {
        let tmp = tempfile::tempdir().unwrap();
        let jwks_path = write_jwks(tmp.path());
        let bundle_path = tmp.path().join("bundle.jws");

        // Start at serial 5.
        std::fs::write(&bundle_path, sign_bundle(&payload(5, 1_048_577))).unwrap();
        let state = PosixMappingState::load_from_files(
            &bundle_path, &jwks_path, "example.com",
        )
        .unwrap();
        assert_eq!(state.serial(), 5);

        // Operator publishes serial 3 by mistake (older copy).
        write_with_distinct_mtime(&bundle_path, &sign_bundle(&payload(3, 1_048_999)));
        let err = state.maybe_reload().unwrap_err();
        assert!(err.to_string().contains("serial"), "{err}");
        // Old bundle preserved.
        assert_eq!(state.serial(), 5);
    }

    #[test]
    fn reload_accepts_equal_serial() {
        // Operators may re-sign with the same serial to extend
        // not_after; this must not be rejected.
        let tmp = tempfile::tempdir().unwrap();
        let jwks_path = write_jwks(tmp.path());
        let bundle_path = tmp.path().join("bundle.jws");

        std::fs::write(&bundle_path, sign_bundle(&payload(7, 1_048_577))).unwrap();
        let state = PosixMappingState::load_from_files(
            &bundle_path, &jwks_path, "example.com",
        )
        .unwrap();

        write_with_distinct_mtime(&bundle_path, &sign_bundle(&payload(7, 1_048_999)));
        assert_eq!(state.maybe_reload().unwrap(), true);
        assert_eq!(state.serial(), 7);
        assert_eq!(
            state.lookup_posix("spiffe://example.com/workloads/alice").unwrap().uid,
            1_048_999,
        );
    }
}
