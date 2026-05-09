//! Signed POSIX-mapping bundle.
//!
//! Defined in `docs/POSIX_IDENTITY.md`. The bundle binds SPIFFE IDs to
//! POSIX `(uid, gid, groups)` triples for a single trust domain. It is
//! signed by a dedicated mapping-authority key whose public part is
//! published as a JWK with `use="p9n-mapping"` inside the SPIFFE trust
//! bundle's JWK Set.
//!
//! The bundle on the wire is a JWS Compact Serialization with
//! `typ="p9n-posix-mapping-bundle"`. Validation rules are enforced at
//! load time per §3.3 of the design doc.

use crate::error::AuthError;
use crate::spiffe::jwt_svid::{algorithm_from_jwk, decoding_key_from_jwk, JwkSet};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Lower bound of the SPIFFE-reserved POSIX uid/gid range, inclusive.
/// See `docs/POSIX_IDENTITY.md` §4.
pub const SPIFFE_UID_MIN: u32 = 1_048_576; // 2^20

/// Upper bound of the SPIFFE-reserved POSIX uid/gid range, inclusive.
pub const SPIFFE_UID_MAX: u32 = 2_147_483_647;

/// `NGROUPS_MAX` on common Linux distributions; bundle entries are
/// rejected if they list more than this many supplementary groups.
pub const MAX_SUPPLEMENTARY_GROUPS: usize = 64;

/// POSIX identity associated with a SPIFFE workload.
///
/// Returned by [`MappingBundle::lookup_posix`] and stored on the
/// session at connection-accept time. Consumers use this to drive
/// `chown` on file creation and to validate `Tsetattr.uid/gid`
/// against the workload's authoritative ownership (see
/// `docs/POSIX_IDENTITY.md` §7.6, §7.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixIdentity {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

/// JWS `typ` header value for a mapping bundle.
pub const BUNDLE_TYP: &str = "p9n-posix-mapping-bundle";

/// JWK `use` field value identifying a mapping-authority key.
pub const BUNDLE_KEY_USE: &str = "p9n-mapping";

/// Hard ceiling on bundle size in bytes (§3.3).
pub const MAX_BUNDLE_BYTES: usize = 4 * 1024 * 1024;

/// Currently supported bundle schema version.
pub const CURRENT_VERSION: u32 = 1;

/// Decoded bundle payload — the JSON object signed inside the JWS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundlePayload {
    pub version: u32,
    pub trust_domain: String,
    pub serial: u64,
    pub issued_at: u64,
    pub not_after: u64,
    pub entries: Vec<BundleEntry>,
}

/// One workload's POSIX mapping inside a bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleEntry {
    pub spiffe_id: String,
    pub uid: u32,
    pub gid: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<u32>,
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub deprecated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated_since: Option<u64>,
}

/// A loaded, signature-verified, validated, and indexed mapping bundle.
#[derive(Debug, Clone)]
pub struct MappingBundle {
    payload: BundlePayload,
    by_spiffe_id: HashMap<String, usize>,
}

impl MappingBundle {
    /// Verify a JWS-encoded bundle and load it into memory.
    ///
    /// `jws_compact` is the bytes of the JWS Compact Serialization; this
    /// method enforces the size cap before any parsing. `jwk_set` is the
    /// caller's local JWK Set (typically extracted from the SPIFFE trust
    /// bundle); only entries with `use=BUNDLE_KEY_USE` qualify as
    /// verification keys for a mapping bundle. `expected_trust_domain`
    /// is the trust domain the validator has been configured for; a
    /// bundle for a different domain is rejected. `now` is Unix seconds
    /// — used only for the `not_after` check, never trusted from the
    /// payload.
    pub fn load_and_verify(
        jws_compact: &[u8],
        jwk_set: &JwkSet,
        expected_trust_domain: &str,
        now: u64,
    ) -> Result<Self, AuthError> {
        if jws_compact.len() > MAX_BUNDLE_BYTES {
            return Err(invalid(&format!(
                "bundle exceeds {MAX_BUNDLE_BYTES}-byte cap ({} bytes)",
                jws_compact.len()
            )));
        }
        let token = std::str::from_utf8(jws_compact)
            .map_err(|e| invalid(&format!("bundle is not valid UTF-8: {e}")))?;

        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| invalid(&format!("header decode: {e}")))?;

        if header.typ.as_deref() != Some(BUNDLE_TYP) {
            return Err(invalid(&format!(
                "typ mismatch: expected {BUNDLE_TYP}, got {:?}",
                header.typ
            )));
        }

        let kid = header.kid.as_deref().unwrap_or("");
        let jwk = jwk_set
            .find_key(kid)
            .ok_or_else(|| invalid(&format!("no JWK matches kid={kid:?}")))?;

        if jwk.use_.as_deref() != Some(BUNDLE_KEY_USE) {
            return Err(invalid(&format!(
                "JWK kid={:?} not authorized for {BUNDLE_KEY_USE} (use={:?})",
                jwk.kid, jwk.use_
            )));
        }

        let key = decoding_key_from_jwk(jwk)?;
        let alg = algorithm_from_jwk(jwk)?;

        // Reject HS-* up front: mapping bundles MUST be signed asymmetrically.
        // The mapping authority's private key never reaches a verifier, so a
        // shared-secret algorithm violates the trust model.
        if matches!(
            alg,
            jsonwebtoken::Algorithm::HS256
                | jsonwebtoken::Algorithm::HS384
                | jsonwebtoken::Algorithm::HS512
        ) {
            return Err(invalid("HMAC algorithms are not permitted for mapping bundles"));
        }

        // Verify signature only; we run our own structural validation.
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.required_spec_claims = HashSet::new();
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.validate_nbf = false;

        let decoded = jsonwebtoken::decode::<BundlePayload>(token, &key, &validation)
            .map_err(|e| invalid(&format!("signature/payload decode: {e}")))?;
        let payload = decoded.claims;

        validate_payload(&payload, expected_trust_domain, now)?;

        let mut by_spiffe_id = HashMap::with_capacity(payload.entries.len());
        for (i, e) in payload.entries.iter().enumerate() {
            if by_spiffe_id.insert(e.spiffe_id.clone(), i).is_some() {
                return Err(invalid(&format!(
                    "duplicate entry for spiffe_id {}",
                    e.spiffe_id
                )));
            }
        }

        Ok(MappingBundle { payload, by_spiffe_id })
    }

    /// Look up a workload's raw bundle entry.
    pub fn lookup(&self, spiffe_id: &str) -> Option<&BundleEntry> {
        let idx = *self.by_spiffe_id.get(spiffe_id)?;
        Some(&self.payload.entries[idx])
    }

    /// Look up a workload and project the result to a `PosixIdentity`
    /// suitable for storing on a session and feeding into `chown`,
    /// wire-gid validation, and `Tsetattr` owner checks.
    pub fn lookup_posix(&self, spiffe_id: &str) -> Option<PosixIdentity> {
        let entry = self.lookup(spiffe_id)?;
        Some(PosixIdentity {
            uid: entry.uid,
            gid: entry.gid,
            groups: entry.groups.clone(),
        })
    }

    pub fn serial(&self) -> u64 { self.payload.serial }
    pub fn issued_at(&self) -> u64 { self.payload.issued_at }
    pub fn not_after(&self) -> u64 { self.payload.not_after }
    pub fn trust_domain(&self) -> &str { &self.payload.trust_domain }
    pub fn entry_count(&self) -> usize { self.payload.entries.len() }
    pub fn is_expired(&self, now: u64) -> bool { self.payload.not_after <= now }
}

fn validate_payload(
    payload: &BundlePayload,
    expected_trust_domain: &str,
    now: u64,
) -> Result<(), AuthError> {
    if payload.version != CURRENT_VERSION {
        return Err(invalid(&format!(
            "unsupported bundle version: {}",
            payload.version
        )));
    }
    if payload.trust_domain != expected_trust_domain {
        return Err(invalid(&format!(
            "trust_domain mismatch: bundle={}, expected={}",
            payload.trust_domain, expected_trust_domain
        )));
    }
    if payload.not_after <= now {
        return Err(invalid(&format!(
            "bundle expired: not_after={}, now={}",
            payload.not_after, now
        )));
    }

    let trust_domain_prefix = format!("spiffe://{}/", payload.trust_domain);
    let mut seen_uids: HashSet<u32> = HashSet::with_capacity(payload.entries.len());

    for e in &payload.entries {
        if !e.spiffe_id.starts_with(&trust_domain_prefix) {
            return Err(invalid(&format!(
                "entry spiffe_id={} not in trust_domain={}",
                e.spiffe_id, payload.trust_domain
            )));
        }
        check_range("uid", e.uid)?;
        check_range("gid", e.gid)?;
        if e.groups.len() > MAX_SUPPLEMENTARY_GROUPS {
            return Err(invalid(&format!(
                "entry {} has {} supplementary groups, max is {MAX_SUPPLEMENTARY_GROUPS}",
                e.spiffe_id,
                e.groups.len()
            )));
        }
        for g in &e.groups {
            check_range("group", *g)?;
        }
        if !e.deprecated && !seen_uids.insert(e.uid) {
            return Err(invalid(&format!(
                "duplicate uid {} among non-deprecated entries",
                e.uid
            )));
        }
    }
    Ok(())
}

fn check_range(name: &str, value: u32) -> Result<(), AuthError> {
    if !(SPIFFE_UID_MIN..=SPIFFE_UID_MAX).contains(&value) {
        return Err(invalid(&format!(
            "{name} {value} outside SPIFFE range [{SPIFFE_UID_MIN}, {SPIFFE_UID_MAX}]"
        )));
    }
    Ok(())
}

fn invalid(msg: &str) -> AuthError {
    AuthError::Jwt(format!("posix-mapping bundle: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spiffe::jwt_svid::Jwk;

    // ── Test fixture: a fixed ECDSA P-256 keypair generated with
    // ── `openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`.
    // ── The x/y coordinates are extracted from the public key DER.
    // ── This keypair is for unit testing only — never reuse in production.
    const TEST_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiVYWvBoz0W8XhaHR\n\
        tkm7T7YeQlWKukKY4jc4OP4q5lehRANCAAS45NzWr0n5A2m2cv202gana0Eicbva\n\
        XxX60iO/d4jQGZ87lXaHPBch/n8BRR4eAmMDb0HoBdJEI3OZdinuLaYW\n\
        -----END PRIVATE KEY-----\n";
    const TEST_PUB_X: &str = "uOTc1q9J-QNptnL9tNoGp2tBInG72l8V-tIjv3eI0Bk";
    const TEST_PUB_Y: &str = "nzuVdoc8FyH-fwFFHh4CYwNvQegF0kQjc5l2Ke4tphY";
    const TEST_KID: &str = "test-key-1";

    fn signer_jwk(use_: Option<&str>) -> Jwk {
        Jwk {
            kty: "EC".into(),
            kid: TEST_KID.into(),
            alg: Some("ES256".into()),
            use_: use_.map(str::to_string),
            n: None,
            e: None,
            crv: Some("P-256".into()),
            x: Some(TEST_PUB_X.into()),
            y: Some(TEST_PUB_Y.into()),
        }
    }

    fn signer_jwk_set(use_: Option<&str>) -> JwkSet {
        JwkSet { keys: vec![signer_jwk(use_)] }
    }

    fn sign(payload: &BundlePayload) -> Vec<u8> {
        sign_with_typ(payload, BUNDLE_TYP, TEST_KID)
    }

    fn sign_with_typ(payload: &BundlePayload, typ: &str, kid: &str) -> Vec<u8> {
        let key = jsonwebtoken::EncodingKey::from_ec_pem(TEST_PRIVATE_PEM.as_bytes())
            .expect("test EC private key parses");
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(kid.to_string());
        header.typ = Some(typ.to_string());
        jsonwebtoken::encode(&header, payload, &key)
            .expect("test sign succeeds")
            .into_bytes()
    }

    fn good_payload() -> BundlePayload {
        BundlePayload {
            version: 1,
            trust_domain: "example.com".into(),
            serial: 1,
            issued_at: 1_000,
            not_after: 1_000_000,
            entries: vec![
                BundleEntry {
                    spiffe_id: "spiffe://example.com/workloads/alice".into(),
                    uid: 1_048_577,
                    gid: 1_048_577,
                    groups: vec![1_048_577, 2_097_152],
                    deprecated: false,
                    deprecated_since: None,
                },
                BundleEntry {
                    spiffe_id: "spiffe://example.com/workloads/bob".into(),
                    uid: 1_048_578,
                    gid: 1_048_578,
                    groups: vec![],
                    deprecated: false,
                    deprecated_since: None,
                },
            ],
        }
    }

    #[test]
    fn loads_and_verifies_a_well_formed_bundle() {
        let p = good_payload();
        let jws = sign(&p);
        let bundle = MappingBundle::load_and_verify(
            &jws,
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .expect("verify succeeds");
        assert_eq!(bundle.entry_count(), 2);
        assert_eq!(bundle.serial(), 1);
        assert_eq!(bundle.trust_domain(), "example.com");
    }

    #[test]
    fn lookup_returns_entry_for_known_spiffe_id() {
        let bundle = MappingBundle::load_and_verify(
            &sign(&good_payload()),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap();
        let alice = bundle.lookup("spiffe://example.com/workloads/alice").unwrap();
        assert_eq!(alice.uid, 1_048_577);
        assert_eq!(alice.gid, 1_048_577);
        assert_eq!(alice.groups, vec![1_048_577, 2_097_152]);
    }

    #[test]
    fn lookup_posix_projects_to_posix_identity() {
        let bundle = MappingBundle::load_and_verify(
            &sign(&good_payload()),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap();
        let id = bundle
            .lookup_posix("spiffe://example.com/workloads/bob")
            .unwrap();
        assert_eq!(id.uid, 1_048_578);
        assert_eq!(id.gid, 1_048_578);
        assert!(id.groups.is_empty());
    }

    #[test]
    fn lookup_returns_none_for_unknown_spiffe_id() {
        let bundle = MappingBundle::load_and_verify(
            &sign(&good_payload()),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap();
        assert!(bundle.lookup("spiffe://example.com/nope").is_none());
    }

    #[test]
    fn rejects_oversized_bundle() {
        let huge = vec![b'A'; MAX_BUNDLE_BYTES + 1];
        let err = MappingBundle::load_and_verify(
            &huge,
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn rejects_typ_mismatch() {
        let p = good_payload();
        let jws = sign_with_typ(&p, "JWT", TEST_KID);
        let err = MappingBundle::load_and_verify(
            &jws,
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("typ mismatch"), "{err}");
    }

    #[test]
    fn rejects_unknown_kid() {
        let p = good_payload();
        let jws = sign_with_typ(&p, BUNDLE_TYP, "rogue-kid");
        let err = MappingBundle::load_and_verify(
            &jws,
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no JWK"), "{err}");
    }

    #[test]
    fn rejects_jwk_without_p9n_mapping_use() {
        let p = good_payload();
        let jws = sign(&p);
        let err = MappingBundle::load_and_verify(
            &jws,
            &signer_jwk_set(None),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not authorized"), "{err}");
    }

    #[test]
    fn rejects_jwk_with_wrong_use() {
        let p = good_payload();
        let jws = sign(&p);
        let err = MappingBundle::load_and_verify(
            &jws,
            &signer_jwk_set(Some("sig")),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not authorized"), "{err}");
    }

    #[test]
    fn rejects_expired_bundle() {
        let mut p = good_payload();
        p.not_after = 100;
        let err = MappingBundle::load_and_verify(
            &sign(&p),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn rejects_trust_domain_mismatch() {
        let p = good_payload();
        let err = MappingBundle::load_and_verify(
            &sign(&p),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "other.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("trust_domain mismatch"), "{err}");
    }

    #[test]
    fn rejects_entry_outside_trust_domain() {
        let mut p = good_payload();
        p.entries[0].spiffe_id = "spiffe://other.com/workloads/alice".into();
        let err = MappingBundle::load_and_verify(
            &sign(&p),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not in trust_domain"), "{err}");
    }

    #[test]
    fn rejects_uid_below_spiffe_range() {
        let mut p = good_payload();
        p.entries[0].uid = 1000;
        let err = MappingBundle::load_and_verify(
            &sign(&p),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("uid 1000"), "{err}");
    }

    #[test]
    fn rejects_uid_above_spiffe_range() {
        let mut p = good_payload();
        p.entries[0].uid = u32::MAX;
        let err = MappingBundle::load_and_verify(
            &sign(&p),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("outside SPIFFE range"), "{err}");
    }

    #[test]
    fn rejects_supplementary_group_outside_range() {
        let mut p = good_payload();
        p.entries[0].groups = vec![1_048_577, 50];
        let err = MappingBundle::load_and_verify(
            &sign(&p),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("group 50"), "{err}");
    }

    #[test]
    fn rejects_too_many_supplementary_groups() {
        let mut p = good_payload();
        p.entries[0].groups = (0..(MAX_SUPPLEMENTARY_GROUPS + 1) as u32)
            .map(|i| SPIFFE_UID_MIN + i)
            .collect();
        let err = MappingBundle::load_and_verify(
            &sign(&p),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("supplementary groups"), "{err}");
    }

    #[test]
    fn rejects_duplicate_uid_among_non_deprecated() {
        let mut p = good_payload();
        p.entries[1].uid = p.entries[0].uid;
        let err = MappingBundle::load_and_verify(
            &sign(&p),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate uid"), "{err}");
    }

    #[test]
    fn allows_deprecated_uid_collision_with_active() {
        // A tombstoned entry sharing a uid with an active entry must be
        // permitted: that's how operator-controlled retirement works.
        let mut p = good_payload();
        p.entries.push(BundleEntry {
            spiffe_id: "spiffe://example.com/workloads/alice-old".into(),
            uid: p.entries[0].uid,
            gid: p.entries[0].gid,
            groups: vec![],
            deprecated: true,
            deprecated_since: Some(900),
        });
        let bundle = MappingBundle::load_and_verify(
            &sign(&p),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .expect("verify succeeds");
        assert_eq!(bundle.entry_count(), 3);
    }

    #[test]
    fn rejects_duplicate_spiffe_id() {
        let mut p = good_payload();
        p.entries[1].spiffe_id = p.entries[0].spiffe_id.clone();
        // Different uids so the uid-uniqueness check doesn't fire first.
        let err = MappingBundle::load_and_verify(
            &sign(&p),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut p = good_payload();
        p.version = 99;
        let err = MappingBundle::load_and_verify(
            &sign(&p),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported bundle version"), "{err}");
    }

    #[test]
    fn rejects_signature_under_different_key() {
        // Sign with the test key, then verify with a JWK whose x/y are
        // truncated/garbled: signature check must fail.
        let p = good_payload();
        let jws = sign(&p);
        let mut bad = signer_jwk_set(Some(BUNDLE_KEY_USE));
        // Corrupt the y coord.
        bad.keys[0].y = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
        let err =
            MappingBundle::load_and_verify(&jws, &bad, "example.com", 500).unwrap_err();
        assert!(
            err.to_string().contains("signature/payload decode")
                || err.to_string().contains("EC key"),
            "{err}"
        );
    }

    #[test]
    fn is_expired_reflects_now_relative_to_not_after() {
        let bundle = MappingBundle::load_and_verify(
            &sign(&good_payload()),
            &signer_jwk_set(Some(BUNDLE_KEY_USE)),
            "example.com",
            500,
        )
        .unwrap();
        assert!(!bundle.is_expired(500));
        assert!(!bundle.is_expired(999_999));
        assert!(bundle.is_expired(1_000_000));
        assert!(bundle.is_expired(2_000_000));
    }

    #[test]
    fn payload_round_trips_through_json() {
        let p = good_payload();
        let json = serde_json::to_vec(&p).unwrap();
        let p2: BundlePayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(p, p2);
    }
}
