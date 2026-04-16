//! Tests for SPIFFE authentication: cert generation, JWT-SVID, trust bundles.

use p9n_auth::spiffe::jwt_svid;

// ── JWT-SVID Capability Token Tests ──

#[test]
fn test_cap_token_encode_decode() {
    let key = [0x42u8; 32];
    let token = jwt_svid::encode_cap_token(
        &key,
        "spiffe://example.com/app/reader",
        "spiffe://example.com/server",
        0x03, // READ | WRITE
        10,   // depth
        u64::MAX / 2, // far future expiry
    )
    .expect("encode failed");

    assert!(!token.is_empty());
    assert!(token.contains('.')); // JWT format: header.payload.signature

    let result = jwt_svid::verify_cap_token(
        &key,
        &token,
        "spiffe://example.com/app/reader",
        "spiffe://example.com/server",
    )
    .expect("verify failed");

    assert_eq!(result.spiffe_id, "spiffe://example.com/app/reader");
    assert_eq!(result.p9n_rights, Some(0x03));
    assert_eq!(result.p9n_depth, Some(10));
}

#[test]
fn test_cap_token_wrong_key_rejected() {
    let key1 = [0x42u8; 32];
    let key2 = [0x99u8; 32]; // different key

    let token = jwt_svid::encode_cap_token(
        &key1,
        "spiffe://a.com/app",
        "spiffe://a.com/srv",
        0xFF, 0,
        u64::MAX / 2,
    )
    .expect("encode failed");

    let result = jwt_svid::verify_cap_token(
        &key2, // wrong key
        &token,
        "spiffe://a.com/app",
        "spiffe://a.com/srv",
    );

    assert!(result.is_err());
}

#[test]
fn test_cap_token_subject_mismatch_rejected() {
    let key = [0x42u8; 32];

    let token = jwt_svid::encode_cap_token(
        &key,
        "spiffe://a.com/alice",
        "spiffe://a.com/srv",
        0xFF, 0,
        u64::MAX / 2,
    )
    .expect("encode failed");

    let result = jwt_svid::verify_cap_token(
        &key,
        &token,
        "spiffe://a.com/bob", // different subject
        "spiffe://a.com/srv",
    );

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("mismatch"), "error should mention mismatch: {err}");
}

#[test]
fn test_cap_token_expired_rejected() {
    let key = [0x42u8; 32];

    let token = jwt_svid::encode_cap_token(
        &key,
        "spiffe://a.com/app",
        "spiffe://a.com/srv",
        0x01, 0,
        1, // expired: Unix epoch + 1 second
    )
    .expect("encode failed");

    let result = jwt_svid::verify_cap_token(
        &key,
        &token,
        "spiffe://a.com/app",
        "spiffe://a.com/srv",
    );

    assert!(result.is_err());
}

#[test]
fn test_extract_spiffe_id_from_jwt() {
    let key = [0x42u8; 32];
    let token = jwt_svid::encode_cap_token(
        &key,
        "spiffe://test.org/workload/api",
        "spiffe://test.org/server",
        0xFF, 5,
        u64::MAX / 2,
    )
    .expect("encode failed");

    let id = jwt_svid::extract_spiffe_id_from_jwt(&token).expect("extract failed");
    assert_eq!(id, "spiffe://test.org/workload/api");
}

// ── JWK Set Tests ──

#[test]
fn test_jwk_set_parse() {
    let json = br#"{
        "keys": [
            {
                "kty": "RSA",
                "kid": "key-1",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB"
            }
        ]
    }"#;

    let jwk_set = jwt_svid::JwkSet::from_json(json).expect("parse failed");
    assert_eq!(jwk_set.keys.len(), 1);
    assert_eq!(jwk_set.keys[0].kty, "RSA");
    assert_eq!(jwk_set.keys[0].kid, "key-1");

    let found = jwk_set.find_key("key-1");
    assert!(found.is_some());
    assert!(jwk_set.find_key("nonexistent").is_none());

    // Empty kid matches first key
    let first = jwk_set.find_key("");
    assert!(first.is_some());
}

// ── Trust Bundle Tests ──

#[test]
fn test_trust_bundle_store() {
    use p9n_auth::spiffe::trust_bundle::TrustBundleStore;

    let store = TrustBundleStore::new();
    assert!(!store.has("example.com"));

    // Add a fake DER cert
    store.add("example.com", vec![vec![0x30, 0x82, 0x01]]);
    assert!(store.has("example.com"));
    assert!(!store.has("other.com"));

    let certs = store.get("example.com").expect("should exist");
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0], vec![0x30, 0x82, 0x01]);

    assert_eq!(store.domains().len(), 1);
}

// ── X.509 Chain Verification ──

fn make_test_ca_and_leaf(
    domain: &str,
    workload: &str,
) -> (Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, KeyPair, SanType};

    // Generate CA
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("{domain} CA"),
    );
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Generate leaf with SPIFFE SAN URI
    let spiffe_id = format!("spiffe://{domain}/{workload}");
    let mut leaf_params = CertificateParams::new(vec![]).unwrap();
    leaf_params.subject_alt_names = vec![SanType::URI(spiffe_id.parse().unwrap())];
    leaf_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        workload.to_string(),
    );
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    (ca_cert.der().to_vec(), leaf_cert.der().to_vec())
}

#[test]
fn test_chain_verify_valid_cert() {
    use p9n_auth::spiffe::chain_verifier;
    use p9n_auth::spiffe::trust_bundle::TrustBundleStore;

    let (ca_der, leaf_der) = make_test_ca_and_leaf("example.com", "app/worker");

    let store = TrustBundleStore::new();
    store.add("example.com", vec![ca_der]);

    let result = chain_verifier::verify_x509_svid(&leaf_der, &store)
        .expect("chain verification should succeed");

    assert_eq!(result.spiffe_id, "spiffe://example.com/app/worker");
    assert_eq!(result.trust_domain, "example.com");
    assert!(result.not_after > 0);
}

#[test]
fn test_chain_verify_unknown_domain() {
    use p9n_auth::spiffe::chain_verifier;
    use p9n_auth::spiffe::trust_bundle::TrustBundleStore;

    let (_, leaf_der) = make_test_ca_and_leaf("unknown.com", "app");

    let store = TrustBundleStore::new(); // empty store

    let err = chain_verifier::verify_x509_svid(&leaf_der, &store)
        .expect_err("should fail for unknown domain");
    assert!(
        err.to_string().contains("untrusted"),
        "error should mention untrusted: {err}"
    );
}

#[test]
fn test_chain_verify_wrong_ca() {
    use p9n_auth::spiffe::chain_verifier;
    use p9n_auth::spiffe::trust_bundle::TrustBundleStore;

    // Leaf signed by CA-A, but store has CA-B
    let (_, leaf_der) = make_test_ca_and_leaf("example.com", "app");
    let (other_ca_der, _) = make_test_ca_and_leaf("example.com", "other");

    let store = TrustBundleStore::new();
    store.add("example.com", vec![other_ca_der]); // wrong CA

    let err = chain_verifier::verify_x509_svid(&leaf_der, &store)
        .expect_err("should fail with wrong CA");
    assert!(
        err.to_string().contains("chain verification failed"),
        "error should mention chain verification: {err}"
    );
}

// ── SPIFFE ID Extraction ──

#[test]
fn test_extract_trust_domain() {
    use p9n_auth::spiffe::x509_svid::extract_trust_domain;

    assert_eq!(extract_trust_domain("spiffe://example.com/app").unwrap(), "example.com");
    assert_eq!(extract_trust_domain("spiffe://a.b.c/x/y/z").unwrap(), "a.b.c");
    assert!(extract_trust_domain("https://example.com").is_err());
    assert!(extract_trust_domain("not-a-uri").is_err());
}

// ── TrustBundleStore lock hardening ──
//
// After the switch to parking_lot, a panic that unwinds while a writer
// holds the lock must not prevent subsequent readers/writers from
// acquiring it. std::sync::RwLock would poison the lock and panic
// every subsequent caller.

#[test]
fn test_trust_store_survives_writer_panic() {
    use p9n_auth::spiffe::trust_bundle::TrustBundleStore;

    let store = std::sync::Arc::new(TrustBundleStore::new());
    store.add("example.com", vec![vec![0u8; 4]]);

    // Spawn a thread that panics *after* mutating the store.
    let s = store.clone();
    let handle = std::thread::spawn(move || {
        s.add("poison.test", vec![vec![1u8; 4]]);
        panic!("simulated writer panic");
    });
    assert!(handle.join().is_err(), "writer thread should have panicked");

    // The lock must still be usable from this thread.
    assert!(store.has("example.com"));
    assert!(store.has("poison.test"));
    store.add("after.panic", vec![vec![2u8; 4]]);
    assert!(store.has("after.panic"));
}

#[test]
fn test_trust_store_concurrent_readers_writers() {
    use p9n_auth::spiffe::trust_bundle::TrustBundleStore;

    let store = std::sync::Arc::new(TrustBundleStore::new());
    let mut handles = Vec::new();
    for i in 0..8 {
        let s = store.clone();
        handles.push(std::thread::spawn(move || {
            for j in 0..50 {
                let td = format!("dom{i}.{j}.test");
                s.add(&td, vec![vec![i as u8; 4]]);
                assert!(s.has(&td));
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(store.domains().len(), 8 * 50);
}
