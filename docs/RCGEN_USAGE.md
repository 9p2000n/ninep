# rcgen Usage for SPIFFE SVID Certificate Generation

## Overview

[rcgen](https://docs.rs/rcgen) is a Rust library for X.509 certificate generation. ninep uses rcgen (`0.13`) as a **dev-dependency** in `p9n-auth` and `p9n-exporter` to generate self-signed SPIFFE X.509-SVID certificates for testing. This document covers how to use rcgen to produce certificates that satisfy SPIFFE SVID requirements.

---

## Dependency Setup

Add rcgen to your `[dev-dependencies]` (or `[dependencies]` if you need runtime generation):

```toml
[dev-dependencies]
rcgen = "0.13"
```

If you also need to convert to rustls types:

```toml
[dev-dependencies]
rcgen = "0.13"
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
```

---

## Core Concepts

### SPIFFE X.509-SVID Requirements

A valid SPIFFE X.509-SVID ([SPIFFE spec](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)) must satisfy:

1. **SPIFFE ID in SAN URI** — The certificate MUST contain exactly one `URI` type Subject Alternative Name with a `spiffe://` URI (e.g., `spiffe://trust-domain/workload/path`)
2. **CA-signed or self-signed** — Leaf certificates are typically signed by a trust domain CA; self-signed is acceptable for testing
3. **Key usage** — Digital signature and key encipherment (rcgen sets reasonable defaults)
4. **No CN reliance** — The SPIFFE ID comes from the SAN, not the Common Name

### rcgen API (v0.13)

| Type | Purpose |
|------|---------|
| `CertificateParams` | Certificate configuration (SAN, CA flag, DN, validity, etc.) |
| `KeyPair` | ECDSA P-256 key pair (default) or RSA |
| `SanType::URI` | URI-type SAN entry for SPIFFE IDs |
| `IsCa::Ca(BasicConstraints::Unconstrained)` | Marks a certificate as a CA |
| `Certificate` | Generated certificate (access DER via `.der()`) |

---

## Recipes

### 1. Self-Signed SVID (Simplest)

For quick tests where you don't need CA chain validation:

```rust
use rcgen::{CertificateParams, KeyPair, SanType};

fn generate_self_signed_svid(spiffe_id: &str) -> (Vec<u8>, Vec<u8>) {
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.subject_alt_names.push(
        SanType::URI(spiffe_id.try_into().unwrap()),
    );

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();
    (cert_der, key_der)
}
```

Usage:

```rust
let (cert_der, key_der) = generate_self_signed_svid(
    "spiffe://example.com/app/worker",
);
```

### 2. CA + Leaf SVID (Chain Validation)

For tests that verify the full X.509 chain — CA signs the leaf, trust store holds the CA:

```rust
use rcgen::{CertificateParams, KeyPair, SanType, IsCa, BasicConstraints, DnType};

fn make_ca_and_leaf(
    trust_domain: &str,
    workload_path: &str,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    // ── Step 1: Generate CA ──
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(
        DnType::CommonName,
        format!("{trust_domain} CA"),
    );
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // ── Step 2: Generate Leaf SVID ──
    let spiffe_id = format!("spiffe://{trust_domain}/{workload_path}");
    let mut leaf_params = CertificateParams::new(vec![]).unwrap();
    leaf_params.subject_alt_names = vec![
        SanType::URI(spiffe_id.parse().unwrap()),
    ];
    leaf_params.distinguished_name.push(
        DnType::CommonName,
        workload_path.to_string(),
    );
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    (
        ca_cert.der().to_vec(),    // CA cert DER (add to trust store)
        leaf_cert.der().to_vec(),  // Leaf cert DER (present in TLS)
        ca_key.serialize_der(),    // CA key (keep for signing more leaves)
        leaf_key.serialize_der(),  // Leaf key (used for TLS handshake)
    )
}
```

Usage with ninep's trust bundle store:

```rust
use p9n_auth::spiffe::trust_bundle::TrustBundleStore;
use p9n_auth::spiffe::chain_verifier;

let (ca_der, leaf_der, _, _) = make_ca_and_leaf("example.com", "app/worker");

let store = TrustBundleStore::new();
store.add("example.com", vec![ca_der]);

let result = chain_verifier::verify_x509_svid(&leaf_der, &store).unwrap();
assert_eq!(result.spiffe_id, "spiffe://example.com/app/worker");
assert_eq!(result.trust_domain, "example.com");
```

### 3. Multiple Workloads Under One CA

Generate one CA, then sign multiple leaf SVIDs for different workloads:

```rust
fn make_multi_workload_certs(trust_domain: &str, workloads: &[&str])
    -> (Vec<u8>, Vec<(String, Vec<u8>, Vec<u8>)>)
{
    // CA (shared)
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(
        DnType::CommonName, format!("{trust_domain} CA"),
    );
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Leaves
    let mut leaves = Vec::new();
    for workload in workloads {
        let spiffe_id = format!("spiffe://{trust_domain}/{workload}");
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.subject_alt_names = vec![
            SanType::URI(spiffe_id.parse().unwrap()),
        ];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &ca_cert, &ca_key).unwrap();
        leaves.push((spiffe_id, cert.der().to_vec(), key.serialize_der()));
    }

    (ca_cert.der().to_vec(), leaves)
}
```

Usage:

```rust
let (ca_der, workloads) = make_multi_workload_certs(
    "prod.example.com",
    &["app/exporter", "app/importer", "app/admin"],
);
// All three workloads share the same CA in the trust store
```

### 4. Convert to rustls Types (for Quinn/QUIC)

ninep's integration tests convert rcgen output to rustls types for QUIC endpoints:

```rust
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn generate_rustls_certs() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.subject_alt_names.push(
        SanType::URI("spiffe://test.local/exporter".try_into().unwrap()),
    );
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    (
        vec![CertificateDer::from(cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
    )
}
```

Then use with Quinn:

```rust
let (certs, key) = generate_rustls_certs();

let server_tls = rustls::ServerConfig::builder()
    .with_no_client_auth()     // or .with_client_cert_verifier() for mTLS
    .with_single_cert(certs, key)
    .unwrap();

let quic_config = quinn::ServerConfig::with_crypto(Arc::new(
    quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
));
```

### 5. Write PEM Files to Disk

For tests that use `SpiffeAuth::from_pem_files()` or for generating development certs:

```rust
use std::fs;

fn write_pem_files(
    cert_path: &str,
    key_path: &str,
    ca_path: &str,
    trust_domain: &str,
    workload: &str,
) {
    let (ca_der, leaf_der, _, leaf_key_der) =
        make_ca_and_leaf(trust_domain, workload);

    // PEM-encode with base64
    let b64 = |der: &[u8]| base64::engine::general_purpose::STANDARD.encode(der);

    let cert_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        b64(&leaf_der),
    );
    let key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        b64(&leaf_key_der),
    );
    let ca_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        b64(&ca_der),
    );

    fs::write(cert_path, cert_pem).unwrap();
    fs::write(key_path, key_pem).unwrap();
    fs::write(ca_path, ca_pem).unwrap();
}
```

> **Note:** For proper PEM line wrapping (76 chars), use `pem` crate or a helper. The simplified version above works with rustls-pemfile but is not strictly RFC 7468 compliant.

### 6. Custom Validity Period

Control certificate expiration for testing rotation and expiry handling:

```rust
use rcgen::CertificateParams;
use time::{OffsetDateTime, Duration};

let mut params = CertificateParams::new(vec![]).unwrap();
params.not_before = OffsetDateTime::now_utc();
params.not_after = OffsetDateTime::now_utc() + Duration::minutes(5); // expires in 5 min

// Use for testing cert rotation, expiry rejection, etc.
```

---

## Integration with ninep Components

### p9n-auth: Chain Verification Testing

```rust
use p9n_auth::spiffe::chain_verifier::verify_x509_svid;
use p9n_auth::spiffe::trust_bundle::TrustBundleStore;

let (ca_der, leaf_der, _, _) = make_ca_and_leaf("myorg.com", "service/api");

let store = TrustBundleStore::new();
store.add("myorg.com", vec![ca_der]);

// Should pass — leaf is signed by the CA in the store
let ok = verify_x509_svid(&leaf_der, &store);
assert!(ok.is_ok());

// Should fail — wrong trust domain
let empty_store = TrustBundleStore::new();
let err = verify_x509_svid(&leaf_der, &empty_store);
assert!(err.is_err());
```

### p9n-auth: SPIFFE ID Extraction

```rust
use p9n_auth::spiffe::x509_svid::{extract_spiffe_id, extract_trust_domain};

let (_, leaf_der, _, _) = make_ca_and_leaf("example.com", "app/reader");
let id = extract_spiffe_id(&leaf_der).unwrap();
assert_eq!(id, "spiffe://example.com/app/reader");

let domain = extract_trust_domain(&id).unwrap();
assert_eq!(domain, "example.com");
```

### p9n-exporter: Full-Stack Integration

See `crates/p9n-exporter/tests/integration_test.rs` for the canonical example — self-signed SVIDs with `SanType::URI` feeding into a Quinn QUIC endpoint, running the full exporter handler stack.

---

## Common Pitfalls

| Pitfall | Fix |
|---------|-----|
| Missing SPIFFE URI in SAN | Always include `SanType::URI("spiffe://...")` — this is what `extract_spiffe_id()` looks for |
| Using CN instead of SAN | SPIFFE spec requires SAN URI; CN is informational only |
| Self-signed leaf in chain verification | `verify_x509_svid()` needs a separate CA cert in the trust store; self-signed leaves fail chain validation |
| DER vs PEM confusion | rcgen produces DER (`.der()`); wrap with PEM headers for file-based loading |
| Expired test certs | Default validity is 1 year from generation; use `not_before`/`not_after` to control |
| Wrong trust domain in store | The trust domain extracted from the leaf's SPIFFE ID must match the key in `TrustBundleStore` |

---

## rcgen vs Production Certificates

| | rcgen (dev/test) | Production (SPIRE) |
|--|--|--|
| **CA** | Self-signed, ephemeral | SPIRE Server upstream CA or external PKI |
| **SVID lifetime** | Default ~1 year | Short-lived (1h default, configurable) |
| **Rotation** | Manual regeneration | Automatic via Workload API |
| **Key storage** | In-memory | Kernel keyring, tmpfs, or Workload API |
| **Trust bundles** | Hardcoded in test | Federated via SPIRE bundle endpoint |
| **Attestation** | None | Node + workload attestation |

For production SPIFFE SVID provisioning, see [SPIRE.md](SPIRE.md).
