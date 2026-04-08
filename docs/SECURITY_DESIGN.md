# Security Architecture

## Overview

ninep implements a 9-layer security model built on SPIFFE workload identity. Every connection is mutually authenticated via X.509-SVIDs over QUIC/TLS 1.3, every file operation is authorized against per-identity access policies, and file ownership maps to configured Linux uid/gid per SPIFFE identity.

---

## Authentication & Authorization Flow

### 1. Connection Establishment (TLS Layer)

For RDMA transport, the same TLS authentication occurs during the TCP+TLS bootstrap phase before RDMA QP exchange (see RDMA Authentication below).

```
Importer                          QUIC/TLS                         Exporter
  │                                   │                               │
  │═════════════ QUIC Handshake (TLS 1.3 mTLS) ═══════════════════════│
  │                                   │                               │
  │ ClientHello + X.509-SVID cert ───►│                               │
  │ (SAN: spiffe://a.com/app/reader)  │                               │
  │                                   │──► rustls WebPkiClientVerifier│
  │                                   │    validate cert chain → CA   │
  │                                   │                               │
  │◄── ServerHello + X.509-SVID cert──│◄── validation passed          │
  │    (SAN: spiffe://b.com/export)   │                               │
  │                                   │                               │
  │══════════ QUIC Connection Up ═════╪═══════════════════════════════│
  │                                   │                               │
  │                                   │    extract_spiffe_id_from_conn()
  │                                   │    ├─ conn.peer_identity()
  │                                   │    ├─ x509_parser: extract SAN URI
  │                                   │    └─ session.spiffe_id =
  │                                   │       "spiffe://a.com/app/reader"
```

**Source**: `connection.rs` → `extract_spiffe_id_from_conn()`

Both sides must present valid X.509-SVIDs signed by a trusted CA. The exporter extracts the client's SPIFFE ID from the TLS peer certificate and stores it immutably in the session for the connection lifetime.

### 2. Protocol Negotiation

```
Importer                                                    Exporter
  │                                                           │
  │── Tversion { msize:65536, "9P2000.N" } ──────────────────►│
  │◄── Rversion { msize:65536, "9P2000.N" } ──────────────────│
  │                                                           │
  │── Tcaps { ["security.spiffe", "dist.session",             │
  │            "fs.watch", "perf.compound"] } ───────────────►│
  │                                                           │  intersect(client, server)
  │◄── Rcaps { ["security.spiffe", "dist.session"] } ─────────│
  │                                                           │
  │── TstartlsSpiffe {                                        │
  │     spiffe_id: "spiffe://a.com/app/reader",               │
  │     trust_domain: "a.com" } ─────────────────────────────►│
  │                                                           │  ① Compare declared ID with TLS cert ID
  │                                                           │     "spiffe://a.com/app/reader"
  │                                                           │     == session.spiffe_id ✓
  │                                                           │  ② session.set_spiffe_verified(true)
  │◄── RstartlsSpiffe {                                       │
  │     spiffe_id: "spiffe://b.com/export",                   │
  │     trust_domain: "b.com" } ──────────────────────────────│
  │                                                           │
  │  (importer verifies exporter's declared ID                │
  │   matches its TLS certificate)                            │
```

**Source**: `handlers/negotiate.rs`, `handlers/spiffe.rs`

TstartlsSpiffe provides application-layer identity confirmation. The declared SPIFFE ID must match the one extracted from the TLS certificate; a mismatch returns EPERM.

### 3. Session Establishment (TLS-Derived Key)

```
Importer                                                    Exporter
  │                                                           │
  │  derive key from TLS:                                     │
  │  conn.export_keying_material(                             │
  │    "9P2000.N session") → K                                │
  │                                                           │
  │── Tsession { key: K, flags: FIDS|WATCHES } ──────────────►│
  │                                                           │  ① session already has key? → EEXIST
  │                                                           │  ② key == [0;16]? → EINVAL
  │                                                           │  ③ session_store[spiffe_id].get(K)?
  │                                                           │     → not found → new session
  │                                                           │  ④ session.set_session_key(K)
  │◄── Rsession { flags: FIDS|WATCHES } ──────────────────────│
```

**Source**: `importer.rs:derive_session_key()`, `handlers/session.rs`

Session keys are derived from TLS 1.3 keying material via RFC 5705 `export_keying_material`. This guarantees:
- **Cryptographic security** — derived from TLS master secret, not predictable
- **Uniqueness** — each TLS session produces a different key
- **No transmission** — both sides derive the same key independently
- **One per connection** — duplicate Tsession on the same connection is rejected

### 4. Filesystem Root Isolation (Tattach)

```
Importer                                                    Exporter
  │                                                           │
  │── Tattach { fid:0, uname:"reader", aname:"" } ───────────►│
  │                                                           │  AccessControl.resolve_root(spiffe_id):
  │                                                           │  ┌─ by_id["spiffe://a.com/app/reader"]?
  │                                                           │  │  → no match
  │                                                           │  ├─ by_domain["a.com"]?
  │                                                           │  │  → match (isolation enabled)
  │                                                           │  └─ extract workload path:
  │                                                           │     "spiffe://a.com/app/reader"
  │                                                           │     → workload = "app/reader"
  │                                                           │     → root = /srv/export/app/reader/
  │                                                           │     → mkdir -p if not exists
  │                                                           │
  │                                                           │  fids.insert(0, FidState {
  │                                                           │    path: "/srv/export/app/reader/",
  │                                                           │    is_dir: true, ...
  │                                                           │  })
  │◄── Rattach { qid } ───────────────────────────────────────│
```

**Source**: `handlers/attach.rs`, `access.rs`

The filesystem root is determined by the peer's SPIFFE ID through a 3-level policy lookup:

1. **Exact SPIFFE ID match** — `by_id["spiffe://a.com/app/reader"]`
2. **Trust domain match** — `by_domain["a.com"]` with workload path derivation
3. **Default policy** — shared export root

When domain-level isolation is enabled, each SPIFFE workload path maps to an isolated subdirectory automatically.

### 5. Per-Request Permission Check

```
  Incoming request (e.g., Twrite { fid:5, data:... })
       │
       ▼
  dispatch() in handlers/mod.rs
       │
       ├─ sid = session.spiffe_id = "spiffe://a.com/app/reader"
       ├─ msg_fid = fid_from_msg(&fc) = Some(5)
       │
       └─ check_perm(session, access, sid, fid, PERM_WRITE)?
            │
            ▼
     ┌───────────────────────────────────────────────┐
     │ Layer 1: Static Policy                        │
     │                                               │
     │  AccessControl.check(sid, PERM_WRITE)         │
     │  ├─ resolve("spiffe://a.com/app/reader")      │
     │  │   → by_domain["a.com"] → policy            │
     │  └─ policy.permissions & PERM_WRITE?          │
     │     → 0x07 & 0x02 = 0x02 ✓ → Ok               │
     │                                               │
     │ Layer 2: Dynamic Capability Token (fallback)  │
     │                                               │
     │  session.check_cap(fid=5, PERM_WRITE)         │
     │  ├─ active_caps.get(5)?                       │
     │  │   → CapToken { rights:0x03, expiry:... }   │
     │  ├─ now < expiry? ✓                           │
     │  └─ rights & PERM_WRITE ≠ 0? ✓ → true         │
     └───────────────────────────────────────────────┘
```

**Source**: `handlers/mod.rs:check_perm()`, `access.rs:check()`, `session.rs:check_cap()`

Every file operation is gated by a two-layer permission check:

1. **Static policy** based on SPIFFE ID (configured at startup)
2. **Dynamic capability token** based on per-fid JWT tokens (granted at runtime via Tcapgrant)

Additional checks for privileged operations:
- `chown`/`chgrp` in Tsetattr requires `PERM_ADMIN` (`access.rs:check_admin()`)
- Twalk checks depth limit via `access.rs:check_depth()`

### 6. Capability Token Grant & Use

```
Importer                                                    Exporter
  │                                                           │
  │ (base permissions = READ only, wants WRITE)               │
  │                                                           │
  │── Tcapgrant { fid:5, rights:0x03,                         │
  │               expiry:now+3600, depth:10 } ───────────────►│
  │                                                           │  ① Look up max allowed by SPIFFE policy
  │                                                           │     policy.permissions = 0x07
  │                                                           │  ② granted = 0x03 & 0x07 = 0x03
  │                                                           │     (cannot exceed policy ceiling)
  │                                                           │  ③ Sign JWT (HS256, server HMAC key):
  │                                                           │     { sub: "spiffe://a.com/app/reader",
  │                                                           │       aud: "spiffe://b.com/export",
  │                                                           │       p9n_rights: 0x03,
  │                                                           │       p9n_depth: 10,
  │                                                           │       exp: now+3600 }
  │◄── Rcapgrant { token: "eyJhbGciOi..." } ──────────────────│
  │                                                           │
  │── Tcapuse { fid:5, token: "eyJhbGciOi..." } ─────────────►│
  │                                                           │  ① Verify JWT signature + expiry
  │                                                           │  ② JWT.sub == session.spiffe_id? ✓
  │                                                           │     (prevents token transfer)
  │                                                           │  ③ Store: session.active_caps[fid:5]
  │◄── Rcapuse { qid } ───────────────────────────────────────│
  │                                                           │
  │── Twrite { fid:5, data:... } ────────────────────────────►│
  │                                                           │  check_perm:
  │                                                           │    ① Static policy: WRITE? → may fail
  │                                                           │    ② Cap token: rights & WRITE ✓
  │◄── Rwrite { count } ──────────────────────────────────────│
```

**Source**: `handlers/capgrant.rs`, `jwt_svid.rs:encode_cap_token()`/`verify_cap_token()`

Capability tokens are HMAC-SHA256 signed JWTs that:
- Are scoped to a specific SPIFFE ID (`sub` claim, non-transferable)
- Cannot exceed the static policy permissions ceiling
- Have an expiry time (capped at 24 hours)
- Include optional `p9n_rights` and `p9n_depth` custom claims

### 7. File Ownership Mapping (SPIFFE → Linux uid/gid)

```
  Policy { uid: 1001, gid: 1001, permissions: PERM_ALL }
       │  (configured per SPIFFE ID or trust domain)
       │
       ▼
  Tlcreate / Tmkdir / Tsymlink / Tmknod
       │
       ├─ File created (owned by exporter process uid)
       │
       ├─ ac.apply_ownership(spiffe_id, path):
       │   ├─ resolve(spiffe_id) → policy
       │   ├─ policy.uid == 0 && gid == 0? → skip (no mapping)
       │   └─ nix::unistd::chown(path, uid:1001, gid:1001)
       │
       └─ File now owned by uid:1001, gid:1001
```

**Source**: `access.rs:apply_ownership()`, called from `handlers/create.rs`, `handlers/dir.rs`, `handlers/mknod.rs`

After file creation, the exporter applies the SPIFFE→uid/gid mapping from the access policy. This ensures files are owned by the correct Linux user, not the exporter process. Requires `CAP_CHOWN` or root.

### 8. Session Resumption with Identity Binding

```
First connection:
  Importer                                    Exporter
    │  derive: export_keying_material → K      │
    │── Tsession { key:K, flags:FIDS|WATCHES}─►│
    │                                          │ session_store["spiffe://a.com/app/reader"]
    │                                          │   .insert(K, SavedSession { flags, saved_at })
    │◄── Rsession { flags:FIDS|WATCHES } ──────│

Reconnection (within 5 min TTL):
  Importer                                    Exporter
    │══ New QUIC mTLS handshake ═══════════════│
    │                                          │ extract_spiffe_id → same identity
    │── Tsession { key:K (saved), flags:... }─►│
    │                                          │ session_store["spiffe://a.com/app/reader"]
    │                                          │   .remove(K) → SavedSession
    │                                          │ ① TTL not expired? ✓
    │                                          │ ② (identity already matched by partition)
    │                                          │ ③ effective = requested & restored
    │◄── Rsession { flags:effective } ─────────│

Different identity attempting resume:
  Attacker (spiffe://evil.com/bot)             Exporter
    │── Tsession { key:K (stolen) } ──────────►│
    │                                          │ session_store["spiffe://evil.com/bot"]
    │                                          │   .get(K) → None (wrong partition)
    │◄── Rsession { flags: 0 } ────────────────│  new session, no state restored
```

**Source**: `session_store.rs`, `handlers/session.rs`

The session store is **partitioned by SPIFFE ID** (`DashMap<String, DashMap<[u8;16], SavedSession>>`). This provides:
- **Identity isolation** — different SPIFFE IDs cannot access each other's sessions
- **No cross-identity probing** — a stolen key only works in the correct identity partition
- **TTL expiry** — sessions expire after 5 minutes (configurable), with periodic GC
- **One-time use** — `resume()` removes the entry, preventing replay

### 9. Trust Bundle Distribution

```
Importer                                    Exporter
  │                                           │
  │── Tfetchbundle { trust_domain:"a.com",    │
  │                  format:0 (X.509 PEM) } ─►│
  │                                           │ trust_store.to_pem("a.com")
  │◄── Rfetchbundle { bundle: <PEM CAs> } ────│
  │                                           │
  │── Tspiffeverify { svid_type:0,            │
  │     spiffe_id:"spiffe://c.com/other",     │
  │     svid: <DER cert> } ──────────────────►│
  │                                           │ ① extract_spiffe_id(svid)
  │                                           │ ② declared == cert ID? ✓
  │                                           │ ③ trust_store.has("c.com")? → No
  │◄── Rspiffeverify { status: UNTRUSTED } ───│
```

**Source**: `handlers/spiffe.rs`

The exporter serves its trust bundle store via Tfetchbundle and validates third-party SVIDs via Tspiffeverify.

---

## Security Layer Summary

```
┌──────────────────────────────────────────────────────────────────┐
│ Layer 1: TLS Transport (QUIC mTLS / TCP+TLS / RDMA bootstrap)    │
│ ├─ rustls WebPkiClientVerifier validates certificate chains      │
│ ├─ Both sides must present valid X.509-SVIDs from trusted CAs    │
│ ├─ RDMA: TCP+TLS bootstrap for auth, then QP exchange over TLS   │
│ └─ Invalid/expired/unsigned → connection refused                 │
├──────────────────────────────────────────────────────────────────┤
│ Layer 2: Identity Extraction (connection setup)                  │
│ ├─ extract_spiffe_id_from_conn() → session.spiffe_id             │
│ └─ Immutable for the connection lifetime                         │
├──────────────────────────────────────────────────────────────────┤
│ Layer 3: Identity Confirmation (TstartlsSpiffe, optional)        │
│ ├─ Declared ID must match TLS certificate ID                     │
│ └─ session.spiffe_verified = true                                │
├──────────────────────────────────────────────────────────────────┤
│ Layer 4: Session Key (TLS-derived, per-connection)               │
│ ├─ export_keying_material("9P2000.N session") → 128-bit key      │
│ ├─ Cryptographically secure, unique per TLS session              │
│ ├─ Duplicate Tsession on same connection → rejected              │
│ └─ Zero key → rejected (must derive from TLS)                    │
├──────────────────────────────────────────────────────────────────┤
│ Layer 5: Filesystem Isolation (Tattach)                          │
│ ├─ AccessControl.resolve_root(spiffe_id) → per-user root         │
│ ├─ 3-level policy lookup: by_id → by_domain → default            │
│ └─ Workload path auto-mapping → /export/{workload}/              │
├──────────────────────────────────────────────────────────────────┤
│ Layer 6: Operation Permissions (every request)                   │
│ ├─ check_perm(spiffe_id, required_permission):                   │
│ │   1. Static policy (SPIFFE ID → Policy.permissions bitmask)    │
│ │   2. Dynamic cap token (fid → CapToken.rights, JWT-verified)   │
│ ├─ Special: chown/chmod requires PERM_ADMIN                      │
│ └─ Walk depth check: check_depth(spiffe_id, wnames.len())        │
├──────────────────────────────────────────────────────────────────┤
│ Layer 7: Capability Tokens (Tcapgrant/Tcapuse, on-demand)        │
│ ├─ HMAC-SHA256 signed JWT with p9n_rights and p9n_depth claims   │
│ ├─ Subject bound to SPIFFE ID (non-transferable)                 │
│ ├─ Rights capped by static policy ceiling                        │
│ └─ Time-limited (max 24 hours)                                   │
├──────────────────────────────────────────────────────────────────┤
│ Layer 8: File Ownership (create operations)                      │
│ ├─ apply_ownership(spiffe_id, path) after lcreate/mkdir/etc.     │
│ ├─ Policy.uid/gid → chown newly created files                    │
│ └─ uid=0 && gid=0 → no mapping (server process ownership)        │
├──────────────────────────────────────────────────────────────────┤
│ Layer 9: Path Escape Prevention (every file operation)           │
│ ├─ backend.resolve() → canonicalize + starts_with(root)          │
│ └─ Prevents symlink traversal outside per-user root              │
└──────────────────────────────────────────────────────────────────┘
```

## Permission Bits

| Bit | Name | Hex | Required For |
|-----|------|-----|-------------|
| 0 | `PERM_READ` | `0x01` | walk, getattr, stat, readdir, readlink, open, read, hash, getacl, getlock |
| 1 | `PERM_WRITE` | `0x02` | write, fsync, allocate, lock |
| 2 | `PERM_CREATE` | `0x04` | lcreate, symlink, link, mkdir, mknod |
| 3 | `PERM_REMOVE` | `0x08` | unlinkat, remove |
| 4 | `PERM_SETATTR` | `0x10` | setattr (mode, size, times) |
| 7 | `PERM_ADMIN` | `0x80` | chown, chgrp, setacl |

Operations requiring multiple bits:
- `rename` / `renameat`: `PERM_REMOVE | PERM_CREATE`
- `copyrange`: `PERM_READ | PERM_WRITE`

## Session Store Design

```
SessionStore structure:
  DashMap<String, DashMap<[u8; 16], SavedSession>>
         │                │              │
         │                │              └─ flags + saved_at (TTL)
         │                └─ session key (128-bit, TLS-derived)
         └─ SPIFFE ID partition ("spiffe://a.com/app/reader")

Properties:
  ├─ Partitioned by identity — zero cross-identity interference
  ├─ One-time resume — entry consumed on use (anti-replay)
  ├─ TTL expiry — default 5 minutes, configurable
  ├─ Periodic GC — every 60 seconds, removes expired + empty partitions
  └─ Key security — derived from TLS, not transmitted, not guessable
```

## Key Files

| Component | File | Purpose |
|-----------|------|---------|
| TLS config | `p9n-auth/src/spiffe/tls_config.rs` | Build mTLS rustls configs (static + dynamic) |
| Cert resolver | `p9n-auth/src/spiffe/cert_resolver.rs` | Hot-reload TLS certs on SVID rotation |
| X.509 SVID | `p9n-auth/src/spiffe/x509_svid.rs` | Load PEM, extract SPIFFE ID from SAN |
| JWT-SVID | `p9n-auth/src/spiffe/jwt_svid.rs` | Verify/sign JWT tokens and cap tokens (HMAC) |
| Trust bundles | `p9n-auth/src/spiffe/trust_bundle.rs` | CA chain store per trust domain |
| Access control | `p9n-exporter/src/access.rs` | Policy resolution, permission check, uid/gid mapping |
| Identity extraction | `p9n-exporter/src/connection.rs` | Extract SPIFFE ID from QUIC TLS cert |
| Permission check | `p9n-exporter/src/handlers/mod.rs` | `check_perm()` two-layer authorization |
| Cap tokens | `p9n-exporter/src/handlers/capgrant.rs` | JWT token grant and activation |
| SPIFFE handlers | `p9n-exporter/src/handlers/spiffe.rs` | TstartlsSpiffe, Tfetchbundle, Tspiffeverify |
| Session handler | `p9n-exporter/src/handlers/session.rs` | Key validation, duplicate rejection, resume |
| Session store | `p9n-exporter/src/session_store.rs` | Per-identity partitioned store with TTL |
| Session state | `p9n-exporter/src/session.rs` | active_caps, spiffe_verified, inflight |
| Ownership mapping | `p9n-exporter/src/handlers/create.rs` | apply_ownership after file creation |
| Key derivation | `p9n-importer/src/importer.rs` | export_keying_material for session key |
| RDMA bootstrap | `p9n-transport/src/rdma/config.rs` | TCP+TLS handshake, QP parameter exchange |
| RDMA handler | `p9n-exporter/src/rdma_connection.rs` | RDMA connection lifecycle + one-sided I/O |
| RDMA token | `p9n-exporter/src/handlers/rdma.rs` | Trdmatoken registration |

---

## RDMA Authentication (feature `rdma`)

RDMA transport reuses the same SPIFFE mTLS authentication as TCP+TLS, but only for the bootstrap phase. Once RDMA QP parameters are exchanged, the TCP connection closes and all data flows over RDMA verbs.

### Authentication Flow

```
Importer                         TCP+TLS                          Exporter
  │                                  │                               │
  │═════ TCP connect to RDMA bootstrap address ══════════════════════│
  │                                  │                               │
  │═════ TLS 1.3 mTLS handshake (same as TCP transport) ═════════════│
  │  Client X.509-SVID ─────────────►│                               │
  │                                  │──► rustls WebPkiClientVerifier│
  │◄──── Server X.509-SVID ──────────│◄── validation passed          │
  │                                  │                               │
  │  derive session key:             │    derive session key:        │
  │  export_keying_material(         │    export_keying_material(    │
  │    "9P2000.N-session") → K       │      "9P2000.N-session") → K  │
  │                                  │                               │
  │◄── server QP endpoint ───────────│ encode(qp_num,lid,gid,psn)    │
  │    (26 bytes over TLS)           │                               │
  │                                  │                               │
  │─── client QP endpoint ──────────►│ decode → remote endpoint      │
  │    (26 bytes over TLS)           │                               │
  │                                  │                               │
  │═════ TCP connection closed ══════╪═══════════════════════════════│
  │                                  │                               │
  │◄═══════════ RDMA verbs (all data) ══════════════════════════════►│
```

### Security Properties

1. **Same authentication strength as TCP+TLS**: The TLS handshake validates both sides' X.509-SVIDs against trusted CAs before any RDMA parameters are exchanged.

2. **Session key derived from TLS**: The 128-bit session key is derived from TLS 1.3 keying material (`export_keying_material`), binding the RDMA session to the authenticated TLS connection.

3. **QP parameters exchanged over encrypted channel**: The QP number, LID, GID, and PSN are transmitted over the TLS stream — a man-in-the-middle cannot inject forged QP parameters.

4. **No encryption on RDMA data path**: After the TCP bootstrap closes, RDMA messages are **not encrypted**. This is by design — RDMA operates on trusted datacenter fabric (InfiniBand or RoCE), where encryption is handled at the network layer or is unnecessary. This matches NFS/RDMA behavior.

5. **RDMA buffer registration security**: Trdmatoken only allows a client to register buffers for its own fids. The server validates fid ownership before storing the remote rkey/addr. One-sided RDMA Read/Write operations are constrained to the registered buffer region.
