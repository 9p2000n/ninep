# SPIFFE-Derived POSIX Identity Design (v2: signed mapping bundle)

**Status**: Draft — replaces the v1 X.509-extension design at this same path.
**Scope**: How importer and exporter resolve, agree on, and run as a
shared POSIX `uid`/`gid`/groups namespace keyed on SPIFFE workload
identity.
**Related docs**: `SECURITY_DESIGN.md`, `SPIRE_SETUP.md`, `ARCH_DESIGN.md`
**Supersedes**: an earlier design (v1) that embedded the mapping in a
custom X.509 extension under PEN `1.3.6.1.4.1.65588.1.1`. v2 preserves
the namespace model and the access-control split unchanged but moves
the `(SPIFFE ID → uid, gid, groups)` mapping out of the SVID into a
separately-signed bundle distributed via the existing `Tfetchbundle`
9P2000.N message.

## 1. Motivation

### 1.1 The uid mismatch problem

The exporter currently maps SPIFFE identity to a server-local
`(uid, gid)` via `AccessControl::Policy`, and `chown`s newly-created
files to those values (`handlers/create.rs`, `handlers/dir.rs`,
`handlers/mknod.rs`). The importer, running as whatever local user
invoked `p9n-importer`, sees `stat.st_uid` set to the server-mapped
value rather than its own `getuid()`.

Consequences are operational, not cosmetic:

- `stat().st_uid == getuid()` never holds, so "is this my file?"
  checks fail for files the client just created.
- `ls -l` prints numeric uids that mean nothing on the client.
- When FUSE is mounted with `default_permissions`, the client kernel
  enforces mode bits against the mismatched uid and returns `EACCES`
  on the client's own files.
- `chown`/`chmod` from the client silently break because the kernel
  considers the calling user a non-owner.

### 1.2 Why not client-side squashing

A simpler fix is to have the importer rewrite `uid/gid` in `FileAttr`
to `getuid()`/`getgid()` before returning to FUSE. It works for the
single-user case but fails for:

- Multi-tenant scenarios where one client host runs multiple workloads
  that should each see their own files as theirs and other workloads'
  files as foreign.
- Servers that legitimately enforce per-file ownership across
  workloads sharing the same export.
- Any code path that depends on distinguishing ownership on the server
  side (e.g., `setattr` flows trusting the client's declared owner).

Rewriting is a patch on the symptom. The root cause is that the two
sides run in different uid namespaces and rely on runtime translation.

### 1.3 The system-level fix: a single signed mapping

This document specifies a different approach: **both sides resolve
`(SPIFFE ID → uid, gid, groups)` from the same signed mapping
bundle**, distributed per trust domain.

- The exporter loads the bundle from a local file at startup, validated
  against a JWK Set delivered through the SPIFFE trust bundle.
- The importer fetches the bundle via the existing `Tfetchbundle`
  9P2000.N message *after* mTLS authentication, validates it against
  its own JWK Set, looks up its own SPIFFE ID, then performs the
  irreversible `setuid` transition before mounting FUSE.

The bundle is the single source of truth: there is no per-cert payload,
no second authentication path, no client-side translation layer, and
no bundle artifact deployed to importer hosts. With the importer
process and the exporter's chown target identical by construction,
`stat` readback matches `getuid` on the client.

This mirrors the model NFSv4 *attempted* to provide via shared
`idmapd` — but with cryptographic integrity, opt-in trust-domain
scoping, and reuse of the existing 9P2000.N trust-distribution
channel.

### 1.4 Why not in the SVID itself

v1 of this design embedded the mapping in an X.509 extension on the
SVID. Two architectural concerns motivated the move:

- **SPIFFE separates identity from authorization by design**.
  `(uid, gid)` are authorization material — they decide what a workload
  can read and write. Embedding them in the SVID couples identity
  issuance with authorization decisions, which the SPIFFE spec
  deliberately keeps separate.
- **SVID portability**. The same SPIFFE ID should be usable by a
  workload that does not run on Linux or does not touch a POSIX
  filesystem. A POSIX-specific extension on every cert in the trust
  domain forces non-POSIX consumers to either ignore the field
  unconditionally or reject the cert.

A bundle distributed outside the SVID keeps the SVID minimal and lets
each consumer that cares about POSIX semantics opt into the bundle.

JWT-SVID claims were also considered. They share the same problem
(POSIX-specific data on a generic identity object) and add per-peer
audience minting, channel-binding, and short-token refresh complexity
that the bundle approach avoids entirely.

## 2. Design Goals

1. **Single source of truth**. `(SPIFFE ID → uid, gid, groups)` lives
   exactly once, in the signed bundle. Both importer and exporter
   resolve from the same authenticated artifact.
2. **Cryptographic integrity**. Tampering is detectable using a key
   distributed via the SPIFFE trust bundle.
3. **No new authentication path**. The bundle's signing key chains to
   SPIFFE; the bundle's transport reuses mTLS.
4. **No wire-protocol additions for delivery**. Reuse `Tfetchbundle`
   with a new bundle-type code; no new message types.
5. **Importer is a network client, not a local cache**. If the exporter
   is unreachable, the importer fails closed and exits. There is no
   degraded mode. See §9.
6. **Graceful coexistence with static `Policy`**. Workloads not in the
   bundle fall back to the existing `Policy.uid/gid` static
   configuration, allowing incremental adoption.
7. **One workload per importer process**. `setuid` is irreversible,
   so each importer instance serves a single workload identity and
   owns a single FUSE mount. Multi-workload hosts run multiple
   importer processes.

### Non-goals

- Support for Windows clients or any non-POSIX client.
- Kerberos, PAM, or traditional user-database integration.
- Dynamic uid reassignment during a workload's lifetime.
- Per-user multi-tenancy within a single importer process.

## 3. The Mapping Bundle

### 3.1 Format

A JSON object signed as a JWS Compact Serialization. The protected
header carries `alg` (RS256/ES256/EdDSA), `kid` (matches a JWK in the
trust bundle), and `typ: "p9n-posix-mapping-bundle"`. The payload is
the canonical UTF-8 JSON encoding of:

```json
{
  "version": 1,
  "trust_domain": "example.com",
  "serial": 42,
  "issued_at": 1715174400,
  "not_after":  1715260800,
  "entries": [
    {
      "spiffe_id": "spiffe://example.com/workloads/app-alice",
      "uid": 1048577,
      "gid": 1048577,
      "groups": [1048577, 2097152]
    },
    {
      "spiffe_id": "spiffe://example.com/workloads/app-bob",
      "uid": 1048578,
      "gid": 1048578,
      "groups": [1048578],
      "deprecated": true,
      "deprecated_since": 1714000000
    }
  ]
}
```

### 3.2 Field semantics

| Field | Notes |
|---|---|
| `version` | Currently `1`. Incompatible future revisions bump this. |
| `trust_domain` | MUST match the validator's expected trust domain. |
| `serial` | Strictly monotonic across publications. Validators MAY reject a bundle whose serial is lower than one they have previously seen. |
| `issued_at` | Unix seconds, informational. |
| `not_after` | Unix seconds. Validators MUST reject expired bundles. Recommended TTL: 24 h. |
| `entries[].spiffe_id` | Full SPIFFE URI. MUST lie within `trust_domain`. |
| `entries[].uid`, `entries[].gid` | u32 in `[2^20, 2^31-1]` (see §4). |
| `entries[].groups` | Optional, ≤ 64 entries each in `[2^20, 2^31-1]`. Absent = empty supplementary set. |
| `entries[].deprecated` | Optional bool. Tombstone marker — the entry is retained for audit and uid non-reuse but the workload is being decommissioned. |
| `entries[].deprecated_since` | Optional Unix seconds, informational. |

### 3.3 Validation rules

A bundle MUST be rejected if any of the following hold:

- The JWS signature does not verify against a JWK in the SPIFFE trust
  bundle whose `use` claim is `"p9n-mapping"`.
- `trust_domain` does not match the validator's configured trust
  domain.
- `not_after` ≤ now.
- Any `entries[].spiffe_id` is not a syntactically valid SPIFFE URI,
  or is not in `trust_domain`.
- Any `entries[].uid` or `entries[].gid` falls outside
  `[1048576, 2147483647]`.
- Any `entries[].groups[i]` falls outside the same range.
- Two non-deprecated entries carry the same `uid` (uniqueness
  invariant).
- The serialized bundle exceeds 4 MB.

The 4 MB ceiling is generous: at ~100 bytes per entry that's > 40 k
workloads. A larger bundle indicates a deployment pathology and is
rejected on principle.

### 3.4 Why JWS

- We already use `jsonwebtoken` for JWT-SVID verification. Re-using it
  for bundle verification is zero new dependencies and zero new
  cryptographic primitives.
- Compact form is single-line ASCII, trivially shippable through
  `Tfetchbundle`'s existing `bytes` payload.
- `kid` lets us rotate signing keys without touching the bundle
  format.

## 4. uid/gid Reservation Policy

```
0             : root
1         ─ 999       : system services (distro-managed)
1000      ─ 65533     : conventional human/service accounts
65534                 : nobody / nogroup
65535     ─ 1048575   : reserved for Linux kernel subuid/subgid
                        ranges used by rootless containers and
                        user-namespace mappings
1048576   ─ 2147483647 : SPIFFE-derived namespace (THIS DESIGN)
2147483648 ─ …         : reserved; avoid (historical tools treat
                         uid_t as signed int32)
```

The SPIFFE range `[2^20, 2^31-1]` provides ~2.1 billion distinct
identities. The lower bound stays above Linux's conventional `subuid`
allocation window so SPIFFE-assigned uids do not collide with
user-namespace-mapped ranges on the same host.

Both importer and exporter MUST reject any entry whose `uid`, `gid`,
or any supplementary group falls outside `[1048576, 2147483647]`.
The check happens during bundle validation, before any value reaches
the session layer.

Administrators assigning uids MUST treat allocations as **immutable
and non-reusable**:

- Once `spiffe://example.com/workload-X` is bound to `uid=5000001`,
  that binding cannot change. A new registration for the same workload
  reuses the same uid.
- When a workload is decommissioned, its entry is **tombstoned** —
  marked `deprecated: true` so the uid is not re-issued to a different
  workload. Tombstones may eventually be removed once no on-disk file
  bears the uid; that is an out-of-band garbage-collection task.
- Two non-deprecated entries with the same uid are a configuration
  error; the bundle-generation tool MUST reject this.

## 5. Signing Authority and Trust Chain

### 5.1 The mapping-authority key

A dedicated keypair signs the bundle. Its public part is published as
a JWK with `use: "p9n-mapping"` inside the SPIFFE trust bundle (the
same JWK Set already returned by `Tfetchbundle(BUNDLE_JWT_KEYS)`).
This means:

- The key's distribution rides the SPIFFE trust bundle's existing
  rotation and federation mechanics.
- A consumer that already trusts the SPIFFE trust bundle automatically
  trusts this key (transitively, by virtue of trusting the SPIFFE CA
  that signs the bundle).
- The key can be rotated without touching the SPIFFE root CA. `kid`
  in the JWS header selects the active key; the JWK Set may carry
  several to support overlap windows.

### 5.2 Why a dedicated key, not the SPIFFE root CA

Decoupling the bundle signature from the SVID-signing CA limits the
blast radius of compromise:

- Compromise of the mapping-authority key forges bundles, but does not
  forge SVIDs, so peers' identities remain trustworthy. Only the
  POSIX-uid binding is suspect, and the on-disk attack requires
  exporter-side path-isolation to also have failed — see §8.
- Compromise of the SVID-signing CA was already catastrophic; no
  additional surface is exposed by giving the mapping authority its
  own key.
- Rotating the mapping-authority key on a faster cadence than the root
  CA is operationally cheaper.

### 5.3 Where the key lives

Any keystore acceptable for SPIRE-server-grade keys:

- HSM (recommended for production).
- Cloud KMS (AWS KMS, GCP KMS, Azure Key Vault) with a JWK-Set
  rendering of the public key.
- Disk-resident PEM file (development and small deployments).

The signing operation itself is performed by an offline or
batch-scheduled bundle-generation tool (§12), not by the running
exporter or importer. Neither runtime ever holds the private key.

## 6. Distribution

### 6.1 Exporter side: local file + mtime watch

The exporter is configured with two paths:

- `--posix-mapping-bundle <path>`: the signed JWS (compact form).
- `--posix-mapping-jwks <path>`: the JWK Set containing the
  mapping-authority public key(s).

Both are loaded at startup, validated, and held in memory. An mtime
watcher on the bundle file triggers reload-and-revalidate on change;
mid-flight requests use the bundle they entered with for the
remainder of their session, avoiding mid-handler resolution races.

If validation fails at startup, the exporter exits with a clear
error. There is no fallback to "serve without mapping" — operators
who genuinely need the legacy static-policy mode set
`--posix-mapping-bundle ""` explicitly to opt out.

### 6.2 Importer side: fetched, never local

The importer carries no bundle file. It carries only:

- Its own SVID (cert + key, from disk or Workload API).
- The SPIFFE trust bundle (or the JWK Set extracted from it),
  containing the mapping-authority public key.

After mTLS, the importer issues `Tfetchbundle(BUNDLE_POSIX_MAPPING)`
to receive the signed JWS bytes verbatim. It validates locally,
looks up its own SPIFFE ID, validates range, and proceeds to
`setuid`. See §7.1 for the full flow.

This removes the bundle file from every importer host. Bundle
distribution to importers is the protocol's responsibility, not the
deployment system's.

### 6.3 New `Tfetchbundle` bundle type

Add a new constant alongside the existing types in
`crates/p9n-proto/src/types.rs`:

```rust
pub const BUNDLE_X509_CAS:      u8 = 0;  // existing
pub const BUNDLE_JWT_KEYS:      u8 = 1;  // existing
pub const BUNDLE_POSIX_MAPPING: u8 = 2;  // new
```

The exporter's `handlers/spiffe.rs::handle_fetchbundle` returns the
cached signed bundle bytes verbatim under this type. No additional
encoding/decoding on the wire — the bytes are already a complete
JWS.

`Tfetchbundle` already accepts pre-attach: it is gated on mTLS, not
on Tattach. This matches what we need (importer must fetch bundle
*before* it can `setuid` and *before* it can attach).

## 7. Identity Resolution Flow

### 7.1 Importer startup

```
[as root, with SVID + JWK Set on disk]
  │
  ├─► (1) Establish QUIC + mTLS to exporter
  │       failure → fail-closed exit after 30 s timeout
  │
  ├─► (2) Tversion / Tcaps           [protocol negotiation]
  │
  ├─► (3) Tfetchbundle(BUNDLE_POSIX_MAPPING)
  │       receives signed JWS bundle
  │
  ├─► (4) Verify signature against local JWK Set
  │       check trust_domain, not_after, uniqueness, range invariants
  │       any failure → fail-closed exit
  │
  ├─► (5) Look up own SPIFFE ID → (uid, gid, groups)
  │       not found → fail-closed exit
  │       deprecated → log warning but proceed (transition window)
  │
  ├─► (6) setgroups(groups)
  │       setresgid(gid, gid, gid)
  │       setresuid(uid, uid, uid)
  │       prctl(PR_CAP_AMBIENT_CLEAR_ALL)
  │       capset(0, 0, 0)
  │       prctl(PR_SET_NO_NEW_PRIVS, 1)
  │
  ├─► (7) mount FUSE
  │       (fusermount3 setuid helper still works post-drop)
  │
  ├─► (8) Tattach
  │
  └─► (9) Serve FUSE requests as the SPIFFE-derived uid
```

Capabilities held during (1)–(5): `CAP_SETUID`, `CAP_SETGID`, plus
whatever the QUIC + rustls path needs (none — both are pure
userspace). For defense-in-depth, the importer can be launched as
`User=nobody` with `AmbientCapabilities=CAP_SETUID CAP_SETGID` so
that even an in-handshake exploit cannot become full root before
the privilege drop runs.

### 7.2 Exposure window analysis

(1)–(5) run as root before the privilege drop. A valid concern is
"what attack surface is increased by deferring `setuid` past the
network handshake?" The answer:

- (1) is QUIC + rustls — userspace network code that is *already* in
  the trusted set (the exporter runs the same stack as root).
- (2)–(3) are protocol message exchange against codec limits already
  enforced (32 MB framing cap, 16-element walk cap, 256-op compound
  cap; bundle has its own 4 MB ceiling).
- (4) is JWS verification — `jsonwebtoken` against a local JWK Set.
- (5) is a `HashMap` lookup.

In none of (1)–(5) does the importer touch a user file, fork, exec,
mount, or open any non-network fd. The pre-drop window is, in effect,
"the same code that runs as root in the exporter, plus a JSON parse."
This is a strictly smaller surface than the old design, where the
importer had to open and parse SVID files and run X.509 extension
parsing as root.

### 7.3 Multi-exporter consistency

A single importer process attaching to multiple exporters MUST, after
its first `setuid`, verify that any subsequent bundle's entry for
itself matches the `(uid, gid, groups)` it has already become.
Mismatch → refuse to attach to that exporter. There is no mechanism
to re-`setuid` mid-process; multi-exporter clients tolerate version
skew between exporters only when the skew does not affect the
client's own entry.

### 7.4 Exporter accept

```
QUIC/TCP handshake completes
  │
  ├─► extract_spiffe_id_from_conn(&conn)        [existing path]
  │
  ├─► AccessControl::resolve(spiffe_id) → &Policy
  │     Policy.{uid,gid,groups} now sourced from the loaded bundle
  │
  ├─► Construct Session with peer_posix bound from Policy
  │
  └─► Run handlers
```

The change at this point is purely the *source* of `Policy.uid/gid/
groups` — the resolution path stays single. Workloads not in the
bundle still resolve through the existing fallback Policy table
(static `--access-policy` YAML), enabling incremental rollout.

### 7.5 No translation on the wire

Because both sides agree on the `(spiffe_id → uid)` mapping, no
on-wire translation is needed. `Stat.uid/gid` in `Rgetattr` responses
carry raw numeric values that are meaningful on both sides. The
importer needs no squashing layer.

### 7.6 Wire `gid` validation in create operations

The `gid` field in `Tlcreate`/`Tmkdir`/`Tmknod`/`Tsymlink` is
overconstrained once `peer_posix` is in effect: the authoritative gid
is already fixed by the bundle, so the wire value cannot be a free
parameter without contradicting the mapping. Wire `gid` is treated
as a *replication* of the authoritative value, not a hint:

- `peer_posix.is_some()`: wire `gid` MUST equal `peer_posix.gid`.
  Otherwise the exporter returns `Rlerror` with `EPERM`.
- `peer_posix.is_none()` and `Policy.gid != 0`: wire `gid` MUST equal
  `Policy.gid`. Otherwise `EPERM`.
- `peer_posix.is_none()` and `Policy.gid == 0`: there is no
  authoritative reference, so create operations MUST fail with
  `EPERM`. Operators who run a single-tenant deployment without a
  bundle MUST configure an explicit static `Policy` (non-zero
  `uid`/`gid`).

The field stays on the wire only for 9P2000.L compatibility. Clients
MUST replicate the authoritative gid, not vary it. Phase-fallback
importers fill wire `gid` with the bundle-derived value regardless
of the local FUSE caller's process gid.

A client that genuinely wants to create a file under a non-primary
supplementary group MUST do so via `Tsetattr` chgrp after creation,
not by varying the wire `gid` on the create message.

`Tsetattr.uid/gid` are not subject to the strict equality rule —
chown is by nature a request to *change* ownership — but the
set-membership and range rule of §7.7 applies. `Tattach.uname` stays
unconstrained: it's a free-form human label with no operational
consequence.

### 7.7 Tsetattr owner validation

When `peer_posix` is in effect, `Tsetattr.uid/gid` (gated by their
respective `valid` bits) are constrained as follows:

- `SETATTR_UID` set: `attr.uid` MUST satisfy
  - `attr.uid == peer_posix.uid` (chown to self / no-op), OR
  - the caller has `PERM_ADMIN` AND `attr.uid` lies in
    `[SPIFFE_UID_MIN, SPIFFE_UID_MAX]`.
- `SETATTR_GID` set: `attr.gid` MUST satisfy
  - `attr.gid ∈ {peer_posix.gid} ∪ peer_posix.groups`
    (POSIX `chgrp` semantics), OR
  - the caller has `PERM_ADMIN` AND `attr.gid` lies in the SPIFFE
    range.

Otherwise the exporter returns `Rlerror` with `EPERM`.

The range guard is the dual of the create-side equality guard
(§7.6): together they guarantee no file under a SPIFFE-derived
deployment can come to be owned by a uid or gid outside the trust
domain's namespace, even when an admin-privileged client issues an
explicit chown.

When `peer_posix` is absent and `Policy` is at its default
(`uid == gid == 0`, no static mapping), the operation MUST fail
with `EPERM` regardless of `PERM_ADMIN`.

## 8. Architectural Role: Label, Not Lock

It is important to be explicit about what the SPIFFE-derived POSIX
mapping does and does not do, because the distinction shapes which
threats this design defends against and which it leaves to other
layers.

**Primary access control boundary: per-workload root.** 9P2000.N's
access control between workloads is established at the *path* level,
not the *uid* level. Each workload attaches to a root derived from
its SPIFFE ID (`AccessControl::resolve_root` and `enable_isolation`).
A fid created in workload A's session can never resolve to a file in
workload B's tree, because every path operation is rooted at A's
subdirectory and `resolve()` rejects any canonicalised result that
escapes it.

This is a strict invariant. Production deployments MUST configure
per-workload roots; deployments that share a single root across
workloads forfeit cross-tenant isolation and SHOULD be treated as
single-tenant.

**Role of the mapping bundle.** Within the path-level boundary, the
bundle supplies a *label*:

- `chown`-on-create writes `peer_posix.uid/gid` into the file's
  metadata so subsequent `stat` calls return values that are
  meaningful on both ends of the connection (the original motivation,
  §1.1).
- `Tsetattr.uid/gid` is constrained against `peer_posix` (§7.7) so a
  workload cannot relabel its own files outside the SPIFFE namespace.
- `Tlcreate/Tmkdir/Tmknod/Tsymlink.gid` is constrained against the
  authoritative gid (§7.6) so the wire field cannot be a free
  parameter contradicting the bundle.

What the mapping does *not* do is gate per-request read/write
operations against `peer_posix`. The exporter process opens files
with its own credentials; the kernel's POSIX permission check is
bypassed in the same way any privileged user-space filesystem server
bypasses it. This is acceptable because the path-level boundary
above already prevents a workload from obtaining a fid that points
at another workload's file.

**Operator responsibilities under this model:**

1. Per-workload roots MUST be strict — derived deterministically from
   SPIFFE ID, never shared between workloads.
2. Each workload's root MUST be exclusively populated by the workload
   itself, or by an operator pre-seed of files owned by that
   workload's bundle-assigned uid. Pre-populating one workload's root
   with files owned by a different uid bypasses the protection model.
3. Anonymous attach (no SPIFFE ID on the peer) MUST be refused; the
   `b23de36` baseline already enforces this.

A future reader looking at the read/write path and seeing no per-uid
enforcement might conclude the bundle "is not really enforced." Under
the model above, that observation is correct but irrelevant — the
enforcement happens one layer earlier, at fid resolution.

## 9. Network Failure Model: Importer Is a Network Client

The importer's only purpose is to project the exporter's filesystem
into the local kernel via FUSE. If the exporter is unreachable, the
importer has nothing to do — and the user can read and write the
local filesystem directly. The design therefore treats network
failure as a terminal condition, not a degraded mode:

- **Startup unreachable** → exit cleanly after a 30 s timeout with a
  clear error. Do not retry indefinitely as root.
- **No local bundle cache**. The bundle exists only in importer
  memory, validated against the JWK Set, used once for `setuid`,
  retained for the connection's lifetime for in-session validation.
  There is no `--allow-stale-bundle`, no `~/.cache/p9n-bundle`, no
  persistence across restarts.
- **Mid-session disconnect** → the existing reconnect logic applies
  for transient drops. If reconnect fails terminally, the FUSE mount
  begins returning `EIO` and the process exits. It does not serve
  cached reads.
- **Lease invalidation** → on disconnect, all leased caches are
  dropped. The lease's lifetime is the connection's lifetime by
  construction.
- **Bundle staleness mid-session** → not handled. Once the importer
  has `setuid`-ed, its uid is fixed for the process lifetime. Bundle
  re-fetch only matters for *new* connections to *new* exporters
  (multi-exporter case, §7.3).

The principle: **loss of exporter ≡ loss of mount**. There is no
half-online state to engineer for.

## 10. Interaction with `AccessControl::Policy`

The existing `AccessControl` layer is unchanged in spirit. It still:

- Resolves the per-identity root directory (multi-tenant isolation).
- Enforces permission masks (`PERM_READ`/`WRITE`/etc.) by SPIFFE ID.
- Caps walk depth.

What changes is the source of `ownership_for(session)`:

```text
fn ownership_for(session) -> (uid, gid, groups):
    if let Some(p) = session.peer_posix {
        return (p.uid, p.gid, p.groups);
    }
    // fallback: existing static policy
    let policy = self.resolve(session.spiffe_id);
    (policy.uid, policy.gid, policy.groups)
```

`session.peer_posix` is populated at connection-accept time from the
loaded bundle (`Bundle.lookup(spiffe_id)`). When the workload is in
the bundle, the in-memory `Policy` is irrelevant for the
`(uid, gid, groups)` axis (it still drives `permissions`, `root`,
`max_depth`).

Static `Policy.uid/gid` is retained as a fallback for workloads not
in the bundle, used only when bundle lookup returns `None`. This is
intentional and load-bearing: it lets operators stage workload
onboarding (publish the bundle, register workloads incrementally)
without forcing an all-or-nothing flip, and it gives single-tenant
deployments a working configuration without standing up a bundle
authority.

## 11. Operational Requirements

### 11.1 SPIRE attestation MUST NOT use `unix:uid:` selectors

The importer process changes its uid from the bootstrap value (root
or `nobody`) to a SPIFFE-derived value during startup. SPIRE Agent
re-attests on SVID rotation; if the registration uses a `unix:uid:`
selector, post-`setuid` attestation fails and SVID rotation breaks.

Use one of:

- `unix:path:/usr/local/bin/p9n-importer` (binary path).
- `k8s:pod-label:app=p9n-importer` (K8s pod label).
- `k8s:ns:<namespace>` + `k8s:sa:<serviceaccount>`.
- `unix:supplementary_gids:<gid>` paired with a pre-`setuid` group.

This is operational guidance, not a code change in this project.

### 11.2 Bundle publishing cadence

- `not_after` SHOULD be ≤ 24 h.
- Operator workflow: any change to the workload registry triggers a
  re-sign and republish.
- A signing-authority outage that exceeds 24 h prevents *new*
  connections (existing connections continue). Per §9 this is
  acceptable; operators should monitor bundle freshness as an SLO.

### 11.3 Tombstoning and uid reuse

Decommissioned workloads' entries are marked `deprecated: true` and
retained in the bundle until no on-disk file owned by that uid
remains anywhere in the trust domain. Removal is an operator decision,
not an automated policy.

A bundle with two non-deprecated entries sharing a `uid` is a
configuration error. The bundle-generation tool MUST detect and
refuse it; runtime validators reject as defense in depth.

### 11.4 Cross-host consistency

The bundle is the same artifact on every exporter host. Operators
must push synchronously to all exporters in a trust domain. Skew is
detected at the importer's multi-exporter consistency check (§7.3),
which fails the *attach* — not the whole importer process — for the
inconsistent exporter.

### 11.5 Mixing bundled and static-Policy workloads

Operators may stage workload onboarding: workloads listed in the
bundle resolve through it, and workloads not yet in the bundle
continue to use the static `Policy.uid/gid` configured via
`--access-policy` YAML. This is the §10 fallback in normal use.

Importers that require a bundle-resolved identity for their own
SPIFFE ID (`--require-posix-mapping` or `--setuid-from-mapping`)
fail closed at startup if the bundle has no entry for them; static
`Policy` on the server side does not satisfy this client-side
requirement.

## 12. Bundle Generation Tooling

A small CLI, shipped with the ninep release, produces signed bundles
from a registry description.

### 12.1 Input format

```yaml
trust_domain: example.com
serial: 42                       # caller's responsibility to monotonic-bump
not_after_hours: 24
signing_key:
  source: file                   # or "kms"
  path: /etc/p9n/mapping-signer.pem
  kid: mapping-key-2026-q2
workloads:
  - spiffe_id: spiffe://example.com/workloads/app-alice
    uid: 1048577
    gid: 1048577
    groups: [1048577, 2097152]
  - spiffe_id: spiffe://example.com/workloads/app-bob
    uid: 1048578
    gid: 1048578
    groups: [1048578]
    deprecated: true
    deprecated_since: 2025-04-01T00:00:00Z
```

### 12.2 Output

A single signed JWS file ready for deployment to all exporters in the
trust domain, plus a JWK file for the mapping-authority public key
suitable for inclusion in the SPIFFE trust bundle.

### 12.3 Validation invariants enforced at generation

- All uids/gids/groups in the SPIFFE range.
- No two non-deprecated entries share a uid.
- Tombstoned entries' uids do not reappear in active entries.
- `serial` strictly greater than the previously-published value (when
  `--previous <path>` is supplied).
- All `spiffe_id` values are syntactically valid SPIFFE URIs in
  `trust_domain`.

The tool is offline and not in the request hot path.

## 13. Testing Strategy

### 13.1 User-namespace harness

Privilege-sensitive tests run inside a Linux user namespace
(`unshare(CLONE_NEWUSER)`), where the test process is "root" as far
as the kernel is concerned and can `setuid` to any uid mapped in
`/proc/self/uid_map`. The harness from v1 carries over without
change; only the test fixture creator differs (signed bundle instead
of forged X.509 extension).

### 13.2 What is tested

- **Bundle parse, valid**: well-formed signed bundle parses cleanly,
  entries indexed correctly.
- **Bundle parse, signature fail**: bundle signed by wrong key
  rejected.
- **Bundle parse, expired**: `not_after` in the past rejected.
- **Bundle parse, range violation**: uid 1000 → rejected; uid 2^32 →
  rejected.
- **Bundle parse, trust-domain mismatch**: bundle for
  `other.com` while validator expects `example.com` → rejected.
- **Bundle parse, duplicate uid**: two non-deprecated entries with
  same uid → rejected.
- **Lookup, hit**: known SPIFFE ID returns expected `(uid, gid,
  groups)`.
- **Lookup, miss**: unknown SPIFFE ID returns `None`, falls through
  to `Policy`.
- **Lookup, deprecated**: deprecated entry returns the value with a
  warning flag; runtime continues.
- **`setuid` transition**: in user namespace, `setuid` to bundle-derived
  uid succeeds; `getuid()` matches afterward.
- **End-to-end importer + exporter** in one user namespace: importer
  fetches bundle via Tfetchbundle, performs setuid, mounts FUSE,
  attaches; exporter resolves the same identity from the same bundle
  on disk. `stat.st_uid` post-create == importer process uid.
- **Multi-exporter consistency**: importer connects to two exporters
  with bundles whose entry for self differs → second attach refused.

### 13.3 What is not tested

- `fusermount3` setuid-helper interaction.
- Real SPIRE-server federation. Covered separately in
  `SPIRE_SETUP.md`.
- Windows or non-Linux. Not supported.

## 14. Rollout

The two sides adopt the bundle independently:

- **Exporter**: started with `--posix-mapping-bundle` and
  `--posix-mapping-jwks` set; otherwise behaves as before, resolving
  POSIX identity from `--access-policy` static `Policy`.
- **Importer**: started with `--posix-mapping-jwks` set; otherwise
  runs without a bundle-resolved POSIX identity (`stat` returns
  whatever uid/gid the exporter wrote). Adding
  `--require-posix-mapping` or `--setuid-from-mapping` makes
  resolution mandatory.

Workloads not yet in the bundle continue to use static `Policy` on
the server side (§11.5). Bundle adoption is per-workload; there is
no flag day.

The PEN sub-arc `1.3.6.1.4.1.65588.1.1`, originally allocated for an
X.509 extension carrying `(uid, gid, groups)` directly in the SVID,
is **retired**. Future allocations under PEN 65588 start at
`.1.2` — the registry note for `.1.1` reads "retired, do not reuse."

## 15. Risks and Open Questions

### 15.1 Risks

- **Mapping-authority key compromise**: forged bundles can rebind
  workload→uid maps. Mitigation: short `not_after` (24 h);
  monotonic `serial` lets validators reject downgrades; HSM/KMS
  storage of the private key.
- **Bundle propagation lag**: an exporter on bundle serial N talks
  to an importer that fetched serial N+1 from a different exporter.
  Detected by §7.3 multi-exporter consistency. Operators are
  responsible for synchronous deployment; lag should be measured.
- **Bundle bloat**: a trust domain with > 40 k workloads exceeds the
  4 MB cap. Mitigation: shard the trust domain; the `1.3.6.1.4.1.65588`
  PEN allocation does not constrain how many trust domains an org
  runs.
- **Capability leakage during pre-drop window**: §7.2 analyses the
  window. Mitigation: minimal-cap startup
  (`AmbientCapabilities=CAP_SETUID CAP_SETGID` + `User=nobody`),
  explicit `capset(0,0,0)` post-drop.
- **Test environment `subuid` availability**: user-namespace harness
  needs `/etc/subuid` entries for the host user. CI images that run
  as a bare user without subuid allocations will fail; document and
  pre-test.

### 15.2 Open questions

1. **Bundle-publication serial reset on trust-domain split/merge**.
   When a trust domain is renamed or split, do we restart `serial` at
   1, or carry it forward? Current draft assumes restart with a
   new `kid` to make the discontinuity unambiguous.
2. **Per-mount identity scope**. A single importer process serving
   multiple FUSE mount points for the same SPIFFE identity is fine.
   For different identities per mount, the design forbids it (one
   process per identity). Revisit if operationally painful.
3. **uid rotation safety**. If an operator accidentally changes a
   workload's uid in a new bundle, existing on-disk files retain the
   old uid and become inaccessible to the renamed workload. Should
   the importer compare its derived uid to a uid recorded in any
   FUSE mount's metadata at attach time? Currently no such check;
   operators are responsible.
4. **Rootless container deployment**. If the importer runs inside a
   user namespace, `uid=1048577` inside the namespace may not equal
   `uid=1048577` on the host. File ownership visibility depends on
   the namespace's `uid_map`. Design assumes host-namespace; rootless
   container deployments need additional documentation.
5. **Trust-domain scoping of the uid range**. `[2^20, 2^31-1]` is
   per-trust-domain, not global. A client mounting from multiple
   trust domains could see uid collisions. Multi-domain importers
   need further thought; current draft assumes one trust domain per
   client host.

These are deliberately left unanswered. Track here, revisit during
implementation.

## 16. Appendix: Example Bundle

### 16.1 Plaintext payload

```json
{
  "version": 1,
  "trust_domain": "example.com",
  "serial": 42,
  "issued_at": 1715174400,
  "not_after":  1715260800,
  "entries": [
    {
      "spiffe_id": "spiffe://example.com/workloads/app-alice",
      "uid": 1048577,
      "gid": 1048577,
      "groups": [1048577, 2097152]
    }
  ]
}
```

### 16.2 JWS Compact Serialization

```
eyJhbGciOiJFUzI1NiIsImtpZCI6Im1hcHBpbmcta2V5LTIwMjYtcTIiLCJ0eXAi
OiJwOW4tcG9zaXgtbWFwcGluZy1idW5kbGUifQ
.
eyJ2ZXJzaW9uIjoxLCJ0cnVzdF9kb21haW4iOiJleGFtcGxlLmNvbSIsInNlcmlh
bCI6NDIsImlzc3VlZF9hdCI6MTcxNTE3NDQwMCwibm90X2FmdGVyIjoxNzE1MjYw
ODAwLCJlbnRyaWVzIjpbeyJzcGlmZmVfaWQiOiJzcGlmZmU6Ly9leGFtcGxlLmNv
bS93b3JrbG9hZHMvYXBwLWFsaWNlIiwidWlkIjoxMDQ4NTc3LCJnaWQiOjEwNDg1
NzcsImdyb3VwcyI6WzEwNDg1NzcsMjA5NzE1Ml19XX0
.
<base64url ECDSA P-256 signature>
```

(Header decodes to `{"alg":"ES256","kid":"mapping-key-2026-q2","typ":
"p9n-posix-mapping-bundle"}`.)

### 16.3 Companion JWK Set entry

```json
{
  "kty": "EC",
  "crv": "P-256",
  "kid": "mapping-key-2026-q2",
  "use": "p9n-mapping",
  "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
}
```

This JWK is published as part of the SPIFFE trust bundle's JWK Set
(`Tfetchbundle BUNDLE_JWT_KEYS`), filterable by `use: "p9n-mapping"`
to distinguish mapping-authority keys from JWT-SVID-signing keys.
