# SPIFFE-Derived POSIX Identity Design

**Status**: Draft — design only, no implementation work committed
**Scope**: How importer and exporter resolve, agree on, and run as a
shared POSIX `uid`/`gid`/groups namespace keyed on SPIFFE workload
identity.
**Related docs**: `SECURITY_DESIGN.md`, `SPIRE_SETUP.md`, `ARCH_DESIGN.md`

## 1. Motivation

### 1.1 The uid mismatch problem

The exporter currently maps SPIFFE identity to a server-local
`(uid, gid)` via `AccessControl::Policy`, and `chown`s newly-created
files to those values (`handlers/create.rs:51`, `handlers/dir.rs:94`,
`handlers/mknod.rs:41`). The importer, running as whatever local user
invoked `p9n-importer`, sees `stat.st_uid` set to the server-mapped
value and not to its own `getuid()`.

The consequences are not cosmetic:

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
to `getuid()`/`getgid()` before returning to FUSE. This was sketched
as "scheme A" during design discussion. It works for the single-user
case but fails for:

- Multi-tenant scenarios where the same client host runs multiple
  workloads that should each see their own files as theirs and other
  workloads' files as foreign.
- Servers that legitimately want to enforce per-file ownership
  (other workloads sharing the same export).
- Any code path that actually depends on distinguishing ownership
  on the server side (e.g., `setattr` flows through to a server
  that trusts the client's declared owner).

Rewriting is a patch on the symptom. The root cause is that the two
sides run in different uid namespaces and rely on runtime translation.

### 1.3 The system-level fix

This document specifies a different approach: **both sides share a
single POSIX identity namespace, keyed on SPIFFE trust domain**. The
canonical `(uid, gid, groups)` for each SPIFFE workload is embedded in
the workload's X.509-SVID as a custom extension. The importer reads
this extension at startup, `setuid`s to the derived uid, and only then
mounts FUSE. The exporter reads the same extension from the peer's
SVID during TLS handshake and uses the same values when chowning files.

With the client process and the server's chown target identical by
construction, `stat` readback matches `getuid` on the client. No
translation layer is needed on the wire or on either side.

This mirrors the model that NFSv3 *tried* to provide via shared NIS,
but uses SPIFFE as the trust anchor and the SVID as the distribution
vehicle — both already in the critical path for authentication.

## 2. Design Goals

1. **Single source of truth**: `(SPIFFE ID → uid, gid, groups)` lives
   exactly once, in the SVID certificate. Both importer and exporter
   read it from the same authenticated place.
2. **No runtime translation**: the wire carries raw numeric `uid/gid`;
   both sides interpret them identically because they share the
   mapping.
3. **No new network service**: no separate directory lookup, no IPC to
   a local daemon beyond what SPIFFE already needs.
4. **Trust chain reuse**: the mapping is signed by the same CA that
   signs the SVID, so tampering is detectable with the existing TLS
   verification path.
5. **Graceful degradation**: a SVID without the extension falls back
   to the existing `Policy.uid/gid` static configuration, so the
   feature is adopted incrementally.
6. **One workload per importer process**: `setuid` is not reversible,
   so each importer instance serves a single workload identity and
   owns a single FUSE mount. Multi-workload hosts run multiple
   importer processes.

### Non-goals

- Support for Windows clients or any non-POSIX client. 9P2000.N is
  Linux-focused; this design inherits that assumption.
- Kerberos, PAM, or traditional user database integration. The SPIFFE
  trust domain is the identity provider.
- Dynamic `uid` reassignment during a workload's lifetime. Once a
  `(spiffe_id → uid)` binding is issued, it is treated as immutable
  for the lifetime of all files created under that identity.
- Per-user multi-tenancy within a single importer process. A client
  host with multiple human users each needs its own importer.

## 3. The `p9nPosixIdentity` X.509 Extension

### 3.1 OID

An Object Identifier under a Private Enterprise Number (PEN) arc
reserved for the ninep project. The arc is **TBD**: production use
requires registering a PEN with IANA and allocating a sub-arc
(e.g., `1.3.6.1.4.1.<pen>.1.1 = p9nPosixIdentity`). Development and
test builds may use a placeholder OID within the experimental range
`2.25.*` (UUID-derived, collision-free but unregistered).

Implementations MUST reject certificates that carry an OID the
runtime does not recognize — a future v2 extension is expected to use
a distinct OID rather than extending this structure in place.

### 3.2 Criticality

The extension is marked **non-critical**. Certificate consumers that
do not understand it MUST ignore it and fall back to other identity
sources. This lets SVIDs continue to pass through standard rustls
verification chains without modification.

### 3.3 ASN.1 definition

```asn1
P9nPosixIdentity ::= SEQUENCE {
    version          INTEGER (1..127),
    uid              INTEGER (1048576..2147483647),
    gid              INTEGER (1048576..2147483647),
    groups           SEQUENCE (SIZE (0..64)) OF INTEGER OPTIONAL,
    trustDomain      UTF8String OPTIONAL
}
```

Field semantics:

| Field | Notes |
|---|---|
| `version` | Currently `1`. Reserved for incompatible future revisions. |
| `uid` | The effective user ID this workload runs as. Range enforced at parse time (see §4). |
| `gid` | The primary group ID. Same range as `uid`. |
| `groups` | Supplementary groups. Each MUST lie within the SPIFFE range. At most 64, matching `NGROUPS_MAX` on common Linux distributions. Absent = empty supplementary group set. |
| `trustDomain` | Optional redundant carrier of the SPIFFE trust domain. Used only for cross-checking against the SPIFFE URI SAN — a mismatch fails parse. Ignored if absent. |

Total DER-encoded size is bounded above by ~800 bytes (64 groups of at
most 10 bytes each). Implementations MUST reject parses larger than 2048
bytes to keep the extension cheap to handle during TLS handshake.

### 3.4 Rationale for cert extension vs. alternatives

| Option | Pros | Cons | Decision |
|---|---|---|---|
| X.509 extension (chosen) | rides existing trust chain, no new protocol, rotates with SVID, zero new services | needs SPIRE plugin or custom signing | **selected** |
| Workload API extension returning PosixIdentity | runtime-dynamic, no cert change | requires SPIRE gRPC protocol change + compatible agents on both sides, ecosystem impact | rejected (deployment friction) |
| Out-of-band YAML/etcd directory | simplest to implement | two sources of truth; drift risk between SPIRE registrations and the directory | rejected (operability) |
| SPIFFE URI path components (`spiffe://example/uid/5000/...`) | no cert change | abuses SPIFFE ID semantics, no sub-tree parent/child relationships, fragile | rejected (abuse of spec) |

The cert-extension approach keeps the invariant "anything the TLS
handshake verifies is trustworthy" and avoids introducing a second
authentication/authorization path.

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

The SPIFFE range `[1048576, 2^31-1]` = `[2^20, 2^31-1]` provides
roughly 2.1 billion distinct identities, which is more than any
foreseeable deployment will need. The lower bound stays above Linux's
conventional `subuid` allocation window so SPIFFE-assigned uids do not
collide with user-namespace-mapped ranges on the same host.

Both importer and exporter MUST reject any `p9nPosixIdentity`
extension whose `uid`, `gid`, or any supplementary group falls outside
`[1048576, 2147483647]`. The check happens during certificate parsing,
before the values ever reach the session layer.

Administrators assigning uids through SPIRE registration MUST treat
allocations as **immutable and non-reusable**:

- Once `spiffe://example.com/workload-X` is bound to `uid=5000001`,
  that binding cannot change. A new registration for the same
  workload reuses the same uid.
- When a workload is decommissioned, its uid is **tombstoned** — the
  SPIRE registration is retained with a `deprecated` flag so the uid
  is not re-issued to a different workload.
- Two registrations pointing at the same uid are a configuration error.
  The SPIRE plugin that synthesizes the extension SHOULD detect this
  during `CreateRegistrationEntry` and refuse.

## 5. Identity Resolution Flow

### 5.1 Importer startup (privilege bootstrap)

```
Process starts as root (or with the minimal cap set below)
  │
  ├─► Load the SVID cert + key
  │     Source: SPIRE Workload API socket, or PEM files, or a
  │             test-only --override-svid path.
  │
  ├─► Validate the cert chain against the trust bundle
  │     (existing p9n-auth logic — unchanged)
  │
  ├─► Parse p9nPosixIdentity extension
  │     Reject if --require-posix-identity is set and no extension
  │     is present. Reject if uid/gid are out of range. Reject if
  │     trustDomain is present and disagrees with the SPIFFE URI SAN.
  │
  ├─► setgroups(groups)
  ├─► setgid(gid)
  ├─► setuid(uid)          ◄── irreversible; any subsequent setuid
  │                             attempt within the process fails
  ├─► prctl(PR_SET_NO_NEW_PRIVS, 1)
  ├─► Drop the capabilities that were only needed for the above
  │   (CAP_SETUID, CAP_SETGID, CAP_CHOWN, CAP_DAC_OVERRIDE)
  │
  ├─► Mount FUSE
  │     fuse3's `unprivileged` feature delegates to the setuid-root
  │     `fusermount3` helper, which continues to work after the
  │     importer process has dropped privs.
  │
  └─► Enter the RPC main loop as the SPIFFE-derived uid
```

The minimal required capabilities at start are `CAP_SETUID`,
`CAP_SETGID`, and whatever FUSE needs (none if using
`fusermount3` setuid helper). Running as full `root` is acceptable
but not required.

If the importer is launched from a systemd unit, the unit should:
- Use `User=root` (or `AmbientCapabilities=CAP_SETUID CAP_SETGID`).
- Use `NoNewPrivileges=` — carefully, because this prevents the
  setuid path; the importer must apply `PR_SET_NO_NEW_PRIVS` itself
  *after* setuid, not via systemd.
- Bind a single SVID source to a single mount point.

### 5.2 Exporter accept

```
QUIC/TCP handshake completes
  │
  ├─► extract_spiffe_id_from_conn(&conn)   [existing path]
  │
  ├─► Parse p9nPosixIdentity from the peer leaf cert
  │     The same validation rules as importer startup apply.
  │     On parse failure or missing extension, record None.
  │
  ├─► Construct Session with:
  │     spiffe_id: Some("spiffe://...")
  │     peer_posix: Option<PosixIdentity>    ◄── new field
  │
  └─► Run handlers
```

When a handler needs to chown a newly-created file, it consults
`session.peer_posix` first:

- `Some(p)`: chown to `(p.uid, p.gid)`. This matches the client process
  uid exactly, so readback has no mismatch.
- `None`: fall back to `AccessControl::Policy.uid/gid` — the existing
  behavior, kept for backward compatibility with clients that have not
  yet adopted the extension.

### 5.3 No translation on the wire

Because both sides agree on the `(spiffe_id → uid)` mapping, no on-
wire translation is needed. `Stat.uid/gid` in `Rgetattr` responses
carry raw numeric values that are meaningful on both sides. The
importer no longer needs a squashing layer.

The `gid` field in `Tlcreate`/`Tmkdir`/`Tmknod`/`Tsymlink` is currently
ignored by the exporter. Under this design it continues to be ignored
when `peer_posix` is present (the authoritative gid comes from the
extension, not from the message), and continues to be ignored when
`peer_posix` is absent (the fallback path uses `Policy.gid`). The
field stays on the wire for protocol compatibility but has no new
semantics.

## 6. Interaction with Existing Access Control

The existing `AccessControl` layer is unchanged in spirit. It still:

- Resolves the per-identity root directory (multi-tenant isolation).
- Enforces permission masks (`PERM_READ`/`WRITE`/etc.) by SPIFFE ID.
- Caps walk depth.

What changes is the source of `ownership_for(session)`:

```
fn ownership_for(session) -> (uid, gid):
    if let Some(p) = session.peer_posix {
        return (p.uid, p.gid);
    }
    // fallback: existing static policy
    let policy = self.resolve(session.spiffe_id);
    (policy.uid, policy.gid)
```

`Policy.uid/gid` is retained but becomes a **fallback**, used only
when the peer SVID has no `p9nPosixIdentity` extension. This lets the
two modes coexist during rollout. The fallback can be removed in a
future release once all clients carry the extension.

## 7. Consistency and Operational Requirements

### 7.1 SPIRE server configuration

This design assumes SPIRE (or an equivalent SPIFFE CA) is the issuer
for both client and server SVIDs, and that SPIRE can be configured to
embed the `p9nPosixIdentity` extension at signing time. Three ways to
achieve this:

1. **SPIRE server plugin (recommended for production)**: A custom
   `UpstreamAuthority` or `X509SVIDTemplate` plugin that reads
   `(uid, gid, groups)` from the registration entry's selectors or
   custom attributes and emits the extension during issuance.
2. **Post-signing injection (recommended for testing)**: Sign the SVID
   normally via SPIRE, then patch the DER to append the extension and
   re-sign. Not production-grade — reserved for test harnesses and
   local development.
3. **Manual SVID issuance**: For single-tenant deployments without
   SPIRE, an operator can run a simple `openssl x509` workflow that
   produces SVIDs with the extension directly. Documented in
   `docs/RCGEN_USAGE.md` as the "manual path".

### 7.2 Registration invariants

SPIRE registrations MUST satisfy:

- **Uniqueness**: no two active registrations carry the same `uid`.
- **Stability**: a registration's `uid` is set once; updates to
  other fields (selectors, TTL) do not change it.
- **Non-reuse**: retired registrations are tombstoned, not deleted,
  until sufficient time has passed that no files bearing that uid
  remain on any exporter.
- **Range compliance**: `uid`, `gid`, and every supplementary group
  lie within `[1048576, 2147483647]`.

A SPIRE plugin enforcing these invariants at registration time is
strongly recommended but not required by this spec.

### 7.3 Drift detection

Operators SHOULD periodically scan the SPIRE server's registration
database and cross-check that:

- No two entries share a `uid`.
- No entry's `uid` falls outside the reserved range.
- Tombstoned entries' uids do not reappear in active entries.

This drift check is out of scope for the ninep project itself — it is
a SPIRE-admin task. ninep's only enforcement point is the parse-time
range check and the per-cert extension validity.

## 8. Testing Strategy

Running `cargo test` under an unprivileged user makes a real
`setuid(1048577)` impossible on the host. The tests need to exercise
the privilege-transition code paths nonetheless.

### 8.1 User namespace harness

The chosen approach is to run privilege-sensitive tests inside a
**Linux user namespace** (`unshare(CLONE_NEWUSER)`). Within the
namespace, the test process is "root" as far as the kernel is
concerned, and can freely call `setuid` to any uid mapped in
`/proc/self/uid_map`.

Structure:

```
cargo test
  │
  ├─► #[test] fn test_importer_setuid_from_svid() {
  │     spawn subprocess via unshare --user --map-root-user \
  │         --map-auto ...
  │     subprocess runs the actual test logic as "root" in the
  │     namespace; can setuid(5000001) because uid_map covers it.
  │     subprocess reports results to parent via pipe/JSON.
  │     parent asserts on the results.
  │ }
```

A test-helper module `tests/common/userns.rs` provides:

```rust
pub fn run_in_userns<F, T>(uid: u32, gid: u32, test: F) -> T
where F: FnOnce() -> T + Send, T: Send + Serialize + DeserializeOwned
```

Implementation uses `nix::sched::unshare(CloneFlags::CLONE_NEWUSER)`
to enter the namespace in a forked child, writes `uid_map`/`gid_map`
from the parent (required before the child can `setuid`), then runs
`test`.

### 8.2 Required `uid_map` entries

The map must cover:

- The host's running user, mapped to namespace uid 0 so the child has
  effective root.
- The SPIFFE range `[1048576, 1048576+N)` for some small `N` (enough
  for the test cases) mapped 1:1 or to arbitrary host subuids.

Example for a test using uid `1048577`:

```
# uid_map
0 $HOST_UID 1
1048576 $HOST_SUBUID_BASE 65536
```

The test's `$HOST_SUBUID_BASE` must be allocated to the host user via
`/etc/subuid`. Most modern distros set this up by default during user
account creation. CI environments may need to configure it explicitly.

### 8.3 What is tested

- **Parse**: given an SVID with a well-formed `p9nPosixIdentity`,
  the parser returns the expected values.
- **Parse, out of range**: uid = 1000 → parser rejects. uid = 2^32 →
  parser rejects.
- **Parse, trust domain mismatch**: URI SAN says `example.com`,
  extension says `other.com` → parser rejects.
- **Parse, missing extension**: cert has no extension → returns
  `None`, does not error.
- **setuid transition**: in a user namespace, load SVID with
  `uid=1048577`, call the privilege-bootstrap routine, verify
  `getuid()==1048577` afterward.
- **End-to-end importer + exporter in one namespace**: start an
  exporter as nsroot, start an importer that `setuid`s to a SPIFFE
  derived uid, perform a full attach-create-stat round trip, verify
  `stat.st_uid == importer_process_uid`.

Tests that do not need the privilege transition (e.g., extension
parsing from raw DER bytes) run directly, without the namespace
harness, so the common case stays fast.

### 8.4 What is not tested

- `fusermount3` setuid helper interaction. That is a property of the
  host's fuse3 installation and is out of scope for unit tests.
- Real SPIRE server plugin integration. That depends on a running
  SPIRE server and is covered separately in `SPIRE_SETUP.md` as a
  manual verification procedure.
- Windows or non-Linux platforms. Not supported.

## 9. Cert Generation Tooling

### 9.1 Production

Production SVIDs are issued by SPIRE. Adding the `p9nPosixIdentity`
extension requires a server-side plugin. The plugin contract:

- Input: a SPIRE registration entry plus its selectors.
- Lookup: the `(uid, gid, groups)` comes from a dedicated field on the
  registration entry (e.g., `posix_identity` selector) or from a
  companion database keyed on the entry's `spiffe_id`.
- Output: a DER-encoded extension injected into the SVID's TBS cert
  before signing.

The plugin itself lives outside the ninep repository — it is a SPIRE
deployment concern. This document specifies the extension format; the
plugin specifies the registration workflow.

### 9.2 Development and testing

The `rcgen` crate used by current integration tests does not support
arbitrary X.509 extensions. For tests, either:

- **Post-process**: generate a normal rcgen cert, then patch the DER
  to insert the extension, then re-sign. Feasible because rcgen
  exposes the CA key. A small helper utility in `tests/common/cert.rs`
  can do this.
- **Use `openssl`**: invoke the system `openssl x509 -extfile`
  workflow with a custom config that defines the extension. Slower
  but requires no rcgen patching. Appropriate for CI on hosts where
  `openssl` is guaranteed present.

The design prefers the post-processing path because it keeps the test
binary self-contained, but either approach satisfies the spec.

### 9.3 The `p9n-cert-tool` utility (proposed)

A small CLI, shipped with the ninep release, that reads a YAML
description like:

```yaml
spiffe_id: spiffe://example.com/workloads/app-alice
trust_domain: example.com
posix:
  uid: 1048577
  gid: 1048577
  groups: [1048577, 2097152]
validity_days: 30
```

and produces a signed SVID (+ key) suitable for local testing, dev
clusters, and reproducing issues without a full SPIRE deployment.
This tool is not part of the hot path — it is a convenience for
operators and developers.

## 10. Rollout and Compatibility

Deployments are expected to adopt this feature gradually:

- **Phase "fallback"**: exporter and importer both ship the parsing
  code, but SVIDs in the field may or may not carry the extension.
  Behavior when absent is identical to the current codebase. No
  user-visible change for clients that have not adopted the extension.
- **Phase "preferred"**: SVID issuance infrastructure (SPIRE plugin)
  is in place; new workloads are registered with posix identities.
  `--require-posix-identity` is opt-in on the importer; the exporter
  uses peer extension when present.
- **Phase "required"**: the `--require-posix-identity` flag is the
  default. Clients without the extension fail fast. Fallback to
  `Policy.uid/gid` is deprecated but still functional for emergency
  recovery.
- **Phase "cleanup"**: `Policy.uid/gid` fallback is removed. All
  deployments require SVIDs with the extension. This is a breaking
  change gated on a major version bump.

Each phase is independently adoptable and does not require both sides
to upgrade in lockstep. A phase "fallback" exporter interoperates with
a phase "preferred" importer and vice versa.

## 11. Risks and Open Questions

### 11.1 Risks

- **OID allocation**: production use requires a registered PEN. Using
  a placeholder OID in the meantime creates a migration obligation
  when the real OID is allocated. Mitigation: the parser reads the
  OID from a `const` in p9n-auth, so a single-line change plus a
  release note suffices.

- **SPIRE plugin availability**: the feature is only useful in
  deployments that can configure the SVID-issuance chain. Sites
  using vanilla SPIRE without a custom plugin cannot produce the
  extension and fall back to the static `Policy.uid/gid` path.
  Mitigation: document the `p9n-cert-tool` workflow for
  small-scale deployments; contribute an upstream plugin example.

- **uid exhaustion**: the reserved range covers ~2.1B identities.
  In principle this is inexhaustible; in practice, if a deployment
  churns through workloads quickly without tombstoning correctly,
  uid reuse could happen. Mitigation: mandatory tombstoning is
  documented above; operational audits are the backstop.

- **Fuse mount ownership**: after `setuid`, the importer process may
  not have permission to call `mount`. The `fusermount3` setuid
  helper handles this transparently, but only when the fuse3
  `unprivileged` feature is used. Deployments that mount as real
  root must do so before `setuid`.

- **Capability leakage**: if the importer forgets to drop
  `CAP_SETUID` after the transition, a compromised importer could
  `setuid` back to root. Mitigation: enforce
  `prctl(PR_SET_NO_NEW_PRIVS)` and explicit capability drop in the
  startup path; cover it with a test that reads `/proc/self/status`
  after transition.

- **Test environment `subuid` availability**: the user namespace
  harness depends on `/etc/subuid` entries. CI images that run as
  a bare user without subuids allocated will fail the namespace
  tests. Mitigation: document the required `/etc/subuid` setup and
  add a pre-test check that errors clearly if it is missing.

### 11.2 Open questions

1. **Groups semantics in 9P2000.N messages**: `Tlcreate` and friends
   carry a `gid` field but no group list. If a client's workload has
   supplementary groups, the server cannot honor them via the current
   message schema. Is this a real limitation or do we only care about
   primary gid for ownership? The design currently punts: the server
   uses the extension's primary gid for `chown`, and supplementary
   groups affect only the importer's own `setgroups` call on its
   local process.

2. **Per-mount identity scope**: can one importer process serve
   multiple FUSE mount points for the same SPIFFE identity? The
   current design answers "yes, as long as they all map to the same
   uid". But if different mounts need different identities, it must
   be "no, one process per identity". The design assumes the latter
   for simplicity; the former may be revisited if operationally
   painful.

3. **Rotation of the uid itself**: if an SVID is re-issued during
   rotation and the operator accidentally changes the uid, existing
   files on the server retain the old uid and become inaccessible
   to the renamed workload. Should the importer refuse to mount if
   its derived uid differs from the uid recorded in any FUSE mount's
   metadata? The design currently has no such safety check.

4. **Interaction with user namespaces at deployment time**: if the
   importer itself runs inside a user namespace (e.g., a rootless
   container), the `uid=1048577` inside the namespace may not equal
   `uid=1048577` on the host. File ownership visibility depends on
   the namespace's `uid_map`. The design assumes the importer runs
   in the host namespace; rootless container deployments need
   additional documentation.

5. **Trust domain scoping of the range**: the reserved
   `[1048576, 2^31-1]` range is *per trust domain*, not global. Two
   independent trust domains may both use uid `1048577` for different
   workloads. If a client mounts exports from both domains, uids
   collide. This design implicitly assumes one trust domain per
   client host; multi-domain clients need further thought.

These questions are intentionally left unanswered. They are tracked
here to be revisited when implementation begins or when a concrete
deployment scenario forces a decision.

## 12. Appendix: Example SVID Extension

DER-encoded `p9nPosixIdentity` for a workload with `uid=1048577`,
`gid=1048577`, groups `[1048577, 2097152]`, trust domain
`example.com`:

```
SEQUENCE {
  INTEGER   1                 -- version
  INTEGER   1048577           -- uid
  INTEGER   1048577           -- gid
  SEQUENCE {
    INTEGER 1048577
    INTEGER 2097152
  }
  UTF8String "example.com"
}
```

Hex (placeholder OID `2.25.1` shown for illustration only):

```
30 2e
  02 01 01               -- version 1
  02 04 00 10 00 01      -- uid 1048577
  02 04 00 10 00 01      -- gid 1048577
  30 0c
    02 04 00 10 00 01
    02 04 00 20 00 00
  0c 0b "example.com"
```

Embedded in an X.509 extension with OID TBD:

```
Extension {
  extnID: 2.25.1              -- placeholder
  critical: FALSE
  extnValue: OCTET STRING { <the SEQUENCE above> }
}
```

Real production use replaces `2.25.1` with the assigned PEN arc OID.
