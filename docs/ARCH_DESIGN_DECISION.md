# Architecture & Design Decisions

This document captures the key architectural decisions made during the design and implementation of ninep, including alternatives considered, trade-offs evaluated, and rationale for the final choices.

---

## 1. Protocol Layer: Why Not Modify the Wire Format

**Decision**: Preserve the 9P wire format `size[4] type[1] tag[2] payload` exactly.

**Alternatives considered**:
- Add version field to header
- Switch to protobuf/flatbuffers encoding
- Add checksum field

**Rationale**: The 7-byte header is the DNA of 9P. Changing it would require every implementation to update their parsers. Instead, we extended the type space (128-253) for 9P2000.N while keeping the header untouched.

---

## 2. Capability Negotiation: Tcaps vs Monolithic Version String

**Decision**: Replace monolithic version strings with composable capability negotiation via Tcaps/Rcaps.

**Problem with version strings**: A client that supports a monolithic version must support ALL of it. There's no way to say "I support readdir but not locking". This forces both sides to implement everything or nothing.

**Design**: After Tversion confirms `"9P2000.N"`, Tcaps exchanges bitmask-indexed capability strings (`"security.spiffe"`, `"fs.watch"`, `"perf.compound"`). The intersection becomes the session's active feature set. The exporter only dispatches to handlers for negotiated capabilities.

**Trade-off**: Two round-trips (Tversion + Tcaps) instead of one. Accepted because the second trip is on the same QUIC connection (sub-millisecond) and the flexibility is worth it.

---

## 3. Transport: Why QUIC Over TCP

**Decision**: QUIC as the primary transport, not TCP+TLS.

**Advantages gained**:
- **Datagram/stream split**: Metadata messages go via QUIC datagrams (no HOL blocking, lowest latency), data messages go via independent streams (flow-controlled, ordered per-stream)
- **Built-in TLS 1.3**: No separate `Tstartls` handshake needed; SPIFFE mTLS happens in the QUIC handshake itself
- **0-RTT resumption**: QUIC session tickets + 9P Tsession enable reconnection without full re-negotiation
- **Connection migration**: Client IP can change without dropping the 9P session
- **Multiplexing**: Thousands of concurrent streams without userspace multiplexing

**Trade-off**: Not compatible with Linux kernel's `mount -t 9p` (which uses TCP). This is the single biggest compatibility cost. We accepted it because:
1. The importer provides a FUSE mount point, so applications don't need kernel 9P support
2. TCP can be added as a second transport later (the protocol layer is transport-agnostic)
3. The performance benefits of QUIC are substantial for remote file systems over WAN

---

## 4. Message Routing: Datagram vs Stream Classification

**Decision**: `classify.rs` maps each MsgType to one of three QUIC channels.

**Classification logic**:
- **Metadata → QUIC Datagrams**: Version, caps, auth, session, health, watch control, lease control, topology, rate limiting. These are small (<1KB), latency-sensitive, and don't need ordering between operations.
- **Data → QUIC Bidirectional Streams**: Walk, read, write, stat, readdir, compound, xattr. These may be large and need per-operation ordering.
- **Push → QUIC Unidirectional Streams**: Rnotify (watch events), Rleasebreak, Rstreamdata. Server-initiated, tag=0xFFFF.

**Datagram fallback**: If a metadata message exceeds `max_datagram_size()` (typically ~1200 bytes), it automatically falls back to a short-lived bidirectional stream. This happens transparently in the transport layer.

**Alternative considered**: All messages on streams (simpler). Rejected because metadata operations (Thealth, Tcaps) would suffer head-of-line blocking behind a large Tread on the same stream.

---

## 5. Concurrency Model: Per-Stream Task Spawning

**Decision**: Each incoming QUIC bidirectional stream spawns a separate tokio task.

**Evolution**:
1. **Initial design**: Serial processing in `select!` loop — one request at a time per connection. QUIC multiplexing completely wasted.
2. **Intermediate**: `&mut Session` required exclusive access, blocking parallelism.
3. **Final**: `Session` uses interior mutability (`AtomicU32`, `Mutex`, `DashMap`), allowing `&Session` (shared reference) in all handlers. Streams spawn tasks freely.

**Why not a thread pool**: tokio's work-stealing scheduler is more efficient than a fixed thread pool for I/O-bound work. The real CPU work (file I/O) is offloaded to `spawn_blocking`.

**Datagram handling**: Initially inline in the `select!` loop (blocking stream accept). Changed to also spawn a task, making the connection handler truly non-blocking — it only accepts QUIC primitives and dispatches.

---

## 6. File I/O: spawn_blocking vs io_uring

**Decision**: Use `tokio::task::spawn_blocking()` for all file system syscalls.

**Problem**: `std::fs::read()`, `nix::fcntl::open()`, `stat()` etc. are blocking syscalls. Running them on tokio async worker threads starves other connections.

**Options evaluated**:

| Approach | Pros | Cons |
|----------|------|------|
| `spawn_blocking` | Zero new deps, works everywhere, simple | Thread pool overhead (~512 threads) |
| `tokio-uring` (io_uring) | True async I/O, zero-copy | Pre-1.0, quinn compatibility unverified, containers block io_uring |
| `monoio` / `compio` | Thread-per-core, 2-3x throughput | Requires full runtime rewrite, no quinn support |
| Dedicated I/O thread pool | Controlled thread count | More code than spawn_blocking for same result |

**Rationale**: `spawn_blocking` is zero-cost adoption (no new dependencies), works on all Linux kernels, works in containers, and provides sufficient performance. tokio's blocking pool (default 512 threads) handles the I/O parallelism. io_uring can be added later behind an `IoBackend` trait without changing handler logic.

**Pattern applied**:
```rust
// Extract from DashMap (quick), then spawn blocking for the syscall
let path = fid_state.path.clone();
drop(fid_state);  // release DashMap lock before blocking

let data = tokio::task::spawn_blocking(move || {
    std::fs::read(&path)  // blocking I/O on dedicated thread
}).await??;
```

---

## 7. FUSE Client: fuse3 Over fuser

**Decision**: Migrate from `fuser` 0.15 (sync) to `fuse3` 0.8 (native async).

**Problem with fuser**: The `Filesystem` trait is synchronous. Every FUSE operation blocked a fuser thread pool thread on `rt.block_on(rpc.call(...).await)`. With 20 fuser threads and 2ms network RTT per RPC, the ceiling was ~10k ops/s.

**Options evaluated**:

| Crate | Async | Migration cost | Maturity |
|-------|-------|----------------|----------|
| fuser 0.15 (current) | No (block_on bridge) | — | Stable |
| fuser 0.17 | Experimental `AsyncFilesystem` | Low | Just released |
| **fuse3 0.8** | **Native async trait** | Medium | Active |
| polyfuse | Event dispatch (not trait) | High | Stable |
| fuse-backend-rs | VFS/ABI layer | Very high | Production (Kata) |

**Why fuse3 over fuser 0.17**: fuse3 was designed async-first, not retrofitted. Its trait returns `Result<ReplyType>` instead of using callback objects, which maps cleanly to our RPC pattern. The `unprivileged` feature avoids needing root for FUSE mounts.

**Trade-off**: Medium migration effort (rewrite filesystem.rs), different Reply API. Accepted because the async benefit eliminates the thread pool bottleneck entirely.

---

## 8. Session State: Interior Mutability vs Lock-Per-Request

**Decision**: `Session` fields use fine-grained interior mutability.

**Evolution**:
1. **v1**: `&mut Session` in all handlers. Per-stream parallelism impossible.
2. **v2**: `Arc<Mutex<Session>>` — lock for each request. Serialized all handlers.
3. **v3 (final)**: Split into concurrent-safe fields:

```rust
pub struct Session {
    pub version: Mutex<Option<String>>,    // written once (Tversion)
    pub msize: AtomicU32,                   // written once, read often
    pub caps: Mutex<CapSet>,                // written once (Tcaps)
    pub fids: FidTable,                     // DashMap — already concurrent
    pub watch_ids: Mutex<HashSet<u32>>,     // infrequent writes
    pub active_caps: DashMap<u32, CapToken>, // per-fid, concurrent
    pub inflight: DashMap<u16, CancellationToken>, // per-tag, concurrent
    pub spiffe_id: Option<String>,          // immutable after construction
    ...
}
```

**Key insight**: Most fields are written once during setup (version, caps) and read-only during operation. The hot-path fields (`fids`, `active_caps`, `inflight`) use `DashMap` (sharded lock-free). This allows truly concurrent handlers with no global serialization point.

---

## 9. Authentication: SPIFFE Over Traditional Auth

**Decision**: SPIFFE X.509-SVIDs as the identity mechanism, not username/password or Kerberos.

**Rationale**:
- 9P in modern infrastructure runs between **workloads**, not users. SPIFFE models workload identity natively.
- mTLS via X.509-SVID provides both authentication and encryption in one step (the QUIC handshake).
- SPIFFE IDs (`spiffe://domain/path`) map naturally to filesystem isolation (`/export/{workload_path}/`).
- Certificate rotation is handled by the SPIFFE Workload API, not by the 9P protocol.

**JWT-SVID for capability tokens**: We reuse the JWT-SVID claim format (`p9n_rights`, `p9n_depth`) for Tcapgrant tokens. These are HMAC-SHA256 signed by the exporter (not RSA/EC) because tokens are only verified by the same exporter that issued them — no need for public-key crypto.

---

## 10. Session Key: TLS Export vs Random Generation

**Decision**: Derive session keys from TLS `export_keying_material` (RFC 5705).

**Options evaluated**:

| Approach | Security | Uniqueness | Implementation |
|----------|----------|------------|----------------|
| Server generates random key, sends in Rsession | Depends on PRNG quality | Good if CSPRNG | Protocol extension needed (Rsession has no key field) |
| Client generates random key, sends in Tsession | Same PRNG concern | Same | Simple but key in transit |
| **TLS export_keying_material** | **Cryptographically secure** | **Deterministic per TLS session** | Both sides derive same key independently |

**Rationale**: `export_keying_material` derives from the TLS 1.3 master secret, which is established during the QUIC handshake. Both client and server derive the identical key without transmitting it. The key is cryptographically unpredictable, unique per TLS session, and bound to the connection.

**Reconnection flow**: The client saves the derived key. On reconnection (new TLS session → different derived key), the client sends the *old* key in Tsession. The server looks it up in the per-SPIFFE-ID session store. After successful resume, both sides can optionally re-derive using the new connection's TLS.

---

## 11. Access Control: Three-Level Policy Lookup

**Decision**: SPIFFE ID → Policy resolution uses a 3-level cascade.

```
1. Exact SPIFFE ID match:  by_id["spiffe://a.com/app/worker-1"]
2. Trust domain match:     by_domain["a.com"]
3. Default policy:         Policy::default() (PERM_ALL)
```

**Design reasoning**:
- **Level 1** enables per-workload rules (e.g., "worker-1 gets read-only, worker-2 gets read-write")
- **Level 2** enables per-organization rules (e.g., "all a.com workloads get isolated subdirectories")
- **Level 3** ensures backward compatibility (single-tenant mode with no SPIFFE config)

**Per-user root isolation**: When a domain policy is configured via `enable_isolation("a.com", perms)`, the exporter automatically derives per-workload subdirectories:
```
spiffe://a.com/app/reader  → /export/app/reader/
spiffe://a.com/app/writer  → /export/app/writer/
```
This happens transparently in `attach.rs` — the client doesn't need to know about the isolation.

---

## 12. Permission Model: Static Policy + Dynamic Capability Tokens

**Decision**: Two-layer permission check — static policy (always on) + dynamic JWT tokens (on-demand).

**Why two layers**:
- **Static policy** covers the common case: a workload's base permissions don't change during a connection.
- **Dynamic tokens** (Tcapgrant/Tcapuse) allow temporary privilege escalation scoped to a specific fid, with expiry. This is essential for workflows like "read-only by default, but the orchestrator grants write access for a deployment window."

**Token security properties**:
- HMAC-SHA256 signed (non-forgeable without the server's key)
- `sub` claim bound to SPIFFE ID (non-transferable between identities)
- `rights` capped by static policy ceiling (cannot escalate beyond what the policy allows)
- Time-limited (max 24 hours)
- One token per fid (new Tcapuse on same fid replaces the old token)

---

## 13. Session Store: Per-Identity Partitioning

**Decision**: `DashMap<String, DashMap<[u8; 16], SavedSession>>` — SPIFFE ID is the outer key.

**Alternative**: Flat `DashMap<[u8; 16], SavedSession>` with SPIFFE ID check in `resume()`.

**Problem with flat design**:
- All identities share the 128-bit key space
- A malicious client could probe session keys of other identities (rejected by SPIFFE check, but the probe reveals timing information)
- Same-identity key collisions (extremely rare but theoretically possible) could corrupt unrelated sessions

**Partitioned design benefits**:
- Different identities' sessions are in different DashMap shards — zero interference
- `resume()` doesn't need to check SPIFFE ID (the partition already ensures it)
- `gc()` can clean up per-identity without touching others
- Key collision only affects replicas of the same workload (acceptable — they share state anyway)

---

## 14. WatchManager: DashMap Over Global Mutex

**Decision**: Replace `Mutex<HashMap<PathBuf, Vec<Reg>>>` with `DashMap<PathBuf, Vec<Reg>>` + `AtomicU32`.

**Problem**: The `notify` crate's OS watcher thread fires a callback when filesystem events occur. If this callback locks the same Mutex that handler threads use for `add_watch`/`remove_watch`, the OS thread blocks — causing event backlog and potential event loss.

**DashMap approach**: The callback only takes a shard-level read lock on the specific path's bucket. Handler threads writing to a different path don't interfere. The OS watcher thread is never blocked by unrelated watch operations.

**Remaining Mutex**: `Mutex<RecommendedWatcher>` for the `notify` watcher itself — only locked during `watch()`/`unwatch()` calls (infrequent).

---

## 15. Buffer Management: Zero-Copy Path

**Decision**: `Buf::into_vec()` for zero-copy encode, `decode_owned()` for zero-copy decode.

**Problem**: The original design allocated 2-3 times per message:
```
encode: Buf::new(256) → marshal → buf.as_bytes().to_vec()  // two allocations
decode: vec![0u8; size] → Buf::from_bytes(data.to_vec())   // two allocations
```

For a 64KB `Rread`, this meant ~256KB of heap allocations per response.

**Fix**: `Buf::into_vec()` transfers ownership of the internal Vec without copying. `decode_owned()` accepts a Vec by value, avoiding the clone in `from_bytes()`. The message data is allocated once and passed through the pipeline.

---

## 16. Shared Context: Arc Consolidation

**Decision**: Bundle server-wide immutable state into a single `Arc<SharedCtx>`.

**Problem**: Each spawned stream task cloned 5 separate Arcs:
```rust
let backend = self.backend.clone();        // Arc +1
let access = self.access.clone();          // Arc +1
let watch_mgr = self.watch_mgr.clone();    // Arc +1
let session_store = self.session_store.clone(); // Arc +1
let ctx = ...                              // total: 5 atomic increments
```

At 10k streams/sec, this is 50k atomic operations/sec (plus 50k decrements on drop).

**Fix**: One `Arc<SharedCtx>` containing all server-wide state. Per-stream spawning does 2 clones (`ctx` + `session`) instead of 6. On ARM (where atomics are full memory barriers), this is a measurable improvement.

---

## 17. Tflush: CancellationToken Integration

**Decision**: Use `tokio_util::sync::CancellationToken` per in-flight request.

**Problem**: Tflush { oldtag } should cancel a running request. But handlers run in spawned tasks, potentially inside `spawn_blocking`. How to interrupt?

**Design**:
```rust
// handle_stream:
let cancel = session.register_inflight(tag);  // DashMap<u16, CancellationToken>
let result = tokio::select! {
    r = dispatch(fc) => r,           // normal execution
    _ = cancel.cancelled() => Err,   // Tflush triggered
};
session.deregister_inflight(tag);
```

**Limitation**: If the handler is inside `spawn_blocking` doing a slow `read()`, the `select!` won't abort the blocking thread — it will return the cancellation error when `spawn_blocking` eventually completes. True mid-syscall cancellation would require `io_uring` with cancellation support.

**Why CancellationToken over oneshot**: CancellationToken can be cloned and checked from multiple places. A handler could periodically check `token.is_cancelled()` during long operations (e.g., between chunks in a large copy).

---

## 18. uid/gid Mapping: Post-Create chown

**Decision**: `apply_ownership()` calls `chown` after file creation, using the SPIFFE policy's uid/gid.

**Options evaluated**:

| Approach | Security | Complexity | Requirements |
|----------|----------|------------|-------------|
| **Post-create chown** | Good (files owned correctly) | Low | CAP_CHOWN or root |
| setfsuid/setfsgid per-thread | Better (process-level isolation) | High | root, careful per-thread state |
| User namespaces + id-mapped mounts | Best (kernel-level isolation) | Very high | Linux 5.12+, mount_setattr |

**Rationale**: Post-create chown is the simplest approach that achieves correct file ownership. It works in `spawn_blocking` threads without per-thread state complexity. The exporter needs `CAP_CHOWN` (or root) to change ownership, which is acceptable for a file server process.

**Trade-off**: Between file creation and chown, there's a brief window where the file is owned by the server process uid. This is acceptable because:
1. The file is inside an isolated per-user root directory
2. The chown happens immediately after creation (same `spawn_blocking` call)
3. Other clients can't access the file during this window (fid namespace isolation)

---

## 19. Compound Operations: Recursive Dispatch with Box::pin

**Decision**: Tcompound dispatches sub-operations through the same `dispatch()` function.

**Problem**: Tcompound contains a list of SubOps, each of which is a complete 9P message. The handler needs to dispatch each sub-op through the full handler pipeline (including access control, permission checks, etc.). But `compound::handle()` calling `dispatch()` creates a recursive async function — Rust requires explicit boxing to avoid infinite-size futures.

**Solution**: `Box::pin(dispatch(session, ctx, watch_tx, sub_fc)).await` for each sub-op. This adds one heap allocation per sub-operation, which is acceptable since compound operations are designed to batch multiple small ops (walk + open + read) into one RTT.

**Alternative considered**: A separate `dispatch_subop()` that handles only the safe subset. Rejected because it would duplicate the permission check logic and miss any handler-specific behavior.

---

## 20. Test Architecture: Direct QUIC Without FUSE

**Decision**: Integration tests connect directly to the exporter via QUIC, bypassing FUSE.

**Problem**: FUSE tests need `fusermount3` and `/dev/fuse`, which may not be available in CI environments or containers.

**Solution**: Tests use `rcgen` to generate self-signed X.509-SVID certificates, create a `quinn::Endpoint` on loopback, and send raw 9P wire-format messages directly. This tests the full stack (QUIC → framing → dispatch → handler → spawn_blocking → filesystem → response) without needing FUSE.

**Test infrastructure**:
```
rcgen (self-signed SPIFFE certs)
  → quinn::Endpoint (loopback QUIC)
    → Buf + codec::marshal (raw 9P wire format)
      → exporter ConnectionHandler (full dispatch)
        → tempfile (temporary export directory)
          → verify results on disk
```

This allows testing concurrent operations, error paths, and filesystem behavior in a hermetic environment.

---

## 21. Symlink Handling: Don't Follow Final Component

**Decision**: `resolve_path()` and `LocalBackend::resolve()` use `symlink_metadata` to detect symlinks at the final path component and avoid calling `canonicalize()` on them.

**Problem**: `std::path::Path::canonicalize()` follows ALL symlinks, including the final component. When `Twalk` walks to `link.txt` (a symlink → `target.txt`), canonicalize resolves it to `target.txt`'s real path. The fid then points at the target, not the symlink. A subsequent `Treadlink` on this fid calls `read_link` on a regular file → **EINVAL**.

**Solution**: Before canonicalizing, check `symlink_metadata(path)`:
- If the final component **is** a symlink: canonicalize only the parent directory (to prevent path escapes), then append the symlink name. The fid points at the symlink itself.
- If the final component is **not** a symlink: canonicalize normally (resolves intermediate symlinks, checks jail boundary).

**Correctness**: 9P semantics require that walk gives a fid for the symlink itself, so that `readlink` returns the target path. Intermediate directory symlinks are still resolved (preventing path-escape attacks via `../` through symlinks), but the leaf symlink is preserved.

---

## 22. Cache Coherence: Lease-Based Invalidation Over Pure TTL

**Decision**: The importer acquires read leases on opened files and trusts the attr cache without TTL checks while a lease is held.

**Problem**: Pure TTL caching (1-second default) has two drawbacks:
1. Stale reads within the TTL window — another client may modify the file
2. Unnecessary round-trips after TTL expiry when the file hasn't changed

**Design**: Three-way coordination between `LeaseMap`, `AttrCache`, and `push_receiver`:

```
open() → Tlease(LEASE_READ) → server grants → LeaseMap.grant(fh, lease_id, ino)
                                                       ↓
getattr() → LeaseMap.has_lease(ino)? → AttrCache.get_leased() [skip TTL]
                                                       ↓
[server breaks lease on modification]                  ↓
Rleasebreak → push_receiver → LeaseMap.break_lease() → AttrCache.invalidate(ino)
                                                       ↓
release() → LeaseMap.release_by_fh(fh) → Tleaseack (if not already broken) → Tclunk
```

**LeaseMap data structures**: Three DashMaps for bidirectional lookup:
- `fh_to_lease: DashMap<u32, u64>` — release needs to find the lease
- `lease_to_ino: DashMap<u64, u64>` — lease break needs to find the inode
- `ino_lease_count: DashMap<u64, u32>` — getattr needs to check if any lease exists

**Fallback**: Lease acquisition is best-effort. If the server doesn't support leases (e.g., feature not negotiated), the `Tlease` call returns an error and the importer falls back to TTL-based caching. No behavioral change for older servers.

**Trade-off**: One extra round-trip per `open()` (the Tlease). Accepted because opens are infrequent compared to getattr calls, and the lease eliminates all getattr round-trips for the duration of the open.

---

## 23. Streaming I/O: Per-Stream State in Session

**Decision**: `Tstreamopen` creates a `StreamState` entry in `Session.active_streams`, tracking the underlying fid's raw fd, direction, and current offset.

**Problem**: The original streaming handler was a stub that echoed acknowledgments without actually performing I/O. Real streaming requires:
1. Mapping `stream_id` → `(fd, direction, offset)` across multiple `Tstreamdata` messages
2. File I/O on the blocking thread pool (same as regular read/write)
3. Automatic fsync on close for write streams

**Design**:
```rust
pub struct StreamState {
    pub raw_fd: i32,           // borrowed from fid's OwnedFd
    pub fid: u32,
    pub direction: u8,         // 0=read, 1=write
    pub offset: Mutex<u64>,    // advanced on each Tstreamdata
}
```

Stored in `Session.active_streams: DashMap<u32, StreamState>`. Stream IDs are allocated from a global `AtomicU32`.

**Write path**: `Tstreamdata` → `spawn_blocking(seek + write)` → advance offset → empty data ack.
**Read path**: `Tstreamdata` → `spawn_blocking(seek + read)` → advance offset → data in response.
**Close**: `Tstreamclose` → remove state; write streams trigger `fsync` for durability.

**Cleanup**: `Session::reset()` clears `active_streams` alongside fids/watches/leases.

---

## 24. SPIFFE Workload API: h2 + Hand-Written Protobuf Over tonic

**Decision**: Implement the gRPC Workload API client using raw `h2` (HTTP/2) + hand-written protobuf encoding/decoding, instead of the `spiffe` crate or `tonic`.

**Problem**: The `spiffe` crate (v0.11) pulls in `tonic`, `prost`, `hyper`, and `tower` — approximately 50+ transitive crates. This would double the dependency count for a feature that many deployments don't need (file-based SVID rotation is sufficient for most).

**Options evaluated**:

| Approach | New direct deps | Transitive | Build impact |
|----------|----------------|------------|-------------|
| `spiffe` crate | 1 | ~50+ | Very large (tonic/prost codegen) |
| `tonic` + `prost` | 3+ | ~40+ | Large (build.rs + protoc) |
| `h2` + `prost` | 2 | ~15 | Medium |
| **`h2` + hand-written** | **2 (`h2`, `http`)** | **~8** | **Small** |

**Why hand-written protobuf works here**: The Workload API only uses 2 message types (`X509SVIDRequest` which is empty, and `X509SVIDResponse` with 4 fields). A full protobuf library with codegen is overkill. The hand-written decoder is ~120 lines, handles unknown fields (forward-compatible), and has 8 unit tests.

**Feature gate**: All Workload API code is behind `#[cfg(feature = "workload-api")]`. Building without the feature adds zero dependencies and zero code. The gRPC module (`grpc/`) is only compiled when enabled.

**Architecture**:
```
grpc/frame.rs  — gRPC 5-byte frame encode/decode + cross-DATA-frame reassembly
grpc/proto.rs  — X509SVIDResponse protobuf decode + DER cert chain splitter
grpc/client.rs — h2 Unix socket connect + FetchX509SVID streaming RPC
```

**Integration**: The client produces `SpiffeIdentity` values sent through the existing `watch::Sender<Arc<SpiffeIdentity>>` channel. The `SpiffeCertResolver` and TLS config code are completely unchanged — they only consume from `watch::Receiver`.

**Reconnection**: A background task loops: `connect → fetch → stream.next() → tx.send()`. On disconnection, exponential backoff (5s → 60s cap) before reconnect. The last known SVID remains active in the `watch::channel` until a new one arrives.
