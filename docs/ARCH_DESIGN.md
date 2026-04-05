# System Architecture

## 1. System Overview

ninep is a Rust implementation of the 9P2000.N remote filesystem protocol, structured as a workspace of 5 crates with strict dependency ordering:

```
                         ┌──────────────┐
                         │   p9n-proto  │  Wire types, codec, capabilities
                         └──────┬───────┘
                                │
                         ┌──────┴───────┐
                         │   p9n-auth   │  SPIFFE identity, JWT, TLS config
                         └──────┬───────┘
                                │
                         ┌──────┴───────┐
                         │ p9n-transport│  QUIC + TCP+TLS dual transport
                         └──────┬───────┘
                        ┌───────┴────────┐
                 ┌──────┴─────┐   ┌──────┴─────┐
                 │p9n-exporter│   │p9n-importer│
                 │  (server)  │   │  (client)  │
                 └────────────┘   └────────────┘
```

No circular dependencies. Each crate can be compiled and tested independently.

---

## 2. Protocol Layer (p9n-proto)

### 2.1 Wire Format

All messages follow the 9P standard frame: `size[4] type[1] tag[2] payload`. Little-endian encoding. The 7-byte header is unchanged from Plan 9's original design.

```
 0       4    5     7                    size
 ├───────┼────┼─────┼────────────────────┤
 │ size  │type│ tag │      payload       │
 └───────┴────┴─────┴────────────────────┘
```

### 2.2 Type System

```
types.rs
  └─ MsgType enum (#[repr(u8)])
       ├─ base messages:     type 6-127   (26 T/R pairs)
       └─ 9P2000.N extensions: type 128-253 (51 T/R pairs)

fcall.rs
  ├─ Msg enum              All message payloads (80+ variants)
  └─ Fcall struct           { size, msg_type, tag, msg }

wire.rs
  ├─ Qid                   { qtype, version, path } — 13 bytes
  ├─ Stat                  Full file attributes (20 fields)
  ├─ StatFs                Filesystem statistics
  ├─ SubOp                 Compound sub-operation
  └─ DirEntry, Flock, etc.
```

### 2.3 Codec

`codec.rs` provides `marshal(buf, fcall)` and `unmarshal(buf)` for all message types. The buffer (`buf.rs`) supports zero-copy via `into_vec()` (ownership transfer) and `from_bytes()` (borrow).

### 2.4 Message Classification

`classify.rs` maps each MsgType to one of three transport classes:

| Class | QUIC Channel | TCP Channel | Examples |
|-------|-------------|-------------|----------|
| **Metadata** | Datagram | Same stream | Tversion, Tcaps, Thealth, Twatch |
| **Data** | Bidirectional stream | Same stream | Twalk, Tread, Twrite, Tgetattr |
| **Push** | Unidirectional stream | tag=0xFFFF on same stream | Rnotify, Rleasebreak |

### 2.5 Capability Negotiation

After Tversion confirms `"9P2000.N"`, Tcaps/Rcaps exchanges capability bitmasks. The `CapSet` uses a `u64` bitmask for 33 known capabilities with linear fallback for custom strings.

```
Client: Tcaps ["security.spiffe", "fs.watch", "perf.compound"]
Server: Rcaps ["security.spiffe", "fs.watch"]   ← intersection
```

---

## 3. Authentication Layer (p9n-auth)

### 3.1 SPIFFE Identity

```
SpiffeIdentity
  ├─ spiffe_id: String        "spiffe://example.com/app/worker"
  ├─ trust_domain: String     "example.com"
  ├─ cert_chain: Vec<Vec<u8>> DER-encoded X.509 chain
  └─ private_key: Vec<u8>     DER-encoded private key
```

Loaded from PEM files (`x509_svid.rs`) or watched for rotation (`workload_api.rs` FileWatch mode).

### 3.2 TLS Configuration

`tls_config.rs` builds standard `rustls::ServerConfig` / `ClientConfig` — used by both QUIC (via quinn) and TCP (via tokio-rustls) without modification.

For SVID rotation, `SpiffeCertResolver` implements `rustls::server::ResolvesServerCert` with `Arc<RwLock<Arc<CertifiedKey>>>` — certificates are hot-swapped without dropping connections.

### 3.3 JWT Capability Tokens

`jwt_svid.rs` provides:
- `verify_jwt_svid()` — verify JWK-signed tokens from external SPIFFE providers
- `encode_cap_token()` / `verify_cap_token()` — HMAC-SHA256 signed tokens for Tcapgrant/Tcapuse

Custom claims: `p9n_rights` (permission bitmask), `p9n_depth` (walk depth limit).

---

## 4. Transport Layer (p9n-transport)

### 4.1 Dual Transport Architecture

```
p9n-transport/
  ├─ framing.rs           Generic AsyncRead/AsyncWrite framing (shared)
  ├─ quic/
  │   ├─ config.rs         Quinn endpoint builder
  │   ├─ connection.rs     QuicTransport (datagram + stream + push)
  │   ├─ datagram.rs       Send with retry, recv with tag dispatch
  │   ├─ streams.rs        Bidirectional stream RPC
  │   ├─ framing.rs        Delegates to generic framing
  │   └─ zero_rtt.rs       0-RTT session detection
  └─ tcp/
      ├─ config.rs         tokio-rustls server/client setup
      └─ connection.rs     TcpTransport (single stream, Mutex<Writer>)
```

### 4.2 QUIC Transport

```
QuicTransport::new(conn)
  │
  ├─ Background task: datagram reader
  │    └─ read_datagram() → DashMap<tag, oneshot::Sender> dispatch
  │       tag == NO_TAG → push_tx channel
  │
  ├─ Background task: push stream acceptor
  │    └─ accept_uni() → spawn reader → push_tx channel
  │
  ├─ rpc(fc):
  │    ├─ Metadata → datagram (register inflight, await tag match, 30s timeout)
  │    │              fallback to stream if > MTU
  │    └─ Data → stream_rpc (open_bi, write, read, close)
  │
  └─ send(fc): classify → datagram or stream (fire-and-forget)
```

### 4.3 TCP Transport

Single bidirectional TLS stream. All messages (request, response, push) multiplexed by tag:

```
Client writer ──[Fcall tag=N]──► TCP stream ──► Server reader
Client reader ◄──[Fcall tag=N]── TCP stream ◄── Server writer
                  [Fcall tag=0xFFFF = push]
```

Writer protected by `Mutex` (handler responses and push notifications may write concurrently).

---

## 5. Exporter (Server) Architecture

### 5.1 Runtime Structure

```
Exporter process
  │
  ├─ tokio runtime (multi-threaded, N = CPU cores)
  │
  ├─ QUIC endpoint (quinn)
  │    └─ accept() → spawn QuicConnectionHandler per connection
  │         └─ select! {
  │              accept_bi → spawn handle_stream per request (concurrent)
  │              read_datagram → spawn handle_datagram (concurrent)
  │              watch_rx → push::send_notify (inline)
  │            }
  │
  ├─ TCP listener (tokio-rustls, optional)
  │    └─ accept_tls() → spawn TcpConnectionHandler per connection
  │         └─ select! {
  │              read_message → dispatch → write_message (serial)
  │              watch_rx → write_message tag=NO_TAG (inline)
  │            }
  │
  ├─ Session GC task (periodic, configurable interval)
  │
  └─ notify OS watcher thread (inotify, independent of tokio)
       └─ callback → DashMap dispatch → per-connection mpsc channels
```

### 5.2 Shared Context

All server-wide state is bundled in `Arc<SharedCtx>`, cloned once per spawned stream/request:

```
SharedCtx
  ├─ backend: LocalBackend        Filesystem operations
  ├─ access: AccessControl        3-level policy lookup
  ├─ session_store: SessionStore  Per-SPIFFE-ID partitioned
  ├─ watch_mgr: WatchManager      DashMap-based event dispatch
  ├─ trust_store: TrustBundleStore
  ├─ server_spiffe_id: String
  ├─ cap_signing_key: [u8; 32]    HMAC key for JWT tokens
  └─ config: ExporterConfig       Runtime configuration
```

### 5.3 Per-Connection Session

Interior mutability enables concurrent handler access:

```
Session (Arc-shared across stream tasks)
  ├─ version: Mutex<Option<String>>       Written once (Tversion)
  ├─ msize: AtomicU32                      Written once, read often
  ├─ caps: Mutex<CapSet>                   Written once (Tcaps)
  ├─ spiffe_id: Option<String>            Immutable after construction
  ├─ session_key: Mutex<Option<[u8;16]>>  Written once (Tsession)
  ├─ fids: FidTable (DashMap)              Concurrent read/write
  ├─ watch_ids: Mutex<HashSet<u32>>       Infrequent writes
  ├─ active_caps: DashMap<u32, CapToken>  Per-fid dynamic permissions
  ├─ active_leases: DashMap<u64, Lease>   Per-lease state tracking
  └─ inflight: DashMap<u16, CancellationToken>  For Tflush cancellation
```

### 5.4 Request Processing Pipeline

```
Incoming Fcall
  │
  ├─ fid_from_msg(fc) → extract fid for permission check
  │
  ├─ Fid validation: session.fids.contains(fid)?
  │   (skip for negotiation messages)
  │
  ├─ check_perm(session, access, spiffe_id, fid, required):
  │   ├─ Layer 1: AccessControl.check(spiffe_id, perm)  ← static policy
  │   └─ Layer 2: session.check_cap(fid, perm)          ← dynamic JWT token
  │
  ├─ Handler dispatch (37 handlers, match on MsgType)
  │   └─ File I/O handlers: spawn_blocking for syscalls
  │
  └─ Response Fcall → framing → QUIC stream or TCP write
```

### 5.5 Handler Organization

37 handler modules grouped by function:

```
handlers/
  Negotiation:  version, negotiate, auth, attach, session
  Filesystem:   walk, create, dir, io, stat, remove, rename, clunk
  Extended I/O: allocate, copy_range, hash, lock, xattr, xattrwalk, acl, mknod
  Watch:        watch (Twatch/Tunwatch via WatchManager)
  Security:     spiffe (TstartlsSpiffe/Tfetchbundle/Tspiffeverify), capgrant
  Distributed:  lease, consistency, compound
  Observability: trace, health, serverstats
  Transport:    quicstream, stream_io, compress, ratelimit
  Catch-all:    stubs (returns ENOSYS for unimplemented messages)
```

### 5.6 File I/O Pattern

All blocking syscalls are offloaded to tokio's blocking thread pool:

```rust
// 1. Extract path/fd from DashMap (quick, no blocking)
let path = fid_state.path.clone();
let raw_fd = fid_state.open_fd.as_ref().unwrap().as_raw_fd();
drop(fid_state);  // release DashMap lock

// 2. Blocking I/O on dedicated thread
let data = tokio::task::spawn_blocking(move || {
    util::with_borrowed_file(raw_fd, |file| {
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; count as usize];
        let n = file.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    })
}).await??;
```

### 5.7 Watch Manager

```
notify::RecommendedWatcher (single OS watcher)
  │ inotify events
  ▼
DashMap<PathBuf, Vec<WatchRegistration>>  ← per-shard read lock (no global lock)
  │ map EventKind → WATCH_* mask bits
  ▼
Per-connection mpsc::Sender<WatchEvent>  ← try_send (non-blocking)
  │
  ▼
ConnectionHandler select! → push::send_notify → QUIC uni stream or TCP write
```

### 5.8 Access Control

```
AccessControl
  │
  ├─ resolve(spiffe_id) → Policy
  │   ├─ by_id["spiffe://a.com/app/worker-1"]    Exact match
  │   ├─ by_domain["a.com"]                       Domain match
  │   └─ default                                   PERM_ALL
  │
  ├─ resolve_root(spiffe_id) → PathBuf
  │   └─ Domain match: "spiffe://a.com/app/reader" → /export/app/reader/
  │
  ├─ check(spiffe_id, required_perm) → Result
  │
  ├─ check_depth(spiffe_id, walk_depth) → Result
  │
  ├─ check_admin(spiffe_id) → Result  (for chown/chmod)
  │
  └─ apply_ownership(spiffe_id, path) → chown to Policy.uid/gid
```

### 5.9 Session Store

Per-SPIFFE-ID partitioned for isolation:

```
SessionStore
  DashMap<String, DashMap<[u8;16], SavedSession>>
         │                │
         │                └─ session key → { flags, saved_at }
         └─ SPIFFE ID partition

  save(key, spiffe_id, flags)   ← on connection close
  resume(&key, &spiffe_id)      ← on Tsession (one-time consume)
  gc()                          ← periodic cleanup (configurable TTL)
```

---

## 6. Importer (Client) Architecture

### 6.1 Connection Setup

```
Importer::connect() / connect_tcp()
  │
  ├─ Establish QUIC or TCP+TLS connection
  ├─ Derive session key: export_keying_material("9P2000.N session")
  ├─ Create QuicRpcClient (QUIC) or TcpRpcClient (TCP)
  │    └─ Wrapped in RpcHandle enum for unified interface
  ├─ Tversion → Rversion (negotiate version + msize)
  ├─ Tcaps → Rcaps (negotiate capabilities)
  ├─ Tattach → Rattach (mount root, get root qid)
  └─ Tsession → Rsession (establish session with TLS-derived key)
```

### 6.2 RPC Layer

```
RpcHandle (enum: Quic | Tcp)
  │
  └─ call(msg_type, msg) → Result<Fcall>
       ├─ TagGuard RAII (auto-free on drop/error/timeout)
       ├─ Register in inflight: DashMap<tag, oneshot::Sender>
       ├─ Send via transport (datagram/stream or TCP serial)
       ├─ Await response (30s timeout)
       └─ Check Rlerror → Err, else Ok

Background reader task:
  └─ Read all responses → dispatch by tag
       tag == NO_TAG → push_tx channel
       tag == N → inflight[N].send(fc)
```

### 6.3 FUSE Filesystem

Native async via `fuse3` — no `block_on()` bridging:

```
P9Filesystem implements fuse3::Filesystem
  │
  ├─ lookup(parent, name):
  │    FidGuard(alloc) → Twalk → Tgetattr → consume() or auto-clunk
  │
  ├─ open(ino, flags):
  │    FidGuard(alloc) → Twalk(clone) → Tlopen → consume()
  │
  ├─ read(fh, offset, size):
  │    Tread { fid: fh as u32 } → Rread { data }
  │
  ├─ write(fh, offset, data):
  │    Twrite → Rwrite { count }
  │
  ├─ release(fh):
  │    Tclunk { fid: fh }
  │
  └─ readdir(parent, offset):
       FidGuard → Twalk(clone) → Tlopen → Treaddir → Tclunk → parse entries
```

### 6.4 Caching

```
InodeMap: DashMap<u64, (fid, Qid)>    ino ↔ (fid, qid) bidirectional
          DashMap<u64, u64>            qid.path → ino

AttrCache: Mutex<LruCache<ino, (Stat, Instant)>>   TTL-based, 4096 entries
           Invalidated by push Rnotify events

FidPool: AtomicU32 monotonic allocator (skips NO_FID/PREV_FID)
         FidGuard: RAII auto-clunk on error paths
```

---

## 7. Data Flow: Reading a File

```
User: cat /mnt/9p/hello.txt

    FUSE kernel                 p9n-importer              p9n-exporter
        │                           │                          │
  1.    │ FUSE_LOOKUP(1,"hello.txt")│                          │
        │──────────────────────────►│                          │
        │                           │ Twalk{fid:0,newfid:1,    │
        │                           │       ["hello.txt"]}     │
        │                           │─────QUIC stream 0───────►│ walk.rs:
        │                           │                          │  resolve → stat
        │                           │◄────Rwalk{[Qid]}─────────│
        │                           │ Tgetattr{fid:1}          │
        │                           │─────QUIC stream 1───────►│ stat.rs:
        │                           │◄────Rgetattr{Stat}───────│  spawn_blocking
        │◄──ReplyEntry{ino:2,attr}──│                          │
        │                           │                          │
  2.    │ FUSE_OPEN(2, O_RDONLY)    │                          │
        │──────────────────────────►│                          │
        │                           │ Twalk{fid:1,newfid:2,[]} │ (clone fid)
        │                           │─────QUIC stream 2───────►│
        │                           │◄────Rwalk{[]}────────────│
        │                           │ Tlopen{fid:2,flags:0}    │
        │                           │─────QUIC stream 3───────►│ io.rs:
        │                           │◄────Rlopen{qid,iounit}───│  nix::open
        │◄──ReplyOpen{fh:2}─────────│                          │
        │                           │                          │
  3.    │ FUSE_READ(fh:2,off:0,4K)  │                          │
        │──────────────────────────►│                          │
        │                           │ Tread{fid:2,0,4096}      │
        │                           │─────QUIC stream 4───────►│ io.rs:
        │                           │                          │  spawn_blocking
        │                           │                          │  seek + read
        │                           │◄────Rread{17 bytes}──────│
        │◄──ReplyData───────────────│                          │
        │                           │                          │
  4.    │ FUSE_RELEASE(fh:2)        │                          │
        │──────────────────────────►│                          │
        │                           │ Tclunk{fid:2}            │
        │                           │─────QUIC stream 5───────►│ clunk.rs:
        │                           │◄────Rclunk{}─────────────│  fids.remove(2)
        │◄──ReplyEmpty──────────────│                          │   → close(fd)
```

---

## 8. Concurrency Model

### 8.1 Exporter

```
Per QUIC connection:
  1 connection handler task (select! loop)
  N stream handler tasks (tokio::spawn per accept_bi, concurrent)
  M blocking I/O tasks (tokio::spawn_blocking, up to 512)

Per TCP connection:
  1 connection handler task (serial read → dispatch → write)
  M blocking I/O tasks (same pool)

Global:
  1 session GC task (periodic)
  1 notify OS watcher thread (independent of tokio)
```

### 8.2 Importer

```
1 tokio runtime
  ├─ fuse3 async filesystem (handles FUSE kernel ops)
  ├─ RPC background datagram reader (QUIC) or stream reader (TCP)
  ├─ RPC background push stream acceptor (QUIC only)
  └─ Push receiver task (cache invalidation)
```

### 8.3 Synchronization Primitives

| Data Structure | Primitive | Contention |
|---------------|-----------|------------|
| FidTable | DashMap (16 shards) | Low — per-fid lock |
| active_caps | DashMap | Low — per-fid |
| active_leases | DashMap | Low — per-lease |
| inflight (tag dispatch) | DashMap | Low — per-tag |
| WatchManager paths | DashMap | Low — per-path shard |
| Session.version/caps | Mutex | None — written once |
| Session.msize | AtomicU32 | None — lock-free |
| Session.authenticated | AtomicBool | None — lock-free |
| TCP writer | Mutex | Medium — serialized writes |

---

## 9. Configuration

`ExporterConfig` centralizes runtime parameters:

```rust
ExporterConfig {
    max_msize: 4 MiB,              // Tversion negotiation ceiling
    session_ttl: 5 min,             // Session store entry lifetime
    session_gc_interval: 60s,       // Cleanup sweep interval
    watch_channel_capacity: 256,    // Per-connection event buffer
    max_lease_duration: 300s,       // Lease grant ceiling
    max_cap_token_ttl: 86400s,      // JWT capability token ceiling
}
```

---

## 10. Error Handling

```
Handler errors → Box<dyn Error + Send + Sync>
  │
  ├─ util::map_io_error() → Linux errno (preserves raw_os_error when available)
  │   ├─ NotFound → 2 (ENOENT)
  │   ├─ PermissionDenied → 13 (EACCES)
  │   ├─ AlreadyExists → 17 (EEXIST)
  │   ├─ InvalidInput → 22 (EINVAL)
  │   ├─ TimedOut → 110 (ETIMEDOUT)
  │   └─ _ → 5 (EIO)
  │
  └─ Fcall { msg_type: Rlerror, tag, msg: Lerror { ecode } }

Blocking task errors → util::join_err() (shared, not duplicated)
Stale fid access → caught in dispatch before handler invocation
Tflush cancellation → CancellationToken + tokio::select!
```

---

## 11. Testing Architecture

```
                    ┌──────────────────────────────┐
                    │  rcgen (self-signed SPIFFE   │
                    │  X.509-SVID certificates)    │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────┴───────────────┐
                    │  quinn::Endpoint (loopback)  │
                    │  127.0.0.1:0 (random port)   │
                    └──────────────┬───────────────┘
                                   │
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
  ┌───────┴────────┐     ┌─────────┴─────────┐     ┌────────┴────────┐
  │ Proto tests    │     │ Auth tests        │     │ Integration     │
  │ (23 tests)     │     │ (8 tests)         │     │ tests (20)      │
  │                │     │                   │     │                 │
  │ codec round-   │     │ JWT sign/verify   │     │ Full QUIC stack │
  │ trips, tag     │     │ JWK parsing       │     │ version/attach  │
  │ allocator,     │     │ trust bundles     │     │ walk/read/write │
  │ classify,      │     │ SPIFFE ID extract │     │ mkdir/readdir   │
  │ capset         │     │                   │     │ lock/lease/hash │
  └────────────────┘     └───────────────────┘     │ session/caps    │
                                                   │ compound/stats  │
                                                   │ stale fid/      │
                                                   │ consistency     │
                                                   └─────────────────┘
                                                            │
                                                   ┌────────┴────────┐
                                                   │  tempfile dirs  │
                                                   │  (isolated per  │
                                                   │   test case)    │
                                                   └─────────────────┘
```

No FUSE mounts, no system privileges, no network access required. Tests are hermetic and run in CI.
