# Thread Model Analysis

## Global Architecture Overview

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                         p9n-exporter (server)                                 │
│                                                                               │
│  Tokio multi-threaded Runtime (#[tokio::main], workers = CPU cores)           │
│  ├─ Main event loop: select! { QUIC accept, TCP accept, RDMA accept, Ctrl-C } │
│  ├─ One tokio task per connection (QuicConnectionHandler / TcpHandler)        │
│  ├─ [QUIC] Additional spawn per stream/datagram                               │
│  ├─ [TCP]  Serial processing per connection                                   │
│  ├─ [RDMA] One handler task + background recv CQ poller per connection        │
│  ├─ All filesystem I/O → spawn_blocking (32 call sites)                       │
│  └─ Session GC periodic task                                                  │
│                                                                               │
│  OS thread (notify crate inotify):                                            │
│  └─ Event callback → DashMap lookup → try_send(mpsc) → watch_rx               │
├───────────────────────────────────────────────────────────────────────────────┤
│                         p9n-importer (client)                                 │
│                                                                               │
│  Tokio multi-threaded Runtime (#[tokio::main], workers = CPU cores)           │
│  ├─ fuse3 native async (no block_on, no spawn_blocking)                       │
│  ├─ [QUIC] Background datagram reader + push stream acceptor                  │
│  ├─ [TCP]  Background single reader task + Arc<Mutex> writer                  │
│  ├─ [RDMA] Background recv CQ poller (AsyncFd) + per-fid RDMA buffers         │
│  ├─ RPC: tag + oneshot channel for request/response matching                  │
│  └─ FidGuard RAII drop → spawn Tclunk                                         │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. p9n-exporter Thread Model

### 1.1 Tokio Runtime

`#[tokio::main]` + `tokio = { features = ["full"] }` = **multi-threaded work-stealing scheduler**. Default worker thread count = CPU core count.

### 1.2 Connection Handling — QUIC vs TCP

**QUIC (concurrent):** One handler task per connection, internal `select!` loop:
- `accept_bi()` → each stream **spawns an independent task**
- `read_datagram()` → each datagram **spawns an independent task**
- `watch_rx.recv()` → push sent on the handler task itself

Multiple streams on the same QUIC connection are **processed in parallel**.

**TCP (serial):** One handler task per connection, `select!` loop:
- `read_message()` → **serial** dispatch handler → write response
- `watch_rx.recv()` → push multiplexed on the same TCP stream
- Writer protected by `Arc<Mutex<WriteHalf>>`

**RDMA (serial with one-sided fast path, feature `rdma`):** One handler task per connection, `select!` loop:
- `transport.recv_push()` → serial dispatch → `transport.send()` response
  - `Tread`/`Twrite` intercepted for RDMA one-sided path (if Trdmatoken registered)
  - Other messages dispatched to standard handlers
- `watch_rx.recv()` → push sent via RDMA Send (tag=NO_TAG)
- `push_rx.recv()` → push sent via RDMA Send

Additionally, one **background recv CQ poller** task per connection:
- Waits on `AsyncFd` (completion channel fd) — zero CPU while idle
- Drains CQ completions → decode Fcall → dispatch by tag via DashMap
- Re-arms CQ notification after draining
- Reposts recv buffer slots from pool after consumption

### 1.3 Filesystem I/O — spawn_blocking + Backend trait

All filesystem operations are offloaded to the **tokio blocking thread pool** (default cap 512 threads) via `tokio::task::spawn_blocking`. Handlers are async and delegate to `Backend` trait methods inside the blocking closure. The `Backend` trait is generic — `LocalBackend` (the default) calls POSIX syscalls; future backends could call cloud APIs.

Example (`handlers/io.rs`):
```rust
let handle = fid_state.handle.clone().ok_or(...)?; // Arc<H> clone (~1ns atomic)
let ctx = ctx.clone();                              // Arc<SharedCtx<B>> clone
let data = tokio::task::spawn_blocking(move || {
    ctx.backend.read(&handle, offset, count)        // Backend trait dispatch
}).await??;
```

Since `Backend` is generic (not `dyn`), the trait dispatch is monomorphized at compile time — zero runtime overhead compared to direct syscalls.

### 1.4 Watch Manager — The Critical OS Thread Boundary

This is the **only non-tokio thread** in the exporter:

```
Filesystem event
  → notify crate's inotify OS thread (not tokio)
    → dispatch_event(): DashMap lookup → try_send(WatchEvent)  [non-blocking!]
      → mpsc channel
        → connection handler task's watch_rx.recv()
          → send Rnotify push via QUIC uni-stream / TCP
```

Key design decisions:
- `try_send()` instead of `send()` — OS thread **never blocks**
- `DashMap` sharded locks — no global lock blocking the inotify thread
- Events silently dropped when channel is full

### 1.5 Shared State Synchronization

| Data Structure | Type | Purpose |
|----------------|------|---------|
| `Session.fids` | `DashMap<u32, FidState<H>>` | Per-connection FID table, handles wrapped in `Arc<H>` for cheap cloning into spawn_blocking |
| `Session.active_caps` | `DashMap` | Capability tokens |
| `Session.inflight` | `DashMap<u16, CancellationToken>` | Tflush cancels in-flight requests |
| `Session.msize` | `AtomicU32` | Message size limit |
| `SessionStore` | Nested `DashMap` | Cross-connection session resumption |
| `WatchManager.watcher` | `Mutex` | Held briefly only during watch/unwatch registration |
| `Session.rdma_tokens` | `DashMap<u32, RdmaToken>` | Per-fid RDMA buffer registration (RDMA only) |
| RDMA `MrPool.free` | `crossbeam::ArrayQueue` | Lock-free slot checkout/return (CAS per op) |
| RDMA `RdmaTransport.inflight` | `DashMap<u16, oneshot>` | Per-tag response dispatch |
| RDMA `RdmaTransport.push_rx` | `Mutex<mpsc::Receiver>` | Single consumer (connection handler) |

### 1.6 Session Cleanup

On connection close (`QuicConnectionHandler::cleanup()`):
1. Session state saved to global `SessionStore`
2. All watches for the connection unregistered (acquires `Mutex` on OS watcher)
3. All FIDs cleared (`DashMap::clear()`)
4. Watch channels removed from `WatchManager`

### 1.7 Garbage Collection

A dedicated tokio task runs periodically to clean expired sessions from the `SessionStore`. Interval is configurable via `config.session_gc_interval`.

---

## 2. p9n-importer Thread Model

### 2.1 Core Property: Fully Async, Zero Blocking

The biggest difference from the exporter: the importer has **no `spawn_blocking` or `block_on` calls**. All file I/O is delegated to the remote exporter via RPC.

Uses the `fuse3` crate (with `tokio-runtime` feature), so FUSE operations are natively async:
```rust
// filesystem.rs — all methods are async fn
async fn read(&self, _req: Request, inode: u64, ...) -> Result<ReplyData> {
    let fc = self.rpc.call(MsgType::Tread, Msg::Read { fid, offset, count }).await?;
    // ...
}
```

`/dev/fuse` read/write is integrated into the tokio event loop by fuse3 internally — no separate thread pool needed.

### 2.2 RPC Request/Response Matching

```
FUSE handler task
  → rpc.call(msg_type, msg)
    → TagAllocator allocates tag (RAII guard, auto-freed on drop)
    → Register oneshot::Sender in DashMap<tag, sender>
    → Classify message:
        Metadata → prefer datagram, fallback to stream
        Data     → always open_bi() stream
    → timeout(30s, oneshot::Receiver)
  ← Response arrives

Background reader task
  → read_datagram() / read_message()
    → Decode → lookup tag in DashMap → oneshot::send(response)
    → tag=NO_TAG → push_tx.send() → push handling
```

### 2.3 QUIC Background Tasks (3)

| Task | Function | Lifetime |
|------|----------|----------|
| Datagram reader | Loop `conn.read_datagram()` → dispatch by tag | Exits on connection close |
| Push stream acceptor | Loop `conn.accept_uni()` → spawn child reader | Exits on connection close |
| Per-stream reader | Read single bi-stream response | Exits after response read |

### 2.4 TCP Background Tasks (1)

A single reader task reads the entire TCP stream, demultiplexing by tag. Writes are serialized by `Arc<Mutex<WriteHalf>>`.

### 2.5 RDMA Background Tasks (1, feature `rdma`)

| Task | Function | Lifetime |
|------|----------|----------|
| Recv CQ poller | `AsyncFd` on completion channel → decode → dispatch by tag | Exits on connection close or QP error |

The poller waits on epoll (zero CPU) until the completion channel signals readiness, then drains all CQ completions. Send completions use busy-poll (sub-microsecond). Per-fid RDMA buffers are managed by `RdmaRpcClient.fid_buffers: DashMap<u32, LeasedSlot>`.

### 2.6 FidGuard RAII Cleanup

```rust
impl Drop for FidGuard {
    fn drop(&mut self) {
        if !self.consumed {
            tokio::spawn(async move {
                let _ = rpc.call(MsgType::Tclunk, Msg::Clunk { fid }).await;
            });
        }
    }
}
```

Error paths never block — an async task is spawned to send Tclunk.

---

## 3. p9n-transport / p9n-auth Layer

### 3.1 QUIC Message Classification and Routing

```
MessageClass::Metadata → QUIC Datagram (small, idempotent: Version/Attach/Stat/Caps...)
                         Fallback to stream on failure, retry 3x with backoff 10/20/40ms
MessageClass::Data     → QUIC Bidirectional Stream (Read/Write/Readdir...)
MessageClass::Push     → QUIC Unidirectional Stream (Rnotify/Rleasebreak...)
```

### 3.2 TLS Certificate Hot Rotation

Two background tasks cooperate:

```
[File Watcher Task, polls every 30s]       [Cert Updater Task]
   │ Check cert/CA file mtime                │ Wait on watch::Receiver
   │ Changed → load SVID                     │ rx.changed() wakes up
   │ → watch::Sender.send(new_identity)  ───→│ Build CertifiedKey
   │                                         │ → RwLock::write() atomic swap
   │                                         ↓
                                     ResolvesServerCert::resolve()
                                     → RwLock::read() returns new cert
```

- `std::sync::RwLock` (not tokio) — TLS callback context is not async
- Existing connections are unaffected (TLS is only used during handshake)
- New connections immediately use the new certificate

---

## 4. Thread Boundary Summary

| Boundary | Direction | Sync Mechanism | Blocking? |
|----------|-----------|----------------|-----------|
| **Exporter**: tokio worker → blocking pool | Backend I/O (filesystem, etc.) | `spawn_blocking` + `Arc<SharedCtx>` | Does not block tokio worker |
| **Exporter**: inotify OS thread → tokio task | Watch events | `mpsc::try_send` + DashMap | OS thread never blocks |
| **Exporter**: tokio task ↔ tokio task | Shared Session | DashMap / Atomic | Lock-free or sharded |
| **Importer**: FUSE task → RPC → background reader | Request/response | `oneshot` channel | Pure async await |
| **Importer**: background reader → FUSE task | Push messages | `mpsc` channel | Pure async |
| **RDMA Exporter**: recv CQ poller → handler task | Decoded Fcall | `mpsc` channel | Pure async (AsyncFd) |
| **RDMA Exporter**: handler task → send pool | Send buffer | `ArrayQueue` (lock-free) | CAS only |
| **RDMA Importer**: recv CQ poller → RPC caller | Response dispatch | `DashMap` + `oneshot` | Lock-free |
| **Transport**: cert watcher → cert updater | Cert rotation | `watch` channel + `RwLock` | Microsecond write lock |

---

## 5. Key Design Points

1. **Exporter has an OS thread boundary** (notify inotify); importer is **pure tokio, zero OS threads**.
2. **Three transport models**: QUIC multi-stream concurrency, TCP single-connection serial, RDMA two-sided Send/Recv with one-sided Read/Write fast path — consistent dispatch pattern on both sides.
3. **Exporter's blocking pool is performance-critical** — 512 thread cap, all Backend I/O goes through it. `Arc<SharedCtx<B>>` and `Arc<H>` are cloned into closures (atomic increment, ~1ns) instead of raw fd integers.
4. **DashMap used throughout** — FID table, Session, inflight, watch registration, RDMA tokens — all sharded locks. StreamState caches `Arc<H>` to avoid per-operation fid lookups.
5. **Importer does no local I/O** — everything is delegated to the exporter, so no `spawn_blocking` needed.
6. **RDMA uses lock-free data structures** — `crossbeam::ArrayQueue` for MR pool slot management (CAS per checkout/return), `DashMap` for tag dispatch and fid buffer tracking. The only mutex is on `push_rx` (single consumer, low contention).
