# 9P2000.N (ninep) vs NFS vs WebDAV

A competitive analysis of ninep's 9P2000.N implementation against NFSv4.1 and WebDAV, based on the actual codebase — not theoretical protocol capabilities.

---

## Wire Overhead

| | 9P2000.N (ninep) | NFSv4.1 | WebDAV |
|--|------------------|---------|--------|
| Header size | **7 bytes** (size[4]+type[1]+tag[2]) | ~40+ bytes (RPC header + XDR) | Hundreds of bytes (HTTP headers) |
| Encoding | Fixed-width little-endian | XDR (4-byte aligned, padding waste) | XML/HTTP text |
| Max message | 4 MiB (negotiated) | ~1 MiB (typical) | Unlimited (HTTP chunked) |
| Compression | ZSTD negotiation (Tcompress) | No native support | HTTP gzip/brotli |

**ninep advantage**: The 7-byte header is the smallest of all three. Fixed-width little-endian encoding makes marshal/unmarshal essentially memcpy-level operations — no XDR 4-byte alignment padding, no HTTP/XML text parsing overhead. For metadata-heavy workloads (many stat/readdir calls), this difference is amplified.

**ninep gap**: HTTP compression (gzip/brotli) is mature and enabled by default. ninep's Tcompress currently only negotiates ZSTD; actual per-message compression is not yet implemented.

---

## Transport & Multiplexing

| | 9P2000.N (ninep) | NFSv4.1 | WebDAV |
|--|------------------|---------|--------|
| Transport | QUIC (primary) + TCP+TLS (fallback) + RDMA (optional) | TCP (+RDMA via NFS/RDMA) | HTTP/1.1 or HTTP/2 |
| Multiplexing | 256 concurrent QUIC streams | Session/Slot (limited concurrency) | HTTP/2 streams or multiple connections |
| Head-of-line blocking | **None** (per-stream independent) | Yes (TCP single connection) | HTTP/2 eliminates app-level HOL, TCP-level remains |
| Metadata channel | QUIC datagrams (zero HOL) | Shared with data | Same |
| Connection migration | QUIC native | Not supported | Not supported |

**ninep core advantage**: QUIC datagram/stream split design. Metadata goes via datagrams (Tversion, Tcaps, Thealth, etc.), data goes via bidirectional streams, server push goes via unidirectional streams. A large Tread on one stream never blocks a Thealth heartbeat probe. NFSv4.1's session/slot model supports concurrency but all operations share a TCP connection — a single packet loss blocks all subsequent operations.

**RDMA parity**: ninep now supports RDMA transport (behind `rdma` feature flag) with InfiniBand/RoCE verbs. Phase 1 uses two-sided Send/Recv for all messages; Phase 3 uses one-sided RDMA Read/Write for Tread/Twrite — the server writes file data directly into client-registered memory (reads) or reads from client memory (writes), bypassing 9P message serialization entirely. Authentication uses TCP+TLS bootstrap with SPIFFE mTLS before switching to RDMA verbs. NFS/RDMA is more mature (kernel integration, pNFS layout support), but ninep's RDMA path is functional and production-ready for datacenter deployments.

### 0-RTT

QUIC 0-RTT is deliberately disabled despite the TLS infrastructure being fully configured. 9P negotiation messages (Tversion, Tcaps, Tsession) are classified as Metadata and routed via QUIC datagrams. During 0-RTT the TLS handshake is not yet confirmed, so datagrams may be silently dropped — triggering a 30-second response timeout. The 1-RTT handshake adds < 1 ms on loopback. See [ARCH_DESIGN_DECISION.md](ARCH_DESIGN_DECISION.md) for the full rationale.

---

## Metadata Operation Latency

| | 9P2000.N (ninep) | NFSv4.1 | WebDAV |
|--|------------------|---------|--------|
| stat | 1 RTT (Tgetattr) | 1 RTT (GETATTR) | 1 RTT (PROPFIND) + XML parse |
| Batching | Tcompound merges multiple ops into 1 RTT | COMPOUND native | Not supported |
| Caching | 4096-entry LRU + 1s TTL + lease bypass | Delegation | No standard cache |
| Directory listing | Treaddir (binary) | READDIR (XDR) | PROPFIND depth=1 (XML) |

**Parity**: Both ninep and NFSv4.1 support compound operations, batching walk+open+read into a single RTT. This matters significantly over WAN.

**ninep advantage vs WebDAV**: WebDAV's PROPFIND returns XML — a directory with 1000 files could generate tens of KB of XML text. ninep's Treaddir returns compact binary encoding (~25+ bytes per dirent = name + qid + offset + type).

**NFSv4.1 advantage vs ninep**: NFS delegation is more mature. NFS can grant write delegation (exclusive), allowing the client to cache all operations locally. ninep supports both read leases (60 seconds) and write leases (exclusive, with conflict detection and automatic break of conflicting read leases).

---

## Large File I/O

| | 9P2000.N (ninep) | NFSv4.1 | WebDAV |
|--|------------------|---------|--------|
| Max read/write unit | 4 MiB (msize) | ~1 MiB | Unlimited |
| Server-side copy | Tcopyrange (`copy_file_range` syscall + `FICLONERANGE` reflink) | COPY/CLONE (reflink) | COPY method (HTTP) |
| Preallocation | Tallocate (fallocate) | ALLOCATE | Not supported |
| Streaming | Tstreamopen/data/close + offset tracking | No equivalent | chunked transfer |
| Server-side hash | Thash (BLAKE3, 64 KiB chunks) | Not supported | Not supported |
| Hole seek | Tseekhole (defined, not yet implemented) | SEEK (sparse files) | Not supported |

**ninep advantage**: Thash lets the client request server-side file hashing (BLAKE3) without transferring the entire file. This is valuable for integrity verification and incremental sync — neither NFS nor WebDAV has an equivalent.

**ninep advantage**: Tcopyrange uses the `copy_file_range(2)` syscall, enabling kernel-optimized data transfer (reflink on btrfs/xfs, in-kernel pipe on ext4). When the `COPY_REFLINK` flag is set, `ioctl(FICLONERANGE)` is used for explicit COW clone requests.

### Zero-Copy I/O Path

The exporter implements two zero-copy optimizations on the data hot path:

**Read path** (Rread): The 9P header and file data share a single pre-allocated buffer. The file is read directly into the data region at offset 11 (7-byte header + 4-byte data-length prefix), and the header is back-filled in-place. This bypasses the normal marshal layer (`put_data` / `extend_from_slice`) entirely, eliminating one full-payload memcpy per read.

**Write path** (Twrite): `Buf::get_data_drain()` uses `Vec::split_off()` to take ownership of the trailing data blob in O(1) instead of `.to_vec()` which copies the entire payload. This applies to Twrite, Rread, Rreaddir, and Tstreamdata unmarshal paths.

| Path | Copies (before) | Copies (after) | Eliminated |
|------|-----------------|----------------|------------|
| Read (4 MiB) | 4 | 3 | `put_data` memcpy (4 MiB + 1 alloc) |
| Write (4 MiB) | 3 | 2 | `get_data` `.to_vec()` (4 MiB + 1 alloc) |

Remaining copies that cannot be eliminated without io_uring or kernel bypass:
1. `read()` syscall: kernel page cache to userspace (unavoidable with POSIX I/O)
2. `write_all()`: userspace to QUIC send buffer (unavoidable with quinn)

---

## Cache Coherence

| | 9P2000.N (ninep) | NFSv4.1 | WebDAV |
|--|------------------|---------|--------|
| Model | Lease (read + write) + TTL (1s) + server push | Delegation + optional strong consistency | ETag / If-Modified-Since |
| Write awareness | Rleasebreak (instant push) | CB_RECALL (callback) | None (polling) |
| Delivery | Best-effort `try_send()` | Reliable callback | Client conditional request |
| Multi-writer | Eventually consistent | Strongly consistent (delegation recall) | Eventually consistent |

**Lease semantics**: Read leases allow multiple connections to share access. Write leases are exclusive — requesting a write lease automatically breaks all read leases held by other connections (Rleasebreak pushed). Conflicting write-vs-write and read-vs-write requests are rejected with EAGAIN.

**Design trade-off**: Lease break is delivered via `try_send()` — if the receiver's channel is full (capacity 64), the message is silently dropped. In extreme concurrent-write scenarios, a client could hold stale cache data for the remainder of the lease period (60 seconds). NFSv4.1's delegation recall is reliable (TCP callback) and must be acknowledged before the write can proceed.

**Mitigation**: The 1-second TTL acts as a safety net. Even if a lease break is lost, the cache expires within 1 second. For most userspace filesystem workloads (config distribution, log collection, build artifact sharing), this is acceptable.

---

## WAN Performance

| | 9P2000.N (ninep) | NFSv4.1 | WebDAV |
|--|------------------|---------|--------|
| High-latency tolerance | QUIC multiplexing + compound | pNFS layouts + compound | HTTP/2 |
| Packet loss recovery | QUIC per-stream recovery | TCP whole-connection blocking | TCP whole-connection blocking |
| Connection migration | QUIC connection migration | Not supported | Not supported |
| Reconnection | Auto-reconnect + Tsession resume (5 min TTL) | NFSv4.1 session + state recovery | Stateless (new connection each time) |
| NAT traversal | QUIC (UDP) | Difficult (TCP + callbacks) | HTTP native traversal |

**ninep's WAN killer feature**: QUIC per-stream packet loss recovery. On a WAN link with 1% packet loss, TCP's single lost packet blocks all subsequent data (HOL blocking), while QUIC only affects the stream where the loss occurred. For concurrent file operations (readdir + multiple stat + read), one file's read latency does not affect another file's metadata operation.

**WebDAV counter**: HTTP naturally traverses nearly all firewalls and proxies. ninep's UDP-based QUIC may be blocked by enterprise firewalls — this is why TCP+TLS is maintained as a fallback transport.

---

## Security Model

| | 9P2000.N (ninep) | NFSv4.1 | WebDAV |
|--|------------------|---------|--------|
| Authentication | SPIFFE mTLS (workload identity) | Kerberos / AUTH_SYS | HTTP Basic/OAuth/certs |
| Transport encryption | TLS 1.3 (built into QUIC) | RPCSEC_GSS (optional) | HTTPS |
| Permission model | 3-level policy + JWT dynamic tokens | POSIX ACL + Kerberos | HTTP-level |
| Filesystem isolation | Per-SPIFFE-ID root directory | Export-level | Virtual paths |
| Certificate hot-reload | ResolvesServerCert + background polling | keytab refresh | Depends on web server |

**ninep advantage**: SPIFFE workload identity is designed for cloud-native environments. `spiffe://domain/app/worker-1` maps directly to filesystem isolation path `/export/app/worker-1/`. NFS's AUTH_SYS relies on UID/GID (easily spoofed); Kerberos is complex to configure. JWT dynamic tokens enable runtime privilege escalation — "read-only by default, grant write access during a deployment window" — neither NFS nor WebDAV has an equivalent mechanism.

---

## Summary

### Where ninep excels

- **WAN / cross-datacenter file access**: QUIC multiplexing + connection migration + auto-reconnect, far superior to NFS's TCP and WebDAV's stateless model
- **Datacenter high-throughput**: RDMA transport with one-sided Read/Write for Tread/Twrite — server DMA writes file data directly into client memory, bypassing 9P message serialization and network stack
- **Metadata-heavy workloads**: 7-byte header + datagram channel + compound batching
- **Cloud-native inter-service file sharing**: SPIFFE identity + per-workload isolation + dynamic permissions
- **File integrity verification**: Server-side BLAKE3 hashing without transferring file content
- **Large file server-side operations**: `copy_file_range` with reflink support, `fallocate`, streaming I/O

### Where ninep falls short

- **RDMA maturity**: RDMA transport is functional but newer than NFS/RDMA — NFS has kernel-level RDMA integration and pNFS layout support for distributed reads
- **Strong consistency**: Lease break is best-effort, less reliable than NFSv4.1 delegation recall
- **Ecosystem maturity**: NFS has 30+ years of kernel-level optimization and production validation; WebDAV has global CDN/proxy infrastructure
- **Kernel integration**: Not compatible with `mount -t 9p` (requires FUSE layer), adding one userspace context switch per VFS operation

### Performance bottlenecks

1. **FUSE layer**: The largest overhead — every VFS operation requires kernel-to-userspace-to-kernel context switching. NFS's kernel client operates entirely in kernel space.
2. **`spawn_blocking` thread pool**: Each file I/O syscall occupies a blocking thread (limit 512). Compared to NFS's kernel zero-copy path, this adds scheduling overhead. Could be addressed with io_uring in the future, though no mature Rust QUIC library supports io_uring today (compio-quic is the closest, but requires leaving the tokio ecosystem).
3. **Remaining memcpy**: The read/write hot paths have been optimized to eliminate one full-payload copy each (pre-allocated read buffer, drain-based unmarshal), but `read()`/`write()` syscall copies and QUIC send-buffer copies remain. These require kernel bypass (io_uring `IORING_OP_SEND_ZC`, kTLS + sendfile for TCP) to eliminate.

---

## Key Numbers

| Parameter | Value | Notes |
|-----------|-------|-------|
| Message header | 7 bytes | vs NFS RPC ~40 bytes |
| Max message | 4 MiB | Negotiated, larger than typical NFS |
| Concurrent streams (QUIC) | 256 bidi + 16 uni | Multiplexing advantage |
| Keep-alive interval | 10 seconds | Prevents idle disconnect |
| Datagram retries | 3 (70ms total) | Auto-fallback to stream if oversized |
| Attribute cache | 4096 entries, 1s TTL | LRU eviction |
| Read lease duration | 60 seconds | Server push on break |
| Write lease | Exclusive, conflict detection | EAGAIN on conflict, breaks others' reads |
| Lease break latency | ~0ms (best-effort) | Async push via unidirectional stream |
| Copy range | `copy_file_range` syscall | Reflink via `FICLONERANGE` ioctl |
| Server-side hash | BLAKE3, 64 KiB chunks | No file transfer needed |
| Rate limit defaults | 100K IOPS, 1 GiB/s | Per-fid, disabled by default |
| Session resume TTL | 5 minutes | Reconnection window |
| Read copies | 3 (optimized from 4) | Pre-allocated buffer bypasses marshal |
| Write copies | 2 (optimized from 3) | Drain unmarshal eliminates .to_vec() |
| RDMA send pool | 32 slots × 4 MB | Concurrent sends, lock-free checkout |
| RDMA recv pool | 64 slots × 4 MB | Pre-posted to receive queue |
| RDMA data pool | 16 slots × 4 MB | Client-side per-fid buffers for one-sided ops |
| RDMA MR registrations | 2 per connection | Down from ~130 per-message (pooled) |
