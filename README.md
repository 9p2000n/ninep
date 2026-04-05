# ninep

A Rust implementation of the [9P2000.N](https://github.com/9p2000n/9P2000.N/tree/main/spec/9P2000.N-protocol.md) protocol — a modular, capability-negotiated extension to the Plan 9 remote filesystem protocol. Supports both QUIC and TCP+TLS transports with SPIFFE workload identity authentication.

## Overview

ninep exports and imports filesystems over the network:

- **p9n-exporter** exports a local directory over QUIC or TCP+TLS, serving 9P2000.N requests
- **p9n-importer** mounts a remote export as a local FUSE filesystem

Both authenticate via SPIFFE X.509-SVIDs (mTLS) and authorize operations through a multi-layer access control system with per-identity filesystem isolation and JWT capability tokens.

## Architecture

```
               QUIC (mTLS via SPIFFE X.509-SVID) or TCP+TLS
 ┌──────────────┐   ──────────────────────────────────   ┌──────────────┐
 │ p9n-importer │◄── metadata (datagrams/serial)      ──►│ p9n-exporter │
 │              │◄── data (streams/serial)            ──►│              │
 │  FUSE mount  │◄── push: Rnotify (inotify events)   ── │   local fs   │
 └──────┬───────┘                                        └──────┬───────┘
        │                                                       │
    /mnt/9p/                                               /srv/export/
```

### Crate Map

| Crate | Purpose |
|-------|---------|
| **p9n-proto** | Wire types (9P2000.N), marshal/unmarshal codec, capability negotiation, message classification |
| **p9n-auth** | SPIFFE X.509-SVID & JWT-SVID, trust bundles, TLS config, cert hot-reload, Workload API (optional) |
| **p9n-transport** | QUIC + TCP+TLS dual transport, datagram/stream routing, 0-RTT support |
| **p9n-exporter** | File exporter: message handlers, local filesystem backend, inotify watch, access control |
| **p9n-importer** | File importer: async FUSE filesystem (fuse3), concurrent RPC, lease-based cache coherence |


## Building

```bash
cargo build --workspace
cargo test --workspace
```

Produces two binaries: `p9n-exporter` and `p9n-importer`.

### Optional features

| Feature | Effect |
|---------|--------|
| `workload-api` | Enables SPIFFE Workload API support (gRPC over Unix socket to SPIRE Agent). Adds `h2` and `http` dependencies. |

```bash
# Build with Workload API support
cargo build --workspace --features workload-api
```

## Usage

Both binaries require SPIFFE X.509-SVID certificates for mutual TLS authentication.

### Exporter

> **Note:** The exporter currently needs to run as **root** (or with equivalent capabilities). This is required for:
>
> - **`CAP_CHOWN`** — SPIFFE-to-uid/gid ownership mapping calls `chown()` on newly created files to assign them to the Linux user configured in the access policy.
> - **`CAP_DAC_OVERRIDE`** — Serving files owned by different users on behalf of authenticated SPIFFE workloads.
> - **`mknod()`** — Creating device nodes and UNIX sockets requires elevated privileges.
> - **`fallocate()`** — Some preallocate modes require root.
>
> As an alternative to full root, you can grant specific capabilities:
> ```bash
> sudo setcap 'cap_chown,cap_dac_override,cap_fowner+eip' target/release/p9n-exporter
> ```
> If uid/gid mapping is not needed (all `Policy.uid = 0`), the exporter can run as a regular user with access to the export directory.

```bash
p9n-exporter \
  --listen [::]:5640 \
  --export /srv/shared \
  --cert  /etc/spiffe/svid.pem \
  --key   /etc/spiffe/key.pem \
  --ca    /etc/spiffe/bundle.pem
```

Optional: add TCP+TLS listener as an alternative to QUIC:

```bash
p9n-exporter \
  --listen [::]:5640 \
  --tcp-listen [::]:5641 \
  --export /srv/shared \
  --cert ... --key ... --ca ...
```

With SPIFFE Workload API (requires `--features workload-api` at build time):

```bash
p9n-exporter \
  --listen [::]:5640 \
  --export /srv/shared \
  --spiffe-agent-socket /run/spire/agent.sock
```

### Importer

```bash
# QUIC mode (default)
p9n-importer \
  --exporter 192.168.1.10:5640 \
  --mount /mnt/9p \
  --cert ... --key ... --ca ...

# TCP mode
p9n-importer \
  --exporter 192.168.1.10:5641 \
  --transport tcp \
  --mount /mnt/9p \
  --cert ... --key ... --ca ...
```

## Transport

### Dual Protocol Support

| | QUIC | TCP+TLS |
|--|------|---------|
| Default port | 5640 | 5641 (optional) |
| Multiplexing | Per-stream (256 concurrent) | Serial with tag-based demux |
| Metadata routing | QUIC datagrams (lowest latency) | Same stream as data |
| Server push | Unidirectional streams | Tag=0xFFFF on same stream |
| 0-RTT resumption | Supported | N/A |
| Linux `mount -t 9p` | Not compatible | Compatible (with TLS) |

### QUIC Message Routing

| Channel | Messages | Rationale |
|---------|----------|-----------|
| **Datagrams** | Tversion, Tcaps, Tsession, Thealth, Twatch, ... | Small control-plane; lowest latency, tag-based response matching |
| **Bidirectional streams** | Twalk, Tread, Twrite, Tgetattr, Treaddir, ... | Data operations; ordered, flow-controlled |
| **Unidirectional streams** | Rnotify, Rleasebreak, Rstreamdata | Server push (tag=0xFFFF) |

## Security

See [SECURITY_DESIGN.md](docs/SECURITY_DESIGN.md) for the full 9-layer security model.

### Summary

```
Layer 1: TLS Transport (QUIC/TCP mTLS)         — certificate chain validation
Layer 2: Identity Extraction                     — SPIFFE ID from TLS peer cert
Layer 3: Identity Confirmation (TstartlsSpiffe)  — declared vs TLS cert match
Layer 4: Session Key (TLS-derived)               — export_keying_material (RFC 5705)
Layer 5: Filesystem Isolation (Tattach)           — per-SPIFFE-ID root directory
Layer 6: Operation Permissions                    — static policy + dynamic cap tokens
Layer 7: Capability Tokens (JWT, HMAC-SHA256)     — non-transferable, time-limited
Layer 8: File Ownership Mapping                   — SPIFFE → Linux uid/gid via chown
Layer 9: Path Escape Prevention                   — canonicalize + starts_with check
```

### Access Control

Permissions are resolved per SPIFFE ID through a 3-level cascade:

1. **Exact ID match**: `by_id["spiffe://a.com/app/worker-1"]`
2. **Trust domain match**: `by_domain["a.com"]` (auto-creates per-workload subdirectories)
3. **Default policy**: `PERM_ALL` (backward compatible single-tenant mode)

Dynamic privilege escalation via Tcapgrant/Tcapuse with JWT tokens containing `p9n_rights` and `p9n_depth` claims.

## Protocol Coverage

### Base Messages

All base message types implemented: Tversion, Tauth, Tattach, Twalk, Tlopen, Tlcreate, Tread, Twrite, Tclunk, Tremove, Tgetattr, Tsetattr, Tstatfs, Treaddir, Tfsync, Tmkdir, Tsymlink, Tmknod, Treadlink, Tlink, Trenameat, Tunlinkat, Trename, Tlock, Tgetlock, Txattrwalk, Txattrcreate, Tflush.

### 9P2000.N Extensions

| Domain | Messages | Status |
|--------|----------|--------|
| **Negotiation** | Tcaps | Implemented |
| **Security** | Tstartls, Tauthneg, Tcapgrant, Tcapuse, Tauditctl, TstartlsSpiffe, Tfetchbundle, Tspiffeverify | 7/8 implemented (Tstartls N/A for QUIC) |
| **Transport** | Tquicstream, Trdmatoken, Trdmanotify, Tcxlmap, Tcxlcoherence | 1/5 (QUIC only; RDMA/CXL future) |
| **Performance** | Tcompound, Tcompress, Tcopyrange, Tallocate, Tseekhole, Tmmaphint | 4/6 implemented |
| **Filesystem** | Twatch, Tunwatch, Tnotify, Tgetacl, Tsetacl, Tsnapshot, Tclone, Txattrget, Txattrset, Txattrlist | 8/10 (snapshot/clone need btrfs/zfs) |
| **Distributed** | Tlease, Tleaserenew, Tleasebreak, Tleaseack, Tsession, Tconsistency, Ttopology | All implemented |
| **Observability** | Ttraceattr, Thealth, Tserverstats | All implemented |
| **Resources** | Tgetquota, Tsetquota, Tratelimit | 2/3 (quota future) |
| **Streaming** | Tasync, Tpoll, Tstreamopen, Tstreamdata, Tstreamclose | 5/5 (all implemented) |
| **Content** | Tsearch, Thash | 1/2 (search P3) |

**Total: 72/77 T-message types implemented (93.5%)**

## File Watching (inotify)

The exporter integrates Linux inotify via the `notify` crate with DashMap-based lock-free event dispatch:

1. Importer sends Twatch to register interest on a fid
2. Global `WatchManager` registers with OS watcher (supports recursive watching)
3. Events mapped to 9P mask bits (CREATE/REMOVE/MODIFY/ATTRIB/RENAME)
4. Per-connection channels route events as Rnotify push messages
5. Automatic cleanup on connection close

## Performance

- **Async I/O**: All file operations use `tokio::task::spawn_blocking()` to avoid blocking the async runtime
- **FUSE**: Native async via `fuse3` — no `block_on()` bridging
- **Concurrency**: Per-QUIC-stream task spawning with `Arc<Session>` interior mutability
- **Zero-copy framing**: `Buf::into_vec()` ownership transfer, `decode_owned()` for received messages
- **Shared context**: Single `Arc<SharedCtx>` per connection instead of 6 separate Arcs
- **Watch dispatch**: `DashMap` per-shard read locks — OS watcher thread never blocks handlers
- **Tag routing**: `DashMap<u16, oneshot::Sender>` for concurrent datagram response matching
- **Cache coherence**: Lease-based attribute caching — TTL-free while lease held, instant invalidation via Rleasebreak push
- **Streaming I/O**: Tstreamopen/Tstreamdata/Tstreamclose with tracked file offsets and fsync-on-close
- **Rate limiting**: Optional per-fid token bucket (IOPS + BPS), async backpressure, configurable via `--enable-rate-limit`

## Testing

```
Proto unit tests:            codec round-trips, tag allocator/guard RAII,
                             buf zero-copy, message classification, capset

Auth unit tests:             JWT cap token sign/verify/reject, JWK parsing,
                             trust bundle store, SPIFFE ID extraction, X.509
                             chain verify (valid/unknown/wrong CA).
                             With workload-api: gRPC frame round-trip/fragment/
                             multi-message, protobuf decode (single/multi/unknown
                             fields/empty), DER cert split (single/multi/long/empty)

Transport unit tests:        framing encode/decode round-trip (5 message types),
                             async write/read via duplex (single, multi-message,
                             too-small reject), router datagram/stream/push

Exporter integration:        version negotiation, walk/getattr, read/write,
                             mkdir/readdir, unlink/rename, remove, symlink/readlink,
                             statfs, concurrent reads, caps, compound, BLAKE3 hash,
                             session (zero key/duplicate), lease lifecycle, stale fid,
                             consistency, server stats, locking, streaming write/read,
                             rate limiting (token bucket throttle)

Importer unit tests:         InodeMap (root, get_or_insert, remove, monotonic, 7),
                             FidPool (monotonic, reserved skip, concurrent, 4),
                             AttrCache (TTL, leased, LRU eviction, invalidate, 6),
                             LeaseMap (grant/release/break, refcount, 6),
                             RpcError (errno, display, 3)
```

Tests use `rcgen` for self-signed SPIFFE certificates and `tempfile` for isolated export directories. Integration tests run the full QUIC loopback stack — no FUSE or system mounts required.

## Project Structure

```
ninep/
  Cargo.toml                          Workspace root
  README.md                           This file
  docs/
    ARCH_DESIGN.md                      Architectural design
    ARCH_DESIGN_DECISION.md             Architectural decisions with rationale
    RCGEN_USAGE.md                      rcgen usage for SPIFFE SVIDs
    SPIRE_SETUP.md                      SPIRE environment setup
    SECURITY_DESIGN.md                  9-layer security architecture
    THREAD_MODEL.md                     Thread model analysis (exporter/importer)

  crates/
    p9n-proto/                         Protocol library (transport-agnostic)
      src/types.rs                       MsgType enum (102 type slots)
      src/fcall.rs                       Msg enum (all message payloads)
      src/codec.rs                       marshal/unmarshal
      src/classify.rs                    Message → Metadata/Data/Push routing
      src/caps.rs                        CapSet with u64 bitmask fast path
      src/tag.rs                         Lock-free tag allocator with RAII guard
      src/buf.rs                         Zero-copy wire buffer
      tests/codec_test.rs                round-trip tests

    p9n-auth/                          SPIFFE authentication
      src/spiffe/x509_svid.rs            Load PEM, extract SPIFFE ID from SAN
      src/spiffe/jwt_svid.rs             JWT-SVID + HMAC cap token sign/verify
      src/spiffe/tls_config.rs           Static + dynamic rustls configs
      src/spiffe/cert_resolver.rs        ResolvesServerCert for SVID hot-reload
      src/spiffe/workload_api.rs         SvidSource: static / file-watch / workload-api
      src/spiffe/trust_bundle.rs         CA chain store per trust domain
      src/spiffe/grpc/                   [workload-api feature] gRPC over Unix socket
        frame.rs                           gRPC length-prefixed frame codec
        proto.rs                           Hand-written protobuf (X509SVIDRequest/Response)
        client.rs                          h2 client for FetchX509SVID streaming RPC
      tests/auth_test.rs                 JWT/JWK/trust/chain tests (+12 grpc tests)

    p9n-transport/                     Dual transport layer
      src/framing.rs                     Generic AsyncRead/AsyncWrite framing
      src/quic/config.rs                 Quinn endpoint builder (SPIFFE mTLS)
      src/quic/connection.rs             QuicTransport with tag-based datagram routing
      src/quic/datagram.rs               Datagram send with retry
      src/quic/streams.rs                Bidirectional stream RPC
      src/quic/router.rs                 Datagram vs stream message routing
      src/quic/zero_rtt.rs               0-RTT session detection
      src/tcp/config.rs                  tokio-rustls server/client setup
      src/tcp/connection.rs              TcpTransport
      tests/transport_test.rs            11 framing + router unit tests

    p9n-exporter/                      File exporter (server)
      src/exporter.rs                    Dual-protocol accept loop (QUIC + TCP)
      src/quic_connection.rs             QUIC connection handler (per-stream spawn)
      src/tcp_connection.rs              TCP connection handler (serial + push)
      src/config.rs                      ExporterConfig (configurable limits)
      src/shared.rs                      SharedCtx (server-wide state)
      src/session.rs                     Per-connection state (interior mutability)
      src/session_store.rs               Per-SPIFFE-ID partitioned session store
      src/access.rs                      3-level policy + uid/gid mapping
      src/watch_manager.rs               DashMap-based inotify event dispatch
      src/util.rs                        Shared join_err/map_io_error/spiffe extraction
      src/handlers/                      handler modules (including rate limiter)
      tests/integration_test.rs          full-stack integration tests

    p9n-importer/                      File importer (client)
      src/importer.rs                    RpcHandle enum (QUIC/TCP), connect + negotiate
      src/quic_rpc.rs                    QUIC RPC with concurrent tag dispatch
      src/tcp_rpc.rs                     TCP RPC with serial tag dispatch
      src/fuse/filesystem.rs             fuse3 async Filesystem trait
      src/fuse/inode_map.rs              Bidirectional ino ↔ (fid, qid)
      src/fuse/fid_pool.rs               FidGuard RAII (auto-clunk on error)
      src/fuse/attr_cache.rs             LRU attribute cache with TTL + lease-aware lookup
      src/fuse/lease_map.rs              Bidirectional lease tracking (fh↔lease_id↔ino)
      src/push_receiver.rs               Server push handler (Rnotify/Rleasebreak → cache)
      tests/importer_test.rs             unit tests (InodeMap, FidPool, AttrCache, LeaseMap, RpcError)
```

## Dependencies

| Role | Crate | Why |
|------|-------|-----|
| QUIC | `quinn` 0.11 | RFC 9000, datagram + 0-RTT support |
| TCP TLS | `tokio-rustls` 0.26 | TLS 1.3 over TCP, alternative to QUIC |
| TLS | `rustls` 0.23 | Pure-Rust TLS, dynamic cert resolver |
| FUSE | `fuse3` 0.8 | Native async userspace filesystem |
| JWT | `jsonwebtoken` 9 | Capability token sign/verify (HS256/RS256/ES256) |
| X.509 | `x509-parser` 0.16 | SPIFFE ID extraction from SAN |
| inotify | `notify` 8 | Cross-platform file watching |
| Hashing | `blake3` 1 | File content hashing (Thash) |
| Async | `tokio` 1 | Runtime for QUIC, TCP, and background tasks |
| Concurrency | `dashmap` 6 | Lock-free fid/inode/watch/session tables |
| Caching | `lru` 0.12 | Attribute and directory entry caches |
| HTTP/2 | `h2` 0.4 | gRPC Workload API client (optional, `workload-api` feature) |

## Related

- [9P2000.N Protocol Specification](https://github.com/9p2000n/9P2000.N/tree/main/spec/9P2000.N-protocol.md)
- [9P2000.N Wire Format](https://github.com/9p2000n/9P2000.N/tree/main/spec/9P2000.N-protocol-format.md)
- [Reference Implementations](https://github.com/9p2000n/9P2000.N/tree/main/ref/) (C, Go, Rust — codec only)
- [SPIRE Environment Setup](docs/SPIRE_SETUP.md) — SPIRE deployment for test and production environments
- [rcgen Usage for SPIFFE SVIDs](docs/RCGEN_USAGE.md) — Generating test certificates with rcgen

## License

MIT
