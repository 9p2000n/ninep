# Tquicstream Implementation RFC (P0)

**Status**: Draft — design approved, implementation pending
**Capability**: `transport.quic.multistream` (`CAP_QUIC_MULTI`)
**Messages**: `Tquicstream` (154), `Rquicstream` (155)
**Related spec**: `../p9/spec/9P2000.N-protocol.md` §11.4

## Motivation

The spec defines `Tquicstream` to bind a logical 9P channel (control / data /
push / bulk) to a specific QUIC stream. In the current codebase the handler
is a fake-success stub: it acknowledges the request without doing anything
and the transport layer's routing table is static (`p9n-proto/src/classify.rs`).
This document describes the minimum implementation that converts the stub into
a real capability.

The real value is **not** protocol compliance for its own sake but the
lifecycle properties of a single persistent push stream versus the current
design, which opens a brand-new `quinn::SendStream` for every push message
(`p9n-exporter/src/push.rs:49`). Concrete wins:

1. **Stream setup amortization** — one `open_uni` per connection lifetime
   instead of one per `Rnotify` / `Rleasebreak` / `Rstreamdata`.
2. **Ordering** — pushes issued in sequence arrive in order. Currently each
   push rides its own stream and can be delivered out of order with respect
   to peer pushes.
3. **Back-pressure** — a slow client throttles the server via the single
   stream's flow control window. Currently parallel streams have no single
   back-pressure point and a slow client can only be handled by quinn's
   connection-level flow control.

## Scope

### In scope (P0)

- `stream_type = 2` (push) binding.
- QUIC transport only.
- One binding per connection; rebinding is not supported.
- Graceful fallback if the bound stream errors mid-session.
- Capability negotiation gated on transport kind.
- Server and importer (client) side implementation.

### Out of scope (P0)

- `stream_type = 0` (control), `= 1` (data), `= 3` (bulk) bindings. The handler
  returns `Rlerror(EOPNOTSUPP)` for these. Rationale:
  - *control* / *data*: the current model opens a fresh bidirectional stream
    per RPC, which gives maximum concurrency. Binding everything to one stream
    would serialize all traffic and hurt throughput.
  - *bulk*: depends on `Tstreamdata`, which is itself a stub. Revisit when
    streaming reads land (P1).
- Dynamic per-connection overrides to `classify::classify`. The static
  classification table remains the source of truth; the push binding is a
  transport-layer detail that does not feed back into `p9n-proto`.
- TCP or RDMA transports. Those return `EOPNOTSUPP` unconditionally.

## Protocol semantics

### Wire format (unchanged from spec)

```
Tquicstream: size[4] 154 tag[2] stream_type[1] stream_id[8]
Rquicstream: size[4] 155 tag[2] stream_id[8]
```

### Field interpretation in this implementation

- `Tquicstream.stream_type`: MUST be `2`. Other values return `EOPNOTSUPP`.
- `Tquicstream.stream_id` (request): semantics are **per `stream_type`**.
  - For `stream_type == 2` (push): the field is **reserved** and MUST be
    `0`. Any non-zero value returns `EINVAL`. The client cannot hold a
    valid QUIC stream id for the push channel because the server is the
    one that opens it, so there is no meaningful value for the client
    to put here.
  - For `stream_type ∈ {0, 1, 3}`: the field's semantics are **reserved**
    for future specification. Because the current implementation rejects
    these stream_types with `EOPNOTSUPP` before reaching the field check,
    the field value is not examined today. A future extension that
    assigns meaning to the field MUST be gated on a new capability bit
    (e.g., `transport.quic.multistream.v2`) so that current servers do
    not misinterpret new client messages.
- `Rquicstream.stream_id`: an **opaque alias** returned by the server. Defined
  as `u64::from(send.id())` where `send` is the persistent `quinn::SendStream`
  the server opened. The client SHOULD NOT interpret or match this value for
  routing — it is informational, useful only for logs and test assertions.
  The client continues to treat any incoming uni-stream as a push stream.

The rationale for the `MUST be 0` rule on request and a server-assigned
value on response: QUIC stream IDs encode initiator side, directionality,
and a per-side monotonic index. For the push channel the server is the
initiator, so the client cannot predict what ID quinn will assign and
cannot pre-declare a meaningful value. Treating the field as a hard
reserved zero (rather than a hint or a client-local handle) eliminates
ambiguity and preserves the semantic space for future stream_types that
may actually need a client-provided id.

### Future extension policy for `Tquicstream.stream_id`

When a later revision of this protocol adds real implementations for
`stream_type` 0/1/3, those implementations MAY assign meaning to the
request `stream_id` field (for example, "please route messages of type X
onto QUIC stream Y that I have already opened"). The transition rules:

1. The new meaning MUST be announced via a new capability bit; current
   servers that do not advertise it continue to return `EOPNOTSUPP` for
   those stream_types.
2. The new meaning applies only when the new capability is negotiated.
   A server that supports both old and new behavior still enforces
   `MUST be 0` for `stream_type == 2` regardless.
3. Clients MUST NOT assume the old MUST-zero rule extends to the new
   stream_types; they MUST consult the capability before sending
   non-zero values.

This keeps today's strict-zero rule forward-compatible with any future
addition.

### Pre-conditions

The server returns `Rlerror` for `Tquicstream` unless **all** of the following
hold:

| Condition | Errno on failure |
|---|---|
| `session.transport_kind == Quic` | `EOPNOTSUPP` |
| `CAP_QUIC_MULTI` in negotiated caps | `EOPNOTSUPP` |
| `stream_type == 2` | `EOPNOTSUPP` |
| `stream_id == 0` (when `stream_type == 2`) | `EINVAL` |
| `session.quic_push_binding` is empty | `EBUSY` |

These checks run in the listed order. The first failure short-circuits.

### Success path

On successful bind:

1. Server opens a new uni-stream: `let send = conn.open_uni().await?;`
2. Server records `alias = u64::from(send.id())`.
3. Server stores the `SendStream` in `QuicPushSender.persistent` (a
   `tokio::sync::Mutex<Option<quinn::SendStream>>`).
4. Server sets `session.quic_push_binding = Some(QuicBinding { alias, ... })`.
5. Server returns `Rquicstream { stream_id: alias }`.
6. All subsequent push messages (Rnotify, Rleasebreak, Rstreamdata) are
   written to this persistent stream. The stream is **not** finished between
   messages — only on connection teardown.

### Fallback on stream error

If `framing::write_message` returns an error while the persistent stream
holds the lock:

1. The error is logged at WARN level with the stream ID.
2. The `persistent` slot is set to `None`, effectively unbinding.
3. The current push message is re-sent via the legacy ephemeral path
   (`conn.open_uni().await?` + write + finish).
4. Subsequent pushes continue on the legacy path for the lifetime of the
   connection. The binding is not restored automatically.
5. The client observes nothing unusual — it still receives the push on
   an incoming uni-stream.

Rationale: the fallback prioritizes delivery over binding fidelity. A
persistent-stream failure is almost always a symptom of connection trouble
that will soon surface as other errors; trying to re-open a replacement
persistent stream would risk an error loop.

### Rebind policy

A client attempting `Tquicstream(push)` twice on the same session receives
`Rlerror(EBUSY)` on the second call. Rebinding after a fallback (where the
server silently unbound itself) is also rejected — the client would have
no way to observe that a fallback occurred, so we disallow retries to
avoid confusing state.

### Client (importer) behavior

1. Include `CAP_QUIC_MULTI` in the client-requested capability list.
2. After `Tattach` completes, if `CAP_QUIC_MULTI` is in the negotiated set,
   send `Tquicstream { stream_type: 2, stream_id: 0 }`.
3. If the server responds with `Rquicstream`, store the returned `stream_id`
   for logging/debugging. No routing change is needed: `quic_rpc.rs`
   already treats every incoming uni-stream as push.
4. If the server responds with `Rlerror(EOPNOTSUPP)`, log at INFO and
   continue. The client falls back to the legacy push path transparently.
5. The client does not retry `Tquicstream` on failure.

## Implementation sketch

### Types

```rust
// p9n-exporter/src/session.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind { Quic, Tcp, Rdma }

pub struct QuicBinding {
    pub alias: u64,
    pub stream_type: u8,
}

pub struct Session<H> {
    // ... existing fields ...
    pub transport_kind: TransportKind,
    pub quic_push_binding: std::sync::OnceLock<QuicBinding>,
}
```

### Push sender

```rust
// p9n-exporter/src/push.rs
pub struct QuicPushSender {
    conn: quinn::Connection,
    persistent: tokio::sync::Mutex<Option<quinn::SendStream>>,
}

impl QuicPushSender {
    pub async fn bind_persistent(&self) -> Result<u64, BindError> {
        let mut slot = self.persistent.lock().await;
        if slot.is_some() { return Err(BindError::AlreadyBound); }
        let send = self.conn.open_uni().await.map_err(BindError::Open)?;
        let alias = u64::from(send.id());
        *slot = Some(send);
        Ok(alias)
    }
}

impl PushSender for QuicPushSender {
    async fn send_push(&self, fc: Fcall) -> Result<(), ...> {
        let mut slot = self.persistent.lock().await;
        if let Some(stream) = slot.as_mut() {
            match framing::write_message(stream, &fc).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!("persistent push stream errored, falling back: {e}");
                    *slot = None;
                }
            }
        }
        drop(slot); // release the mutex before the slower ephemeral path
        let mut send = self.conn.open_uni().await?;
        framing::write_message(&mut send, &fc).await?;
        send.finish()?;
        Ok(())
    }
}
```

### Handler dispatch

The handler needs to reach `QuicPushSender::bind_persistent()`, which is
owned by the connection handler (not inside `SharedCtx`). A new trait
crosses the gap:

```rust
// p9n-exporter/src/push.rs
#[async_trait::async_trait]
pub trait PushBinder: Send + Sync {
    async fn bind_push(&self) -> Result<u64, BindError>;
}

// QUIC impl delegates to QuicPushSender.
// TCP impl returns BindError::NotSupported.
// RDMA impl returns BindError::NotSupported.
```

`handlers::dispatch()` gains a `push_binder: &dyn PushBinder` parameter,
plumbed through from each connection handler's run loop. Handlers that
don't need it (the vast majority) ignore it.

### Handler body

```rust
// p9n-exporter/src/handlers/quicstream.rs
pub async fn handle<H>(
    session: &Session<H>,
    binder: &dyn PushBinder,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Quicstream { stream_type, stream_id: req_stream_id } = fc.msg else { ... };
    let tag = fc.tag;

    if session.transport_kind != TransportKind::Quic {
        return lerror(tag, libc::EOPNOTSUPP);
    }
    if !session.caps().has(CAP_QUIC_MULTI) {
        return lerror(tag, libc::EOPNOTSUPP);
    }
    if stream_type != 2 {
        return lerror(tag, libc::EOPNOTSUPP);
    }
    if req_stream_id != 0 {
        // reserved for push; see §3.3
        return lerror(tag, libc::EINVAL);
    }
    if session.quic_push_binding.get().is_some() {
        return lerror(tag, libc::EBUSY);
    }

    let alias = binder.bind_push().await.map_err(|_| ...)?;
    let _ = session.quic_push_binding.set(QuicBinding { alias, stream_type: 2 });

    Ok(Fcall {
        size: 0, msg_type: MsgType::Rquicstream, tag,
        msg: Msg::Rquicstream { stream_id: alias },
    })
}
```

## Test plan

Tests live in `crates/p9n-exporter/tests/integration_test.rs` using the
existing QUIC harness.

| # | Test | Asserts |
|---|---|---|
| 1 | `test_quicstream_cap_negotiated_on_quic` | Client negotiating caps on QUIC receives `CAP_QUIC_MULTI` |
| 2 | `test_quicstream_cap_not_offered_on_tcp` | Same Tcaps over TCP returns a set without `CAP_QUIC_MULTI` |
| 3 | `test_quicstream_bind_push_happy_path` | `Tquicstream(2, 0)` returns `Rquicstream` with a non-zero alias |
| 4 | `test_quicstream_bind_persistence` | After bind, two Rnotify pushes arrive on the same `quinn::RecvStream` (compare `recv.id()`) |
| 5 | `test_quicstream_ebusy_on_rebind` | Second `Tquicstream(2)` returns `Rlerror(EBUSY)` |
| 6 | `test_quicstream_eopnotsupp_wrong_type` | `Tquicstream(0)`, `(1)`, `(3)` return `Rlerror(EOPNOTSUPP)` |
| 7 | `test_quicstream_einval_nonzero_stream_id` | `Tquicstream(2, stream_id != 0)` returns `Rlerror(EINVAL)`; a follow-up `Tquicstream(2, 0)` still binds successfully |
| 8 | `test_quicstream_eopnotsupp_without_cap` | Skip Tcaps negotiation, send Tquicstream, receive `Rlerror(EOPNOTSUPP)` |
| 9 | `test_quicstream_fallback_after_reset` | After binding, forcibly close the persistent stream from the client side; next push arrives via a fresh ephemeral uni-stream |
| 10 | `test_quicstream_eopnotsupp_on_tcp` | Send `Tquicstream(2)` over TCP connection, receive `Rlerror(EOPNOTSUPP)` |
| 11 | `test_quicstream_legacy_client_compat` | Client that never sends Tquicstream continues to receive pushes (ephemeral uni-streams) |

## Timing

Estimated ~4.5 days total:

| Phase | Work | Days |
|---|---|---|
| 0 | This RFC | 0.5 |
| 1 | Session state + `TransportKind` | 0.5 |
| 2 | Persistent push stream + handler + `PushBinder` trait | 1.5 |
| 3 | Cap advertisement | 0.25 |
| 4 | Importer client support | 0.5 |
| 5 | Non-QUIC rejection | 0.25 |
| 6 | Integration tests (10 cases) | 1.0 |
| 7 | Docs / cleanup (README, ARCH_DESIGN, CLAUDE.md) | 0.25 |

## Open risks

1. **`async_trait` dependency** — the `PushBinder` trait needs async. The
   workspace does not currently pull in `async-trait`. Alternative: use
   `impl Future + Send` in the trait method signature (stable, no new dep).
   Prefer the latter.
2. **Mutex contention on push hot path** — every push now takes a mutex on
   `persistent`. In steady state with the persistent stream bound this is a
   single uncontested acquire per push. Measure if it matters; if so switch
   to `parking_lot::Mutex` or a lock-free cell.
3. **Stream ID stability** — if quinn changes how it assigns server-initiated
   uni-stream IDs across versions, the alias semantics still hold because
   we treat it as opaque. No mitigation needed.
4. **CAP_QUIC_MULTI ordering with Tcaps** — the cap must be in the server's
   set at the moment Tcaps runs. Since `transport_kind` is set at connection
   accept time (before any 9P traffic), this is safe.
