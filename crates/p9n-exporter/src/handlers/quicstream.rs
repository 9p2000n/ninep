//! Handle Tquicstream: bind a logical 9P channel to a QUIC stream.
//!
//! P0 implements `stream_type = 2` (push) only. See docs/QUICSTREAM.md
//! for the full design and the rationale for cutting control/data/bulk.
//!
//! The handler itself owns no transport state. It validates pre-conditions
//! in the session, forwards a bind request through the `BindTx` channel
//! owned by the QUIC connection run loop, and records the result in
//! `session.quic_push_binding`.

use crate::handlers::HandlerResult;
use crate::push::{BindError, BindTx};
use crate::session::{QuicBinding, Session, TransportKind};
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::{MsgType, CAP_QUIC_MULTI};
use tokio::sync::oneshot;

const STREAM_TYPE_PUSH: u8 = 2;

pub async fn handle<H: Send + Sync + 'static>(
    session: &Session<H>,
    bind_tx: Option<&BindTx>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Quicstream { stream_type, stream_id: req_stream_id } = fc.msg else {
        return Err("expected Quicstream".into());
    };
    let tag = fc.tag;

    // 1. Non-QUIC transports never support Tquicstream.
    if session.transport_kind != TransportKind::Quic {
        return Ok(lerror(tag, libc::EOPNOTSUPP as u32));
    }
    // 2. Capability must have been negotiated.
    if !session.has_cap(CAP_QUIC_MULTI) {
        return Ok(lerror(tag, libc::EOPNOTSUPP as u32));
    }
    // 3. P0 only accepts the push channel.
    if stream_type != STREAM_TYPE_PUSH {
        return Ok(lerror(tag, libc::EOPNOTSUPP as u32));
    }
    // 4. For push bindings the request stream_id field is reserved and
    //    MUST be 0. The client cannot hold a valid QUIC stream id for
    //    the push channel (the server opens it), so any non-zero value
    //    is a protocol error. Rejecting non-zero here also preserves
    //    the semantic space for future stream_types that may assign
    //    meaning to the field. See docs/QUICSTREAM.md §3.3.
    if req_stream_id != 0 {
        return Ok(lerror(tag, libc::EINVAL as u32));
    }
    // 5. One binding per session; rebinding is rejected.
    if session.quic_push_binding.lock().is_some() {
        return Ok(lerror(tag, libc::EBUSY as u32));
    }
    // 6. The QUIC connection loop must have given us a bind channel. A
    //    missing channel is a programmer error — fail loud in debug and
    //    EOPNOTSUPP in release.
    let bind_tx = match bind_tx {
        Some(tx) => tx,
        None => {
            debug_assert!(false, "QUIC session without bind channel");
            return Ok(lerror(tag, libc::EOPNOTSUPP as u32));
        }
    };

    let (tx, rx) = oneshot::channel();
    if bind_tx.send(tx).await.is_err() {
        // Run loop has exited. The connection is tearing down anyway;
        // report EIO so the client sees a concrete failure.
        return Ok(lerror(tag, libc::EIO as u32));
    }
    let bind_result = match rx.await {
        Ok(r) => r,
        Err(_) => return Ok(lerror(tag, libc::EIO as u32)),
    };

    let alias = match bind_result {
        Ok(a) => a,
        Err(BindError::AlreadyBound) => return Ok(lerror(tag, libc::EBUSY as u32)),
        Err(BindError::NotSupported) => return Ok(lerror(tag, libc::EOPNOTSUPP as u32)),
        Err(BindError::Io(e)) => {
            tracing::warn!("Tquicstream bind failed: {e}");
            return Ok(lerror(tag, libc::EIO as u32));
        }
    };

    // Racing rebind check: two concurrent Tquicstream handlers could both
    // clear step 4 and reach here. The first to insert wins; the second
    // must release its alias. In practice this is impossible because dispatch
    // processes messages sequentially per session, but defend against it.
    let mut slot = session.quic_push_binding.lock();
    if slot.is_some() {
        tracing::warn!("Tquicstream: racing rebind detected, dropping alias {alias}");
        return Ok(lerror(tag, libc::EBUSY as u32));
    }
    *slot = Some(QuicBinding {
        alias,
        stream_type: STREAM_TYPE_PUSH,
    });
    drop(slot);

    tracing::debug!("Tquicstream bound: type={stream_type} alias={alias}");

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rquicstream,
        tag,
        msg: Msg::Rquicstream { stream_id: alias },
    })
}

fn lerror(tag: u16, ecode: u32) -> Fcall {
    Fcall {
        size: 0,
        msg_type: MsgType::Rlerror,
        tag,
        msg: Msg::Lerror { ecode },
    }
}
