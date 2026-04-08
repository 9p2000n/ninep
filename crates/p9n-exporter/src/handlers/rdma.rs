//! RDMA token exchange handler.
//!
//! Implements Trdmatoken: the client registers an RDMA memory region for a
//! specific fid. The server stores the remote rkey/addr/length so it can
//! later use RDMA Write (for reads) or RDMA Read (for writes) directly
//! to/from the client's buffer, bypassing the 9P message payload.

use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::{RdmaToken, Session};
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;

/// Handle Trdmatoken: register client's RDMA buffer for a fid.
///
/// The client sends its rkey/addr/length so the server can perform
/// one-sided RDMA operations on subsequent Tread/Twrite requests.
///
/// Response: Rrdmatoken with server's own RDMA buffer info (if available).
pub fn handle<H: Send + Sync + 'static>(
    session: &Session<H>,
    _ctx: &Arc<SharedCtx<impl Backend>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Rdmatoken {
        fid,
        direction,
        rkey,
        addr,
        length,
    } = fc.msg
    else {
        return Err("expected Rdmatoken message".into());
    };

    // Validate direction: 0 = READ, 1 = WRITE.
    if direction > 1 {
        return Err(format!("invalid RDMA direction: {direction}").into());
    }

    // Validate fid exists.
    if !session.fids.contains(fid) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("fid {fid} not found"),
        )
        .into());
    }

    tracing::debug!(
        fid,
        direction,
        rkey,
        addr = format!("{addr:#x}"),
        length,
        "RDMA token registered"
    );

    // Store the client's RDMA token for this fid.
    session.rdma_tokens.insert(
        fid,
        RdmaToken {
            direction,
            rkey,
            addr,
            length,
        },
    );

    // Respond with server's RDMA info. For now, we return zeros since
    // the server uses its own MrPool internally and doesn't expose its
    // buffer addresses to the client. The client only needs to know that
    // the token was accepted.
    //
    // In future, the server could expose its pool's rkey/addr so the
    // client can do RDMA Read/Write in the other direction.
    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rrdmatoken,
        tag: fc.tag,
        msg: Msg::Rrdmatoken {
            rkey: 0,
            addr: 0,
            length: 0,
        },
    })
}
