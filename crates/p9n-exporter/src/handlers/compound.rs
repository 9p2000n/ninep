//! Handle Tcompound: execute a batch of sub-operations sequentially.
//!
//! Each SubOp is decoded as a standalone Fcall, dispatched through the normal
//! handler pipeline, and the result is re-encoded as a SubOp in the response.

use crate::backend::Backend;
use crate::handlers::{HandlerResult, PushTx};
use crate::session::Session;
use crate::shared::SharedCtx;
use crate::watch_manager::WatchEvent;
use p9n_proto::buf::Buf;
use p9n_proto::codec;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use p9n_proto::wire::SubOp;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Handle Tcompound: execute sub-operations sequentially, collecting results.
///
/// Each SubOp carries a message type + raw payload. We wrap it in a Fcall header,
/// dispatch through the normal handler, and re-encode the response as a SubOp.
///
/// If any sub-op fails, we stop and return the results collected so far
/// (partial success is valid per the 9P2000.N spec).
pub async fn handle<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    watch_tx: &mpsc::Sender<WatchEvent>,
    push_tx: &PushTx,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Compound { ops } = fc.msg else {
        return Err("expected Compound message".into());
    };
    let tag = fc.tag;

    let mut results: Vec<SubOp> = Vec::with_capacity(ops.len());

    for (i, op) in ops.iter().enumerate() {
        // Decode the sub-operation: reconstruct a full Fcall from SubOp payload
        let sub_fc = decode_subop(op, tag)?;

        // Dispatch through normal handler pipeline
        // Box::pin to avoid infinite-sized future from recursive async dispatch
        let sub_result = Box::pin(crate::handlers::dispatch(session, ctx, watch_tx, push_tx, sub_fc)).await;

        match sub_result {
            Ok(response) => {
                // Encode the response back into a SubOp
                let result_op = encode_subop(&response)?;
                results.push(result_op);
            }
            Err(e) => {
                // On error, encode Rlerror as the failed sub-op result and stop
                tracing::debug!("compound sub-op {i} failed: {e}");
                let err_fc = Fcall {
                    size: 0,
                    msg_type: MsgType::Rlerror,
                    tag: 0,
                    msg: Msg::Lerror { ecode: crate::util::map_io_error(&*e) },
                };
                if let Ok(err_op) = encode_subop(&err_fc) {
                    results.push(err_op);
                }
                break;
            }
        }
    }

    tracing::debug!("compound: {}/{} sub-ops completed", results.len(), ops.len());

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rcompound,
        tag,
        msg: Msg::Rcompound { results },
    })
}

/// Decode a SubOp into a full Fcall for dispatch.
///
/// SubOp wire: opsize[4] type[1] payload[opsize-5]
/// We need to wrap it as: size[4] type[1] tag[2] payload
fn decode_subop(op: &SubOp, parent_tag: u16) -> Result<Fcall, Box<dyn std::error::Error + Send + Sync>> {
    // Build a wire-format message from the SubOp
    let mut buf = Buf::new(HEADER_SIZE + op.payload.len());
    let total_size = (HEADER_SIZE + op.payload.len()) as u32;
    buf.put_u32(total_size);
    buf.put_u8(op.msg_type as u8);
    buf.put_u16(parent_tag);
    buf.put_bytes(&op.payload);

    let mut rbuf = Buf::from_bytes(buf.into_vec());
    let fc = codec::unmarshal(&mut rbuf)?;
    Ok(fc)
}

/// Encode a response Fcall back into a SubOp.
fn encode_subop(fc: &Fcall) -> Result<SubOp, Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = Buf::new(256);
    codec::marshal(&mut buf, fc)?;
    let wire = buf.into_vec();

    // Extract payload (skip the header: size[4] + type[1] + tag[2] = 7 bytes)
    let payload = if wire.len() > HEADER_SIZE {
        wire[HEADER_SIZE..].to_vec()
    } else {
        Vec::new()
    };

    Ok(SubOp {
        msg_type: fc.msg_type,
        payload,
    })
}
