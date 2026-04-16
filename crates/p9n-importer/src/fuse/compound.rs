//! Client-side helpers for building and parsing Tcompound messages.
//!
//! Combines multiple 9P sub-operations into a single round-trip, reducing
//! latency for common operation pairs like walk+getattr and setattr+getattr.

use crate::error::RpcError;
use crate::rpc_client::RpcClient;
use p9n_proto::buf::Buf;
use p9n_proto::codec;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::{MsgType, HEADER_SIZE};
use p9n_proto::wire::SubOp;

/// Encode an (msg_type, msg) pair into a SubOp for inclusion in a Tcompound.
pub fn encode_subop(msg_type: MsgType, msg: &Msg) -> Result<SubOp, RpcError> {
    let fc = Fcall {
        size: 0,
        msg_type,
        tag: 0, // dummy tag; compound handler overwrites with parent tag
        msg: msg.clone(),
    };
    let mut buf = Buf::new(256);
    codec::marshal(&mut buf, &fc).map_err(|e| RpcError::from(format!("compound encode: {e}")))?;
    let wire = buf.into_vec();
    let payload = if wire.len() > HEADER_SIZE {
        wire[HEADER_SIZE..].to_vec()
    } else {
        Vec::new()
    };
    Ok(SubOp { msg_type, payload })
}

/// Decode a response SubOp back into a full Fcall.
///
/// If the sub-op is an Rlerror, returns `Err(RpcError::NineP { ecode })`.
pub fn decode_subop(op: &SubOp) -> Result<Fcall, RpcError> {
    let total_size = (HEADER_SIZE + op.payload.len()) as u32;
    let mut buf = Buf::new(HEADER_SIZE + op.payload.len());
    buf.put_u32(total_size);
    buf.put_u8(op.msg_type as u8);
    buf.put_u16(0); // dummy tag
    buf.put_bytes(&op.payload);

    let mut rbuf = Buf::from_bytes(buf.into_vec());
    let fc =
        codec::unmarshal(&mut rbuf).map_err(|e| RpcError::from(format!("compound decode: {e}")))?;

    // Convert Rlerror to RpcError so callers can use `?`
    match &fc.msg {
        Msg::Lerror { ecode } => Err(RpcError::NineP { ecode: *ecode }),
        _ => Ok(fc),
    }
}

/// Send a Tcompound and return the response SubOps.
pub async fn send_compound(
    rpc: &RpcClient,
    ops: Vec<SubOp>,
) -> Result<Vec<SubOp>, RpcError> {
    let nops = ops.len();
    tracing::trace!(nops, "compound send");
    let resp = rpc
        .call(MsgType::Tcompound, Msg::Compound { ops })
        .await?;
    match resp.msg {
        Msg::Rcompound { results } => {
            tracing::trace!(nops, nresults = results.len(), "compound recv");
            Ok(results)
        }
        _ => Err(RpcError::from("expected Rcompound response")),
    }
}
