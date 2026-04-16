//! Handle Thash: compute file hash via Backend.

use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use std::sync::Arc;
use crate::util::{fid_not_open, join_err, unknown_fid};

pub async fn handle<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Hash { fid, algo, offset, length } = fc.msg else {
        return Err("expected Hash".into());
    };
    let tag = fc.tag;
    tracing::trace!(tag, fid, algo, offset, length, "Thash received");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Thash"))?;
    let handle = fid_state.handle.as_ref()
        .ok_or_else(|| fid_not_open(fid, "Thash"))?
        .clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let hash = tokio::task::spawn_blocking(move || {
        ctx.backend.hash(&handle, algo, offset, length)
    }).await.map_err(join_err)??;

    tracing::trace!(tag, fid, algo, hash_len = hash.len(), "Thash result");

    Ok(Fcall { size: 0, msg_type: MsgType::Rhash, tag, msg: Msg::Rhash { algo, hash } })
}
