use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use crate::util::{fid_not_open, join_err, unknown_fid};

/// Handle Tallocate: preallocate file space via fallocate.
pub async fn handle<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Allocate {
        fid,
        mode,
        offset,
        length,
    } = fc.msg
    else {
        return Err("expected Allocate message".into());
    };
    let tag = fc.tag;
    tracing::debug!(
        tag, fid,
        mode = format_args!("{:#x}", mode),
        offset, length,
        "Tallocate received",
    );

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Tallocate"))?;
    let handle = fid_state
        .handle
        .as_ref()
        .ok_or_else(|| fid_not_open(fid, "Tallocate"))?
        .clone();
    drop(fid_state);

    let ctx = ctx.clone();
    tokio::task::spawn_blocking(move || {
        ctx.backend.allocate(&handle, mode, offset, length)
    })
    .await
    .map_err(join_err)??;

    tracing::debug!(tag, fid, offset, length, "Tallocate result");

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rallocate,
        tag,
        msg: Msg::Empty,
    })
}
