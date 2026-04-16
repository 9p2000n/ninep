//! Handle Tlock / Tgetlock: POSIX file locking.

use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use crate::util::{fid_not_open, join_err, unknown_fid};

pub async fn handle_lock<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Lock { fid, lock_type, flags, start, length, proc_id, client_id: _ } = fc.msg else {
        return Err("expected Lock message".into());
    };
    let tag = fc.tag;
    tracing::debug!(
        tag, fid, lock_type,
        flags = format_args!("{:#x}", flags),
        start, length, proc_id,
        "Tlock received",
    );

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Tlock"))?;
    let handle = fid_state.handle.as_ref()
        .ok_or_else(|| fid_not_open(fid, "Tlock"))?
        .clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let status = tokio::task::spawn_blocking(move || {
        ctx.backend.lock(&handle, lock_type, flags, start, length, proc_id)
    }).await.map_err(join_err)??;

    tracing::debug!(tag, fid, lock_type, status, "Tlock result");

    Ok(Fcall { size: 0, msg_type: MsgType::Rlock, tag, msg: Msg::Rlock { status } })
}

pub async fn handle_getlock<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::GetlockReq { fid, lock_type, start, length, proc_id, client_id: _ } = fc.msg else {
        return Err("expected GetlockReq message".into());
    };
    let tag = fc.tag;
    tracing::debug!(tag, fid, lock_type, start, length, proc_id, "Tgetlock received");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Tgetlock"))?;
    let handle = fid_state.handle.as_ref()
        .ok_or_else(|| fid_not_open(fid, "Tgetlock"))?
        .clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let result = tokio::task::spawn_blocking(move || {
        ctx.backend.getlock(&handle, lock_type, start, length, proc_id)
    }).await.map_err(join_err)??;

    tracing::debug!(
        tag, fid,
        result_lock_type = result.0,
        result_start = result.1,
        result_length = result.2,
        result_proc_id = result.3,
        "Tgetlock result",
    );

    Ok(Fcall {
        size: 0, msg_type: MsgType::Rgetlock, tag,
        msg: Msg::RgetlockResp {
            lock_type: result.0,
            start: result.1,
            length: result.2,
            proc_id: result.3,
            client_id: String::new(),
        },
    })
}
