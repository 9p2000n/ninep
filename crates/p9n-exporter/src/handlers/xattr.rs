//! Handle Txattrget, Txattrset, Txattrlist via Backend xattr methods.

use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use crate::util::{join_err, unknown_fid};

pub async fn handle<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    match fc.msg_type {
        MsgType::Txattrget => handle_xattrget(session, ctx, fc).await,
        MsgType::Txattrset => handle_xattrset(session, ctx, fc).await,
        MsgType::Txattrlist => handle_xattrlist(session, ctx, fc).await,
        _ => Err("unexpected xattr message type".into()),
    }
}

async fn handle_xattrget<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Xattrget { fid, name } = fc.msg else {
        return Err("expected Xattrget".into());
    };
    let tag = fc.tag;
    tracing::trace!(tag, fid, name = %name, "Txattrget received");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Txattrget"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let name_for_log = name.clone();
    let data = tokio::task::spawn_blocking(move || {
        ctx.backend.xattr_get(&path, &name)
    }).await.map_err(join_err)??;

    tracing::trace!(tag, fid, name = %name_for_log, n = data.len(), "Txattrget result");

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rxattrget,
        tag,
        msg: Msg::Rxattrget { data },
    })
}

async fn handle_xattrset<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Xattrset { fid, name, data, flags } = fc.msg else {
        return Err("expected Xattrset".into());
    };
    let tag = fc.tag;
    let data_len = data.len();
    tracing::debug!(
        tag, fid,
        name = %name,
        len = data_len,
        flags = format_args!("{:#x}", flags),
        "Txattrset received",
    );

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Txattrset"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let name_for_log = name.clone();
    tokio::task::spawn_blocking(move || {
        ctx.backend.xattr_set(&path, &name, &data, flags)
    }).await.map_err(join_err)??;

    tracing::debug!(tag, fid, name = %name_for_log, len = data_len, "Txattrset result");

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rxattrset,
        tag,
        msg: Msg::Empty,
    })
}

async fn handle_xattrlist<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Xattrlist { fid, cookie, count } = fc.msg else {
        return Err("expected Xattrlist".into());
    };
    let tag = fc.tag;
    tracing::trace!(tag, fid, cookie, count, "Txattrlist received");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Txattrlist"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let raw_names = tokio::task::spawn_blocking(move || {
        ctx.backend.xattr_list(&path)
    }).await.map_err(join_err)??;

    // Parse null-separated list into individual names
    let all_names: Vec<String> = raw_names
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();

    let total = all_names.len();
    // Apply pagination: skip entries before cookie, limit to count
    let start = cookie as usize;
    let names: Vec<String> = all_names.into_iter()
        .skip(start)
        .take(if count > 0 { count as usize } else { usize::MAX })
        .collect();

    // Next cookie = start + returned count (0 if no more)
    let next_cookie = if names.is_empty() { 0 } else { (start + names.len()) as u64 };

    tracing::trace!(
        tag, fid,
        cookie,
        returned = names.len(),
        next_cookie,
        total,
        "Txattrlist result",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rxattrlist,
        tag,
        msg: Msg::Rxattrlist { cookie: next_cookie, names },
    })
}
