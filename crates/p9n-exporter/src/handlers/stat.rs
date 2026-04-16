use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use std::sync::Arc;
use crate::util::{join_err, unknown_fid};

pub async fn handle_getattr<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Getattr { fid, mask } = fc.msg else {
        return Err("expected Getattr message".into());
    };
    let tag = fc.tag;
    tracing::trace!(tag, fid, mask = format_args!("{:#x}", mask), "Tgetattr received");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Tgetattr"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let (stat, qid) = tokio::task::spawn_blocking(move || {
        ctx.backend.getattr(&path)
    })
    .await
    .map_err(join_err)??;

    tracing::trace!(
        tag, fid,
        valid = format_args!("{:#x}", stat.valid),
        qid_path = qid.path,
        size = stat.size,
        "Tgetattr result",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rgetattr,
        tag,
        msg: Msg::Rgetattr {
            valid: stat.valid,
            qid,
            stat,
        },
    })
}

/// Handle Tsetattr with access control enforcement.
///
/// - Mode/size/time changes require PERM_SETATTR (checked by dispatch)
/// - uid/gid changes additionally require PERM_ADMIN
pub async fn handle_setattr<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Setattr { fid, attr } = fc.msg else {
        return Err("expected Setattr message".into());
    };
    let tag = fc.tag;
    let valid = attr.valid;
    let touches_owner = attr.valid & (P9_SETATTR_UID | P9_SETATTR_GID) != 0;
    tracing::debug!(
        tag, fid,
        valid = format_args!("{:#x}", valid),
        touches_owner,
        "Tsetattr received",
    );

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Tsetattr"))?;
    let path = fid_state.path.clone();
    let qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break read leases held by other connections on this file.
    ctx.lease_mgr.break_for_write(qid_path, session.conn_id);

    // chown/chgrp require admin permission
    if touches_owner {
        ctx.access.check_admin(session.spiffe_id.as_deref())?;
    }

    let ctx = ctx.clone();
    tokio::task::spawn_blocking(move || {
        ctx.backend.setattr(&path, &attr)
    })
    .await
    .map_err(join_err)??;

    tracing::debug!(
        tag, fid, qid_path,
        valid = format_args!("{:#x}", valid),
        "Tsetattr result",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rsetattr,
        tag,
        msg: Msg::Empty,
    })
}

pub async fn handle_statfs<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Statfs { fid } = fc.msg else {
        return Err("expected Statfs message".into());
    };
    let tag = fc.tag;
    tracing::trace!(tag, fid, "Tstatfs received");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Tstatfs"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let stat = tokio::task::spawn_blocking(move || {
        ctx.backend.statfs(&path)
    })
    .await
    .map_err(join_err)??;

    tracing::trace!(
        tag, fid,
        bsize = stat.bsize,
        blocks = stat.blocks,
        bfree = stat.bfree,
        files = stat.files,
        "Tstatfs result",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rstatfs,
        tag,
        msg: Msg::Rstatfs { stat },
    })
}
