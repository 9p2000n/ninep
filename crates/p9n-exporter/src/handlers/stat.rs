use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use std::sync::Arc;
use crate::util::join_err;

pub async fn handle_getattr<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Getattr { fid, mask: _ } = fc.msg else {
        return Err("expected Getattr message".into());
    };
    let tag = fc.tag;
    tracing::trace!("getattr: fid={fid}");

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let (stat, qid) = tokio::task::spawn_blocking(move || {
        ctx.backend.getattr(&path)
    })
    .await
    .map_err(join_err)??;

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
    tracing::trace!("setattr: fid={fid} valid={:#x}", attr.valid);

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    let qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break read leases held by other connections on this file.
    ctx.lease_mgr.break_for_write(qid_path, session.conn_id);

    // chown/chgrp require admin permission
    if attr.valid & (P9_SETATTR_UID | P9_SETATTR_GID) != 0 {
        ctx.access.check_admin(session.spiffe_id.as_deref())?;
    }

    let ctx = ctx.clone();
    tokio::task::spawn_blocking(move || {
        ctx.backend.setattr(&path, &attr)
    })
    .await
    .map_err(join_err)??;

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
    tracing::trace!("statfs: fid={fid}");

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let stat = tokio::task::spawn_blocking(move || {
        ctx.backend.statfs(&path)
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rstatfs,
        tag,
        msg: Msg::Rstatfs { stat },
    })
}
