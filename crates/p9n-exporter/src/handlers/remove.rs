use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use crate::util::join_err;

/// Handle Tunlinkat: remove a file or directory.
pub async fn handle_unlinkat<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Unlinkat {
        dirfid,
        name,
        flags,
    } = fc.msg
    else {
        return Err("expected Unlinkat message".into());
    };
    let tag = fc.tag;
    tracing::trace!("unlinkat: dirfid={dirfid} name={name} flags={flags:#x}");

    let fid_state = session
        .fids
        .get(dirfid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let target = fid_state.path.join(&name);
    let dir_qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the parent directory (its listing is changing).
    ctx.lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let resolved = ctx.backend.resolve(&target)?;
    // AT_REMOVEDIR = 0x200
    let is_dir = flags & 0x200 != 0;

    let ctx = ctx.clone();
    tokio::task::spawn_blocking(move || {
        ctx.backend.unlink(&resolved, is_dir)
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Runlinkat,
        tag,
        msg: Msg::Empty,
    })
}

/// Handle Tremove: remove the file/dir referenced by fid, then clunk the fid.
///
/// Maps to the same logic as Tunlinkat but operates on the fid's own path.
pub async fn handle_remove<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Remove { fid } = fc.msg else {
        return Err("expected Remove message".into());
    };
    let tag = fc.tag;
    tracing::trace!("remove: fid={fid}");

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    let is_dir = fid_state.is_dir;
    let qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the file being removed.
    ctx.lease_mgr.break_for_write(qid_path, session.conn_id);

    let resolved = ctx.backend.resolve(&path)?;

    let ctx = ctx.clone();
    tokio::task::spawn_blocking(move || {
        ctx.backend.unlink(&resolved, is_dir)
    })
    .await
    .map_err(join_err)??;

    // Clunk the fid after removal (per 9P spec)
    session.fids.remove(fid);

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rremove,
        tag,
        msg: Msg::Empty,
    })
}

/// Handle Trenameat: rename a file or directory.
pub async fn handle_renameat<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Renameat {
        olddirfid,
        oldname,
        newdirfid,
        newname,
    } = fc.msg
    else {
        return Err("expected Renameat message".into());
    };
    let tag = fc.tag;
    tracing::trace!("renameat: olddirfid={olddirfid} oldname={oldname} newdirfid={newdirfid} newname={newname}");

    let old_dir = session
        .fids
        .get(olddirfid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown olddirfid"))?;
    let old_path = old_dir.path.join(&oldname);
    let old_dir_qid = old_dir.qid.path;
    drop(old_dir);

    let new_dir = session
        .fids
        .get(newdirfid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown newdirfid"))?;
    let new_path = new_dir.path.join(&newname);
    let new_dir_qid = new_dir.qid.path;
    drop(new_dir);

    // Break leases on both source and destination parent directories.
    ctx.lease_mgr.break_for_write(old_dir_qid, session.conn_id);
    if new_dir_qid != old_dir_qid {
        ctx.lease_mgr.break_for_write(new_dir_qid, session.conn_id);
    }

    let resolved_old = ctx.backend.resolve(&old_path)?;
    let resolved_new = ctx.backend.resolve(&new_path)?;

    let ctx = ctx.clone();
    tokio::task::spawn_blocking(move || {
        ctx.backend.rename(&resolved_old, &resolved_new)
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rrenameat,
        tag,
        msg: Msg::Empty,
    })
}
