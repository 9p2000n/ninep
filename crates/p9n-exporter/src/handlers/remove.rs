use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use crate::util::{join_err, unknown_fid};

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
    // AT_REMOVEDIR = 0x200
    let is_dir = flags & 0x200 != 0;
    tracing::debug!(
        tag, dirfid,
        name = %name,
        flags = format_args!("{:#x}", flags),
        is_dir,
        "Tunlinkat received",
    );

    let fid_state = session.fids.get(dirfid).ok_or_else(|| unknown_fid(dirfid, "Tunlinkat"))?;
    let target = fid_state.path.join(&name);
    let dir_qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the parent directory (its listing is changing).
    ctx.lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let ctx = ctx.clone();
    let name_for_log = name.clone();
    tokio::task::spawn_blocking(move || {
        let resolved = ctx.backend.resolve(&target)?;
        ctx.backend.unlink(&resolved, is_dir)
    })
    .await
    .map_err(join_err)??;

    tracing::debug!(tag, dirfid, name = %name_for_log, is_dir, "Tunlinkat result");

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
    tracing::debug!(tag, fid, "Tremove received");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Tremove"))?;
    let path = fid_state.path.clone();
    let is_dir = fid_state.is_dir;
    let qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the file being removed.
    ctx.lease_mgr.break_for_write(qid_path, session.conn_id);

    let ctx = ctx.clone();
    tokio::task::spawn_blocking(move || {
        let resolved = ctx.backend.resolve(&path)?;
        ctx.backend.unlink(&resolved, is_dir)
    })
    .await
    .map_err(join_err)??;

    // Clunk the fid after removal (per 9P spec)
    session.fids.remove(fid);

    tracing::debug!(
        tag, fid, qid_path, is_dir,
        fids_total = session.fids.len(),
        "Tremove result",
    );

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
    tracing::debug!(
        tag, olddirfid, newdirfid,
        oldname = %oldname,
        newname = %newname,
        "Trenameat received",
    );

    let old_dir = session.fids.get(olddirfid).ok_or_else(|| unknown_fid(olddirfid, "Trenameat"))?;
    let old_path = old_dir.path.join(&oldname);
    let old_dir_qid = old_dir.qid.path;
    drop(old_dir);

    let new_dir = session.fids.get(newdirfid).ok_or_else(|| unknown_fid(newdirfid, "Trenameat"))?;
    let new_path = new_dir.path.join(&newname);
    let new_dir_qid = new_dir.qid.path;
    drop(new_dir);

    // Break leases on both source and destination parent directories.
    ctx.lease_mgr.break_for_write(old_dir_qid, session.conn_id);
    if new_dir_qid != old_dir_qid {
        ctx.lease_mgr.break_for_write(new_dir_qid, session.conn_id);
    }

    let cross_dir = new_dir_qid != old_dir_qid;
    let ctx = ctx.clone();
    let oldname_for_log = oldname.clone();
    let newname_for_log = newname.clone();
    tokio::task::spawn_blocking(move || {
        let resolved_old = ctx.backend.resolve(&old_path)?;
        let resolved_new = ctx.backend.resolve(&new_path)?;
        ctx.backend.rename(&resolved_old, &resolved_new)
    })
    .await
    .map_err(join_err)??;

    tracing::debug!(
        tag, olddirfid, newdirfid,
        oldname = %oldname_for_log,
        newname = %newname_for_log,
        cross_dir,
        "Trenameat result",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rrenameat,
        tag,
        msg: Msg::Empty,
    })
}
