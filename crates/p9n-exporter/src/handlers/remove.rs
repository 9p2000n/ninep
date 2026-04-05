use crate::backend::local::LocalBackend;
use crate::handlers::HandlerResult;
use crate::lease_manager::LeaseManager;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use crate::util::join_err;

/// Handle Tunlinkat: remove a file or directory.
pub async fn handle_unlinkat(
    session: &Session,
    backend: &LocalBackend,
    lease_mgr: &LeaseManager,
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

    let fid_state = session
        .fids
        .get(dirfid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let target = fid_state.path.join(&name);
    let dir_qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the parent directory (its listing is changing).
    lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let resolved = backend.resolve(&target)?;

    tokio::task::spawn_blocking(move || {
        // AT_REMOVEDIR = 0x200
        if flags & 0x200 != 0 {
            std::fs::remove_dir(&resolved)
        } else {
            std::fs::remove_file(&resolved)
        }
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
pub async fn handle_remove(
    session: &Session,
    backend: &LocalBackend,
    lease_mgr: &LeaseManager,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Remove { fid } = fc.msg else {
        return Err("expected Remove message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    let is_dir = fid_state.is_dir;
    let qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the file being removed.
    lease_mgr.break_for_write(qid_path, session.conn_id);

    let resolved = backend.resolve(&path)?;

    tokio::task::spawn_blocking(move || {
        if is_dir {
            std::fs::remove_dir(&resolved)
        } else {
            std::fs::remove_file(&resolved)
        }
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
pub async fn handle_renameat(
    session: &Session,
    backend: &LocalBackend,
    lease_mgr: &LeaseManager,
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
    lease_mgr.break_for_write(old_dir_qid, session.conn_id);
    if new_dir_qid != old_dir_qid {
        lease_mgr.break_for_write(new_dir_qid, session.conn_id);
    }

    let resolved_old = backend.resolve(&old_path)?;
    let resolved_new = backend.resolve(&new_path)?;

    tokio::task::spawn_blocking(move || {
        std::fs::rename(&resolved_old, &resolved_new)
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
