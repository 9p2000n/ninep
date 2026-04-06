use crate::backend::Backend;
use crate::fid_table::FidState;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use crate::util::join_err;

/// Handle Tlcreate: create and open a new file.
pub async fn handle_lcreate<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Lcreate {
        fid,
        name,
        flags,
        mode,
        gid: _,
    } = fc.msg
    else {
        return Err("expected Lcreate message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let dir_path = fid_state.path.clone();
    let dir_qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the parent directory (its contents are changing).
    ctx.lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let msize = session.get_msize();
    let spiffe_id = session.spiffe_id.clone();

    let ctx_clone = ctx.clone();
    let (owned_handle, qid, resolved_path) = tokio::task::spawn_blocking(move || {
        ctx_clone.backend.lcreate(&dir_path, &name, flags, mode)
    })
    .await
    .map_err(join_err)??;

    let (uid, gid) = ctx.access.ownership_for(spiffe_id.as_deref());
    if uid != 0 || gid != 0 {
        ctx.backend.chown(&resolved_path, uid, gid)?;
    }

    let iounit = msize - 24;

    // Update the fid to point to the new file (per 9P semantics, lcreate changes the fid)
    session.fids.insert(
        fid,
        FidState {
            path: resolved_path,
            qid: qid.clone(),
            handle: Some(Arc::new(owned_handle)),
            is_dir: false,
        },
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rlcreate,
        tag,
        msg: Msg::Rlcreate { qid, iounit },
    })
}

/// Handle Tsymlink: create a symbolic link.
pub async fn handle_symlink<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Symlink {
        fid,
        name,
        symtgt,
        gid: _,
    } = fc.msg
    else {
        return Err("expected Symlink message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let dir_path = fid_state.path.clone();
    let dir_qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the parent directory (its contents are changing).
    ctx.lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let spiffe_id = session.spiffe_id.clone();

    let ctx_clone = ctx.clone();
    let (qid, resolved_path) = tokio::task::spawn_blocking(move || {
        ctx_clone.backend.symlink(&dir_path, &name, &symtgt)
    })
    .await
    .map_err(join_err)??;

    let (uid, gid) = ctx.access.ownership_for(spiffe_id.as_deref());
    if uid != 0 || gid != 0 {
        ctx.backend.chown(&resolved_path, uid, gid)?;
    }

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rsymlink,
        tag,
        msg: Msg::Rsymlink { qid },
    })
}

/// Handle Tlink: create a hard link.
pub async fn handle_link<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Link { dfid, fid, name } = fc.msg else {
        return Err("expected Link message".into());
    };
    let tag = fc.tag;

    let dfid_state = session
        .fids
        .get(dfid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown dfid"))?;
    let dir_path = dfid_state.path.clone();
    let dir_qid_path = dfid_state.qid.path;
    drop(dfid_state);

    // Break leases on the parent directory (its contents are changing).
    ctx.lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let target_path = fid_state.path.clone();
    drop(fid_state);

    let ctx = ctx.clone();
    tokio::task::spawn_blocking(move || {
        ctx.backend.link(&target_path, &dir_path, &name)
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rlink,
        tag,
        msg: Msg::Empty,
    })
}
