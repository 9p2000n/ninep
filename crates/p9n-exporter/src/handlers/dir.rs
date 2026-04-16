use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use crate::util::join_err;

/// Handle Treaddir: list directory entries.
///
/// Returns raw directory entry data in the 9P readdir format:
/// qid[13] offset[8] type[1] name_len[2] name[name_len]
pub async fn handle_readdir<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Readdir { fid, offset, count } = fc.msg else {
        return Err("expected Readdir message".into());
    };
    let tag = fc.tag;
    tracing::trace!("readdir: fid={fid} offset={offset} count={count}");

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;

    if !fid_state.is_dir {
        return Err(
            std::io::Error::new(std::io::ErrorKind::NotADirectory, "not a directory").into(),
        );
    }

    let dir_path = fid_state.path.clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let data = tokio::task::spawn_blocking(move || {
        ctx.backend.readdir(&dir_path, offset, count)
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rreaddir,
        tag,
        msg: Msg::Rreaddir { data },
    })
}

/// Handle Tmkdir: create a directory.
pub async fn handle_mkdir<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Mkdir {
        dfid,
        name,
        mode,
        gid: _,
    } = fc.msg
    else {
        return Err("expected Mkdir message".into());
    };
    let tag = fc.tag;
    tracing::trace!("mkdir: dfid={dfid} name={name} mode={mode:#o}");

    let fid_state = session
        .fids
        .get(dfid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let parent_path = fid_state.path.clone();
    let dir_qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the parent directory (its contents are changing).
    ctx.lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let spiffe_id = session.spiffe_id.clone();
    let (uid, gid) = ctx.access.ownership_for(spiffe_id.as_deref());

    let ctx_clone = ctx.clone();
    let (qid, _resolved_path) = tokio::task::spawn_blocking(move || {
        let (qid, resolved_path) = ctx_clone.backend.mkdir(&parent_path, &name, mode)?;
        if uid != 0 || gid != 0 {
            ctx_clone.backend.chown(&resolved_path, uid, gid)?;
        }
        Ok::<_, std::io::Error>((qid, resolved_path))
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rmkdir,
        tag,
        msg: Msg::Rmkdir { qid },
    })
}
