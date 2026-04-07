//! Handle Trename (legacy rename, maps to rename syscall).

use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use crate::util::join_err;

pub async fn handle<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Rename { fid, dfid, name } = fc.msg else {
        return Err("expected Rename message".into());
    };
    let tag = fc.tag;
    tracing::trace!("rename: fid={fid} dfid={dfid} name={name}");

    let fid_state = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let old_path = fid_state.path.clone();
    let fid_qid_path = fid_state.qid.path;
    drop(fid_state);

    let dfid_state = session.fids.get(dfid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown dfid"))?;
    let new_dir = dfid_state.path.clone();
    let dfid_qid_path = dfid_state.qid.path;
    drop(dfid_state);

    // Break leases on the renamed file and the target directory.
    ctx.lease_mgr.break_for_write(fid_qid_path, session.conn_id);
    ctx.lease_mgr.break_for_write(dfid_qid_path, session.conn_id);

    let new_path = new_dir.join(&name);
    let resolved_old = ctx.backend.resolve(&old_path)?;
    let resolved_new = ctx.backend.resolve(&new_path)?;

    let ctx = ctx.clone();
    tokio::task::spawn_blocking(move || {
        ctx.backend.rename(&resolved_old, &resolved_new)
    }).await.map_err(join_err)??;

    Ok(Fcall { size: 0, msg_type: MsgType::Rrename, tag, msg: Msg::Empty })
}
