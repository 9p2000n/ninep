//! Handle Tmknod: create device nodes, FIFOs, sockets.

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
    let Msg::Mknod { dfid, name, mode, major, minor, gid: _ } = fc.msg else {
        return Err("expected Mknod message".into());
    };
    let tag = fc.tag;

    let fid_state = session.fids.get(dfid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let parent_path = fid_state.path.clone();
    let dir_qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the parent directory (its contents are changing).
    ctx.lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let spiffe_id = session.spiffe_id.clone();

    let ctx_clone = ctx.clone();
    let (qid, resolved_path) = tokio::task::spawn_blocking(move || {
        ctx_clone.backend.mknod(&parent_path, &name, mode, major, minor)
    }).await.map_err(join_err)??;

    let (uid, gid) = ctx.access.ownership_for(spiffe_id.as_deref());
    if uid != 0 || gid != 0 {
        ctx.backend.chown(&resolved_path, uid, gid)?;
    }

    Ok(Fcall { size: 0, msg_type: MsgType::Rmknod, tag, msg: Msg::Rmknod { qid } })
}
