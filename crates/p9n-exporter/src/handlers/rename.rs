//! Handle Trename (legacy rename, maps to rename syscall).

use crate::backend::local::LocalBackend;
use crate::handlers::HandlerResult;
use crate::lease_manager::LeaseManager;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use crate::util::join_err;

pub async fn handle(session: &Session, backend: &LocalBackend, lease_mgr: &LeaseManager, fc: Fcall) -> HandlerResult {
    let Msg::Rename { fid, dfid, name } = fc.msg else {
        return Err("expected Rename message".into());
    };
    let tag = fc.tag;

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
    lease_mgr.break_for_write(fid_qid_path, session.conn_id);
    lease_mgr.break_for_write(dfid_qid_path, session.conn_id);

    let new_path = new_dir.join(&name);
    let resolved_old = backend.resolve(&old_path)?;
    let resolved_new = backend.resolve(&new_path)?;

    tokio::task::spawn_blocking(move || {
        std::fs::rename(&resolved_old, &resolved_new)
    }).await.map_err(join_err)??;

    Ok(Fcall { size: 0, msg_type: MsgType::Rrename, tag, msg: Msg::Empty })
}
