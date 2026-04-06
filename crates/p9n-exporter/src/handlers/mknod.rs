//! Handle Tmknod: create device nodes, FIFOs, sockets.

use crate::access::AccessControl;
use crate::backend::Backend;
use crate::backend::local::LocalBackend;
use crate::handlers::HandlerResult;
use crate::lease_manager::LeaseManager;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use crate::util::join_err;

pub async fn handle(session: &Session, backend: &LocalBackend, ac: &AccessControl, lease_mgr: &LeaseManager, fc: Fcall) -> HandlerResult {
    let Msg::Mknod { dfid, name, mode, major, minor, gid: _ } = fc.msg else {
        return Err("expected Mknod message".into());
    };
    let tag = fc.tag;

    let fid_state = session.fids.get(dfid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let dir_path = fid_state.path.clone();
    let dir_qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the parent directory (its contents are changing).
    lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let node_path = dir_path.join(&name);
    let resolved = backend.resolve(&node_path)?;
    let spiffe_id = session.spiffe_id.clone();

    let (qid, resolved_path) = tokio::task::spawn_blocking(move || {
        let dev = nix::sys::stat::makedev(major as u64, minor as u64);
        let nix_mode = nix::sys::stat::Mode::from_bits_truncate(mode as nix::sys::stat::mode_t);
        // Determine SFlag from mode
        let sflag = match mode & libc::S_IFMT as u32 {
            x if x == libc::S_IFCHR as u32 => nix::sys::stat::SFlag::S_IFCHR,
            x if x == libc::S_IFBLK as u32 => nix::sys::stat::SFlag::S_IFBLK,
            x if x == libc::S_IFIFO as u32 => nix::sys::stat::SFlag::S_IFIFO,
            x if x == libc::S_IFSOCK as u32 => nix::sys::stat::SFlag::S_IFSOCK,
            _ => nix::sys::stat::SFlag::S_IFREG,
        };
        nix::sys::stat::mknod(&resolved, sflag, nix_mode, dev)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let meta = std::fs::symlink_metadata(&resolved)?;
        Ok::<_, std::io::Error>((LocalBackend::make_qid(&meta), resolved))
    }).await.map_err(join_err)??;

    let (uid, gid) = ac.ownership_for(spiffe_id.as_deref());
    if uid != 0 || gid != 0 {
        backend.chown(&resolved_path, uid, gid)?;
    }

    Ok(Fcall { size: 0, msg_type: MsgType::Rmknod, tag, msg: Msg::Rmknod { qid } })
}
