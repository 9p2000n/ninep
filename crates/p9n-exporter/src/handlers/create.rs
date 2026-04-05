use crate::access::AccessControl;
use crate::backend::local::LocalBackend;
use crate::fid_table::FidState;
use crate::handlers::HandlerResult;
use crate::lease_manager::LeaseManager;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::os::unix::io::{FromRawFd, OwnedFd};
use crate::util::join_err;

/// Handle Tlcreate: create and open a new file.
pub async fn handle_lcreate(
    session: &Session,
    backend: &LocalBackend,
    ac: &AccessControl,
    lease_mgr: &LeaseManager,
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
    lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let file_path = dir_path.join(&name);
    let resolved = backend.resolve(&file_path)?;

    let msize = session.get_msize();
    let spiffe_id = session.spiffe_id.clone();

    let (owned_fd, qid, resolved_path) = tokio::task::spawn_blocking(move || {
        // Build open flags
        let mut oflags = nix::fcntl::OFlag::O_CREAT;
        let access = flags & 0x03;
        match access {
            0 => oflags |= nix::fcntl::OFlag::O_RDONLY,
            1 => oflags |= nix::fcntl::OFlag::O_WRONLY,
            2 => oflags |= nix::fcntl::OFlag::O_RDWR,
            _ => oflags |= nix::fcntl::OFlag::O_RDONLY,
        }
        if flags & 0o1000 != 0 {
            oflags |= nix::fcntl::OFlag::O_TRUNC;
        }
        if flags & 0o2000 != 0 {
            oflags |= nix::fcntl::OFlag::O_APPEND;
        }
        if flags & 0o200 != 0 {
            oflags |= nix::fcntl::OFlag::O_EXCL;
        }

        let nix_mode = nix::sys::stat::Mode::from_bits_truncate(mode as nix::sys::stat::mode_t);
        let fd = nix::fcntl::open(resolved.as_os_str(), oflags, nix_mode)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let meta = std::fs::metadata(&resolved)?;
        let qid = LocalBackend::make_qid(&meta);

        Ok::<_, std::io::Error>((owned_fd, qid, resolved))
    })
    .await
    .map_err(join_err)??;

    ac.apply_ownership(spiffe_id.as_deref(), &resolved_path)?;

    let iounit = msize - 24;

    // Update the fid to point to the new file (per 9P semantics, lcreate changes the fid)
    session.fids.insert(
        fid,
        FidState {
            path: resolved_path,
            qid: qid.clone(),
            open_fd: Some(owned_fd),
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
pub async fn handle_symlink(
    session: &Session,
    backend: &LocalBackend,
    ac: &AccessControl,
    lease_mgr: &LeaseManager,
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
    let link_path = fid_state.path.join(&name);
    let dir_qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the parent directory (its contents are changing).
    lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let resolved = backend.resolve(&link_path)?;
    let spiffe_id = session.spiffe_id.clone();

    let (qid, resolved_path) = tokio::task::spawn_blocking(move || {
        std::os::unix::fs::symlink(&symtgt, &resolved)?;
        let meta = std::fs::symlink_metadata(&resolved)?;
        Ok::<_, std::io::Error>((LocalBackend::make_qid(&meta), resolved))
    })
    .await
    .map_err(join_err)??;

    ac.apply_ownership(spiffe_id.as_deref(), &resolved_path)?;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rsymlink,
        tag,
        msg: Msg::Rsymlink { qid },
    })
}

/// Handle Tlink: create a hard link.
pub async fn handle_link(
    session: &Session,
    backend: &LocalBackend,
    lease_mgr: &LeaseManager,
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
    let link_path = dfid_state.path.join(&name);
    let dir_qid_path = dfid_state.qid.path;
    drop(dfid_state);

    // Break leases on the parent directory (its contents are changing).
    lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let target_path = fid_state.path.clone();
    drop(fid_state);

    let resolved = backend.resolve(&link_path)?;

    tokio::task::spawn_blocking(move || {
        std::fs::hard_link(&target_path, &resolved)
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
