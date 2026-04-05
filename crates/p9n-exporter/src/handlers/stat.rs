use crate::access::AccessControl;
use crate::backend::local::LocalBackend;
use crate::handlers::HandlerResult;
use crate::lease_manager::LeaseManager;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use crate::util::join_err;

pub async fn handle_getattr(
    session: &Session,
    _backend: &LocalBackend,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Getattr { fid, mask: _ } = fc.msg else {
        return Err("expected Getattr message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let (stat, qid) = tokio::task::spawn_blocking(move || {
        let meta = std::fs::symlink_metadata(&path)?;
        let stat = LocalBackend::make_stat(&meta);
        let qid = LocalBackend::make_qid(&meta);
        Ok::<_, std::io::Error>((stat, qid))
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rgetattr,
        tag,
        msg: Msg::Rgetattr {
            valid: stat.valid,
            qid,
            stat,
        },
    })
}

/// Handle Tsetattr with access control enforcement.
///
/// - Mode/size/time changes require PERM_SETATTR (checked by dispatch)
/// - uid/gid changes additionally require PERM_ADMIN
pub async fn handle_setattr(
    session: &Session,
    ac: &AccessControl,
    lease_mgr: &LeaseManager,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Setattr { fid, attr } = fc.msg else {
        return Err("expected Setattr message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    let qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break read leases held by other connections on this file.
    lease_mgr.break_for_write(qid_path, session.conn_id);

    // chown/chgrp require admin permission
    if attr.valid & (P9_SETATTR_UID | P9_SETATTR_GID) != 0 {
        ac.check_admin(session.spiffe_id.as_deref())?;
    }

    tokio::task::spawn_blocking(move || {
        setattr_blocking(&path, &attr)
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rsetattr,
        tag,
        msg: Msg::Empty,
    })
}

fn setattr_blocking(
    path: &PathBuf,
    attr: &p9n_proto::wire::SetAttr,
) -> Result<(), std::io::Error> {
    if attr.valid & P9_SETATTR_MODE != 0 {
        let perms = std::fs::Permissions::from_mode(attr.mode);
        std::fs::set_permissions(path, perms)?;
    }

    if attr.valid & P9_SETATTR_SIZE != 0 {
        let file = std::fs::OpenOptions::new().write(true).open(path)?;
        file.set_len(attr.size)?;
    }

    if attr.valid & (P9_SETATTR_UID | P9_SETATTR_GID) != 0 {
        let uid = if attr.valid & P9_SETATTR_UID != 0 {
            Some(nix::unistd::Uid::from_raw(attr.uid))
        } else {
            None
        };
        let gid = if attr.valid & P9_SETATTR_GID != 0 {
            Some(nix::unistd::Gid::from_raw(attr.gid))
        } else {
            None
        };
        nix::unistd::chown(path, uid, gid)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    }

    if attr.valid & (P9_SETATTR_ATIME | P9_SETATTR_MTIME) != 0 {
        let atime = if attr.valid & P9_SETATTR_ATIME_SET != 0 {
            nix::sys::time::TimeSpec::new(attr.atime_sec as i64, attr.atime_nsec as i64)
        } else if attr.valid & P9_SETATTR_ATIME != 0 {
            nix::sys::time::TimeSpec::UTIME_NOW
        } else {
            nix::sys::time::TimeSpec::UTIME_OMIT
        };
        let mtime = if attr.valid & P9_SETATTR_MTIME_SET != 0 {
            nix::sys::time::TimeSpec::new(attr.mtime_sec as i64, attr.mtime_nsec as i64)
        } else if attr.valid & P9_SETATTR_MTIME != 0 {
            nix::sys::time::TimeSpec::UTIME_NOW
        } else {
            nix::sys::time::TimeSpec::UTIME_OMIT
        };
        nix::sys::stat::utimensat(
            None,
            path,
            &atime,
            &mtime,
            nix::sys::stat::UtimensatFlags::NoFollowSymlink,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    }

    Ok(())
}

pub async fn handle_statfs(
    session: &Session,
    _backend: &LocalBackend,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Statfs { fid } = fc.msg else {
        return Err("expected Statfs message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let stat = tokio::task::spawn_blocking(move || {
        LocalBackend::make_statfs(&path)
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rstatfs,
        tag,
        msg: Msg::Rstatfs { stat },
    })
}
