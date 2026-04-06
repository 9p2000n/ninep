//! Handle Tlock / Tgetlock: POSIX file locking.

use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::os::unix::io::AsRawFd;
use crate::util::join_err;

pub async fn handle_lock(session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::Lock { fid, lock_type, flags, start, length, proc_id, client_id: _ } = fc.msg else {
        return Err("expected Lock message".into());
    };
    let tag = fc.tag;

    let fid_state = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let raw_fd = fid_state.handle.as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "fid not open"))?
        .as_raw_fd();
    drop(fid_state);

    let blocking = flags & p9n_proto::types::P9_LOCK_FLAGS_BLOCK != 0;

    let status = tokio::task::spawn_blocking(move || {
        let l_type = match lock_type {
            0 => libc::F_RDLCK as i16,  // P9_LOCK_TYPE_RDLCK
            1 => libc::F_WRLCK as i16,  // P9_LOCK_TYPE_WRLCK
            2 => libc::F_UNLCK as i16,  // P9_LOCK_TYPE_UNLCK
            _ => libc::F_RDLCK as i16,
        };

        let mut flock = libc::flock {
            l_type,
            l_whence: libc::SEEK_SET as i16,
            l_start: start as i64,
            l_len: length as i64,
            l_pid: proc_id as i32,
        };

        let cmd = if blocking { libc::F_SETLKW } else { libc::F_SETLK };
        let rc = unsafe { libc::fcntl(raw_fd, cmd, &mut flock) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) || err.raw_os_error() == Some(libc::EACCES) {
                return Ok(p9n_proto::types::P9_LOCK_BLOCKED);
            }
            return Err(err);
        }
        Ok(p9n_proto::types::P9_LOCK_SUCCESS)
    }).await.map_err(join_err)??;

    Ok(Fcall { size: 0, msg_type: MsgType::Rlock, tag, msg: Msg::Rlock { status } })
}

pub async fn handle_getlock(session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::GetlockReq { fid, lock_type, start, length, proc_id, client_id: _ } = fc.msg else {
        return Err("expected GetlockReq message".into());
    };
    let tag = fc.tag;

    let fid_state = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let raw_fd = fid_state.handle.as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "fid not open"))?
        .as_raw_fd();
    drop(fid_state);

    let result = tokio::task::spawn_blocking(move || {
        let l_type = match lock_type {
            0 => libc::F_RDLCK as i16,
            1 => libc::F_WRLCK as i16,
            _ => libc::F_RDLCK as i16,
        };
        let mut flock = libc::flock {
            l_type,
            l_whence: libc::SEEK_SET as i16,
            l_start: start as i64,
            l_len: length as i64,
            l_pid: proc_id as i32,
        };
        let rc = unsafe { libc::fcntl(raw_fd, libc::F_GETLK, &mut flock) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let out_type = match flock.l_type as i32 {
            libc::F_RDLCK => 0u8,
            libc::F_WRLCK => 1,
            _ => 2, // UNLCK = no conflicting lock
        };
        Ok((out_type, flock.l_start as u64, flock.l_len as u64, flock.l_pid as u32))
    }).await.map_err(join_err)??;

    Ok(Fcall {
        size: 0, msg_type: MsgType::Rgetlock, tag,
        msg: Msg::RgetlockResp {
            lock_type: result.0,
            start: result.1,
            length: result.2,
            proc_id: result.3,
            client_id: String::new(),
        },
    })
}
