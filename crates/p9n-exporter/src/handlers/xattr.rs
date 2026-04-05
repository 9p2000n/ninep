//! Handle Txattrget, Txattrset, Txattrlist via libc xattr syscalls.

use crate::backend::local::LocalBackend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::ffi::CString;
use std::path::PathBuf;
use crate::util::join_err;

pub async fn handle(session: &Session, _backend: &LocalBackend, fc: Fcall) -> HandlerResult {
    match fc.msg_type {
        MsgType::Txattrget => handle_xattrget(session, fc).await,
        MsgType::Txattrset => handle_xattrset(session, fc).await,
        MsgType::Txattrlist => handle_xattrlist(session, fc).await,
        _ => Err("unexpected xattr message type".into()),
    }
}

async fn handle_xattrget(session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::Xattrget { fid, name } = fc.msg else {
        return Err("expected Xattrget".into());
    };
    let tag = fc.tag;

    let fid_state = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let data = tokio::task::spawn_blocking(move || {
        xattr_get(&path, &name)
    }).await.map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rxattrget,
        tag,
        msg: Msg::Rxattrget { data },
    })
}

async fn handle_xattrset(session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::Xattrset { fid, name, data, flags } = fc.msg else {
        return Err("expected Xattrset".into());
    };
    let tag = fc.tag;

    let fid_state = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    tokio::task::spawn_blocking(move || {
        xattr_set(&path, &name, &data, flags)
    }).await.map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rxattrset,
        tag,
        msg: Msg::Empty,
    })
}

async fn handle_xattrlist(session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::Xattrlist { fid, cookie, count } = fc.msg else {
        return Err("expected Xattrlist".into());
    };
    let tag = fc.tag;

    let fid_state = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let all_names = tokio::task::spawn_blocking(move || {
        xattr_list(&path)
    }).await.map_err(join_err)??;

    // Apply pagination: skip entries before cookie, limit to count
    let start = cookie as usize;
    let names: Vec<String> = all_names.into_iter()
        .skip(start)
        .take(if count > 0 { count as usize } else { usize::MAX })
        .collect();

    // Next cookie = start + returned count (0 if no more)
    let next_cookie = if names.is_empty() { 0 } else { (start + names.len()) as u64 };

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rxattrlist,
        tag,
        msg: Msg::Rxattrlist { cookie: next_cookie, names },
    })
}

// ── libc xattr wrappers ──

fn xattr_get(path: &PathBuf, name: &str) -> std::io::Result<Vec<u8>> {
    let c_path = path_to_cstring(path)?;
    let c_name = CString::new(name).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    // First call: get size
    let size = unsafe {
        libc::getxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0)
    };
    if size < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut buf = vec![0u8; size as usize];
    let n = unsafe {
        libc::getxattr(c_path.as_ptr(), c_name.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len())
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

fn xattr_set(path: &PathBuf, name: &str, data: &[u8], flags: u32) -> std::io::Result<()> {
    let c_path = path_to_cstring(path)?;
    let c_name = CString::new(name).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let rc = unsafe {
        libc::setxattr(c_path.as_ptr(), c_name.as_ptr(), data.as_ptr() as *const _, data.len(), flags as i32)
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn xattr_list(path: &PathBuf) -> std::io::Result<Vec<String>> {
    let c_path = path_to_cstring(path)?;

    // First call: get size
    let size = unsafe { libc::listxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; size as usize];
    let n = unsafe { libc::listxattr(c_path.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len()) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Parse null-separated list
    let names = buf[..n as usize]
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();

    Ok(names)
}

fn path_to_cstring(path: &PathBuf) -> std::io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
}
