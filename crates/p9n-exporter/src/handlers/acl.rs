//! Handle Tgetacl / Tsetacl: POSIX ACL via system.posix_acl_access xattr.

use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::ffi::CString;
use std::path::PathBuf;
use crate::util::join_err;

pub async fn handle(session: &Session, fc: Fcall) -> HandlerResult {
    match fc.msg_type {
        MsgType::Tgetacl => handle_getacl(session, fc).await,
        MsgType::Tsetacl => handle_setacl(session, fc).await,
        _ => Err("unexpected ACL message".into()),
    }
}

async fn handle_getacl(session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::Getacl { fid, acl_type } = fc.msg else { return Err("expected Getacl".into()); };
    let tag = fc.tag;

    let fid_state = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let xattr_name = acl_xattr_name(acl_type);

    let data = tokio::task::spawn_blocking(move || {
        xattr_get_raw(&path, &xattr_name)
    }).await.map_err(join_err)??;

    Ok(Fcall { size: 0, msg_type: MsgType::Rgetacl, tag, msg: Msg::Rgetacl { data } })
}

async fn handle_setacl(session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::Setacl { fid, acl_type, data } = fc.msg else { return Err("expected Setacl".into()); };
    let tag = fc.tag;

    let fid_state = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let xattr_name = acl_xattr_name(acl_type);

    tokio::task::spawn_blocking(move || {
        xattr_set_raw(&path, &xattr_name, &data)
    }).await.map_err(join_err)??;

    Ok(Fcall { size: 0, msg_type: MsgType::Rsetacl, tag, msg: Msg::Empty })
}

fn acl_xattr_name(acl_type: u8) -> String {
    match acl_type {
        0 => "system.posix_acl_access".into(),
        1 => "system.posix_acl_default".into(),
        _ => format!("system.posix_acl_{acl_type}"),
    }
}

fn xattr_get_raw(path: &PathBuf, name: &str) -> std::io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let c_name = CString::new(name).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let size = unsafe { libc::getxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 { return Err(std::io::Error::last_os_error()); }
    let mut buf = vec![0u8; size as usize];
    let n = unsafe { libc::getxattr(c_path.as_ptr(), c_name.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len()) };
    if n < 0 { return Err(std::io::Error::last_os_error()); }
    buf.truncate(n as usize);
    Ok(buf)
}

fn xattr_set_raw(path: &PathBuf, name: &str, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let c_name = CString::new(name).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let rc = unsafe { libc::setxattr(c_path.as_ptr(), c_name.as_ptr(), data.as_ptr() as *const _, data.len(), 0) };
    if rc < 0 { return Err(std::io::Error::last_os_error()); }
    Ok(())
}
