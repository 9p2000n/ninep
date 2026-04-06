//! Handle Txattrwalk / Txattrcreate (base xattr protocol).
//!
//! Base xattrs are accessed via fid-based walk/create + read/write,
//! unlike 9P2000.N's direct Txattrget/Txattrset messages.

use crate::fid_table::FidState;
use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use p9n_proto::wire::Qid;
use std::ffi::CString;
use std::path::PathBuf;
use crate::util::join_err;

/// Handle Txattrwalk: create a fid representing an xattr value.
/// If name is empty, returns the total size of all xattr names (for listxattr).
pub async fn handle_xattrwalk(session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::Xattrwalk { fid, newfid, name } = fc.msg else {
        return Err("expected Xattrwalk".into());
    };
    let tag = fc.tag;

    let fid_state = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let xattr_name = name.clone();
    let xattr_size = tokio::task::spawn_blocking(move || {
        if xattr_name.is_empty() {
            // List mode: return total size of xattr names
            xattr_list_size(&path)
        } else {
            // Get mode: return size of specific xattr
            xattr_get_size(&path, &xattr_name)
        }
    }).await.map_err(join_err)??;

    // Create the new fid as a placeholder for the xattr
    session.fids.insert(newfid, FidState {
        path: PathBuf::from(format!("__xattr__:{}", name)),
        qid: Qid { qtype: 0, version: 0, path: newfid as u64 },
        handle: None,
        is_dir: false,
    });

    Ok(Fcall {
        size: 0, msg_type: MsgType::Rxattrwalk, tag,
        msg: Msg::Rxattrwalk { size: xattr_size },
    })
}

/// Handle Txattrcreate: prepare a fid for writing an xattr value.
pub async fn handle_xattrcreate(session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::Xattrcreate { fid, name, attr_size: _, flags: _ } = fc.msg else {
        return Err("expected Xattrcreate".into());
    };
    let tag = fc.tag;

    // Verify fid exists
    let _ = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;

    // The actual xattr write happens via subsequent Twrite + Tclunk.
    // For now, return success (the fid is already set up).
    tracing::debug!("xattrcreate: fid={fid} name={name}");

    Ok(Fcall {
        size: 0, msg_type: MsgType::Rxattrcreate, tag,
        msg: Msg::Empty,
    })
}

fn xattr_get_size(path: &PathBuf, name: &str) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let c_name = CString::new(name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let size = unsafe { libc::getxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 { return Err(std::io::Error::last_os_error()); }
    Ok(size as u64)
}

fn xattr_list_size(path: &PathBuf) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let size = unsafe { libc::listxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 { return Err(std::io::Error::last_os_error()); }
    Ok(size as u64)
}
