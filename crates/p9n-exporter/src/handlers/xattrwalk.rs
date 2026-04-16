//! Handle Txattrwalk / Txattrcreate (base xattr protocol).
//!
//! Base xattrs are accessed via fid-based walk/create + read/write,
//! unlike 9P2000.N's direct Txattrget/Txattrset messages.

use crate::backend::Backend;
use crate::fid_table::FidState;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use p9n_proto::wire::Qid;
use std::path::PathBuf;
use std::sync::Arc;
use crate::util::{join_err, unknown_fid};

/// Handle Txattrwalk: create a fid representing an xattr value.
/// If name is empty, returns the total size of all xattr names (for listxattr).
pub async fn handle_xattrwalk<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Xattrwalk { fid, newfid, name } = fc.msg else {
        return Err("expected Xattrwalk".into());
    };
    let tag = fc.tag;
    let list_mode = name.is_empty();
    tracing::debug!(
        tag, fid, newfid,
        name = %name,
        list_mode,
        "Txattrwalk received",
    );

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Txattrwalk"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let xattr_name = name.clone();
    let ctx = ctx.clone();
    let xattr_size = tokio::task::spawn_blocking(move || {
        if xattr_name.is_empty() {
            // List mode: return total size of xattr names
            ctx.backend.xattr_list_size(&path)
        } else {
            // Get mode: return size of specific xattr
            ctx.backend.xattr_size(&path, &xattr_name)
        }
    }).await.map_err(join_err)??;

    // Create the new fid as a placeholder for the xattr
    session.fids.insert(newfid, FidState {
        path: PathBuf::from(format!("__xattr__:{}", name)),
        qid: Qid { qtype: 0, version: 0, path: newfid as u64 },
        handle: None,
        is_dir: false,
    });

    tracing::debug!(
        tag, fid, newfid,
        name = %name,
        list_mode,
        size = xattr_size,
        "Txattrwalk result",
    );

    Ok(Fcall {
        size: 0, msg_type: MsgType::Rxattrwalk, tag,
        msg: Msg::Rxattrwalk { size: xattr_size },
    })
}

/// Handle Txattrcreate: prepare a fid for writing an xattr value.
pub fn handle_xattrcreate<H: Send + Sync + 'static>(
    session: &Session<H>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Xattrcreate { fid, name, attr_size, flags } = fc.msg else {
        return Err("expected Xattrcreate".into());
    };
    let tag = fc.tag;
    tracing::debug!(
        tag, fid,
        name = %name,
        attr_size,
        flags = format_args!("{:#x}", flags),
        "Txattrcreate received",
    );

    // Verify fid exists
    let _ = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Txattrcreate"))?;

    // The actual xattr write happens via subsequent Twrite + Tclunk.
    // For now, return success (the fid is already set up).

    Ok(Fcall {
        size: 0, msg_type: MsgType::Rxattrcreate, tag,
        msg: Msg::Empty,
    })
}
