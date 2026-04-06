use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use crate::util::join_err;

/// Handle Tcopyrange: server-side copy between two open files.
///
/// Uses the backend's `copy_range` method which delegates to
/// `copy_file_range(2)` for kernel-optimized data transfer (reflink on
/// btrfs/xfs, in-kernel pipe on ext4, etc.) or `ioctl(FICLONERANGE)`
/// when the `COPY_REFLINK` flag is set.
pub async fn handle<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Copyrange {
        src_fid,
        src_off,
        dst_fid,
        dst_off,
        count,
        flags,
    } = fc.msg
    else {
        return Err("expected Copyrange message".into());
    };
    let tag = fc.tag;

    let src_state = session
        .fids
        .get(src_fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown src_fid"))?;
    let src_handle = src_state
        .handle
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "src not open"))?
        .clone();
    drop(src_state);

    let dst_state = session
        .fids
        .get(dst_fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown dst_fid"))?;
    let dst_handle = dst_state
        .handle
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "dst not open"))?
        .clone();
    drop(dst_state);

    let ctx = ctx.clone();
    let total_copied = tokio::task::spawn_blocking(move || {
        ctx.backend.copy_range(&src_handle, src_off, &dst_handle, dst_off, count, flags)
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rcopyrange,
        tag,
        msg: Msg::Rcopyrange {
            count: total_copied as u64,
        },
    })
}
