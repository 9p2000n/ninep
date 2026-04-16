use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use crate::util::{fid_not_open, join_err, unknown_fid};

/// Handle Tlopen: open a file associated with a fid.
pub async fn handle_lopen<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Lopen { fid, flags } = fc.msg else {
        return Err("expected Lopen message".into());
    };
    let tag = fc.tag;
    tracing::debug!(tag, fid, flags = format_args!("{:#x}", flags), "Tlopen received");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Tlopen"))?;
    let path = fid_state.path.clone();
    let is_dir = fid_state.is_dir;
    drop(fid_state);

    let msize = session.get_msize();

    let ctx = ctx.clone();
    let (owned_handle, qid) = tokio::task::spawn_blocking(move || {
        ctx.backend.open(&path, flags, is_dir)
    })
    .await
    .map_err(join_err)??;

    // Update fid with the opened handle
    if let Some(mut fid_state) = session.fids.get_mut(fid) {
        fid_state.handle = Some(Arc::new(owned_handle));
    }

    let iounit = msize - 24;

    tracing::debug!(
        tag, fid, is_dir,
        qid_path = qid.path,
        iounit,
        "Tlopen result",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rlopen,
        tag,
        msg: Msg::Rlopen { qid, iounit },
    })
}

/// Handle Tread: read bytes from an open file.
///
/// Returns pre-encoded wire bytes via `ReadResult::Raw` to avoid copying the
/// file data through the marshal layer (`put_data` / `extend_from_slice`).
/// The 9P header and data-length prefix are written directly into the same
/// buffer that receives the file data -- one allocation, one read, zero
/// intermediate copies.
pub async fn handle_read<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> Result<ReadResult, Box<dyn std::error::Error + Send + Sync>> {
    let Msg::Read { fid, offset, count } = fc.msg else {
        return Err("expected Read message".into());
    };
    let tag = fc.tag;
    tracing::trace!(tag, fid, offset, count, "Tread received");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Tread"))?;
    let handle = fid_state
        .handle
        .as_ref()
        .ok_or_else(|| fid_not_open(fid, "Tread"))?
        .clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let wire = tokio::task::spawn_blocking(move || {
        // Wire layout: size[4] + type[1] + tag[2] + count[4] + data[n]
        //              ^^^^^^^^ header (7 bytes) ^^^^^^^^ ^^^^ data prefix
        const HDR: usize = 7 + 4; // 9P header + data length prefix

        let mut buf = vec![0u8; HDR + count as usize];

        // Read file data directly into the data region (offset HDR)
        let n = ctx.backend.read_into(&handle, offset, &mut buf[HDR..])?;

        // Truncate to actual size
        buf.truncate(HDR + n);
        let total = buf.len() as u32;

        // Back-fill the 9P header in-place
        buf[0..4].copy_from_slice(&total.to_le_bytes());       // size[4]
        buf[4] = MsgType::Rread as u8;                         // type[1]
        buf[5..7].copy_from_slice(&tag.to_le_bytes());         // tag[2]
        buf[7..11].copy_from_slice(&(n as u32).to_le_bytes()); // data count[4]

        Ok::<_, std::io::Error>(buf)
    })
    .await
    .map_err(join_err)??;

    Ok(ReadResult::Raw(wire))
}

/// Result of handle_read -- pre-encoded wire bytes for the zero-copy fast path.
pub enum ReadResult {
    /// Pre-encoded wire bytes ready to send directly on the QUIC stream.
    Raw(Vec<u8>),
}

/// Fallback read handler returning a regular Fcall.
///
/// Used by the TCP transport and Tcompound dispatch where we cannot bypass the
/// marshal layer.  This still goes through the standard encode path.
pub async fn handle_read_fcall<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Read { fid, offset, count } = fc.msg else {
        return Err("expected Read message".into());
    };
    let tag = fc.tag;
    tracing::trace!(tag, fid, offset, count, "Tread received (fcall path)");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Tread"))?;
    let handle = fid_state
        .handle
        .as_ref()
        .ok_or_else(|| fid_not_open(fid, "Tread"))?
        .clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let data = tokio::task::spawn_blocking(move || {
        ctx.backend.read(&handle, offset, count)
    })
    .await
    .map_err(join_err)??;

    tracing::trace!(tag, fid, n = data.len(), "Tread result (fcall path)");

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rread,
        tag,
        msg: Msg::Rread { data },
    })
}

/// Handle Twrite: write bytes to an open file.
pub async fn handle_write<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Write { fid, offset, data } = fc.msg else {
        return Err("expected Write message".into());
    };
    let tag = fc.tag;
    let data_len = data.len();
    tracing::debug!(tag, fid, offset, len = data_len, "Twrite received");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Twrite"))?;
    let handle = fid_state
        .handle
        .as_ref()
        .ok_or_else(|| fid_not_open(fid, "Twrite"))?
        .clone();
    let qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break read leases held by other connections on this file.
    ctx.lease_mgr.break_for_write(qid_path, session.conn_id);

    let ctx = ctx.clone();
    let n = tokio::task::spawn_blocking(move || {
        ctx.backend.write(&handle, offset, &data)
    })
    .await
    .map_err(join_err)??;

    tracing::debug!(
        tag, fid, offset,
        requested = data_len,
        n,
        short = (n as usize) < data_len,
        "Twrite result",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rwrite,
        tag,
        msg: Msg::Rwrite { count: n as u32 },
    })
}

/// Handle Treadlink: read a symbolic link target.
pub async fn handle_readlink<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Readlink { fid } = fc.msg else {
        return Err("expected Readlink message".into());
    };
    let tag = fc.tag;
    tracing::trace!(tag, fid, "Treadlink received");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Treadlink"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let ctx = ctx.clone();
    let target_str = tokio::task::spawn_blocking(move || {
        ctx.backend.readlink(&path)
    })
    .await
    .map_err(join_err)??;

    tracing::trace!(tag, fid, target_len = target_str.len(), "Treadlink result");

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rreadlink,
        tag,
        msg: Msg::Rreadlink {
            target: target_str,
        },
    })
}

/// Handle Tfsync: flush file data to disk.
pub async fn handle_fsync<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Fsync { fid } = fc.msg else {
        return Err("expected Fsync message".into());
    };
    let tag = fc.tag;
    tracing::debug!(tag, fid, "Tfsync received");

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Tfsync"))?;
    let handle = fid_state.handle.clone();
    drop(fid_state);

    let had_handle = handle.is_some();
    if let Some(handle) = handle {
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || {
            ctx.backend.fsync(&handle)
        })
        .await
        .map_err(join_err)??;
    }

    tracing::debug!(tag, fid, had_handle, "Tfsync result");

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rfsync,
        tag,
        msg: Msg::Empty,
    })
}
