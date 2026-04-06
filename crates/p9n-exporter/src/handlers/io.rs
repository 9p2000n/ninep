use crate::backend::local::LocalBackend;
use crate::handlers::HandlerResult;
use crate::lease_manager::LeaseManager;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::io::{Read, Seek, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use crate::util::join_err;

/// Handle Tlopen: open a file associated with a fid.
pub async fn handle_lopen(session: &Session, _backend: &LocalBackend, fc: Fcall) -> HandlerResult {
    let Msg::Lopen { fid, flags } = fc.msg else {
        return Err("expected Lopen message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    let is_dir = fid_state.is_dir;
    let qid = fid_state.qid.clone();
    drop(fid_state);

    let msize = session.get_msize();

    let owned_fd = tokio::task::spawn_blocking(move || -> std::io::Result<OwnedFd> {
        if is_dir {
            let fd = nix::fcntl::open(
                path.as_os_str(),
                nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
                nix::sys::stat::Mode::empty(),
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        } else {
            let mut oflags = nix::fcntl::OFlag::empty();
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

            let fd = nix::fcntl::open(
                path.as_os_str(),
                oflags,
                nix::sys::stat::Mode::empty(),
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    })
    .await
    .map_err(join_err)??;

    // Update fid with the opened fd
    if let Some(mut fid_state) = session.fids.get_mut(fid) {
        fid_state.handle = Some(Arc::new(owned_fd));
    }

    let iounit = msize - 24;

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
/// buffer that receives the file data — one allocation, one read, zero
/// intermediate copies.
pub async fn handle_read(session: &Session, _backend: &LocalBackend, fc: Fcall) -> Result<ReadResult, Box<dyn std::error::Error + Send + Sync>> {
    let Msg::Read { fid, offset, count } = fc.msg else {
        return Err("expected Read message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let raw_fd = fid_state
        .handle
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "fid not open"))?
        .as_raw_fd();
    drop(fid_state);

    let wire = tokio::task::spawn_blocking(move || {
        // Wire layout: size[4] + type[1] + tag[2] + count[4] + data[n]
        //              ^^^^^^^^ header (7 bytes) ^^^^^^^^ ^^^^ data prefix
        const HDR: usize = 7 + 4; // 9P header + data length prefix

        let mut buf = vec![0u8; HDR + count as usize];

        // Read file data directly into the data region (offset HDR)
        let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        file.seek(std::io::SeekFrom::Start(offset))?;
        let n = file.read(&mut buf[HDR..])?;
        std::mem::forget(file);

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

/// Result of handle_read — pre-encoded wire bytes for the zero-copy fast path.
pub enum ReadResult {
    /// Pre-encoded wire bytes ready to send directly on the QUIC stream.
    Raw(Vec<u8>),
}

/// Fallback read handler returning a regular Fcall.
///
/// Used by the TCP transport and Tcompound dispatch where we cannot bypass the
/// marshal layer.  This still goes through the standard encode path.
pub async fn handle_read_fcall(session: &Session, _backend: &LocalBackend, fc: Fcall) -> HandlerResult {
    let Msg::Read { fid, offset, count } = fc.msg else {
        return Err("expected Read message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let raw_fd = fid_state
        .handle
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "fid not open"))?
        .as_raw_fd();
    drop(fid_state);

    let data = tokio::task::spawn_blocking(move || {
        let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        file.seek(std::io::SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; count as usize];
        let n = file.read(&mut buf)?;
        buf.truncate(n);
        std::mem::forget(file);
        Ok::<_, std::io::Error>(buf)
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rread,
        tag,
        msg: Msg::Rread { data },
    })
}

/// Handle Twrite: write bytes to an open file.
pub async fn handle_write(session: &Session, _backend: &LocalBackend, lease_mgr: &LeaseManager, fc: Fcall) -> HandlerResult {
    let Msg::Write { fid, offset, data } = fc.msg else {
        return Err("expected Write message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let raw_fd = fid_state
        .handle
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "fid not open"))?
        .as_raw_fd();
    let qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break read leases held by other connections on this file.
    lease_mgr.break_for_write(qid_path, session.conn_id);

    let n = tokio::task::spawn_blocking(move || {
        let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        file.seek(std::io::SeekFrom::Start(offset))?;
        let n = file.write(&data)?;
        std::mem::forget(file);
        Ok::<_, std::io::Error>(n)
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rwrite,
        tag,
        msg: Msg::Rwrite { count: n as u32 },
    })
}

/// Handle Treadlink: read a symbolic link target.
pub async fn handle_readlink(
    session: &Session,
    _backend: &LocalBackend,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Readlink { fid } = fc.msg else {
        return Err("expected Readlink message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let target_str = tokio::task::spawn_blocking(move || {
        let target = std::fs::read_link(&path)?;
        Ok::<_, std::io::Error>(target.to_string_lossy().to_string())
    })
    .await
    .map_err(join_err)??;

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
pub async fn handle_fsync(session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::Fsync { fid } = fc.msg else {
        return Err("expected Fsync message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;

    let raw_fd = fid_state.handle.as_ref().map(|fd| fd.as_raw_fd());
    drop(fid_state);

    if let Some(raw_fd) = raw_fd {
        tokio::task::spawn_blocking(move || {
            nix::unistd::fsync(raw_fd)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        })
        .await
        .map_err(join_err)??;
    }

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rfsync,
        tag,
        msg: Msg::Empty,
    })
}
