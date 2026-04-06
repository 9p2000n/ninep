use crate::backend::local::LocalBackend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::{self, MsgType};
use std::os::unix::io::AsRawFd;
use crate::util::join_err;

/// Handle Tcopyrange: server-side copy between two open files.
///
/// Uses `copy_file_range(2)` for kernel-optimized data transfer (reflink on
/// btrfs/xfs, in-kernel pipe on ext4, etc.).  When the `COPY_REFLINK` flag is
/// set, an `ioctl(FICLONERANGE)` is attempted instead — this requests a
/// copy-on-write clone and fails with EOPNOTSUPP on filesystems that do not
/// support it.
pub async fn handle(session: &Session, _backend: &LocalBackend, fc: Fcall) -> HandlerResult {
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
    let src_raw = src_state
        .handle
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "src not open"))?
        .as_raw_fd();
    drop(src_state);

    let dst_state = session
        .fids
        .get(dst_fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown dst_fid"))?;
    let dst_raw = dst_state
        .handle
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "dst not open"))?
        .as_raw_fd();
    drop(dst_state);

    let total_copied = tokio::task::spawn_blocking(move || {
        if flags & types::COPY_REFLINK != 0 {
            reflink_range(src_raw, src_off, dst_raw, dst_off, count)
        } else {
            copy_file_range_loop(src_raw, src_off, dst_raw, dst_off, count)
        }
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

/// Kernel-optimized copy via `copy_file_range(2)`.  Loops until `count` bytes
/// have been transferred or EOF is reached.
fn copy_file_range_loop(
    src_raw: i32,
    src_off: u64,
    dst_raw: i32,
    dst_off: u64,
    count: u64,
) -> Result<usize, std::io::Error> {
    use std::os::fd::BorrowedFd;

    // SAFETY: the raw fds are borrowed from OwnedFd in the fid table and
    // remain valid for the duration of the spawn_blocking closure.
    let src_fd = unsafe { BorrowedFd::borrow_raw(src_raw) };
    let dst_fd = unsafe { BorrowedFd::borrow_raw(dst_raw) };

    let mut off_in = src_off as i64;
    let mut off_out = dst_off as i64;
    let mut remaining = count as usize;
    let mut total: usize = 0;

    while remaining > 0 {
        let n = nix::fcntl::copy_file_range(
            src_fd,
            Some(&mut off_in),
            dst_fd,
            Some(&mut off_out),
            remaining,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        if n == 0 {
            break; // EOF
        }
        remaining -= n;
        total += n;
    }
    Ok(total)
}

/// COW clone via `ioctl(FICLONERANGE)`.  Fails with EOPNOTSUPP if the
/// filesystem does not support reflinks.
fn reflink_range(
    src_raw: i32,
    src_off: u64,
    dst_raw: i32,
    dst_off: u64,
    count: u64,
) -> Result<usize, std::io::Error> {
    #[repr(C)]
    struct FileCloneRange {
        src_fd: i64,
        src_offset: u64,
        src_length: u64,
        dest_offset: u64,
    }

    // FICLONERANGE = _IOW(0x94, 13, struct file_clone_range)
    // = 0x4020940d on x86-64/aarch64
    const FICLONERANGE: libc::c_ulong = 0x4020940d;

    let arg = FileCloneRange {
        src_fd: src_raw as i64,
        src_offset: src_off,
        src_length: count,
        dest_offset: dst_off,
    };
    let ret = unsafe { libc::ioctl(dst_raw, FICLONERANGE, &arg) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(count as usize)
}
