use crate::backend::local::LocalBackend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::io::{Read, Seek, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use crate::util::join_err;

/// Handle Tcopyrange: server-side copy between two open files.
pub async fn handle(session: &Session, _backend: &LocalBackend, fc: Fcall) -> HandlerResult {
    let Msg::Copyrange {
        src_fid,
        src_off,
        dst_fid,
        dst_off,
        count,
        flags: _,
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
        .open_fd
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "src not open"))?
        .as_raw_fd();
    drop(src_state);

    let dst_state = session
        .fids
        .get(dst_fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown dst_fid"))?;
    let dst_raw = dst_state
        .open_fd
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "dst not open"))?
        .as_raw_fd();
    drop(dst_state);

    let total_copied = tokio::task::spawn_blocking(move || {
        let mut src_file = unsafe { std::fs::File::from_raw_fd(src_raw) };
        let mut dst_file = unsafe { std::fs::File::from_raw_fd(dst_raw) };

        src_file.seek(std::io::SeekFrom::Start(src_off))?;
        dst_file.seek(std::io::SeekFrom::Start(dst_off))?;

        let mut remaining = count as usize;
        let mut total_copied: usize = 0;
        let mut buf = vec![0u8; remaining.min(64 * 1024)];

        while remaining > 0 {
            let to_read = remaining.min(buf.len());
            let n = src_file.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            dst_file.write_all(&buf[..n])?;
            remaining -= n;
            total_copied += n;
        }

        // Don't let File drop close the borrowed fds
        std::mem::forget(src_file);
        std::mem::forget(dst_file);

        Ok::<_, std::io::Error>(total_copied)
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
