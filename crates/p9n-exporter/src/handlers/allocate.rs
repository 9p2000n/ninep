use crate::backend::local::LocalBackend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::os::unix::io::AsRawFd;
use crate::util::join_err;

/// Handle Tallocate: preallocate file space via fallocate.
pub async fn handle(session: &Session, _backend: &LocalBackend, fc: Fcall) -> HandlerResult {
    let Msg::Allocate {
        fid,
        mode,
        offset,
        length,
    } = fc.msg
    else {
        return Err("expected Allocate message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let raw_fd = fid_state
        .open_fd
        .as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "fid not open"))?
        .as_raw_fd();
    drop(fid_state);

    tokio::task::spawn_blocking(move || {
        let flags = nix::fcntl::FallocateFlags::from_bits_truncate(mode as i32);
        nix::fcntl::fallocate(raw_fd, flags, offset as i64, length as i64)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rallocate,
        tag,
        msg: Msg::Empty,
    })
}
