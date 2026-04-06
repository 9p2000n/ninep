//! Handle Thash: compute file hash (BLAKE3).

use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use std::io::{Read, Seek};
use std::os::unix::io::{AsRawFd, FromRawFd};
use crate::util::join_err;

pub async fn handle(session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::Hash { fid, algo, offset, length } = fc.msg else {
        return Err("expected Hash".into());
    };
    let tag = fc.tag;

    if algo != HASH_BLAKE3 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
            format!("unsupported hash algo: {algo}, only BLAKE3({HASH_BLAKE3}) supported")).into());
    }

    let fid_state = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let raw_fd = fid_state.handle.as_ref()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "fid not open"))?
        .as_raw_fd();
    drop(fid_state);

    let hash = tokio::task::spawn_blocking(move || {
        let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        file.seek(std::io::SeekFrom::Start(offset))?;

        let mut hasher = blake3::Hasher::new();
        let mut remaining = if length == 0 { u64::MAX } else { length };
        let mut buf = [0u8; 65536];

        while remaining > 0 {
            let to_read = (remaining as usize).min(buf.len());
            let n = file.read(&mut buf[..to_read])?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
            remaining -= n as u64;
        }

        std::mem::forget(file);
        Ok::<_, std::io::Error>(hasher.finalize().as_bytes().to_vec())
    }).await.map_err(join_err)??;

    Ok(Fcall { size: 0, msg_type: MsgType::Rhash, tag, msg: Msg::Rhash { algo: HASH_BLAKE3, hash } })
}
