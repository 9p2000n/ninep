//! Handle streaming I/O: Tstreamopen, Tstreamdata, Tstreamclose.

use crate::handlers::HandlerResult;
use crate::session::{Session, StreamState};
use crate::util::{join_err, with_borrowed_file};
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::io::{Read, Seek, Write};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

static NEXT_STREAM_ID: AtomicU32 = AtomicU32::new(1);

const STREAM_WRITE: u8 = 1;

pub async fn handle(session: &Session, fc: Fcall) -> HandlerResult {
    let tag = fc.tag;
    match fc.msg_type {
        MsgType::Tstreamopen => {
            let Msg::Streamopen { fid, direction, offset, count: _ } = fc.msg else {
                return Err("expected Streamopen".into());
            };
            let fid_state = session.fids.get(fid)
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
            let raw_fd = fid_state.open_fd.as_ref()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "fid not open"))?
                .as_raw_fd();
            drop(fid_state);

            let stream_id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
            session.active_streams.insert(stream_id, StreamState {
                raw_fd,
                fid,
                direction,
                offset: Mutex::new(offset),
            });

            tracing::debug!("stream opened: id={stream_id} fid={fid} dir={direction} offset={offset}");
            Ok(Fcall { size: 0, msg_type: MsgType::Rstreamopen, tag, msg: Msg::Rstreamopen { stream_id } })
        }
        MsgType::Tstreamdata => {
            let Msg::Streamdata { stream_id, seq, data } = fc.msg else {
                return Err("expected Streamdata".into());
            };

            let stream = session.active_streams.get(&stream_id)
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown stream"))?;
            let raw_fd = stream.raw_fd;
            let direction = stream.direction;
            let offset = *stream.offset.lock().unwrap();
            drop(stream);

            if direction == STREAM_WRITE {
                let data_len = data.len();
                let written = tokio::task::spawn_blocking(move || {
                    with_borrowed_file(raw_fd, |file| {
                        file.seek(std::io::SeekFrom::Start(offset))?;
                        file.write(&data)
                    })
                })
                .await
                .map_err(join_err)??;

                if let Some(stream) = session.active_streams.get(&stream_id) {
                    *stream.offset.lock().unwrap() += written as u64;
                }

                tracing::debug!("stream write: id={stream_id} seq={seq} len={data_len} written={written}");
                Ok(Fcall { size: 0, msg_type: MsgType::Rstreamdata, tag, msg: Msg::Streamdata { stream_id, seq, data: Vec::new() } })
            } else {
                // Read direction: respond with file data.
                let chunk = (session.get_msize() - 24) as usize;
                let read_data = tokio::task::spawn_blocking(move || {
                    with_borrowed_file(raw_fd, |file| {
                        file.seek(std::io::SeekFrom::Start(offset))?;
                        let mut buf = vec![0u8; chunk];
                        let n = file.read(&mut buf)?;
                        buf.truncate(n);
                        Ok(buf)
                    })
                })
                .await
                .map_err(join_err)??;

                let read_len = read_data.len();
                if let Some(stream) = session.active_streams.get(&stream_id) {
                    *stream.offset.lock().unwrap() += read_len as u64;
                }

                tracing::debug!("stream read: id={stream_id} seq={seq} len={read_len}");
                Ok(Fcall { size: 0, msg_type: MsgType::Rstreamdata, tag, msg: Msg::Streamdata { stream_id, seq, data: read_data } })
            }
        }
        MsgType::Tstreamclose => {
            let Msg::Streamclose { stream_id } = fc.msg else {
                return Err("expected Streamclose".into());
            };

            if let Some((_, stream)) = session.active_streams.remove(&stream_id) {
                // Fsync on close for write streams to ensure durability.
                if stream.direction == STREAM_WRITE {
                    let raw_fd = stream.raw_fd;
                    let _ = tokio::task::spawn_blocking(move || {
                        nix::unistd::fsync(raw_fd)
                    }).await;
                }
            }

            tracing::debug!("stream closed: id={stream_id}");
            Ok(Fcall { size: 0, msg_type: MsgType::Rstreamclose, tag, msg: Msg::Empty })
        }
        _ => Err("unexpected stream message".into()),
    }
}
