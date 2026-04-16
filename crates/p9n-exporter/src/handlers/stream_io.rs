//! Handle streaming I/O: Tstreamopen, Tstreamdata, Tstreamclose.

use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::{Session, StreamState};
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use parking_lot::Mutex;
use crate::util::join_err;

static NEXT_STREAM_ID: AtomicU32 = AtomicU32::new(1);

const STREAM_WRITE: u8 = 1;

pub async fn handle<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let tag = fc.tag;
    match fc.msg_type {
        MsgType::Tstreamopen => {
            let Msg::Streamopen { fid, direction, offset, count: _ } = fc.msg else {
                return Err("expected Streamopen".into());
            };
            let fid_state = session.fids.get(fid)
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
            let handle = fid_state.handle.as_ref()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "fid not open"))?
                .clone();
            drop(fid_state);

            let stream_id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
            session.active_streams.insert(stream_id, StreamState {
                handle,
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
            let handle = stream.handle.clone();
            let direction = stream.direction;
            let offset = *stream.offset.lock();
            drop(stream);

            if direction == STREAM_WRITE {
                let data_len = data.len();
                let ctx = ctx.clone();
                let written = tokio::task::spawn_blocking(move || {
                    ctx.backend.write(&handle, offset, &data)
                })
                .await
                .map_err(join_err)??;

                if let Some(stream) = session.active_streams.get(&stream_id) {
                    *stream.offset.lock() += written as u64;
                }

                tracing::debug!("stream write: id={stream_id} seq={seq} len={data_len} written={written}");
                Ok(Fcall { size: 0, msg_type: MsgType::Rstreamdata, tag, msg: Msg::Streamdata { stream_id, seq, data: Vec::new() } })
            } else {
                // Read direction: respond with file data.
                let chunk = (session.get_msize() - 24) as u32;
                let ctx = ctx.clone();
                let read_data = tokio::task::spawn_blocking(move || {
                    ctx.backend.read(&handle, offset, chunk)
                })
                .await
                .map_err(join_err)??;

                let read_len = read_data.len();
                if let Some(stream) = session.active_streams.get(&stream_id) {
                    *stream.offset.lock() += read_len as u64;
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
                    let handle = stream.handle;
                    let ctx = ctx.clone();
                    match tokio::task::spawn_blocking(move || ctx.backend.fsync(&handle)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => tracing::warn!("stream {stream_id} fsync failed on close: {e}"),
                        Err(e) => tracing::warn!("stream {stream_id} fsync task panicked: {e}"),
                    }
                }
            }

            tracing::debug!("stream closed: id={stream_id}");
            Ok(Fcall { size: 0, msg_type: MsgType::Rstreamclose, tag, msg: Msg::Empty })
        }
        _ => Err("unexpected stream message".into()),
    }
}
