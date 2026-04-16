//! Watch/Unwatch handlers with real inotify integration via WatchManager.

use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use crate::watch_manager::WatchEvent;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use tokio::sync::mpsc;
use crate::util::unknown_fid;

pub fn handle<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    watch_tx: &mpsc::Sender<WatchEvent>,
    fc: Fcall,
) -> HandlerResult {
    let tag = fc.tag;

    match fc.msg_type {
        MsgType::Twatch => {
            let (fid, mask, flags) = match &fc.msg {
                Msg::Watch { fid, mask, flags } => (*fid, *mask, *flags),
                _ => return Err("invalid Twatch payload".into()),
            };

            tracing::debug!(
                tag, fid,
                mask = format_args!("{:#x}", mask),
                flags = format_args!("{:#x}", flags),
                "Twatch received",
            );

            // Resolve the fid to a filesystem path
            let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Twatch"))?;
            let path = fid_state.path.clone();
            drop(fid_state);

            // Verify the path is within the exported tree
            let resolved = ctx.backend.resolve(&path)?;

            // Register the watch
            let watch_id = ctx.watch_mgr.add_watch(&resolved, mask, flags, watch_tx.clone())?;
            session.add_watch_id(watch_id);

            tracing::info!(
                tag, fid,
                path = %resolved.display(),
                mask = format_args!("{:#x}", mask),
                flags = format_args!("{:#x}", flags),
                watch_id,
                active_watches = session.watch_id_list().len(),
                "Twatch registered",
            );

            Ok(Fcall {
                size: 0,
                msg_type: MsgType::Rwatch,
                tag,
                msg: Msg::Rwatch { watch_id },
            })
        }

        MsgType::Tunwatch => {
            let watch_id = match &fc.msg {
                Msg::Unwatch { watch_id } => *watch_id,
                _ => return Err("invalid Tunwatch payload".into()),
            };

            tracing::debug!(tag, watch_id, "Tunwatch received");

            ctx.watch_mgr.remove_watch(watch_id)?;
            session.remove_watch_id(watch_id);

            tracing::info!(
                tag, watch_id,
                active_watches = session.watch_id_list().len(),
                "Tunwatch removed",
            );

            Ok(Fcall {
                size: 0,
                msg_type: MsgType::Runwatch,
                tag,
                msg: Msg::Empty,
            })
        }

        _ => Err("unexpected watch message type".into()),
    }
}
