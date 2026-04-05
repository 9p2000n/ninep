use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::watch_manager::WatchManager;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use tokio::sync::mpsc;
use crate::watch_manager::WatchEvent;

pub fn handle(
    session: &Session,
    watch_mgr: &WatchManager,
    watch_tx: &mpsc::Sender<WatchEvent>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Version { msize, version } = fc.msg else {
        return Err("expected Version message".into());
    };

    // Per 9P spec: Tversion aborts all outstanding I/O and clunks all fids.
    // Remove all watches first (before clearing fids).
    for wid in session.watch_id_list() {
        let _ = watch_mgr.remove_watch(wid);
    }
    watch_mgr.remove_all_for_sender(watch_tx);
    session.reset();

    // Negotiate version: we only support 9P2000.N, no fallback
    let negotiated = if version == VERSION_9P2000_N {
        VERSION_9P2000_N.to_string()
    } else {
        "unknown".to_string()
    };

    // Negotiate msize: use the smaller of client and server max
    let server_max: u32 = 4 * 1024 * 1024; // 4 MiB
    let negotiated_msize = msize.min(server_max);

    session.set_version(negotiated.clone());
    session.set_msize(negotiated_msize);

    tracing::info!("version negotiated: {negotiated}, msize={negotiated_msize}");

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rversion,
        tag: fc.tag,
        msg: Msg::Version {
            msize: negotiated_msize,
            version: negotiated,
        },
    })
}
