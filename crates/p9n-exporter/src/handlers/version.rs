use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::watch_manager::WatchManager;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use tokio::sync::mpsc;
use crate::watch_manager::WatchEvent;

pub fn handle<H: Send + Sync + 'static>(
    session: &Session<H>,
    watch_mgr: &WatchManager,
    watch_tx: &mpsc::Sender<WatchEvent>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Version { msize, version } = fc.msg else {
        return Err("expected Version message".into());
    };

    let prev_version = session.get_version().unwrap_or_default();
    let prev_msize = session.get_msize();
    let fids_before = session.fids.len();
    let watches_before = session.watch_id_list().len();
    tracing::info!(
        requested_version = %version,
        requested_msize = msize,
        prev_version = %prev_version,
        prev_msize,
        fids_before,
        watches_before,
        "Tversion: resetting session state",
    );

    // Per 9P spec: Tversion aborts all outstanding I/O and clunks all fids.
    // Remove all watches first (before clearing fids).
    let wids = session.watch_id_list();
    for wid in &wids {
        let _ = watch_mgr.remove_watch(*wid);
    }
    watch_mgr.remove_all_for_sender(watch_tx);
    session.reset();

    // Negotiate version: we only support 9P2000.N, no fallback
    let (negotiated, version_match) = if version == VERSION_9P2000_N {
        (VERSION_9P2000_N.to_string(), true)
    } else {
        ("unknown".to_string(), false)
    };

    // Negotiate msize: use the smaller of client and server max
    let server_max: u32 = 4 * 1024 * 1024; // 4 MiB
    let negotiated_msize = msize.min(server_max);
    let msize_clamped = negotiated_msize < msize;

    session.set_version(negotiated.clone());
    session.set_msize(negotiated_msize);

    tracing::info!(
        version = %negotiated,
        version_match,
        msize = negotiated_msize,
        msize_clamped,
        watches_cleared = wids.len(),
        fids_cleared = fids_before,
        "Tversion negotiated",
    );

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
