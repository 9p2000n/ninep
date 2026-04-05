//! Handle Tflush: cancel an in-flight request by tag.

use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;

/// Handle Tflush { oldtag }: cancel the in-flight request identified by oldtag.
///
/// If the request is still running, its CancellationToken is triggered.
/// The handler should check the token and abort early.
pub fn handle(session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::Flush { oldtag } = fc.msg else {
        return Err("expected Flush message".into());
    };

    let cancelled = session.cancel_inflight(oldtag);
    if cancelled {
        tracing::debug!("flush: cancelled in-flight tag {oldtag}");
    } else {
        tracing::debug!("flush: tag {oldtag} not found (already completed)");
    }

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rflush,
        tag: fc.tag,
        msg: Msg::Empty,
    })
}
