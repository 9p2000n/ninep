use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;

pub fn handle<H: Send + Sync + 'static>(session: &Session<H>, fc: Fcall) -> HandlerResult {
    let Msg::Clunk { fid } = fc.msg else {
        return Err("expected Clunk message".into());
    };
    let tag = fc.tag;
    let removed = session.fids.remove(fid).is_some();
    tracing::debug!(
        tag, fid,
        removed,
        fids_total = session.fids.len(),
        "Tclunk",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rclunk,
        tag,
        msg: Msg::Empty,
    })
}
