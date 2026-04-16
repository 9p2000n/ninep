use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;

/// Handle Thealth: return server health status.
pub fn handle<H: Send + Sync + 'static>(_session: &Session<H>, fc: Fcall) -> HandlerResult {
    let tag = fc.tag;
    tracing::trace!(tag, "Thealth received");
    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rhealth,
        tag,
        msg: Msg::Rhealth {
            status: 0, // healthy
            load: 0,
            metrics: Vec::new(),
        },
    })
}
