use crate::handlers::HandlerResult;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;

/// Catch-all handler for unimplemented messages. Returns Rlerror with ENOSYS (38).
pub fn handle(fc: Fcall) -> HandlerResult {
    tracing::debug!(msg_type = ?fc.msg_type, "unhandled message type (ENOSYS)");

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rlerror,
        tag: fc.tag,
        msg: Msg::Lerror { ecode: 38 }, // ENOSYS
    })
}
