use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;

/// Handle Thealth: return server health status.
pub fn handle(_session: &Session, fc: Fcall) -> HandlerResult {
    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rhealth,
        tag: fc.tag,
        msg: Msg::Rhealth {
            status: 0, // healthy
            load: 0,
            metrics: Vec::new(),
        },
    })
}
