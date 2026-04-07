use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;

pub fn handle<H: Send + Sync + 'static>(session: &Session<H>, fc: Fcall) -> HandlerResult {
    let Msg::Clunk { fid } = fc.msg else {
        return Err("expected Clunk message".into());
    };
    tracing::trace!("clunk: fid={fid}");

    session.fids.remove(fid);

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rclunk,
        tag: fc.tag,
        msg: Msg::Empty,
    })
}
