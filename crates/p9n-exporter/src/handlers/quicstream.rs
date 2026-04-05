//! Handle Tquicstream: bind 9P channel to QUIC stream type.

use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;

pub fn handle(_session: &Session, fc: Fcall) -> HandlerResult {
    let Msg::Quicstream { stream_type, stream_id } = fc.msg else {
        return Err("expected Quicstream".into());
    };
    let tag = fc.tag;

    tracing::debug!("quicstream bind: type={stream_type} id={stream_id}");

    // Acknowledge the stream binding
    Ok(Fcall { size: 0, msg_type: MsgType::Rquicstream, tag, msg: Msg::Rquicstream { stream_id } })
}
