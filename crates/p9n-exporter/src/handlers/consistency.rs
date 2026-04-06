//! Handle Tconsistency: negotiate consistency level.

use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;

pub fn handle<H: Send + Sync + 'static>(_session: &Session<H>, fc: Fcall) -> HandlerResult {
    let Msg::Consistency { fid: _, level } = fc.msg else {
        return Err("expected Consistency".into());
    };
    let tag = fc.tag;

    // Single-node exporter: always linearizable (level=3)
    // Reject levels > 3 as invalid
    if level > 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid consistency level: {level} (max 3)"),
        ).into());
    }

    // We always operate at linearizable, but report the requested level
    // (since we meet or exceed any requested level on a single node)
    Ok(Fcall { size: 0, msg_type: MsgType::Rconsistency, tag, msg: Msg::Rconsistency { level: 3 } })
}
