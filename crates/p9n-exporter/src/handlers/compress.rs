//! Handle Tcompress: negotiate compression algorithm.

use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;

pub fn handle<H: Send + Sync + 'static>(_session: &Session<H>, fc: Fcall) -> HandlerResult {
    let Msg::Compress { algo, level: _ } = fc.msg else {
        return Err("expected Compress".into());
    };
    let tag = fc.tag;

    // Accept zstd if requested, otherwise respond with algo=0 (none)
    let accepted = if algo == COMPRESS_ZSTD { COMPRESS_ZSTD } else { 0 };

    tracing::debug!("compress negotiated: requested={algo}, accepted={accepted}");

    Ok(Fcall { size: 0, msg_type: MsgType::Rcompress, tag, msg: Msg::Rcompress { algo: accepted } })
}
