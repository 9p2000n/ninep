//! Handle Tserverstats: return server runtime statistics.

use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::backend::Backend;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use p9n_proto::wire::ServerStat;
use std::sync::Arc;

pub fn handle<B: Backend>(session: &Session<B::Handle>, _ctx: &Arc<SharedCtx<B>>, fc: Fcall) -> HandlerResult {
    let Msg::ServerstatsReq { mask } = fc.msg else {
        return Err("expected ServerstatsReq".into());
    };
    let tag = fc.tag;
    tracing::trace!(tag, mask = format_args!("{:#x}", mask), "Tserverstats received");

    let uptime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let stats = vec![
        ServerStat { name: "uptime_sec".into(), stat_type: 0, value: uptime },
        ServerStat { name: "fids_open".into(), stat_type: 0, value: session.fids.len() as u64 },
        ServerStat { name: "active_watches".into(), stat_type: 0, value: session.watch_id_list().len() as u64 },
        ServerStat { name: "active_leases".into(), stat_type: 0, value: session.active_leases.len() as u64 },
        ServerStat { name: "active_caps".into(), stat_type: 0, value: session.active_caps.len() as u64 },
        ServerStat { name: "server_spiffe_id".into(), stat_type: 1, value: 0 }, // type 1 = string indicator
    ];

    tracing::trace!(tag, n_stats = stats.len(), "Tserverstats result");

    Ok(Fcall { size: 0, msg_type: MsgType::Rserverstats, tag, msg: Msg::Rserverstats { stats } })
}
