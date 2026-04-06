//! Handle Tratelimit: set per-fid rate limits.
//!
//! When `config.enable_rate_limit` is true, creates a token-bucket rate limiter
//! for the specified fid. When disabled, acknowledges the request without enforcement.

use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::{RateLimiter, Session};
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;

pub fn handle<B: Backend>(session: &Session<B::Handle>, ctx: &Arc<SharedCtx<B>>, fc: Fcall) -> HandlerResult {
    let Msg::Ratelimit { fid, iops, bps } = fc.msg else {
        return Err("expected Ratelimit".into());
    };
    let tag = fc.tag;

    // Cap to server-configured maximums.
    let effective_iops = if iops > 0 { iops.min(ctx.config.max_iops) } else { 0 };
    let effective_bps = if bps > 0 { bps.min(ctx.config.max_bps) } else { 0 };

    if ctx.config.enable_rate_limit && (effective_iops > 0 || effective_bps > 0) {
        session.rate_limits.insert(fid, RateLimiter::new(effective_iops, effective_bps));
        tracing::debug!(
            "rate limit set: fid={fid} iops={effective_iops} bps={effective_bps}"
        );
    } else if ctx.config.enable_rate_limit && iops == 0 && bps == 0 {
        // iops=0 bps=0 means remove the limit.
        session.rate_limits.remove(&fid);
        tracing::debug!("rate limit removed: fid={fid}");
    } else {
        tracing::debug!(
            "rate limit acknowledged (not enforced): fid={fid} iops={iops} bps={bps}"
        );
    }

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rratelimit,
        tag,
        msg: Msg::Rratelimit {
            iops: effective_iops,
            bps: effective_bps,
        },
    })
}
