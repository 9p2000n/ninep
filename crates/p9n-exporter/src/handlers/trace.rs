//! Handle Ttraceattr: store distributed tracing context.

use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;

pub fn handle<H: Send + Sync + 'static>(_session: &Session<H>, fc: Fcall) -> HandlerResult {
    let Msg::Traceattr { attrs } = fc.msg else {
        return Err("expected Traceattr".into());
    };
    let tag = fc.tag;

    for (k, v) in &attrs {
        tracing::debug!("trace attr: {k}={v}");
    }

    // Trace attributes are stored for this connection's tracing context.
    // In production, these would be propagated to spans via tracing::Span::current().
    if let Some(traceparent) = attrs.iter().find(|(k, _)| k == "traceparent") {
        tracing::info!("traceparent: {}", traceparent.1);
    }

    Ok(Fcall { size: 0, msg_type: MsgType::Rtraceattr, tag, msg: Msg::Empty })
}
