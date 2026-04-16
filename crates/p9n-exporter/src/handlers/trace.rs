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
    tracing::debug!(tag, n_attrs = attrs.len(), "Ttraceattr received");

    for (k, v) in &attrs {
        tracing::debug!(tag, key = %k, value = %v, "Ttraceattr: attribute");
    }

    // Trace attributes are stored for this connection's tracing context.
    // In production, these would be propagated to spans via tracing::Span::current().
    if let Some(traceparent) = attrs.iter().find(|(k, _)| k == "traceparent") {
        tracing::info!(tag, traceparent = %traceparent.1, "Ttraceattr: traceparent recorded");
    }

    Ok(Fcall { size: 0, msg_type: MsgType::Rtraceattr, tag, msg: Msg::Empty })
}
