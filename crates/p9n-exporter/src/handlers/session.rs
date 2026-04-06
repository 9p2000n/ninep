use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::session_store::SessionStore;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;

/// Handle Tsession: establish or resume a session.
///
/// - If session already has a key → reject (one Tsession per connection)
/// - Non-zero key matching stored session → resume
/// - Non-zero key, no match → new session with client-provided key
/// - All-zero key → error (client should provide a key derived from TLS)
pub fn handle<H: Send + Sync + 'static>(session: &Session<H>, session_store: &SessionStore, fc: Fcall) -> HandlerResult {
    let Msg::Session { key, flags } = fc.msg else {
        return Err("expected Session message".into());
    };
    let tag = fc.tag;

    // Reject duplicate Tsession on same connection
    if session.get_session_key().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "session already established on this connection",
        )
        .into());
    }

    if key == [0u8; 16] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "session key must be non-zero (derive via TLS export_keying_material)",
        )
        .into());
    }

    // Try resume first
    match session_store.resume(&key, &session.spiffe_id) {
        Some(restored) => {
            let effective = flags & restored;
            session.set_session_key(key);
            tracing::info!(
                "session resumed, requested={flags:#x}, restored={restored:#x}, effective={effective:#x}"
            );
            Ok(Fcall {
                size: 0,
                msg_type: MsgType::Rsession,
                tag,
                msg: Msg::Rsession { flags: effective },
            })
        }
        None => {
            // New session with client-provided key
            session.set_session_key(key);
            let supported = flags & (SESSION_FIDS | SESSION_LEASES | SESSION_WATCHES);
            tracing::info!("new session, flags={supported:#x}");
            Ok(Fcall {
                size: 0,
                msg_type: MsgType::Rsession,
                tag,
                msg: Msg::Rsession { flags: supported },
            })
        }
    }
}
