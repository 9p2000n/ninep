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
    let key_prefix = format!("{:02x}{:02x}{:02x}{:02x}", key[0], key[1], key[2], key[3]);

    tracing::debug!(
        flags_requested = format_args!("{:#x}", flags),
        key_prefix = %key_prefix,
        "Tsession received",
    );

    // Reject duplicate Tsession on same connection
    if session.get_session_key().is_some() {
        tracing::warn!(
            key_prefix = %key_prefix,
            "Tsession rejected: session already established on this connection",
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "session already established on this connection",
        )
        .into());
    }

    if key == [0u8; 16] {
        tracing::warn!("Tsession rejected: zero key");
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
            let dropped = flags & !restored;
            session.set_session_key(key);
            tracing::info!(
                key_prefix = %key_prefix,
                flags_requested = format_args!("{:#x}", flags),
                flags_restored = format_args!("{:#x}", restored),
                flags_effective = format_args!("{:#x}", effective),
                flags_dropped = format_args!("{:#x}", dropped),
                "Tsession resumed",
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
            let unsupported = flags & !(SESSION_FIDS | SESSION_LEASES | SESSION_WATCHES);
            tracing::info!(
                key_prefix = %key_prefix,
                flags_requested = format_args!("{:#x}", flags),
                flags_supported = format_args!("{:#x}", supported),
                flags_unsupported = format_args!("{:#x}", unsupported),
                "Tsession new",
            );
            Ok(Fcall {
                size: 0,
                msg_type: MsgType::Rsession,
                tag,
                msg: Msg::Rsession { flags: supported },
            })
        }
    }
}
