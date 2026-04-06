//! Tauth handler: marks the connection as authenticated.
//!
//! In the QUIC/SPIFFE model, authentication happens at the TLS layer (mTLS).
//! Tauth is kept for protocol compliance — it creates an auth fid that attach
//! can reference, confirming the auth handshake was intentional.

use crate::fid_table::FidState;
use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use p9n_proto::wire::Qid;
use std::path::PathBuf;

pub fn handle<H: Send + Sync + 'static>(session: &Session<H>, fc: Fcall) -> HandlerResult {
    let Msg::Auth { afid, uname, aname } = fc.msg else {
        return Err("expected Auth message".into());
    };

    tracing::debug!("Tauth afid={afid} uname={uname} aname={aname}");

    // In QUIC+SPIFFE mode, the TLS handshake already authenticated the peer.
    // We create the auth fid as a marker that the client went through the
    // auth protocol, so Tattach can verify afid was set up.
    let qid = Qid {
        qtype: p9n_proto::types::QT_AUTH,
        version: 0,
        path: afid as u64,
    };

    session.fids.insert(
        afid,
        FidState {
            path: PathBuf::from("/auth"),
            qid: qid.clone(),
            handle: None,
            is_dir: false,
        },
    );

    session.set_authenticated(true);

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rauth,
        tag: fc.tag,
        msg: Msg::Rauth { aqid: qid },
    })
}
