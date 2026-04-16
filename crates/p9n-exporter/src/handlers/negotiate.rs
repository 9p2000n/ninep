use crate::handlers::HandlerResult;
use crate::session::{Session, TransportKind};
use p9n_proto::caps;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;

/// Handle Tcaps: intersect client capabilities with server capabilities.
pub fn handle_caps<H: Send + Sync + 'static>(session: &Session<H>, fc: Fcall) -> HandlerResult {
    let Msg::Caps { caps: client_caps } = fc.msg else {
        return Err("expected Caps message".into());
    };

    tracing::debug!(
        n_requested = client_caps.len(),
        requested = ?client_caps,
        transport = ?session.transport_kind,
        "Tcaps received",
    );

    // Build server capability set
    let mut server_caps = caps::CapSet::new();
    for cap in &[
        CAP_SPIFFE,
        CAP_COMPOUND,
        CAP_WATCH,
        CAP_XATTR2,
        CAP_LEASE,
        CAP_SESSION,
        CAP_HEALTH,
        CAP_COPY,
        CAP_ALLOC,
        CAP_QUIC,
    ] {
        server_caps.add(cap);
    }
    // Advertise CAP_QUIC_MULTI only on QUIC transports. TCP and RDMA
    // connections never support Tquicstream, so offering the capability
    // would set up a round-trip that can only fail.
    if session.transport_kind == TransportKind::Quic {
        server_caps.add(CAP_QUIC_MULTI);
    }

    // Build client capability set
    let mut client_set = caps::CapSet::new();
    for cap in &client_caps {
        client_set.add(cap);
    }

    // Intersect
    let negotiated = caps::intersect(&client_set, &server_caps);
    session.set_caps(negotiated.clone());

    let result_caps: Vec<String> = negotiated.caps().to_vec();
    let dropped: Vec<&String> = client_caps.iter().filter(|c| !result_caps.contains(c)).collect();
    tracing::info!(
        n_requested = client_caps.len(),
        n_server = server_caps.caps().len(),
        n_negotiated = result_caps.len(),
        negotiated = ?result_caps,
        dropped = ?dropped,
        "Tcaps negotiated",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rcaps,
        tag: fc.tag,
        msg: Msg::Caps { caps: result_caps },
    })
}

/// Handle Tauthneg: select authentication mechanism.
pub fn handle_authneg<H: Send + Sync + 'static>(_session: &Session<H>, fc: Fcall) -> HandlerResult {
    let Msg::Authneg { mechs } = fc.msg else {
        return Err("expected Authneg message".into());
    };

    // Server supports mTLS and SPIFFE-X.509 (both provided by the QUIC TLS handshake)
    let supported = [AUTH_MTLS, AUTH_SPIFFE_X509];
    let matched = mechs.iter().any(|m| supported.contains(&m.as_str()));
    let selected = mechs
        .iter()
        .find(|m| supported.contains(&m.as_str()))
        .cloned()
        .unwrap_or_else(|| AUTH_MTLS.to_string());

    tracing::info!(
        offered = ?mechs,
        supported = ?supported,
        selected = %selected,
        fallback = !matched,
        "Tauthneg negotiated",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rauthneg,
        tag: fc.tag,
        msg: Msg::Rauthneg {
            mech: selected,
            challenge: Vec::new(), // mTLS: no additional challenge needed
        },
    })
}
