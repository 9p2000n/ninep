//! Capability grant/use handlers: Tcapgrant and Tcapuse.
//!
//! Tcapgrant: server signs a JWT capability token scoped to a fid.
//! Tcapuse: client presents the token to activate permissions on a fid.

use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::{CapToken, Session};
use crate::shared::SharedCtx;
use p9n_auth::spiffe::jwt_svid;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use crate::util::unknown_fid;

const MAX_CAP_TTL: u64 = 86400; // 24 hours maximum token lifetime

/// Handle Tcapgrant: sign a capability token for a client.
pub fn handle_capgrant<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Capgrant {
        fid,
        rights,
        expiry,
        depth,
    } = fc.msg
    else {
        return Err("expected Capgrant message".into());
    };
    let tag = fc.tag;
    tracing::debug!(
        tag, fid,
        rights = format_args!("{:#x}", rights),
        depth,
        expiry,
        "Tcapgrant received",
    );

    let client_id = session
        .spiffe_id
        .as_deref()
        .ok_or_else(|| {
            tracing::debug!(fid, "Tcapgrant rejected: no SPIFFE identity");
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Tcapgrant requires SPIFFE identity",
            )
        })?;

    // Granted rights cannot exceed the client's policy maximum
    let policy = ctx.access.resolve(Some(client_id));
    let granted_rights = rights & (policy.permissions as u64);
    let dropped_rights = rights & !(policy.permissions as u64);

    // Cap the expiry to MAX_CAP_TTL from now
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let effective_expiry = if expiry > 0 {
        expiry.min(now + MAX_CAP_TTL)
    } else {
        now + 3600 // default 1 hour
    };
    let expiry_clamped = expiry > 0 && effective_expiry < expiry;

    // Sign the token
    let token = jwt_svid::encode_cap_token(
        &ctx.cap_signing_key,
        client_id,
        &ctx.server_spiffe_id,
        granted_rights,
        depth,
        effective_expiry,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    })?;

    tracing::info!(
        tag, fid,
        client_id = %client_id,
        rights_requested = format_args!("{:#x}", rights),
        rights_granted = format_args!("{:#x}", granted_rights),
        rights_dropped = format_args!("{:#x}", dropped_rights),
        depth,
        effective_expiry,
        expiry_clamped,
        "Tcapgrant signed",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rcapgrant,
        tag,
        msg: Msg::Rcapgrant { token },
    })
}

/// Handle Tcapuse: verify and activate a capability token on a fid.
pub fn handle_capuse<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Capuse { fid, token } = fc.msg else {
        return Err("expected Capuse message".into());
    };
    let tag = fc.tag;
    tracing::debug!(tag, fid, token_len = token.len(), "Tcapuse received");

    let client_id = session
        .spiffe_id
        .as_deref()
        .ok_or_else(|| {
            tracing::debug!(fid, "Tcapuse rejected: no SPIFFE identity");
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Tcapuse requires SPIFFE identity",
            )
        })?;

    // Verify the token
    let result = jwt_svid::verify_cap_token(
        &ctx.cap_signing_key,
        &token,
        client_id,
        &ctx.server_spiffe_id,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            e.to_string(),
        ))
    })?;

    let rights = result.p9n_rights.unwrap_or(0);
    let depth = result.p9n_depth.unwrap_or(0);
    let expiry = result.expiry;

    // Store the active capability in the session
    session.active_caps.insert(
        fid,
        CapToken {
            rights,
            depth,
            expiry,
        },
    );

    // Look up the fid's qid for the response
    let qid = session
        .fids
        .get(fid)
        .map(|s| s.qid.clone())
        .ok_or_else(|| unknown_fid(fid, "Tcapuse"))?;

    tracing::info!(
        tag, fid,
        client_id = %client_id,
        rights = format_args!("{:#x}", rights),
        depth,
        expiry,
        active_caps = session.active_caps.len(),
        "Tcapuse activated",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rcapuse,
        tag,
        msg: Msg::Rcapuse { qid },
    })
}
