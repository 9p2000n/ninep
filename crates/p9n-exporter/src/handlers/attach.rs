use crate::backend::Backend;
use crate::fid_table::FidState;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;

/// Handle Tattach: attach to the filesystem with identity-based root isolation.
///
/// The root directory is determined by the peer's SPIFFE ID via AccessControl:
/// - If an explicit policy maps the ID to a subdirectory, use that
/// - If domain-level isolation is enabled, derive from SPIFFE workload path
/// - Otherwise, use the shared export root
pub fn handle<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Attach {
        fid,
        afid,
        uname,
        aname,
    } = fc.msg
    else {
        return Err("expected Attach message".into());
    };

    let fid_in_use = session.fids.contains(fid);
    tracing::debug!(
        fid,
        afid,
        uname = %uname,
        aname = %aname,
        fid_in_use,
        "Tattach received",
    );

    // Resolve the root directory based on SPIFFE identity
    let user_root = ctx.access.resolve_root(session.spiffe_id.as_deref());

    // If aname is non-empty, use it as a sub-path within the user's root
    let attach_root = if aname.is_empty() {
        tracing::debug!(user_root = %user_root.display(), "Tattach using user root (aname empty)");
        user_root.clone()
    } else {
        let sub = user_root.join(&aname);
        // Verify the sub-path doesn't escape the user's root via backend resolve
        let canonical = sub.canonicalize().unwrap_or(sub.clone());
        if !canonical.starts_with(&user_root) {
            tracing::warn!(
                user_root = %user_root.display(),
                attempted = %sub.display(),
                canonical = %canonical.display(),
                "Tattach rejected: aname escapes user root",
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "aname escapes user root",
            )
            .into());
        }
        tracing::debug!(
            user_root = %user_root.display(),
            attach_root = %canonical.display(),
            "Tattach resolved aname within user root",
        );
        canonical
    };

    // Ensure the root directory exists and get its Qid.
    let (qid, _is_dir) = ctx.backend.attach(&attach_root)?;

    session.fids.insert(
        fid,
        FidState {
            path: attach_root.clone(),
            qid: qid.clone(),
            handle: None,
            is_dir: true,
        },
    );

    tracing::info!(
        fid,
        uname = %uname,
        aname = %aname,
        root = %attach_root.display(),
        qid_path = qid.path,
        qid_version = qid.version,
        fids_total = session.fids.len(),
        "Tattach completed",
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rattach,
        tag: fc.tag,
        msg: Msg::Rattach { qid },
    })
}
