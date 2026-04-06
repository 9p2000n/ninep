use crate::access::AccessControl;
use crate::backend::Backend;
use crate::backend::local::LocalBackend;
use crate::fid_table::FidState;
use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;

/// Handle Tattach: attach to the filesystem with identity-based root isolation.
///
/// The root directory is determined by the peer's SPIFFE ID via AccessControl:
/// - If an explicit policy maps the ID to a subdirectory, use that
/// - If domain-level isolation is enabled, derive from SPIFFE workload path
/// - Otherwise, use the shared export root
pub fn handle(
    session: &Session,
    backend: &LocalBackend,
    ac: &AccessControl,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Attach {
        fid,
        afid: _,
        uname,
        aname,
    } = fc.msg
    else {
        return Err("expected Attach message".into());
    };

    // Resolve the root directory based on SPIFFE identity
    let user_root = ac.resolve_root(session.spiffe_id.as_deref());

    // If aname is non-empty, use it as a sub-path within the user's root
    let attach_root = if aname.is_empty() {
        user_root.clone()
    } else {
        let sub = user_root.join(&aname);
        // Verify the sub-path doesn't escape the user's root
        let canonical = sub.canonicalize().unwrap_or(sub.clone());
        if !canonical.starts_with(&user_root) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "aname escapes user root",
            )
            .into());
        }
        canonical
    };

    // Ensure the root directory exists and get its Qid.
    let (qid, _is_dir) = backend.attach(&attach_root)?;

    session.fids.insert(
        fid,
        FidState {
            path: attach_root.clone(),
            qid: qid.clone(),
            open_fd: None,
            is_dir: true,
        },
    );

    tracing::info!(
        "attach fid={fid} uname={uname} aname={aname} spiffe={} root={}",
        session.spiffe_id.as_deref().unwrap_or("anonymous"),
        attach_root.display()
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rattach,
        tag: fc.tag,
        msg: Msg::Rattach { qid },
    })
}
