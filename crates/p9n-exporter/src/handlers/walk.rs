use crate::access::AccessControl;
use crate::backend::local::LocalBackend;
use crate::fid_table::FidState;
use crate::handlers::HandlerResult;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use p9n_proto::wire::Qid;
use std::path::PathBuf;
use crate::util::join_err;

/// Resolve a path, preventing escape outside root. Standalone version for spawn_blocking.
///
/// Symlinks are not followed at the final component — the returned path points at the
/// symlink itself so that readlink works. Intermediate components are still canonicalized
/// to detect path-escape attempts.
fn resolve_path(root: &PathBuf, path: &PathBuf) -> Result<PathBuf, std::io::Error> {
    // Check if the final component is a symlink (don't follow it).
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.is_symlink() {
            let parent = path.parent().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path")
            })?;
            let name = path.file_name().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path")
            })?;
            let canonical_parent = parent.canonicalize()?;
            if !canonical_parent.starts_with(root) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "path escape",
                ));
            }
            return Ok(canonical_parent.join(name));
        }
    }
    // Not a symlink — canonicalize normally.
    if let Ok(canonical) = path.canonicalize() {
        if canonical.starts_with(root) {
            return Ok(canonical);
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "path escape",
        ));
    }
    // Non-existent path: canonicalize parent + append name
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        let canonical_parent = parent.canonicalize().unwrap_or_else(|_| parent.to_path_buf());
        if !canonical_parent.starts_with(root) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "path escape",
            ));
        }
        return Ok(canonical_parent.join(name));
    }
    Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))
}

pub async fn handle(
    session: &Session,
    backend: &LocalBackend,
    ac: &AccessControl,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Walk {
        fid,
        newfid,
        wnames,
    } = fc.msg
    else {
        return Err("expected Walk message".into());
    };
    let tag = fc.tag;

    // Check newfid collision
    if newfid != fid && session.fids.contains(newfid) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("fid {newfid} already in use"),
        )
        .into());
    }

    // Check walk depth limit
    ac.check_depth(session.spiffe_id.as_deref(), wnames.len() as u16)?;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let current_path = fid_state.path.clone();
    drop(fid_state);

    // Walk with zero names: clone the fid (no I/O needed)
    if wnames.is_empty() {
        let fid_state = session
            .fids
            .get(fid)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
        session.fids.insert(
            newfid,
            FidState {
                path: fid_state.path.clone(),
                qid: fid_state.qid.clone(),
                handle: None,
                is_dir: fid_state.is_dir,
            },
        );
        return Ok(Fcall {
            size: 0,
            msg_type: MsgType::Rwalk,
            tag,
            msg: Msg::Rwalk { qids: Vec::new() },
        });
    }

    let root = backend.root().to_path_buf();

    let (qids, final_path, final_is_dir) = tokio::task::spawn_blocking(move || {
        let mut qids: Vec<Qid> = Vec::with_capacity(wnames.len());
        let mut current = current_path;

        for name in &wnames {
            current = current.join(name);
            let resolved = resolve_path(&root, &current)?;
            let meta = std::fs::symlink_metadata(&resolved)?;
            qids.push(LocalBackend::make_qid(&meta));
            current = resolved;
        }

        let last_meta = std::fs::symlink_metadata(&current)?;
        Ok::<_, std::io::Error>((qids, current, last_meta.is_dir()))
    })
    .await
    .map_err(join_err)??;

    let last_qid = qids.last().cloned().unwrap_or_else(|| Qid {
        qtype: 0,
        version: 0,
        path: 0,
    });

    session.fids.insert(
        newfid,
        FidState {
            path: final_path,
            qid: last_qid,
            handle: None,
            is_dir: final_is_dir,
        },
    );

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rwalk,
        tag,
        msg: Msg::Rwalk { qids },
    })
}
