use crate::backend::Backend;
use crate::fid_table::FidState;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use p9n_proto::wire::Qid;
use std::sync::Arc;
use crate::util::{join_err, unknown_fid};

pub async fn handle<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
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
    let nwname = wnames.len();
    tracing::trace!(tag, fid, newfid, nwname, ?wnames, "Twalk received");

    // Check newfid collision
    if newfid != fid && session.fids.contains(newfid) {
        tracing::debug!(fid, newfid, "Twalk rejected: newfid already in use");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("fid {newfid} already in use"),
        )
        .into());
    }

    // Check walk depth limit
    ctx.access.check_depth(session.spiffe_id.as_deref(), wnames.len() as u16)?;

    let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Twalk"))?;
    let current_path = fid_state.path.clone();
    drop(fid_state);

    // Walk with zero names: clone the fid (no I/O needed)
    if wnames.is_empty() {
        let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Twalk"))?;
        let path = fid_state.path.clone();
        let qid = fid_state.qid.clone();
        let is_dir = fid_state.is_dir;
        drop(fid_state); // Release DashMap read lock before insert to avoid deadlock
        tracing::trace!(
            fid,
            newfid,
            path = %path.display(),
            qid_path = qid.path,
            "Twalk(0): cloned fid",
        );
        session.fids.insert(
            newfid,
            FidState {
                path,
                qid,
                handle: None,
                is_dir,
            },
        );
        return Ok(Fcall {
            size: 0,
            msg_type: MsgType::Rwalk,
            tag,
            msg: Msg::Rwalk { qids: Vec::new() },
        });
    }

    let ctx_cloned = ctx.clone();
    let start_path = current_path.clone();
    let wnames_owned = wnames.clone();

    let result = tokio::task::spawn_blocking(move || {
        let mut qids: Vec<Qid> = Vec::with_capacity(wnames_owned.len());
        let mut current = start_path;
        let mut is_dir = false;

        for (i, name) in wnames_owned.iter().enumerate() {
            let target = current.join(name);
            match ctx_cloned.backend.walk_component(&current, name) {
                Ok((resolved, qid, component_is_dir)) => {
                    qids.push(qid);
                    current = resolved;
                    is_dir = component_is_dir;
                }
                Err(e) => {
                    return Err((
                        i,
                        name.clone(),
                        target,
                        std::io::Error::new(e.kind(), format!("{}: {e}", current.join(name).display())),
                    ));
                }
            }
        }

        Ok((qids, current, is_dir))
    })
    .await
    .map_err(join_err)?;

    let (qids, final_path, final_is_dir) = match result {
        Ok(v) => v,
        Err((i, name, target, e)) => {
            tracing::debug!(
                fid,
                newfid,
                failed_at = i,
                failed_name = %name,
                failed_path = %target.display(),
                error = %e,
                "Twalk: component resolution failed",
            );
            return Err(e.into());
        }
    };

    let last_qid = qids.last().cloned().unwrap_or_else(|| Qid {
        qtype: 0,
        version: 0,
        path: 0,
    });

    tracing::trace!(
        fid,
        newfid,
        nwname,
        nqid = qids.len(),
        final_path = %final_path.display(),
        final_qid_path = last_qid.path,
        final_is_dir,
        "Twalk: completed",
    );

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
