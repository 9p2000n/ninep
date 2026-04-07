use crate::backend::Backend;
use crate::fid_table::FidState;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use p9n_proto::wire::Qid;
use std::sync::Arc;
use crate::util::join_err;

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
    tracing::trace!("walk: fid={fid} newfid={newfid} wnames={wnames:?}");

    // Check newfid collision
    if newfid != fid && session.fids.contains(newfid) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("fid {newfid} already in use"),
        )
        .into());
    }

    // Check walk depth limit
    ctx.access.check_depth(session.spiffe_id.as_deref(), wnames.len() as u16)?;

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
        let path = fid_state.path.clone();
        let qid = fid_state.qid.clone();
        let is_dir = fid_state.is_dir;
        drop(fid_state); // Release DashMap read lock before insert to avoid deadlock
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

    let ctx = ctx.clone();

    let (qids, final_path, final_is_dir) = tokio::task::spawn_blocking(move || {
        let mut qids: Vec<Qid> = Vec::with_capacity(wnames.len());
        let mut current = current_path;
        let mut is_dir = false;

        for name in &wnames {
            let target = current.join(name);
            let (resolved, qid, component_is_dir) = ctx.backend.walk_component(&current, name)
                .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", target.display())))?;
            qids.push(qid);
            current = resolved;
            is_dir = component_is_dir;
        }

        Ok::<_, std::io::Error>((qids, current, is_dir))
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
