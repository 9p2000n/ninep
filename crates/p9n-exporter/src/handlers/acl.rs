//! Handle Tgetacl / Tsetacl: POSIX ACL via system.posix_acl_access xattr.

use crate::backend::Backend;
use crate::handlers::HandlerResult;
use crate::session::Session;
use crate::shared::SharedCtx;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use crate::util::join_err;

pub async fn handle<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    match fc.msg_type {
        MsgType::Tgetacl => handle_getacl(session, ctx, fc).await,
        MsgType::Tsetacl => handle_setacl(session, ctx, fc).await,
        _ => Err("unexpected ACL message".into()),
    }
}

async fn handle_getacl<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Getacl { fid, acl_type } = fc.msg else { return Err("expected Getacl".into()); };
    let tag = fc.tag;

    let fid_state = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let xattr_name = acl_xattr_name(acl_type);

    let ctx = ctx.clone();
    let data = tokio::task::spawn_blocking(move || {
        ctx.backend.xattr_get(&path, &xattr_name)
    }).await.map_err(join_err)??;

    Ok(Fcall { size: 0, msg_type: MsgType::Rgetacl, tag, msg: Msg::Rgetacl { data } })
}

async fn handle_setacl<B: Backend>(
    session: &Session<B::Handle>,
    ctx: &Arc<SharedCtx<B>>,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Setacl { fid, acl_type, data } = fc.msg else { return Err("expected Setacl".into()); };
    let tag = fc.tag;

    let fid_state = session.fids.get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let path = fid_state.path.clone();
    drop(fid_state);

    let xattr_name = acl_xattr_name(acl_type);

    let ctx = ctx.clone();
    tokio::task::spawn_blocking(move || {
        ctx.backend.xattr_set(&path, &xattr_name, &data, 0)
    }).await.map_err(join_err)??;

    Ok(Fcall { size: 0, msg_type: MsgType::Rsetacl, tag, msg: Msg::Empty })
}

fn acl_xattr_name(acl_type: u8) -> String {
    match acl_type {
        0 => "system.posix_acl_access".into(),
        1 => "system.posix_acl_default".into(),
        _ => format!("system.posix_acl_{acl_type}"),
    }
}
