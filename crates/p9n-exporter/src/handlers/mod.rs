use crate::access;
use crate::session::Session;
use crate::shared::SharedCtx;
use crate::watch_manager::WatchEvent;
use p9n_proto::fcall::Fcall;
use p9n_proto::types::MsgType;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Push channel sender type used to deliver Rleasebreak messages to a connection.
pub type PushTx = mpsc::Sender<Fcall>;

pub mod acl;
pub mod allocate;
pub mod attach;
pub mod auth;
pub mod capgrant;
pub mod clunk;
pub mod compress;
pub mod compound;
pub mod consistency;
pub mod copy_range;
pub mod create;
pub mod dir;
pub mod flush;
pub mod hash;
pub mod health;
pub mod io;
pub mod lease;
pub mod lock;
pub mod mknod;
pub mod negotiate;
pub mod quicstream;
pub mod ratelimit;
pub mod remove;
pub mod rename;
pub mod serverstats;
pub mod session;
pub mod spiffe;
pub mod stat;
pub mod stream_io;
pub mod stubs;
pub mod trace;
pub mod version;
pub mod walk;
pub mod watch;
pub mod xattr;
pub mod xattrwalk;

pub type HandlerResult = Result<Fcall, Box<dyn std::error::Error + Send + Sync>>;

/// Check permission: first static policy, then active capability tokens.
fn check_perm(
    session: &Session,
    ac: &crate::access::AccessControl,
    sid: Option<&str>,
    fid: Option<u32>,
    required: u32,
) -> Result<(), std::io::Error> {
    // 1. Static policy check
    if ac.check(sid, required).is_ok() {
        return Ok(());
    }
    // 2. Dynamic capability token check (if fid available)
    if let Some(fid) = fid {
        if session.check_cap(fid, required) {
            return Ok(());
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("access denied: required={required:#x}"),
    ))
}

/// Extract fid from common message types (for capability-based permission checks).
fn fid_from_msg(fc: &Fcall) -> Option<u32> {
    use p9n_proto::fcall::Msg;
    match &fc.msg {
        Msg::Read { fid, .. }
        | Msg::Write { fid, .. }
        | Msg::Lopen { fid, .. }
        | Msg::Getattr { fid, .. }
        | Msg::Setattr { fid, .. }
        | Msg::Statfs { fid }
        | Msg::Readdir { fid, .. }
        | Msg::Fsync { fid }
        | Msg::Readlink { fid } => Some(*fid),
        Msg::Lcreate { fid, .. } | Msg::Symlink { fid, .. } => Some(*fid),
        Msg::Mkdir { dfid, .. } => Some(*dfid),
        Msg::Mknod { dfid, .. } => Some(*dfid),
        Msg::Link { dfid, .. } => Some(*dfid),
        Msg::Unlinkat { dirfid, .. } => Some(*dirfid),
        Msg::Remove { fid } => Some(*fid),
        Msg::Rename { fid, .. } => Some(*fid),
        Msg::Walk { fid, .. } => Some(*fid),
        Msg::Lock { fid, .. } | Msg::GetlockReq { fid, .. } => Some(*fid),
        Msg::Xattrwalk { fid, .. } | Msg::Xattrcreate { fid, .. } => Some(*fid),
        Msg::Hash { fid, .. } | Msg::Getacl { fid, .. } | Msg::Setacl { fid, .. }
        | Msg::Streamopen { fid, .. } | Msg::Ratelimit { fid, .. }
        | Msg::Consistency { fid, .. } => Some(*fid),
        _ => None,
    }
}

/// Apply per-fid rate limiting if enabled and a limiter is registered.
/// `bytes` is the estimated I/O size (Tread count, Twrite data.len, 0 for metadata ops).
async fn check_rate_limit(session: &Session, ctx: &Arc<SharedCtx>, fid: Option<u32>, bytes: u64) {
    if !ctx.config.enable_rate_limit {
        return;
    }
    if let Some(fid) = fid {
        if let Some(limiter) = session.rate_limits.get(&fid) {
            limiter.acquire(1, bytes).await;
        }
    }
}

/// Extract the I/O byte count from a read/write message for rate limiting.
fn io_bytes(fc: &Fcall) -> u64 {
    use p9n_proto::fcall::Msg;
    match &fc.msg {
        Msg::Read { count, .. } => *count as u64,
        Msg::Write { data, .. } => data.len() as u64,
        Msg::Readdir { count, .. } => *count as u64,
        _ => 0,
    }
}

pub async fn dispatch(
    session: &Session,
    ctx: &Arc<SharedCtx>,
    watch_tx: &mpsc::Sender<WatchEvent>,
    push_tx: &PushTx,
    fc: Fcall,
) -> HandlerResult {
    let sid = session.spiffe_id.as_deref();
    let msg_fid = fid_from_msg(&fc);

    // Validate fid exists for operations that reference one (skip negotiation messages)
    if let Some(fid) = msg_fid {
        match fc.msg_type {
            // Skip messages where fid might not exist yet (attach creates fid 0)
            MsgType::Tversion | MsgType::Tcaps | MsgType::Tauthneg | MsgType::Tauth
            | MsgType::Tattach | MsgType::Tsession | MsgType::Tflush | MsgType::Thealth
            | MsgType::TstartlsSpiffe | MsgType::Tfetchbundle | MsgType::Tspiffeverify
            | MsgType::Tcapgrant | MsgType::Tcompress | MsgType::Tconsistency
            | MsgType::Ttraceattr | MsgType::Tserverstats | MsgType::Tquicstream => {}
            _ => {
                if !session.fids.contains(fid) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("stale fid {fid}"),
                    ).into());
                }
            }
        }
    }

    match fc.msg_type {
        // ── Negotiation (no access check) ──
        MsgType::Tversion => version::handle(session, &ctx.watch_mgr, watch_tx, fc),
        MsgType::Tcaps => negotiate::handle_caps(session, fc),
        MsgType::Tauthneg => negotiate::handle_authneg(session, fc),
        MsgType::Tauth => auth::handle(session, fc),
        MsgType::Tattach => attach::handle(session, &ctx.backend, &ctx.access, fc),
        MsgType::Tsession => session::handle(session, &ctx.session_store, fc),
        MsgType::Tflush => flush::handle(session, fc),
        MsgType::Tclunk => clunk::handle(session, fc),
        MsgType::Thealth => health::handle(session, fc),

        // ── SPIFFE (P0 + P2) ──
        MsgType::TstartlsSpiffe => spiffe::handle_startls_spiffe(session, ctx, fc),
        MsgType::Tfetchbundle => spiffe::handle_fetchbundle(session, ctx, fc),
        MsgType::Tspiffeverify => spiffe::handle_spiffeverify(session, ctx, fc),

        // ── Capability grant/use (P1) ──
        MsgType::Tcapgrant => capgrant::handle_capgrant(session, ctx, fc),
        MsgType::Tcapuse => capgrant::handle_capuse(session, ctx, fc),

        // ── Read ──
        MsgType::Twalk => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_READ)?;
            walk::handle(session, &ctx.backend, &ctx.access, fc).await
        }
        MsgType::Tgetattr => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_READ)?;
            stat::handle_getattr(session, &ctx.backend, fc).await
        }
        MsgType::Tstatfs => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_READ)?;
            stat::handle_statfs(session, &ctx.backend, fc).await
        }
        MsgType::Treaddir => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_READ)?;
            check_rate_limit(session, ctx, msg_fid, io_bytes(&fc)).await;
            dir::handle_readdir(session, &ctx.backend, fc).await
        }
        MsgType::Treadlink => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_READ)?;
            io::handle_readlink(session, &ctx.backend, fc).await
        }
        MsgType::Tlopen => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_READ)?;
            io::handle_lopen(session, &ctx.backend, fc).await
        }
        MsgType::Tread => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_READ)?;
            check_rate_limit(session, ctx, msg_fid, io_bytes(&fc)).await;
            io::handle_read(session, &ctx.backend, fc).await
        }
        MsgType::Tgetlock => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_READ)?;
            lock::handle_getlock(session, fc).await
        }

        // ── Write ──
        MsgType::Twrite => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_WRITE)?;
            check_rate_limit(session, ctx, msg_fid, io_bytes(&fc)).await;
            io::handle_write(session, &ctx.backend, &ctx.lease_mgr, fc).await
        }
        MsgType::Tfsync => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_WRITE)?;
            io::handle_fsync(session, fc).await
        }
        MsgType::Tlock => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_WRITE)?;
            lock::handle_lock(session, fc).await
        }

        // ── Create ──
        MsgType::Tlcreate => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_CREATE)?;
            create::handle_lcreate(session, &ctx.backend, &ctx.access, &ctx.lease_mgr, fc).await
        }
        MsgType::Tsymlink => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_CREATE)?;
            create::handle_symlink(session, &ctx.backend, &ctx.access, &ctx.lease_mgr, fc).await
        }
        MsgType::Tlink => {
            // link doesn't create a new inode, no ownership needed
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_CREATE)?;
            create::handle_link(session, &ctx.backend, &ctx.lease_mgr, fc).await
        }
        MsgType::Tmkdir => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_CREATE)?;
            dir::handle_mkdir(session, &ctx.backend, &ctx.access, &ctx.lease_mgr, fc).await
        }
        MsgType::Tmknod => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_CREATE)?;
            mknod::handle(session, &ctx.backend, &ctx.access, &ctx.lease_mgr, fc).await
        }

        // ── Remove ──
        MsgType::Tunlinkat => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_REMOVE)?;
            remove::handle_unlinkat(session, &ctx.backend, &ctx.lease_mgr, fc).await
        }
        MsgType::Tremove => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_REMOVE)?;
            remove::handle_remove(session, &ctx.backend, &ctx.lease_mgr, fc).await
        }
        MsgType::Trenameat => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_REMOVE | access::PERM_CREATE)?;
            remove::handle_renameat(session, &ctx.backend, &ctx.lease_mgr, fc).await
        }
        MsgType::Trename => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_REMOVE | access::PERM_CREATE)?;
            rename::handle(session, &ctx.backend, &ctx.lease_mgr, fc).await
        }

        // ── Setattr ──
        MsgType::Tsetattr => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_SETATTR)?;
            stat::handle_setattr(session, &ctx.access, &ctx.lease_mgr, fc).await
        }

        // ── Watch ──
        MsgType::Twatch | MsgType::Tunwatch => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_READ)?;
            watch::handle(session, &ctx.backend, &ctx.watch_mgr, watch_tx, fc)
        }

        // ── Extensions ──
        MsgType::Tlease | MsgType::Tleaserenew | MsgType::Tleaseack => {
            lease::handle(session, &ctx.lease_mgr, push_tx, ctx.config.max_lease_duration, fc)
        }
        MsgType::Tcompound => compound::handle(session, ctx, watch_tx, push_tx, fc).await,
        MsgType::Tcopyrange => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_READ | access::PERM_WRITE)?;
            copy_range::handle(session, &ctx.backend, fc).await
        }
        MsgType::Tallocate => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_WRITE)?;
            allocate::handle(session, &ctx.backend, fc).await
        }
        MsgType::Txattrget | MsgType::Txattrset | MsgType::Txattrlist => {
            xattr::handle(session, &ctx.backend, fc).await
        }
        MsgType::Txattrwalk => xattrwalk::handle_xattrwalk(session, fc).await,
        MsgType::Txattrcreate => xattrwalk::handle_xattrcreate(session, fc).await,

        // ── Compression negotiation ──
        MsgType::Tcompress => compress::handle(session, fc),

        // ── Consistency negotiation ──
        MsgType::Tconsistency => consistency::handle(session, fc),

        // ── Content hashing ──
        MsgType::Thash => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_READ)?;
            hash::handle(session, fc).await
        }

        // ── ACL ──
        MsgType::Tgetacl => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_READ)?;
            acl::handle(session, fc).await
        }
        MsgType::Tsetacl => {
            check_perm(session, &ctx.access, sid, msg_fid, access::PERM_ADMIN)?;
            acl::handle(session, fc).await
        }

        // ── Stream I/O ──
        MsgType::Tstreamopen | MsgType::Tstreamdata | MsgType::Tstreamclose => {
            stream_io::handle(session, fc).await
        }

        // ── Observability ──
        MsgType::Ttraceattr => trace::handle(session, fc),
        MsgType::Tserverstats => serverstats::handle(session, ctx, fc),

        // ── Resource management ──
        MsgType::Tratelimit => ratelimit::handle(session, ctx, fc),

        // ── Transport ──
        MsgType::Tquicstream => quicstream::handle(session, fc),

        _ => stubs::handle(fc),
    }
}
