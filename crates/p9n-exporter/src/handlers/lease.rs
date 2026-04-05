//! Handle Tlease / Tleaserenew / Tleaseack with state tracking.

use crate::handlers::{HandlerResult, PushTx};
use crate::lease_manager::LeaseManager;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT_LEASE_ID: AtomicU64 = AtomicU64::new(1);

pub fn handle(session: &Session, lease_mgr: &LeaseManager, push_tx: &PushTx, fc: Fcall) -> HandlerResult {
    let tag = fc.tag;
    match fc.msg_type {
        MsgType::Tlease => {
            let Msg::Lease { fid, lease_type, duration } = fc.msg else {
                return Err("expected Lease".into());
            };
            // Verify fid exists and get qid_path for the global lease registry
            let qid_path = {
                let fid_state = session.fids.get(fid)
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
                fid_state.qid.path
            };

            let lease_id = NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed);
            let effective_duration = duration.min(300); // cap at 5 minutes
            let expiry = Instant::now() + Duration::from_secs(effective_duration as u64);

            // Store lease in session (per-connection state)
            session.active_leases.insert(lease_id, (fid, lease_type, expiry, effective_duration));

            // Register in global lease manager (cross-connection visibility)
            lease_mgr.register(
                lease_id,
                qid_path,
                lease_type,
                session.conn_id,
                push_tx.clone(),
            );

            tracing::debug!("lease granted: id={lease_id} fid={fid} type={lease_type} dur={effective_duration}s");

            Ok(Fcall {
                size: 0, msg_type: MsgType::Rlease, tag,
                msg: Msg::Rlease { lease_id, lease_type, duration: effective_duration },
            })
        }
        MsgType::Tleaserenew => {
            let Msg::Leaserenew { lease_id, duration } = fc.msg else {
                return Err("expected Leaserenew".into());
            };

            // Validate lease exists and update expiry
            let effective_duration = duration.min(300);
            match session.active_leases.get_mut(&lease_id) {
                Some(mut entry) => {
                    entry.2 = Instant::now() + Duration::from_secs(effective_duration as u64);
                    entry.3 = effective_duration;
                    tracing::debug!("lease renewed: id={lease_id} dur={effective_duration}s");
                }
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("lease {lease_id} not found"),
                    ).into());
                }
            }

            Ok(Fcall {
                size: 0, msg_type: MsgType::Rleaserenew, tag,
                msg: Msg::Rleaserenew { duration: effective_duration },
            })
        }
        MsgType::Tleaseack => {
            let Msg::Leaseack { lease_id } = fc.msg else {
                return Err("expected Leaseack".into());
            };

            // Remove from session and global lease manager
            session.active_leases.remove(&lease_id);
            lease_mgr.acknowledge(lease_id);
            tracing::debug!("lease ack: id={lease_id}");

            Ok(Fcall {
                size: 0, msg_type: MsgType::Rleaseack, tag,
                msg: Msg::Empty,
            })
        }
        _ => Err("unexpected lease message type".into()),
    }
}
