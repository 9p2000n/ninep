//! Handle Tlease / Tleaserenew / Tleaseack with state tracking.

use crate::handlers::{HandlerResult, PushTx};
use crate::lease_manager::{GrantResult, LeaseManager};
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use crate::util::unknown_fid;

static NEXT_LEASE_ID: AtomicU64 = AtomicU64::new(1);

pub fn handle<H: Send + Sync + 'static>(
    session: &Session<H>,
    lease_mgr: &LeaseManager,
    push_tx: &PushTx,
    max_lease_duration: u32,
    fc: Fcall,
) -> HandlerResult {
    let tag = fc.tag;
    match fc.msg_type {
        MsgType::Tlease => {
            let Msg::Lease { fid, lease_type, duration } = fc.msg else {
                return Err("expected Lease".into());
            };
            tracing::debug!(tag, fid, lease_type, requested_duration = duration, "Tlease received");

            // Verify fid exists and get qid_path for the global lease registry
            let qid_path = {
                let fid_state = session.fids.get(fid).ok_or_else(|| unknown_fid(fid, "Tlease"))?;
                fid_state.qid.path
            };

            // Check for conflicts with existing leases from other connections.
            match lease_mgr.try_grant(qid_path, lease_type, session.conn_id) {
                GrantResult::Granted => {}
                GrantResult::Conflict => {
                    tracing::warn!(
                        fid,
                        qid_path,
                        lease_type,
                        "Tlease conflict: existing incompatible lease on this qid",
                    );
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "lease conflict",
                    ).into());
                }
            }

            let lease_id = NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed);
            let effective_duration = duration.min(max_lease_duration);
            let clamped = effective_duration < duration;
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

            tracing::info!(
                lease_id,
                fid,
                qid_path,
                lease_type,
                duration = effective_duration,
                requested_duration = duration,
                clamped,
                active_leases = session.active_leases.len(),
                "Tlease granted",
            );

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
            let effective_duration = duration.min(max_lease_duration);
            match session.active_leases.get_mut(&lease_id) {
                Some(mut entry) => {
                    let prev_duration = entry.3;
                    entry.2 = Instant::now() + Duration::from_secs(effective_duration as u64);
                    entry.3 = effective_duration;
                    tracing::debug!(
                        lease_id,
                        fid = entry.0,
                        prev_duration,
                        new_duration = effective_duration,
                        requested_duration = duration,
                        "Tleaserenew updated",
                    );
                }
                None => {
                    tracing::debug!(lease_id, "Tleaserenew rejected: lease not found");
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
            let was_present = session.active_leases.remove(&lease_id).is_some();
            lease_mgr.acknowledge(lease_id);
            tracing::debug!(
                lease_id,
                was_present,
                active_leases = session.active_leases.len(),
                "Tleaseack",
            );

            Ok(Fcall {
                size: 0, msg_type: MsgType::Rleaseack, tag,
                msg: Msg::Empty,
            })
        }
        _ => Err("unexpected lease message type".into()),
    }
}
