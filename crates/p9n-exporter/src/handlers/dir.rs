use crate::access::AccessControl;
use crate::backend::local::LocalBackend;
use crate::handlers::HandlerResult;
use crate::lease_manager::LeaseManager;
use crate::session::Session;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use crate::util::join_err;

/// Handle Treaddir: list directory entries.
///
/// Returns raw directory entry data in the 9P readdir format:
/// qid[13] offset[8] type[1] name_len[2] name[name_len]
pub async fn handle_readdir(
    session: &Session,
    _backend: &LocalBackend,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Readdir { fid, offset, count } = fc.msg else {
        return Err("expected Readdir message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(fid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;

    if !fid_state.is_dir {
        return Err(
            std::io::Error::new(std::io::ErrorKind::NotADirectory, "not a directory").into(),
        );
    }

    let dir_path = fid_state.path.clone();
    drop(fid_state);

    let data = tokio::task::spawn_blocking(move || {
        readdir_blocking(&dir_path, offset, count)
    })
    .await
    .map_err(join_err)??;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rreaddir,
        tag,
        msg: Msg::Rreaddir { data },
    })
}

fn readdir_blocking(
    dir_path: &PathBuf,
    offset: u64,
    count: u32,
) -> Result<Vec<u8>, std::io::Error> {
    let entries = std::fs::read_dir(dir_path)?;
    let mut data = Vec::new();
    let mut entry_offset: u64 = 0;

    for entry_result in entries {
        let entry = entry_result?;

        // Skip entries before the requested offset
        if entry_offset < offset {
            entry_offset += 1;
            continue;
        }

        let name = entry.file_name();
        let name_bytes = name.as_encoded_bytes();
        let meta = entry.metadata()?;
        let qid = LocalBackend::make_qid(&meta);

        // Compute dtype
        let dtype: u8 = if meta.is_dir() {
            4 // DT_DIR
        } else if meta.file_type().is_symlink() {
            10 // DT_LNK
        } else {
            8 // DT_REG
        };

        // Entry format: qid[13] offset[8] type[1] name_len[2] name[n]
        let entry_size = 13 + 8 + 1 + 2 + name_bytes.len();
        if data.len() + entry_size > count as usize {
            break;
        }

        // Qid: type[1] version[4] path[8]
        data.push(qid.qtype);
        data.extend_from_slice(&qid.version.to_le_bytes());
        data.extend_from_slice(&qid.path.to_le_bytes());

        entry_offset += 1;
        data.extend_from_slice(&entry_offset.to_le_bytes());

        data.push(dtype);

        data.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        data.extend_from_slice(name_bytes);
    }

    Ok(data)
}

/// Handle Tmkdir: create a directory.
pub async fn handle_mkdir(
    session: &Session,
    backend: &LocalBackend,
    ac: &AccessControl,
    lease_mgr: &LeaseManager,
    fc: Fcall,
) -> HandlerResult {
    let Msg::Mkdir {
        dfid,
        name,
        mode,
        gid: _,
    } = fc.msg
    else {
        return Err("expected Mkdir message".into());
    };
    let tag = fc.tag;

    let fid_state = session
        .fids
        .get(dfid)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "unknown fid"))?;
    let dir_path = fid_state.path.join(&name);
    let dir_qid_path = fid_state.qid.path;
    drop(fid_state);

    // Break leases on the parent directory (its contents are changing).
    lease_mgr.break_for_write(dir_qid_path, session.conn_id);

    let resolved = backend.resolve(&dir_path)?;
    let spiffe_id = session.spiffe_id.clone();

    let (qid, resolved_path) = tokio::task::spawn_blocking(move || {
        std::fs::create_dir(&resolved)?;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(&resolved, perms)?;
        let meta = std::fs::metadata(&resolved)?;
        Ok::<_, std::io::Error>((LocalBackend::make_qid(&meta), resolved))
    })
    .await
    .map_err(join_err)??;

    ac.apply_ownership(spiffe_id.as_deref(), &resolved_path)?;

    Ok(Fcall {
        size: 0,
        msg_type: MsgType::Rmkdir,
        tag,
        msg: Msg::Rmkdir { qid },
    })
}
