//! Async FUSE filesystem implementation using fuse3.
//!
//! All operations are natively async — no block_on() bridging needed.

use fuse3::raw::prelude::*;
use fuse3::{Errno, Inode, Result as FuseResult, Timestamp};

use crate::error::RpcError;
use crate::fuse::attr_cache::AttrCache;
use crate::fuse::fid_pool::{FidGuard, FidPool};
use crate::fuse::inode_map::InodeMap;
use crate::fuse::lease_map::LeaseMap;
use crate::importer::Importer;
use crate::rpc_client::RpcClient;
use crate::shutdown::ShutdownHandle;
use p9n_proto::fcall::Msg;
use p9n_proto::types::*;
use p9n_proto::wire::{SetAttr, Stat};
use std::ffi::{OsStr, OsString};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

const TTL: Duration = Duration::from_secs(1);

pub struct P9Filesystem {
    rpc: Arc<RpcClient>,
    inodes: Arc<InodeMap>,
    fids: FidPool,
    attrs: Arc<AttrCache>,
    leases: Arc<LeaseMap>,
    /// Handle for the background push receiver task.
    _push_handle: tokio::task::JoinHandle<()>,
}

impl P9Filesystem {
    /// Create the FUSE filesystem and a `ShutdownHandle` for graceful cleanup.
    ///
    /// The `ShutdownHandle` captures `Arc` clones of shared state so that
    /// `main()` can drive ordered shutdown after fuse3 consumes `Self`.
    pub fn new(rpc: Arc<RpcClient>, importer: Importer) -> (Self, ShutdownHandle) {
        let inodes = Arc::new(InodeMap::new());
        inodes.set_root(importer.root_fid, importer.root_qid.clone());
        let attrs = Arc::new(AttrCache::new(4096, Duration::from_secs(1)));
        let leases = Arc::new(LeaseMap::new());

        let push_handle = crate::push_receiver::spawn_push_handler(
            importer.push_rx,
            inodes.clone(),
            attrs.clone(),
            leases.clone(),
        );

        let shutdown = ShutdownHandle::new(
            rpc.clone(),
            leases.clone(),
            inodes.clone(),
        );

        let fs = Self {
            rpc,
            inodes,
            fids: FidPool::new(),
            attrs,
            leases,
            _push_handle: push_handle,
        };

        (fs, shutdown)
    }
}

/// Convert an RpcError to a FUSE Errno, preserving 9P errno codes.
fn rpc_err(e: RpcError) -> Errno {
    match e.errno() {
        Some(ecode) => Errno::from(ecode),
        None => Errno::from(libc::EIO),
    }
}

/// Clunk a replaced fid in the background to prevent server-side fid leaks.
fn clunk_old_fid(rpc: &Arc<RpcClient>, old_fid: Option<u32>) {
    if let Some(fid) = old_fid {
        let rpc = rpc.clone();
        tokio::spawn(async move {
            let _ = rpc.call(MsgType::Tclunk, Msg::Clunk { fid }).await;
        });
    }
}

fn stat_to_attr(ino: u64, stat: &Stat) -> FileAttr {
    let kind = if stat.qid.qtype & 0x80 != 0 {
        FileType::Directory
    } else if stat.qid.qtype & 0x02 != 0 {
        FileType::Symlink
    } else {
        FileType::RegularFile
    };

    FileAttr {
        ino,
        size: stat.size,
        blocks: stat.blocks,
        atime: Timestamp::new(stat.atime_sec as i64, stat.atime_nsec as u32),
        mtime: Timestamp::new(stat.mtime_sec as i64, stat.mtime_nsec as u32),
        ctime: Timestamp::new(stat.ctime_sec as i64, stat.ctime_nsec as u32),
        kind,
        perm: (stat.mode & 0o7777) as u16,
        nlink: stat.nlink as u32,
        uid: stat.uid,
        gid: stat.gid,
        rdev: stat.rdev as u32,
        blksize: stat.blksize as u32,
    }
}

/// Walk from a parent fid to create a new fid, returning the walked QIDs.
async fn walk_to(
    rpc: &RpcClient,
    parent_fid: u32,
    new_fid: u32,
    wnames: Vec<String>,
) -> Result<Vec<p9n_proto::wire::Qid>, RpcError> {
    let resp = rpc
        .call(MsgType::Twalk, Msg::Walk {
            fid: parent_fid,
            newfid: new_fid,
            wnames,
        })
        .await?;
    match resp.msg {
        Msg::Rwalk { qids } => Ok(qids),
        _ => Err(RpcError::from("bad walk response")),
    }
}

/// Getattr on a fid, returning the Stat.
async fn getattr(rpc: &RpcClient, fid: u32) -> Result<Stat, RpcError> {
    let resp = rpc
        .call(MsgType::Tgetattr, Msg::Getattr {
            fid,
            mask: P9_GETATTR_ALL,
        })
        .await?;
    match resp.msg {
        Msg::Rgetattr { valid: _, qid: _, stat } => Ok(stat),
        _ => Err(RpcError::from("bad getattr response")),
    }
}

impl Filesystem for P9Filesystem {
    type DirEntryStream<'a> = futures_util::stream::Iter<std::vec::IntoIter<FuseResult<DirectoryEntry>>>
    where
        Self: 'a;

    type DirEntryPlusStream<'a> = futures_util::stream::Iter<std::vec::IntoIter<FuseResult<DirectoryEntryPlus>>>
    where
        Self: 'a;

    async fn init(&self, _req: Request) -> FuseResult<ReplyInit> {
        Ok(ReplyInit {
            max_write: NonZeroU32::new(65536).unwrap(),
        })
    }

    async fn destroy(&self, _req: Request) {}

    async fn lookup(&self, _req: Request, parent: Inode, name: &OsStr) -> FuseResult<ReplyEntry> {
        let name_str = name.to_string_lossy().to_string();

        let parent_fid = self.inodes.get_fid(parent).ok_or(Errno::from(libc::ENOENT))?;
        let guard = FidGuard::new(self.fids.alloc(), self.rpc.clone());

        let qids = walk_to(&self.rpc, parent_fid, guard.fid(), vec![name_str])
            .await
            .map_err(rpc_err)?;
        if qids.is_empty() {
            return Err(Errno::from(libc::ENOENT));
        }

        let stat = getattr(&self.rpc, guard.fid()).await.map_err(rpc_err)?;
        let walk_qid = qids[0].clone();
        let fid = guard.consume();
        let result = self.inodes.get_or_insert(fid, &walk_qid);
        clunk_old_fid(&self.rpc, result.old_fid);
        let attr = stat_to_attr(result.ino, &stat);
        self.attrs.put(result.ino, stat);
        Ok(ReplyEntry { ttl: TTL, attr, generation: 0 })
    }

    async fn getattr(
        &self, _req: Request, inode: Inode, _fh: Option<u64>, _flags: u32,
    ) -> FuseResult<ReplyAttr> {
        // If there's an active lease, trust the cache without TTL checks.
        if self.leases.has_lease(inode) {
            if let Some(stat) = self.attrs.get_leased(inode) {
                return Ok(ReplyAttr { ttl: TTL, attr: stat_to_attr(inode, &stat) });
            }
        } else if let Some(stat) = self.attrs.get(inode) {
            return Ok(ReplyAttr { ttl: TTL, attr: stat_to_attr(inode, &stat) });
        }

        let fid = self.inodes.get_fid(inode).ok_or(Errno::from(libc::ENOENT))?;
        let stat = getattr(&self.rpc, fid).await.map_err(rpc_err)?;
        self.attrs.put(inode, stat.clone());
        Ok(ReplyAttr { ttl: TTL, attr: stat_to_attr(inode, &stat) })
    }

    async fn setattr(
        &self, _req: Request, inode: Inode, _fh: Option<u64>,
        set_attr: fuse3::SetAttr,
    ) -> FuseResult<ReplyAttr> {
        let fid = self.inodes.get_fid(inode).ok_or(Errno::from(libc::ENOENT))?;

        let mut valid = 0u32;
        let mut attr = SetAttr {
            valid: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
        };

        if let Some(mode) = set_attr.mode {
            valid |= P9_SETATTR_MODE;
            attr.mode = mode;
        }
        if let Some(uid) = set_attr.uid {
            valid |= P9_SETATTR_UID;
            attr.uid = uid;
        }
        if let Some(gid) = set_attr.gid {
            valid |= P9_SETATTR_GID;
            attr.gid = gid;
        }
        if let Some(size) = set_attr.size {
            valid |= P9_SETATTR_SIZE;
            attr.size = size;
        }
        if let Some(atime) = set_attr.atime {
            valid |= P9_SETATTR_ATIME | P9_SETATTR_ATIME_SET;
            attr.atime_sec = atime.sec as u64;
            attr.atime_nsec = atime.nsec as u64;
        }
        if let Some(mtime) = set_attr.mtime {
            valid |= P9_SETATTR_MTIME | P9_SETATTR_MTIME_SET;
            attr.mtime_sec = mtime.sec as u64;
            attr.mtime_nsec = mtime.nsec as u64;
        }

        attr.valid = valid;
        self.rpc
            .call(MsgType::Tsetattr, Msg::Setattr { fid, attr })
            .await
            .map_err(rpc_err)?;

        // Invalidate cache and re-fetch
        self.attrs.invalidate(inode);
        let stat = getattr(&self.rpc, fid).await.map_err(rpc_err)?;
        self.attrs.put(inode, stat.clone());
        Ok(ReplyAttr { ttl: TTL, attr: stat_to_attr(inode, &stat) })
    }

    async fn readlink(&self, _req: Request, inode: Inode) -> FuseResult<ReplyData> {
        let fid = self.inodes.get_fid(inode).ok_or(Errno::from(libc::ENOENT))?;
        let resp = self.rpc
            .call(MsgType::Treadlink, Msg::Readlink { fid })
            .await
            .map_err(rpc_err)?;

        match resp.msg {
            Msg::Rreadlink { target } => Ok(ReplyData { data: target.into_bytes().into() }),
            _ => Err(Errno::from(libc::EIO)),
        }
    }

    async fn mknod(
        &self, req: Request, parent: Inode, name: &OsStr,
        mode: u32, rdev: u32,
    ) -> FuseResult<ReplyEntry> {
        let parent_fid = self.inodes.get_fid(parent).ok_or(Errno::from(libc::ENOENT))?;
        let name_str = name.to_string_lossy().to_string();

        let resp = self.rpc
            .call(MsgType::Tmknod, Msg::Mknod {
                dfid: parent_fid,
                name: name_str.clone(),
                mode,
                major: (rdev >> 8) & 0xFFF,
                minor: rdev & 0xFF,
                gid: req.gid,
            })
            .await
            .map_err(rpc_err)?;

        match resp.msg {
            Msg::Rmknod { qid: _ } => {}
            _ => return Err(Errno::from(libc::EIO)),
        };

        // Lookup the new node to get full attrs
        self.lookup(req, parent, name).await
    }

    async fn mkdir(
        &self, req: Request, parent: Inode, name: &OsStr, mode: u32,
        _umask: u32,
    ) -> FuseResult<ReplyEntry> {
        let parent_fid = self.inodes.get_fid(parent).ok_or(Errno::from(libc::ENOENT))?;
        let name_str = name.to_string_lossy().to_string();

        self.rpc
            .call(MsgType::Tmkdir, Msg::Mkdir {
                dfid: parent_fid,
                name: name_str,
                mode,
                gid: req.gid,
            })
            .await
            .map_err(rpc_err)?;

        // Lookup the new directory to get full attrs and assign inode
        self.lookup(req, parent, name).await
    }

    async fn unlink(&self, _req: Request, parent: Inode, name: &OsStr) -> FuseResult<()> {
        let parent_fid = self.inodes.get_fid(parent).ok_or(Errno::from(libc::ENOENT))?;
        let name_str = name.to_string_lossy().to_string();

        self.rpc
            .call(MsgType::Tunlinkat, Msg::Unlinkat {
                dirfid: parent_fid,
                name: name_str,
                flags: 0,
            })
            .await
            .map_err(rpc_err)?;
        Ok(())
    }

    async fn rmdir(&self, _req: Request, parent: Inode, name: &OsStr) -> FuseResult<()> {
        let parent_fid = self.inodes.get_fid(parent).ok_or(Errno::from(libc::ENOENT))?;
        let name_str = name.to_string_lossy().to_string();

        self.rpc
            .call(MsgType::Tunlinkat, Msg::Unlinkat {
                dirfid: parent_fid,
                name: name_str,
                flags: libc::AT_REMOVEDIR as u32,
            })
            .await
            .map_err(rpc_err)?;
        Ok(())
    }

    async fn symlink(
        &self, req: Request, parent: Inode, name: &OsStr, link: &OsStr,
    ) -> FuseResult<ReplyEntry> {
        let parent_fid = self.inodes.get_fid(parent).ok_or(Errno::from(libc::ENOENT))?;
        let name_str = name.to_string_lossy().to_string();
        let link_str = link.to_string_lossy().to_string();

        self.rpc
            .call(MsgType::Tsymlink, Msg::Symlink {
                fid: parent_fid,
                name: name_str,
                symtgt: link_str,
                gid: req.gid,
            })
            .await
            .map_err(rpc_err)?;

        self.lookup(req, parent, name).await
    }

    async fn rename(
        &self, _req: Request, parent: Inode, name: &OsStr,
        new_parent: Inode, new_name: &OsStr,
    ) -> FuseResult<()> {
        let old_dirfid = self.inodes.get_fid(parent).ok_or(Errno::from(libc::ENOENT))?;
        let new_dirfid = self.inodes.get_fid(new_parent).ok_or(Errno::from(libc::ENOENT))?;
        let old_name_str = name.to_string_lossy().to_string();
        let new_name_str = new_name.to_string_lossy().to_string();

        self.rpc
            .call(MsgType::Trenameat, Msg::Renameat {
                olddirfid: old_dirfid,
                oldname: old_name_str,
                newdirfid: new_dirfid,
                newname: new_name_str,
            })
            .await
            .map_err(rpc_err)?;
        Ok(())
    }

    async fn link(
        &self, req: Request, inode: Inode, new_parent: Inode, new_name: &OsStr,
    ) -> FuseResult<ReplyEntry> {
        let fid = self.inodes.get_fid(inode).ok_or(Errno::from(libc::ENOENT))?;
        let dfid = self.inodes.get_fid(new_parent).ok_or(Errno::from(libc::ENOENT))?;
        let name_str = new_name.to_string_lossy().to_string();

        self.rpc
            .call(MsgType::Tlink, Msg::Link {
                dfid,
                fid,
                name: name_str,
            })
            .await
            .map_err(rpc_err)?;

        self.lookup(req, new_parent, new_name).await
    }

    async fn open(&self, _req: Request, inode: Inode, flags: u32) -> FuseResult<ReplyOpen> {
        let fid = self.inodes.get_fid(inode).ok_or(Errno::from(libc::ENOENT))?;
        let guard = FidGuard::new(self.fids.alloc(), self.rpc.clone());

        walk_to(&self.rpc, fid, guard.fid(), vec![]).await.map_err(rpc_err)?;
        self.rpc
            .call(MsgType::Tlopen, Msg::Lopen {
                fid: guard.fid(),
                flags,
            })
            .await
            .map_err(rpc_err)?;

        let open_fid = guard.consume();

        // Try to acquire a read lease for cache coherence.
        // Best-effort: if the server doesn't support leases, we fall back to TTL.
        if let Ok(resp) = self.rpc.call(MsgType::Tlease, Msg::Lease {
            fid: open_fid, lease_type: LEASE_READ, duration: 60,
        }).await {
            if let Msg::Rlease { lease_id, .. } = resp.msg {
                self.leases.grant(open_fid, lease_id, inode);
            }
        }

        Ok(ReplyOpen { fh: open_fid as u64, flags: 0 })
    }

    async fn read(
        &self, _req: Request, _inode: Inode, fh: u64, offset: u64, size: u32,
    ) -> FuseResult<ReplyData> {
        let fid = fh as u32;
        let resp = self.rpc
            .call(MsgType::Tread, Msg::Read {
                fid,
                offset,
                count: size,
            })
            .await
            .map_err(rpc_err)?;

        match resp.msg {
            Msg::Rread { data } => Ok(ReplyData { data: data.into() }),
            _ => Err(Errno::from(libc::EIO)),
        }
    }

    async fn write(
        &self, _req: Request, _inode: Inode, fh: u64, offset: u64,
        data: &[u8], _write_flags: u32, _flags: u32,
    ) -> FuseResult<ReplyWrite> {
        let fid = fh as u32;
        let resp = self.rpc
            .call(MsgType::Twrite, Msg::Write {
                fid,
                offset,
                data: data.to_vec(),
            })
            .await
            .map_err(rpc_err)?;

        match resp.msg {
            Msg::Rwrite { count } => Ok(ReplyWrite { written: count }),
            _ => Err(Errno::from(libc::EIO)),
        }
    }

    async fn release(
        &self, _req: Request, _inode: Inode, fh: u64, _flags: u32,
        _lock_owner: u64, _flush: bool,
    ) -> FuseResult<()> {
        let fid = fh as u32;
        // Release lease if one was held (returns None if already broken by server).
        if let Some(lease_id) = self.leases.release_by_fh(fid) {
            let _ = self.rpc.call(MsgType::Tleaseack, Msg::Leaseack { lease_id }).await;
        }
        let _ = self.rpc.call(MsgType::Tclunk, Msg::Clunk { fid }).await;
        Ok(())
    }

    async fn fsync(
        &self, _req: Request, _inode: Inode, fh: u64, _datasync: bool,
    ) -> FuseResult<()> {
        let fid = fh as u32;
        self.rpc
            .call(MsgType::Tfsync, Msg::Fsync { fid })
            .await
            .map_err(rpc_err)?;
        Ok(())
    }

    async fn create(
        &self, req: Request, parent: Inode, name: &OsStr,
        mode: u32, flags: u32,
    ) -> FuseResult<ReplyCreated> {
        let parent_fid = self.inodes.get_fid(parent).ok_or(Errno::from(libc::ENOENT))?;
        let guard = FidGuard::new(self.fids.alloc(), self.rpc.clone());
        let name_str = name.to_string_lossy().to_string();

        // Walk to parent to get a new fid for lcreate
        walk_to(&self.rpc, parent_fid, guard.fid(), vec![]).await.map_err(rpc_err)?;

        let resp = self.rpc
            .call(MsgType::Tlcreate, Msg::Lcreate {
                fid: guard.fid(),
                name: name_str,
                flags,
                mode,
                gid: req.gid,
            })
            .await
            .map_err(rpc_err)?;

        let qid = match resp.msg {
            Msg::Rlcreate { qid, iounit: _ } => qid,
            _ => return Err(Errno::from(libc::EIO)),
        };

        let open_fid = guard.consume();
        let result = self.inodes.get_or_insert(open_fid, &qid);
        clunk_old_fid(&self.rpc, result.old_fid);

        // Fetch attrs for the new file
        // Note: the fid is now open, so we can getattr on it
        let stat = getattr(&self.rpc, open_fid).await.map_err(rpc_err)?;
        let attr = stat_to_attr(result.ino, &stat);
        self.attrs.put(result.ino, stat);

        Ok(ReplyCreated {
            ttl: TTL,
            attr,
            generation: 0,
            fh: open_fid as u64,
            flags: 0,
        })
    }

    async fn opendir(&self, _req: Request, inode: Inode, _flags: u32) -> FuseResult<ReplyOpen> {
        // Stateless: we open the directory fresh in readdir/readdirplus.
        let _fid = self.inodes.get_fid(inode).ok_or(Errno::from(libc::ENOENT))?;
        Ok(ReplyOpen { fh: 0, flags: 0 })
    }

    async fn releasedir(&self, _req: Request, _inode: Inode, _fh: u64, _flags: u32) -> FuseResult<()> {
        Ok(())
    }

    async fn readdir<'a>(
        &'a self, _req: Request, parent: Inode, _fh: u64, offset: i64,
    ) -> FuseResult<ReplyDirectory<Self::DirEntryStream<'a>>> {
        let fid = self.inodes.get_fid(parent).ok_or(Errno::from(libc::ENOENT))?;
        let guard = FidGuard::new(self.fids.alloc(), self.rpc.clone());

        walk_to(&self.rpc, fid, guard.fid(), vec![]).await.map_err(rpc_err)?;
        self.rpc
            .call(MsgType::Tlopen, Msg::Lopen {
                fid: guard.fid(),
                flags: L_O_RDONLY,
            })
            .await
            .map_err(rpc_err)?;

        let resp = self.rpc
            .call(MsgType::Treaddir, Msg::Readdir {
                fid: guard.fid(),
                offset: offset as u64,
                count: 65536,
            })
            .await
            .map_err(rpc_err)?;

        let _ = self.rpc.call(MsgType::Tclunk, Msg::Clunk { fid: guard.fid() }).await;
        let _ = guard.consume();

        match resp.msg {
            Msg::Rreaddir { data } => {
                let entries: Vec<FuseResult<DirectoryEntry>> =
                    parse_readdir_entries(&data, offset).into_iter().map(Ok).collect();
                Ok(ReplyDirectory {
                    entries: futures_util::stream::iter(entries),
                })
            }
            _ => Err(Errno::from(libc::EIO)),
        }
    }

    async fn readdirplus<'a>(
        &'a self, _req: Request, parent: Inode, _fh: u64, offset: u64, _lock_owner: u64,
    ) -> FuseResult<ReplyDirectoryPlus<Self::DirEntryPlusStream<'a>>> {
        let fid = self.inodes.get_fid(parent).ok_or(Errno::from(libc::ENOENT))?;
        let guard = FidGuard::new(self.fids.alloc(), self.rpc.clone());

        walk_to(&self.rpc, fid, guard.fid(), vec![]).await.map_err(rpc_err)?;
        self.rpc
            .call(MsgType::Tlopen, Msg::Lopen {
                fid: guard.fid(),
                flags: L_O_RDONLY,
            })
            .await
            .map_err(rpc_err)?;

        let resp = self.rpc
            .call(MsgType::Treaddir, Msg::Readdir {
                fid: guard.fid(),
                offset,
                count: 65536,
            })
            .await
            .map_err(rpc_err)?;

        let dir_fid = guard.fid();
        let _ = self.rpc.call(MsgType::Tclunk, Msg::Clunk { fid: dir_fid }).await;
        let _ = guard.consume();

        match resp.msg {
            Msg::Rreaddir { data } => {
                let raw_entries = parse_readdir_entries(&data, offset as i64);
                let mut plus_entries: Vec<FuseResult<DirectoryEntryPlus>> = Vec::with_capacity(raw_entries.len());

                for entry in raw_entries {
                    // Walk parent→child and getattr to get full attributes
                    let child_guard = FidGuard::new(self.fids.alloc(), self.rpc.clone());
                    let name_str = entry.name.to_string_lossy().to_string();
                    let attr_result = async {
                        let qids = walk_to(&self.rpc, fid, child_guard.fid(), vec![name_str])
                            .await.map_err(rpc_err)?;
                        if qids.is_empty() {
                            return Err(Errno::from(libc::ENOENT));
                        }
                        let stat = getattr(&self.rpc, child_guard.fid()).await.map_err(rpc_err)?;
                        let walk_qid = qids[0].clone();
                        let child_fid = child_guard.consume();
                        let result = self.inodes.get_or_insert(child_fid, &walk_qid);
                        clunk_old_fid(&self.rpc, result.old_fid);
                        let attr = stat_to_attr(result.ino, &stat);
                        self.attrs.put(result.ino, stat);
                        Ok((result.ino, attr))
                    }.await;

                    if let Ok((ino, attr)) = attr_result {
                        plus_entries.push(Ok(DirectoryEntryPlus {
                            inode: ino,
                            generation: 0,
                            kind: entry.kind,
                            name: entry.name,
                            offset: entry.offset,
                            attr,
                            entry_ttl: TTL,
                            attr_ttl: TTL,
                        }));
                    }
                    // Skip entries we can't stat — the kernel will do a
                    // separate lookup if it needs them.
                }

                Ok(ReplyDirectoryPlus {
                    entries: futures_util::stream::iter(plus_entries),
                })
            }
            _ => Err(Errno::from(libc::EIO)),
        }
    }

    async fn statfs(&self, _req: Request, inode: Inode) -> FuseResult<ReplyStatFs> {
        let fid = self.inodes.get_fid(inode).ok_or(Errno::from(libc::ENOENT))?;
        let resp = self.rpc
            .call(MsgType::Tstatfs, Msg::Statfs { fid })
            .await
            .map_err(rpc_err)?;

        match resp.msg {
            Msg::Rstatfs { stat } => Ok(ReplyStatFs {
                blocks: stat.blocks, bfree: stat.bfree, bavail: stat.bavail,
                files: stat.files, ffree: stat.ffree,
                bsize: stat.bsize, namelen: stat.namelen, frsize: stat.bsize,
            }),
            _ => Err(Errno::from(libc::EIO)),
        }
    }
}

/// Parse 9P readdir raw data into fuse3 DirectoryEntry items.
fn parse_readdir_entries(data: &[u8], offset: i64) -> Vec<DirectoryEntry> {
    let mut entries = Vec::new();
    let mut pos = 0;
    let mut idx = offset;

    while pos < data.len() {
        if pos + 24 > data.len() { break; }
        // qid: type[1] version[4] path[8] = 13 bytes
        let ino = u64::from_le_bytes(data[pos + 5..pos + 13].try_into().unwrap_or([0; 8]));
        pos += 13;
        let _entry_offset = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap_or([0; 8]));
        pos += 8;
        let dtype = data[pos];
        pos += 1;
        if pos + 2 > data.len() { break; }
        let name_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + name_len > data.len() { break; }
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
        pos += name_len;

        idx += 1;
        let kind = match dtype {
            4 => FileType::Directory,
            10 => FileType::Symlink,
            _ => FileType::RegularFile,
        };

        entries.push(DirectoryEntry {
            inode: ino,
            kind,
            name: OsString::from(name),
            offset: idx,
        });
    }
    entries
}
