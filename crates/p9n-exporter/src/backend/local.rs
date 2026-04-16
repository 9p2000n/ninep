//! Local filesystem backend.

use super::Backend;
use p9n_proto::types::*;
use p9n_proto::wire::{Qid, SetAttr, Stat, StatFs};
use std::ffi::CString;
use std::io::{self, Read, Seek, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

pub struct LocalBackend {
    root: PathBuf,
}

impl LocalBackend {
    pub fn new(root: String) -> Result<Self, Box<dyn std::error::Error>> {
        let path = PathBuf::from(&root);
        if !path.is_dir() {
            std::fs::create_dir_all(&path)?;
        }
        tracing::info!("exporting {root}");
        Ok(Self {
            root: path.canonicalize()?,
        })
    }

    fn path_to_cstring(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    /// Borrow a raw fd safely for the duration of a closure.
    fn with_borrowed_file<F, T>(fd: &OwnedFd, f: F) -> io::Result<T>
    where
        F: FnOnce(&mut std::fs::File) -> io::Result<T>,
    {
        let raw = fd.as_raw_fd();
        let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
        let result = f(&mut file);
        std::mem::forget(file); // don't close the borrowed fd
        result
    }
}

// ── Public inherent methods (backward compatibility) ──
//
// These delegate to the Backend trait implementation. They exist so that
// existing handler code can call `backend.root()`, `backend.resolve()`,
// `LocalBackend::make_qid()`, etc. without importing the Backend trait.
// They will be removed once all handlers are migrated to generic `B: Backend`.
impl LocalBackend {
    pub fn root(&self) -> &Path {
        <Self as Backend>::root(self)
    }

    pub fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        <Self as Backend>::resolve(self, path)
    }

    pub fn make_qid(meta: &std::fs::Metadata) -> Qid {
        let qtype = if meta.is_dir() {
            QT_DIR
        } else if meta.file_type().is_symlink() {
            QT_SYMLINK
        } else {
            QT_FILE
        };
        Qid {
            qtype,
            version: meta.mtime() as u32,
            path: meta.ino(),
        }
    }

    pub fn make_stat(meta: &std::fs::Metadata) -> Stat {
        Stat {
            valid: P9_GETATTR_BASIC,
            qid: Self::make_qid(meta),
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            nlink: meta.nlink(),
            rdev: meta.rdev(),
            size: meta.size(),
            blksize: meta.blksize(),
            blocks: meta.blocks(),
            atime_sec: meta.atime() as u64,
            atime_nsec: meta.atime_nsec() as u64,
            mtime_sec: meta.mtime() as u64,
            mtime_nsec: meta.mtime_nsec() as u64,
            ctime_sec: meta.ctime() as u64,
            ctime_nsec: meta.ctime_nsec() as u64,
            btime_sec: 0,
            btime_nsec: 0,
            gen: 0,
            data_version: 0,
        }
    }

    pub fn make_statfs(path: &Path) -> io::Result<StatFs> {
        let svfs = nix::sys::statvfs::statvfs(path)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok(StatFs {
            fs_type: 0x01021997,
            bsize: svfs.block_size() as u32,
            blocks: svfs.blocks(),
            bfree: svfs.blocks_free(),
            bavail: svfs.blocks_available(),
            files: svfs.files(),
            ffree: svfs.files_free(),
            fsid: svfs.filesystem_id() as u64,
            namelen: svfs.name_max() as u32,
        })
    }
}

impl Backend for LocalBackend {
    type Handle = OwnedFd;

    // ── Path resolution ──

    fn root(&self) -> &Path {
        &self.root
    }

    fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        tracing::trace!("backend resolve: {}", path.display());
        // Check if final component is a symlink (don't follow it).
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.is_symlink() {
                if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
                    let canonical_parent = parent.canonicalize()?;
                    if !canonical_parent.starts_with(&self.root) {
                        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "path escape"));
                    }
                    return Ok(canonical_parent.join(name));
                }
            }
        }

        // Not a symlink — canonicalize normally.
        if let Ok(canonical) = path.canonicalize() {
            if canonical.starts_with(&self.root) {
                return Ok(canonical);
            }
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "path escape"));
        }

        // Non-existent path (creation) — canonicalize parent + append name.
        if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
            let canonical_parent = parent.canonicalize().unwrap_or_else(|_| parent.to_path_buf());
            if !canonical_parent.starts_with(&self.root) {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "path escape"));
            }
            return Ok(canonical_parent.join(name));
        }

        Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))
    }

    // ── Attach ──

    fn attach(&self, root: &Path) -> io::Result<(Qid, bool)> {
        tracing::trace!("backend attach: {}", root.display());
        if !root.is_dir() {
            std::fs::create_dir_all(root)?;
        }
        let meta = std::fs::metadata(root)?;
        Ok((Self::make_qid(&meta), meta.is_dir()))
    }

    // ── Walk ──

    fn walk_component(&self, parent: &Path, name: &str) -> io::Result<(PathBuf, Qid, bool)> {
        tracing::trace!("backend walk: parent={} name={name}", parent.display());
        let target = parent.join(name);
        let resolved = self.resolve(&target)?;
        let meta = std::fs::symlink_metadata(&resolved)?;
        let qid = Self::make_qid(&meta);
        let is_dir = meta.is_dir();
        Ok((resolved, qid, is_dir))
    }

    // ── Open ──

    fn open(&self, path: &Path, flags: u32, is_dir: bool) -> io::Result<(OwnedFd, Qid)> {
        tracing::trace!("backend open: {} flags={flags:#x} is_dir={is_dir}", path.display());
        let (owned_fd, meta) = if is_dir {
            let fd = nix::fcntl::open(
                path.as_os_str(),
                nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_DIRECTORY,
                nix::sys::stat::Mode::empty(),
            )
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            let meta = std::fs::metadata(path)?;
            (owned, meta)
        } else {
            let mut oflags = nix::fcntl::OFlag::empty();
            match flags & 0x03 {
                0 => oflags |= nix::fcntl::OFlag::O_RDONLY,
                1 => oflags |= nix::fcntl::OFlag::O_WRONLY,
                2 => oflags |= nix::fcntl::OFlag::O_RDWR,
                _ => oflags |= nix::fcntl::OFlag::O_RDONLY,
            }
            if flags & 0o1000 != 0 {
                oflags |= nix::fcntl::OFlag::O_TRUNC;
            }
            if flags & 0o2000 != 0 {
                oflags |= nix::fcntl::OFlag::O_APPEND;
            }
            let fd = nix::fcntl::open(
                path.as_os_str(),
                oflags,
                nix::sys::stat::Mode::empty(),
            )
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            let meta = std::fs::symlink_metadata(path)?;
            (owned, meta)
        };
        Ok((owned_fd, Self::make_qid(&meta)))
    }

    // ── Read / Write ──

    fn read(&self, handle: &OwnedFd, offset: u64, count: u32) -> io::Result<Vec<u8>> {
        tracing::trace!("backend read: offset={offset} count={count}");
        Self::with_borrowed_file(handle, |file| {
            file.seek(io::SeekFrom::Start(offset))?;
            let mut buf = vec![0u8; count as usize];
            let n = file.read(&mut buf)?;
            buf.truncate(n);
            Ok(buf)
        })
    }

    fn read_into(&self, handle: &OwnedFd, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        tracing::trace!("backend read_into: offset={offset} len={}", buf.len());
        Self::with_borrowed_file(handle, |file| {
            file.seek(io::SeekFrom::Start(offset))?;
            file.read(buf)
        })
    }

    fn write(&self, handle: &OwnedFd, offset: u64, data: &[u8]) -> io::Result<usize> {
        tracing::trace!("backend write: offset={offset} len={}", data.len());
        Self::with_borrowed_file(handle, |file| {
            file.seek(io::SeekFrom::Start(offset))?;
            file.write(data)
        })
    }

    fn fsync(&self, handle: &OwnedFd) -> io::Result<()> {
        tracing::trace!("backend fsync");
        nix::unistd::fsync(handle.as_raw_fd())
            .map_err(|e| io::Error::from_raw_os_error(e as i32))
    }

    // ── Create ──

    fn lcreate(
        &self,
        dir: &Path,
        name: &str,
        flags: u32,
        mode: u32,
    ) -> io::Result<(OwnedFd, Qid, PathBuf)> {
        tracing::trace!("backend lcreate: dir={} name={name} flags={flags:#x} mode={mode:#o}", dir.display());
        let file_path = dir.join(name);
        let resolved = self.resolve(&file_path)?;

        let mut oflags = nix::fcntl::OFlag::O_CREAT;
        match flags & 0x03 {
            0 => oflags |= nix::fcntl::OFlag::O_RDONLY,
            1 => oflags |= nix::fcntl::OFlag::O_WRONLY,
            2 => oflags |= nix::fcntl::OFlag::O_RDWR,
            _ => oflags |= nix::fcntl::OFlag::O_RDONLY,
        }
        if flags & 0o1000 != 0 {
            oflags |= nix::fcntl::OFlag::O_TRUNC;
        }
        if flags & 0o2000 != 0 {
            oflags |= nix::fcntl::OFlag::O_APPEND;
        }
        if flags & 0o200 != 0 {
            oflags |= nix::fcntl::OFlag::O_EXCL;
        }

        let nix_mode = nix::sys::stat::Mode::from_bits_truncate(mode as nix::sys::stat::mode_t);
        let fd = nix::fcntl::open(resolved.as_os_str(), oflags, nix_mode)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let meta = std::fs::metadata(&resolved)?;
        let qid = Self::make_qid(&meta);
        Ok((owned_fd, qid, resolved))
    }

    fn symlink(&self, dir: &Path, name: &str, target: &str) -> io::Result<(Qid, PathBuf)> {
        tracing::trace!("backend symlink: dir={} name={name} target={target}", dir.display());
        let link_path = dir.join(name);
        let resolved = self.resolve(&link_path)?;
        std::os::unix::fs::symlink(target, &resolved)?;
        let meta = std::fs::symlink_metadata(&resolved)?;
        Ok((Self::make_qid(&meta), resolved))
    }

    fn link(&self, target: &Path, dir: &Path, name: &str) -> io::Result<()> {
        tracing::trace!("backend link: target={} dir={} name={name}", target.display(), dir.display());
        let link_path = dir.join(name);
        let resolved = self.resolve(&link_path)?;
        std::fs::hard_link(target, &resolved)
    }

    fn mkdir(&self, parent: &Path, name: &str, mode: u32) -> io::Result<(Qid, PathBuf)> {
        tracing::trace!("backend mkdir: parent={} name={name} mode={mode:#o}", parent.display());
        let dir_path = parent.join(name);
        let resolved = self.resolve(&dir_path)?;
        std::fs::create_dir(&resolved)?;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(&resolved, perms)?;
        let meta = std::fs::metadata(&resolved)?;
        Ok((Self::make_qid(&meta), resolved))
    }

    fn mknod(
        &self,
        parent: &Path,
        name: &str,
        mode: u32,
        major: u32,
        minor: u32,
    ) -> io::Result<(Qid, PathBuf)> {
        tracing::trace!("backend mknod: parent={} name={name} mode={mode:#o}", parent.display());
        let node_path = parent.join(name);
        let resolved = self.resolve(&node_path)?;
        let dev = nix::sys::stat::makedev(major as u64, minor as u64);
        let nix_mode = nix::sys::stat::Mode::from_bits_truncate(mode as nix::sys::stat::mode_t);
        let sflag = match mode & libc::S_IFMT as u32 {
            x if x == libc::S_IFCHR as u32 => nix::sys::stat::SFlag::S_IFCHR,
            x if x == libc::S_IFBLK as u32 => nix::sys::stat::SFlag::S_IFBLK,
            x if x == libc::S_IFIFO as u32 => nix::sys::stat::SFlag::S_IFIFO,
            x if x == libc::S_IFSOCK as u32 => nix::sys::stat::SFlag::S_IFSOCK,
            _ => nix::sys::stat::SFlag::S_IFREG,
        };
        nix::sys::stat::mknod(&resolved, sflag, nix_mode, dev)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        let meta = std::fs::symlink_metadata(&resolved)?;
        Ok((Self::make_qid(&meta), resolved))
    }

    // ── Metadata ──

    fn getattr(&self, path: &Path) -> io::Result<(Stat, Qid)> {
        tracing::trace!("backend getattr: {}", path.display());
        let meta = std::fs::symlink_metadata(path)?;
        let stat = Self::make_stat(&meta);
        let qid = Self::make_qid(&meta);
        Ok((stat, qid))
    }

    fn setattr(&self, path: &Path, attr: &SetAttr) -> io::Result<()> {
        tracing::trace!("backend setattr: {}", path.display());
        if attr.valid & P9_SETATTR_MODE != 0 {
            let perms = std::fs::Permissions::from_mode(attr.mode);
            std::fs::set_permissions(path, perms)?;
        }
        if attr.valid & P9_SETATTR_SIZE != 0 {
            let file = std::fs::OpenOptions::new().write(true).open(path)?;
            file.set_len(attr.size)?;
        }
        if attr.valid & (P9_SETATTR_UID | P9_SETATTR_GID) != 0 {
            let uid = if attr.valid & P9_SETATTR_UID != 0 {
                Some(nix::unistd::Uid::from_raw(attr.uid))
            } else {
                None
            };
            let gid = if attr.valid & P9_SETATTR_GID != 0 {
                Some(nix::unistd::Gid::from_raw(attr.gid))
            } else {
                None
            };
            nix::unistd::chown(path, uid, gid)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        }
        if attr.valid & (P9_SETATTR_ATIME | P9_SETATTR_MTIME) != 0 {
            let atime = if attr.valid & P9_SETATTR_ATIME_SET != 0 {
                nix::sys::time::TimeSpec::new(attr.atime_sec as i64, attr.atime_nsec as i64)
            } else if attr.valid & P9_SETATTR_ATIME != 0 {
                nix::sys::time::TimeSpec::UTIME_NOW
            } else {
                nix::sys::time::TimeSpec::UTIME_OMIT
            };
            let mtime = if attr.valid & P9_SETATTR_MTIME_SET != 0 {
                nix::sys::time::TimeSpec::new(attr.mtime_sec as i64, attr.mtime_nsec as i64)
            } else if attr.valid & P9_SETATTR_MTIME != 0 {
                nix::sys::time::TimeSpec::UTIME_NOW
            } else {
                nix::sys::time::TimeSpec::UTIME_OMIT
            };
            nix::sys::stat::utimensat(
                None,
                path,
                &atime,
                &mtime,
                nix::sys::stat::UtimensatFlags::NoFollowSymlink,
            )
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        }
        Ok(())
    }

    fn statfs(&self, path: &Path) -> io::Result<StatFs> {
        tracing::trace!("backend statfs: {}", path.display());
        let svfs = nix::sys::statvfs::statvfs(path)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok(StatFs {
            fs_type: 0x01021997, // V9FS_MAGIC
            bsize: svfs.block_size() as u32,
            blocks: svfs.blocks(),
            bfree: svfs.blocks_free(),
            bavail: svfs.blocks_available(),
            files: svfs.files(),
            ffree: svfs.files_free(),
            fsid: svfs.filesystem_id() as u64,
            namelen: svfs.name_max() as u32,
        })
    }

    fn readlink(&self, path: &Path) -> io::Result<String> {
        tracing::trace!("backend readlink: {}", path.display());
        let target = std::fs::read_link(path)?;
        Ok(target.to_string_lossy().to_string())
    }

    // ── Directory listing ──

    fn readdir(&self, path: &Path, offset: u64, count: u32) -> io::Result<Vec<u8>> {
        tracing::trace!("backend readdir: {} offset={offset} count={count}", path.display());
        let entries = std::fs::read_dir(path)?;
        let mut data = Vec::new();
        let mut entry_offset: u64 = 0;

        for entry_result in entries {
            let entry = entry_result?;
            if entry_offset < offset {
                entry_offset += 1;
                continue;
            }

            let name = entry.file_name();
            let name_bytes = name.as_encoded_bytes();
            let meta = entry.metadata()?;
            let qid = Self::make_qid(&meta);

            let dtype: u8 = if meta.is_dir() {
                4 // DT_DIR
            } else if meta.file_type().is_symlink() {
                10 // DT_LNK
            } else {
                8 // DT_REG
            };

            // Entry: qid[13] + offset[8] + type[1] + name_len[2] + name[n]
            let entry_size = 13 + 8 + 1 + 2 + name_bytes.len();
            if data.len() + entry_size > count as usize {
                break;
            }

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

    // ── Delete / Rename ──

    fn unlink(&self, path: &Path, is_dir: bool) -> io::Result<()> {
        tracing::trace!("backend unlink: {} is_dir={is_dir}", path.display());
        if is_dir {
            std::fs::remove_dir(path)
        } else {
            std::fs::remove_file(path)
        }
    }

    fn rename(&self, old: &Path, new: &Path) -> io::Result<()> {
        tracing::trace!("backend rename: {} → {}", old.display(), new.display());
        std::fs::rename(old, new)
    }

    // ── Extended attributes ──

    fn xattr_get(&self, path: &Path, name: &str) -> io::Result<Vec<u8>> {
        tracing::trace!("backend xattr_get: {} name={name}", path.display());
        let c_path = Self::path_to_cstring(path)?;
        let c_name = CString::new(name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let size = unsafe {
            libc::getxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0)
        };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; size as usize];
        let n = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    fn xattr_set(&self, path: &Path, name: &str, data: &[u8], flags: u32) -> io::Result<()> {
        tracing::trace!("backend xattr_set: {} name={name}", path.display());
        let c_path = Self::path_to_cstring(path)?;
        let c_name = CString::new(name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let rc = unsafe {
            libc::setxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                data.as_ptr() as *const _,
                data.len(),
                flags as i32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn xattr_list(&self, path: &Path) -> io::Result<Vec<u8>> {
        tracing::trace!("backend xattr_list: {}", path.display());
        let c_path = Self::path_to_cstring(path)?;
        let size = unsafe { libc::listxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size as usize];
        let n = unsafe {
            libc::listxattr(c_path.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len())
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    fn xattr_size(&self, path: &Path, name: &str) -> io::Result<u64> {
        tracing::trace!("backend xattr_size: {} name={name}", path.display());
        let c_path = Self::path_to_cstring(path)?;
        let c_name = CString::new(name)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let size = unsafe {
            libc::getxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0)
        };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(size as u64)
    }

    fn xattr_list_size(&self, path: &Path) -> io::Result<u64> {
        tracing::trace!("backend xattr_list_size: {}", path.display());
        let c_path = Self::path_to_cstring(path)?;
        let size = unsafe { libc::listxattr(c_path.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(size as u64)
    }

    // ── File locking ──

    fn lock(
        &self,
        handle: &OwnedFd,
        lock_type: u8,
        flags: u32,
        start: u64,
        length: u64,
        proc_id: u32,
    ) -> io::Result<u8> {
        tracing::trace!("backend lock: type={lock_type} flags={flags} start={start} length={length}");
        let l_type = match lock_type {
            0 => libc::F_RDLCK as i16,
            1 => libc::F_WRLCK as i16,
            2 => libc::F_UNLCK as i16,
            _ => libc::F_RDLCK as i16,
        };
        let mut flock = libc::flock {
            l_type,
            l_whence: libc::SEEK_SET as i16,
            l_start: start as i64,
            l_len: length as i64,
            l_pid: proc_id as i32,
        };
        let blocking = flags & P9_LOCK_FLAGS_BLOCK != 0;
        let cmd = if blocking { libc::F_SETLKW } else { libc::F_SETLK };
        let rc = unsafe { libc::fcntl(handle.as_raw_fd(), cmd, &mut flock) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN)
                || err.raw_os_error() == Some(libc::EACCES)
            {
                return Ok(P9_LOCK_BLOCKED);
            }
            return Err(err);
        }
        Ok(P9_LOCK_SUCCESS)
    }

    fn getlock(
        &self,
        handle: &OwnedFd,
        lock_type: u8,
        start: u64,
        length: u64,
        proc_id: u32,
    ) -> io::Result<(u8, u64, u64, u32)> {
        tracing::trace!("backend getlock: type={lock_type} start={start} length={length}");
        let l_type = match lock_type {
            0 => libc::F_RDLCK as i16,
            1 => libc::F_WRLCK as i16,
            _ => libc::F_RDLCK as i16,
        };
        let mut flock = libc::flock {
            l_type,
            l_whence: libc::SEEK_SET as i16,
            l_start: start as i64,
            l_len: length as i64,
            l_pid: proc_id as i32,
        };
        let rc = unsafe { libc::fcntl(handle.as_raw_fd(), libc::F_GETLK, &mut flock) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let out_type = match flock.l_type as i32 {
            libc::F_RDLCK => 0u8,
            libc::F_WRLCK => 1,
            _ => 2, // UNLCK
        };
        Ok((out_type, flock.l_start as u64, flock.l_len as u64, flock.l_pid as u32))
    }

    // ── Advanced I/O ──

    fn copy_range(
        &self,
        src: &OwnedFd,
        src_off: u64,
        dst: &OwnedFd,
        dst_off: u64,
        count: u64,
        flags: u32,
    ) -> io::Result<usize> {
        tracing::trace!("backend copy_range: src_off={src_off} dst_off={dst_off} count={count} flags={flags}");
        use std::os::fd::BorrowedFd;

        if flags & COPY_REFLINK != 0 {
            // COW clone via ioctl(FICLONERANGE)
            #[repr(C)]
            struct FileCloneRange {
                src_fd: i64,
                src_offset: u64,
                src_length: u64,
                dest_offset: u64,
            }
            const FICLONERANGE: libc::c_ulong = 0x4020940d;
            let arg = FileCloneRange {
                src_fd: src.as_raw_fd() as i64,
                src_offset: src_off,
                src_length: count,
                dest_offset: dst_off,
            };
            let ret = unsafe { libc::ioctl(dst.as_raw_fd(), FICLONERANGE, &arg) };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(count as usize)
        } else {
            // Kernel-optimized copy via copy_file_range(2)
            let src_fd = unsafe { BorrowedFd::borrow_raw(src.as_raw_fd()) };
            let dst_fd = unsafe { BorrowedFd::borrow_raw(dst.as_raw_fd()) };
            let mut off_in = src_off as i64;
            let mut off_out = dst_off as i64;
            let mut remaining = count as usize;
            let mut total: usize = 0;
            while remaining > 0 {
                match nix::fcntl::copy_file_range(
                    src_fd,
                    Some(&mut off_in),
                    dst_fd,
                    Some(&mut off_out),
                    remaining,
                ) {
                    Ok(0) => break,
                    Ok(n) => {
                        remaining -= n;
                        total += n;
                    }
                    Err(e) => {
                        if total > 0 {
                            // Partial copy succeeded. Return what we have
                            // (write(2) short-write semantics). The client
                            // can retry for the remainder.
                            tracing::debug!(
                                "copy_range partial: {total} of {count} bytes before error: {e}"
                            );
                            break;
                        }
                        return Err(io::Error::from_raw_os_error(e as i32));
                    }
                }
            }
            Ok(total)
        }
    }

    fn allocate(
        &self,
        handle: &OwnedFd,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        tracing::trace!("backend allocate: mode={mode} offset={offset} length={length}");
        let flags = nix::fcntl::FallocateFlags::from_bits_truncate(mode as i32);
        nix::fcntl::fallocate(handle.as_raw_fd(), flags, offset as i64, length as i64)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))
    }

    fn hash(
        &self,
        handle: &OwnedFd,
        algo: u8,
        offset: u64,
        length: u64,
    ) -> io::Result<Vec<u8>> {
        tracing::trace!("backend hash: algo={algo} offset={offset} length={length}");
        if algo != HASH_BLAKE3 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported hash algorithm: {algo}"),
            ));
        }
        Self::with_borrowed_file(handle, |file| {
            file.seek(io::SeekFrom::Start(offset))?;
            let mut hasher = blake3::Hasher::new();
            let mut buf = vec![0u8; 65536];
            let mut remaining = if length == 0 { u64::MAX } else { length };
            while remaining > 0 {
                let to_read = (remaining as usize).min(buf.len());
                let n = file.read(&mut buf[..to_read])?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                remaining = remaining.saturating_sub(n as u64);
            }
            Ok(hasher.finalize().as_bytes().to_vec())
        })
    }

    // ── Ownership ──

    fn chown(&self, path: &Path, uid: u32, gid: u32) -> io::Result<()> {
        tracing::trace!("backend chown: {} uid={uid} gid={gid}", path.display());
        let nix_uid = if uid != 0 {
            Some(nix::unistd::Uid::from_raw(uid))
        } else {
            None
        };
        let nix_gid = if gid != 0 {
            Some(nix::unistd::Gid::from_raw(gid))
        } else {
            None
        };
        nix::unistd::chown(path, nix_uid, nix_gid)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))
    }
}
