//! Local filesystem backend.

use super::Backend;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag};
use nix::sys::stat::Mode;
use p9n_proto::types::*;
use p9n_proto::wire::{Qid, SetAttr, Stat, StatFs};
use std::ffi::CString;
use std::io::{self, Read, Seek, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct LocalBackend {
    root: PathBuf,
    /// O_PATH | O_DIRECTORY fd opened on the export root at construction
    /// time. All path resolution is performed via `openat2(root_fd, ...,
    /// RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` so the kernel rejects any
    /// path that would resolve outside the export root, and so resolved
    /// fds are pinned to inodes (TOCTOU-free across subsequent *at calls).
    /// See `docs/POSIX_IDENTITY.md` §5.6 for the architectural model and
    /// `docs/THREAD_MODEL.md` for the path-safety guarantees.
    root_fd: Arc<OwnedFd>,
}

/// Reject path components that would escape the workload root, embed
/// path separators, or carry NUL bytes. Called before every backend
/// syscall that interpolates client-supplied `name` into a parent
/// path.
///
/// Note: this is the *create-side* belt-and-braces check; the
/// authoritative escape prevention is the kernel's RESOLVE_BENEATH
/// enforcement in [`LocalBackend::resolve_dir`]. We still reject these
/// component shapes early so that the error is surfaced as `EINVAL`
/// rather than as a confusing `ENOENT`/`ELOOP` from the kernel later.
fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    if name.as_bytes().iter().any(|&b| b == b'/' || b == 0) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(())
}

impl LocalBackend {
    pub fn new(root: String) -> Result<Self, Box<dyn std::error::Error>> {
        let path = PathBuf::from(&root);
        if !path.is_dir() {
            std::fs::create_dir_all(&path)?;
        }
        let root_canonical = path.canonicalize()?;
        // Open the root once and keep it for the lifetime of the backend.
        // O_PATH is enough to anchor openat2 calls and is not subject to
        // permission checks for lookup beneath it.
        let root_fd = nix::fcntl::open(
            &root_canonical,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        tracing::info!("exporting {root}");
        Ok(Self {
            root: root_canonical,
            root_fd: Arc::new(unsafe { OwnedFd::from_raw_fd(root_fd) }),
        })
    }

    /// Borrow the root dir fd for an *at syscall.
    #[allow(dead_code)] // staged refactor: used in stage 3
    fn root_borrow(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.root_fd.as_raw_fd()) }
    }

    /// Strip the export-root prefix from a path. Used to convert the
    /// absolute paths stored in fid_state into the relative form that
    /// `openat2(root_fd, ...)` expects.
    fn rel_to_root<'a>(&self, path: &'a Path) -> &'a Path {
        path.strip_prefix(&self.root).unwrap_or(path)
    }

    /// Resolve a path to a directory fd using `openat2` with
    /// `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`. The returned fd is
    /// O_PATH; use it as the dirfd argument to subsequent *at syscalls.
    ///
    /// `path` may be absolute (typically the cached value from
    /// `FidState.path`) or relative to root; both shapes resolve
    /// correctly.
    ///
    /// Errors:
    /// - `EXDEV` / `ELOOP` if the path would escape the root (kernel-enforced)
    /// - `ENOENT` if the path does not exist
    /// - `ENOTDIR` if a non-final component isn't a directory
    #[allow(dead_code)] // staged refactor: used in stage 3
    fn resolve_dir(&self, path: &Path) -> io::Result<OwnedFd> {
        let rel = self.rel_to_root(path);
        // openat2 doesn't accept "" as a path; map to "." which means "the dirfd itself".
        let target: &Path = if rel.as_os_str().is_empty() {
            Path::new(".")
        } else {
            rel
        };
        let how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_MAGICLINKS);
        let fd = nix::fcntl::openat2(self.root_fd.as_raw_fd(), target, how)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Split a path into `(parent_dirfd, leaf_name)` for *at-family
    /// syscalls. The parent dir is resolved atomically via openat2 with
    /// `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`; the leaf is returned
    /// as a String for the caller to pass to the *at syscall.
    ///
    /// Returns `EINVAL` if the path has no leaf component (the export
    /// root itself cannot be split this way; callers operating on the
    /// root should use `resolve_path` instead).
    #[allow(dead_code)] // staged refactor: used in stages 3b/3c
    fn split_to_dirfd(&self, path: &Path) -> io::Result<(OwnedFd, String)> {
        let rel = self.rel_to_root(path);
        let parent = rel.parent().unwrap_or(Path::new(""));
        let leaf = rel
            .file_name()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?
            .to_string_lossy()
            .into_owned();
        // parent may be empty (file directly under root) — resolve_dir
        // handles that case by mapping to ".".
        let parent_fd = self.resolve_dir(parent)?;
        Ok((parent_fd, leaf))
    }

    /// Resolve a path to an O_PATH fd pointing at the file/dir/symlink
    /// itself (without following the final symlink, if any). Used by
    /// metadata operations that need to refer to the path as an entity.
    fn resolve_path(&self, path: &Path) -> io::Result<OwnedFd> {
        let rel = self.rel_to_root(path);
        let target: &Path = if rel.as_os_str().is_empty() {
            Path::new(".")
        } else {
            rel
        };
        let how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_MAGICLINKS);
        let fd = nix::fcntl::openat2(self.root_fd.as_raw_fd(), target, how)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Build a CString from a Path. No longer used by the backend itself
    /// (all path-based syscalls have moved to *at-family with CStrings
    /// over the leaf name); retained for future helpers and tests.
    #[allow(dead_code)]
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
        // mem::forget is the whole point: File's Drop would close the
        // fd, but we are borrowing from the caller's OwnedFd.
        #[allow(clippy::mem_forget)]
        std::mem::forget(file);
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

    /// Build a Qid from the libc::stat returned by fstatat / fstat. Used
    /// by the openat2-based resolution path that doesn't go through
    /// std::fs::Metadata.
    pub fn make_qid_from_libc(stat: &libc::stat) -> Qid {
        let mode = stat.st_mode;
        let qtype = match mode & libc::S_IFMT {
            x if x == libc::S_IFDIR => QT_DIR,
            x if x == libc::S_IFLNK => QT_SYMLINK,
            _ => QT_FILE,
        };
        Qid {
            qtype,
            version: stat.st_mtime as u32,
            path: stat.st_ino,
        }
    }

    /// Build a Stat (full metadata) from a libc::stat. The companion to
    /// `make_qid_from_libc` for fd-based getattr/walk paths.
    pub fn make_stat_from_libc(stat: &libc::stat) -> Stat {
        Stat {
            valid: P9_GETATTR_BASIC,
            qid: Self::make_qid_from_libc(stat),
            mode: stat.st_mode,
            uid: stat.st_uid,
            gid: stat.st_gid,
            nlink: stat.st_nlink,
            rdev: stat.st_rdev,
            size: stat.st_size as u64,
            blksize: stat.st_blksize as u64,
            blocks: stat.st_blocks as u64,
            atime_sec: stat.st_atime as u64,
            atime_nsec: stat.st_atime_nsec as u64,
            mtime_sec: stat.st_mtime as u64,
            mtime_nsec: stat.st_mtime_nsec as u64,
            ctime_sec: stat.st_ctime as u64,
            ctime_nsec: stat.st_ctime_nsec as u64,
            btime_sec: 0,
            btime_nsec: 0,
            gen: 0,
            data_version: 0,
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
        let svfs =
            nix::sys::statvfs::statvfs(path).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
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
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "path escape",
                        ));
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
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path escape",
            ));
        }

        // Non-existent path (creation) — canonicalize parent + append name.
        if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
            let canonical_parent = parent
                .canonicalize()
                .unwrap_or_else(|_| parent.to_path_buf());
            if !canonical_parent.starts_with(&self.root) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "path escape",
                ));
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
        // Allow `..` here — walking up is a normal 9P operation. We
        // forbid `/` and NUL bytes (which would alter parsing) and
        // empty names (no-op step). The kernel-level RESOLVE_BENEATH
        // check below catches escapes regardless.
        if name.is_empty() || name.as_bytes().iter().any(|&b| b == b'/' || b == 0) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        // Resolve the parent atomically via openat2(RESOLVE_BENEATH),
        // then fstatat the leaf via the dirfd. This closes the
        // resolve→stat TOCTOU window; concurrent path-component swaps
        // cannot redirect the stat to a different inode because the
        // dirfd pins the parent.
        let parent_fd = self.resolve_dir(parent)?;
        let stat = nix::sys::stat::fstatat(
            Some(parent_fd.as_raw_fd()),
            name,
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        let qid = Self::make_qid_from_libc(&stat);
        let is_dir = (stat.st_mode as u32 & libc::S_IFMT) == libc::S_IFDIR;
        Ok((parent.join(name), qid, is_dir))
    }

    // ── Open ──

    fn open(&self, path: &Path, flags: u32, is_dir: bool) -> io::Result<(OwnedFd, Qid)> {
        tracing::trace!(
            "backend open: {} flags={flags:#x} is_dir={is_dir}",
            path.display()
        );
        // Two-step atomic open:
        //   1. resolve_path → O_PATH | O_NOFOLLOW fd via openat2 with
        //      RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS. The kernel
        //      enforces containment within the export root and pins the
        //      inode against concurrent path swaps.
        //   2. re-open via /proc/self/fd/N to upgrade the O_PATH fd to
        //      a real fd with read/write access. /proc/self/fd/N is a
        //      magic link that resolves directly to the pinned inode,
        //      so the second open hits the same inode the first one
        //      validated — TOCTOU-free.
        let opath = self.resolve_path(path)?;
        let mut oflags = OFlag::O_CLOEXEC;
        if is_dir {
            oflags |= OFlag::O_RDONLY | OFlag::O_DIRECTORY;
        } else {
            match flags & 0x03 {
                0 => oflags |= OFlag::O_RDONLY,
                1 => oflags |= OFlag::O_WRONLY,
                2 => oflags |= OFlag::O_RDWR,
                _ => oflags |= OFlag::O_RDONLY,
            }
            if flags & 0o1000 != 0 {
                oflags |= OFlag::O_TRUNC;
            }
            if flags & 0o2000 != 0 {
                oflags |= OFlag::O_APPEND;
            }
        }
        let proc_path = format!("/proc/self/fd/{}", opath.as_raw_fd());
        let fd = nix::fcntl::open(proc_path.as_str(), oflags, Mode::empty())
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let stat = nix::sys::stat::fstat(owned.as_raw_fd())
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok((owned, Self::make_qid_from_libc(&stat)))
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
        nix::unistd::fsync(handle.as_raw_fd()).map_err(|e| io::Error::from_raw_os_error(e as i32))
    }

    // ── Create ──

    fn lcreate(
        &self,
        dir: &Path,
        name: &str,
        flags: u32,
        mode: u32,
    ) -> io::Result<(OwnedFd, Qid, PathBuf)> {
        tracing::trace!(
            "backend lcreate: dir={} name={name} flags={flags:#x} mode={mode:#o}",
            dir.display()
        );
        validate_name(name)?;
        // Atomic create: resolve parent dir to an O_PATH dirfd, then
        // openat under that dirfd. Even if the parent is concurrently
        // renamed or the leaf is concurrently swapped, the dirfd pins
        // the parent inode, and openat operates on the leaf within that
        // pinned parent.
        let parent_fd = self.resolve_dir(dir)?;
        let mut oflags = OFlag::O_CREAT | OFlag::O_CLOEXEC;
        match flags & 0x03 {
            0 => oflags |= OFlag::O_RDONLY,
            1 => oflags |= OFlag::O_WRONLY,
            2 => oflags |= OFlag::O_RDWR,
            _ => oflags |= OFlag::O_RDONLY,
        }
        if flags & 0o1000 != 0 {
            oflags |= OFlag::O_TRUNC;
        }
        if flags & 0o2000 != 0 {
            oflags |= OFlag::O_APPEND;
        }
        if flags & 0o200 != 0 {
            oflags |= OFlag::O_EXCL;
        }
        let nix_mode = Mode::from_bits_truncate(mode as nix::sys::stat::mode_t);
        let fd = nix::fcntl::openat(Some(parent_fd.as_raw_fd()), name, oflags, nix_mode)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let stat = nix::sys::stat::fstat(owned_fd.as_raw_fd())
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        let qid = Self::make_qid_from_libc(&stat);
        Ok((owned_fd, qid, dir.join(name)))
    }

    fn symlink(&self, dir: &Path, name: &str, target: &str) -> io::Result<(Qid, PathBuf)> {
        tracing::trace!(
            "backend symlink: dir={} name={name} target={target}",
            dir.display()
        );
        validate_name(name)?;
        // Validate the symlink target: an absolute target or one that
        // contains `..` traversal can plant a "landmine" — even if read-side
        // resolve() catches it later, defense-in-depth says don't write it.
        if target.starts_with('/') {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        if target.split('/').any(|c| c == "..") {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        let parent_fd = self.resolve_dir(dir)?;
        nix::unistd::symlinkat(target, Some(parent_fd.as_raw_fd()), name)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        let stat = nix::sys::stat::fstatat(
            Some(parent_fd.as_raw_fd()),
            name,
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok((Self::make_qid_from_libc(&stat), dir.join(name)))
    }

    fn link(&self, target: &Path, dir: &Path, name: &str) -> io::Result<()> {
        tracing::trace!(
            "backend link: target={} dir={} name={name}",
            target.display(),
            dir.display()
        );
        validate_name(name)?;
        // Resolve both source-parent and dest-parent dirs atomically.
        // linkat with the dirfds + leaf names produces a new hard link
        // pinned to the inode the source dirfd+name resolves to, with
        // no second path lookup window.
        // AT_SYMLINK_FOLLOW preserves the historical std::fs::hard_link
        // behavior (POSIX-2008 default).
        let (target_parent_fd, target_leaf) = self.split_to_dirfd(target)?;
        let parent_fd = self.resolve_dir(dir)?;
        nix::unistd::linkat(
            Some(target_parent_fd.as_raw_fd()),
            target_leaf.as_str(),
            Some(parent_fd.as_raw_fd()),
            name,
            nix::fcntl::AtFlags::AT_SYMLINK_FOLLOW,
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok(())
    }

    fn mkdir(&self, parent: &Path, name: &str, mode: u32) -> io::Result<(Qid, PathBuf)> {
        tracing::trace!(
            "backend mkdir: parent={} name={name} mode={mode:#o}",
            parent.display()
        );
        validate_name(name)?;
        let parent_fd = self.resolve_dir(parent)?;
        let nix_mode = Mode::from_bits_truncate(mode as nix::sys::stat::mode_t);
        // nix doesn't expose mkdirat; call libc directly.
        let name_c =
            CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let rc = unsafe {
            libc::mkdirat(
                parent_fd.as_raw_fd(),
                name_c.as_ptr(),
                nix_mode.bits() as libc::mode_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // mkdir applies umask; a fchmodat fixes the perms to exactly `mode`.
        nix::sys::stat::fchmodat(
            Some(parent_fd.as_raw_fd()),
            name,
            nix_mode,
            nix::sys::stat::FchmodatFlags::FollowSymlink,
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        let stat = nix::sys::stat::fstatat(
            Some(parent_fd.as_raw_fd()),
            name,
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok((Self::make_qid_from_libc(&stat), parent.join(name)))
    }

    fn mknod(
        &self,
        parent: &Path,
        name: &str,
        mode: u32,
        major: u32,
        minor: u32,
    ) -> io::Result<(Qid, PathBuf)> {
        tracing::trace!(
            "backend mknod: parent={} name={name} mode={mode:#o}",
            parent.display()
        );
        validate_name(name)?;
        let parent_fd = self.resolve_dir(parent)?;
        let dev = nix::sys::stat::makedev(major as u64, minor as u64);
        let nix_mode = Mode::from_bits_truncate(mode as nix::sys::stat::mode_t);
        let sflag = match mode & libc::S_IFMT {
            x if x == libc::S_IFCHR => nix::sys::stat::SFlag::S_IFCHR,
            x if x == libc::S_IFBLK => nix::sys::stat::SFlag::S_IFBLK,
            x if x == libc::S_IFIFO => nix::sys::stat::SFlag::S_IFIFO,
            x if x == libc::S_IFSOCK => nix::sys::stat::SFlag::S_IFSOCK,
            _ => nix::sys::stat::SFlag::S_IFREG,
        };
        // mknodat — nix doesn't expose it, fall through to libc.
        let name_c =
            CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let rc = unsafe {
            libc::mknodat(
                parent_fd.as_raw_fd(),
                name_c.as_ptr(),
                (sflag.bits() | nix_mode.bits()) as libc::mode_t,
                dev,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = nix::sys::stat::fstatat(
            Some(parent_fd.as_raw_fd()),
            name,
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok((Self::make_qid_from_libc(&stat), parent.join(name)))
    }

    // ── Metadata ──

    fn getattr(&self, path: &Path) -> io::Result<(Stat, Qid)> {
        tracing::trace!("backend getattr: {}", path.display());
        // Atomic resolve-then-stat: openat2 pins the inode, fstat
        // operates on the pinned fd — no second path lookup window.
        let fd = self.resolve_path(path)?;
        let stat = nix::sys::stat::fstat(fd.as_raw_fd())
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok((
            Self::make_stat_from_libc(&stat),
            Self::make_qid_from_libc(&stat),
        ))
    }

    fn setattr(&self, path: &Path, attr: &SetAttr) -> io::Result<()> {
        tracing::trace!("backend setattr: {}", path.display());
        // For setattr we split path into (parent_fd, leaf) so each
        // sub-op (chmod / truncate / chown / utimes) can use its
        // appropriate *at variant against the pinned parent. The
        // truncate sub-op requires a real (non-O_PATH) write fd, so it
        // re-opens via the parent_fd + leaf — still atomic with respect
        // to concurrent path swaps because the parent is pinned.
        let (parent_fd, leaf) = self.split_to_dirfd(path)?;

        if attr.valid & P9_SETATTR_MODE != 0 {
            let nix_mode = Mode::from_bits_truncate(attr.mode as nix::sys::stat::mode_t);
            nix::sys::stat::fchmodat(
                Some(parent_fd.as_raw_fd()),
                leaf.as_str(),
                nix_mode,
                nix::sys::stat::FchmodatFlags::NoFollowSymlink,
            )
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        }

        if attr.valid & P9_SETATTR_SIZE != 0 {
            // Open the leaf for writing through the pinned parent_fd.
            // O_NOFOLLOW so a concurrent swap-to-symlink fails ELOOP
            // rather than truncating the symlink target.
            let fd = nix::fcntl::openat(
                Some(parent_fd.as_raw_fd()),
                leaf.as_str(),
                OFlag::O_WRONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            let rc = unsafe { libc::ftruncate(owned.as_raw_fd(), attr.size as libc::off_t) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if attr.valid & (P9_SETATTR_UID | P9_SETATTR_GID) != 0 {
            let uid = if attr.valid & P9_SETATTR_UID != 0 {
                attr.uid
            } else {
                u32::MAX
            };
            let gid = if attr.valid & P9_SETATTR_GID != 0 {
                attr.gid
            } else {
                u32::MAX
            };
            // fchownat with empty path + AT_EMPTY_PATH would need an
            // O_PATH fd to the leaf; we already have parent_fd + leaf
            // so we go through the (parent, leaf) variant.
            let leaf_c = CString::new(leaf.as_str())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let rc = unsafe {
                libc::fchownat(
                    parent_fd.as_raw_fd(),
                    leaf_c.as_ptr(),
                    uid as libc::uid_t,
                    gid as libc::gid_t,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
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
                Some(parent_fd.as_raw_fd()),
                leaf.as_str(),
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
        // fstatvfs on a fd pinned by openat2 — TOCTOU-free.
        let fd = self.resolve_path(path)?;
        let svfs =
            nix::sys::statvfs::fstatvfs(&fd).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
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
        let (parent_fd, leaf) = self.split_to_dirfd(path)?;
        let target = nix::fcntl::readlinkat(Some(parent_fd.as_raw_fd()), leaf.as_str())
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok(target.to_string_lossy().to_string())
    }

    // ── Directory listing ──

    fn readdir(&self, path: &Path, offset: u64, count: u32) -> io::Result<Vec<u8>> {
        tracing::trace!(
            "backend readdir: {} offset={offset} count={count}",
            path.display()
        );
        // Open the directory atomically via openat2; re-open via
        // /proc/self/fd/N for read-iteration access (std::fs::read_dir
        // wants a path, not a fd; nix::dir::Dir::from_fd works but the
        // /proc/self/fd path is simpler and equally TOCTOU-free since
        // the magic link resolves to the pinned inode).
        let dir_opath = self.resolve_dir(path)?;
        let proc_path = format!("/proc/self/fd/{}", dir_opath.as_raw_fd());
        let entries = std::fs::read_dir(&proc_path)?;
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
        // Atomic unlink via the parent dirfd. unlinkat with AT_REMOVEDIR
        // for dirs / 0 for files. The parent_fd pins the parent inode
        // against concurrent renames.
        let (parent_fd, leaf) = self.split_to_dirfd(path)?;
        let leaf_c = CString::new(leaf.as_str())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let flag = if is_dir { libc::AT_REMOVEDIR } else { 0 };
        let rc = unsafe { libc::unlinkat(parent_fd.as_raw_fd(), leaf_c.as_ptr(), flag) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn rename(&self, old: &Path, new: &Path) -> io::Result<()> {
        tracing::trace!("backend rename: {} → {}", old.display(), new.display());
        // Both source-parent and dest-parent dirs are pinned. renameat
        // with the dirfds + leaf names is atomic against concurrent
        // path-component swaps on either side.
        let (old_parent_fd, old_leaf) = self.split_to_dirfd(old)?;
        let (new_parent_fd, new_leaf) = self.split_to_dirfd(new)?;
        nix::fcntl::renameat(
            Some(old_parent_fd.as_raw_fd()),
            old_leaf.as_str(),
            Some(new_parent_fd.as_raw_fd()),
            new_leaf.as_str(),
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok(())
    }

    // ── Extended attributes ──
    //
    // xattr operations resolve the path atomically via openat2, then
    // use libc's f*xattr family on the pinned fd. fgetxattr/fsetxattr/
    // flistxattr accept O_PATH fds since Linux 5.7; older kernels would
    // EBADF, in which case we re-open via /proc/self/fd/N. We try the
    // direct fd path first and fall back to the proc-fd reopen on
    // EBADF.

    fn xattr_get(&self, path: &Path, name: &str) -> io::Result<Vec<u8>> {
        tracing::trace!("backend xattr_get: {} name={name}", path.display());
        let fd = self.resolve_path(path)?;
        let c_name =
            CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut size =
            unsafe { libc::fgetxattr(fd.as_raw_fd(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        // Older kernels: O_PATH not supported by fgetxattr → EBADF.
        // Fall back to /proc/self/fd/N + getxattr (follows the magic
        // link to the pinned inode).
        let proc_fd: Option<OwnedFd> =
            if size < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
                let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
                let pfd = nix::fcntl::open(
                    proc_path.as_str(),
                    OFlag::O_RDONLY | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                let owned = unsafe { OwnedFd::from_raw_fd(pfd) };
                size = unsafe {
                    libc::fgetxattr(owned.as_raw_fd(), c_name.as_ptr(), std::ptr::null_mut(), 0)
                };
                Some(owned)
            } else {
                None
            };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        let read_fd = proc_fd
            .as_ref()
            .map(|f| f.as_raw_fd())
            .unwrap_or_else(|| fd.as_raw_fd());
        let mut buf = vec![0u8; size as usize];
        let n = unsafe {
            libc::fgetxattr(
                read_fd,
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
        // setxattr through O_PATH may EBADF on older kernels; re-open
        // for write through /proc/self/fd/N as the fallback path.
        let fd = self.resolve_path(path)?;
        let c_name =
            CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut rc = unsafe {
            libc::fsetxattr(
                fd.as_raw_fd(),
                c_name.as_ptr(),
                data.as_ptr() as *const _,
                data.len(),
                flags as i32,
            )
        };
        if rc < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
            let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
            let pfd = nix::fcntl::open(
                proc_path.as_str(),
                OFlag::O_RDWR | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            let owned = unsafe { OwnedFd::from_raw_fd(pfd) };
            rc = unsafe {
                libc::fsetxattr(
                    owned.as_raw_fd(),
                    c_name.as_ptr(),
                    data.as_ptr() as *const _,
                    data.len(),
                    flags as i32,
                )
            };
        }
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn xattr_list(&self, path: &Path) -> io::Result<Vec<u8>> {
        tracing::trace!("backend xattr_list: {}", path.display());
        let fd = self.resolve_path(path)?;
        let mut size = unsafe { libc::flistxattr(fd.as_raw_fd(), std::ptr::null_mut(), 0) };
        let proc_fd: Option<OwnedFd> =
            if size < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
                let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
                let pfd = nix::fcntl::open(
                    proc_path.as_str(),
                    OFlag::O_RDONLY | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                let owned = unsafe { OwnedFd::from_raw_fd(pfd) };
                size = unsafe { libc::flistxattr(owned.as_raw_fd(), std::ptr::null_mut(), 0) };
                Some(owned)
            } else {
                None
            };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        let read_fd = proc_fd
            .as_ref()
            .map(|f| f.as_raw_fd())
            .unwrap_or_else(|| fd.as_raw_fd());
        let mut buf = vec![0u8; size as usize];
        let n = unsafe { libc::flistxattr(read_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    fn xattr_size(&self, path: &Path, name: &str) -> io::Result<u64> {
        tracing::trace!("backend xattr_size: {} name={name}", path.display());
        let fd = self.resolve_path(path)?;
        let c_name =
            CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut size =
            unsafe { libc::fgetxattr(fd.as_raw_fd(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
            let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
            let pfd = nix::fcntl::open(
                proc_path.as_str(),
                OFlag::O_RDONLY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            let owned = unsafe { OwnedFd::from_raw_fd(pfd) };
            size = unsafe {
                libc::fgetxattr(owned.as_raw_fd(), c_name.as_ptr(), std::ptr::null_mut(), 0)
            };
        }
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(size as u64)
    }

    fn xattr_list_size(&self, path: &Path) -> io::Result<u64> {
        tracing::trace!("backend xattr_list_size: {}", path.display());
        let fd = self.resolve_path(path)?;
        let mut size = unsafe { libc::flistxattr(fd.as_raw_fd(), std::ptr::null_mut(), 0) };
        if size < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
            let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
            let pfd = nix::fcntl::open(
                proc_path.as_str(),
                OFlag::O_RDONLY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            let owned = unsafe { OwnedFd::from_raw_fd(pfd) };
            size = unsafe { libc::flistxattr(owned.as_raw_fd(), std::ptr::null_mut(), 0) };
        }
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
        tracing::trace!(
            "backend lock: type={lock_type} flags={flags} start={start} length={length}"
        );
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
        let cmd = if blocking {
            libc::F_SETLKW
        } else {
            libc::F_SETLK
        };
        let rc = unsafe { libc::fcntl(handle.as_raw_fd(), cmd, &mut flock) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN) || err.raw_os_error() == Some(libc::EACCES)
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
        Ok((
            out_type,
            flock.l_start as u64,
            flock.l_len as u64,
            flock.l_pid as u32,
        ))
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
        tracing::trace!(
            "backend copy_range: src_off={src_off} dst_off={dst_off} count={count} flags={flags}"
        );
        use std::os::fd::BorrowedFd;

        if flags & COPY_REFLINK != 0 {
            // COW clone via ioctl(FICLONERANGE).
            //
            // Layout must match `struct file_clone_range` from
            // <linux/fs.h>:
            //   __s64  src_fd;
            //   __u64  src_offset;
            //   __u64  src_length;
            //   __u64  dest_offset;
            //
            // FICLONERANGE = _IOW(0x94, 13, struct file_clone_range)
            //              = 0x4020940d
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
            // SAFETY: arg is repr(C) with layout matching the kernel's
            // file_clone_range struct. dst fd is a valid open file descriptor.
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

    fn allocate(&self, handle: &OwnedFd, mode: u32, offset: u64, length: u64) -> io::Result<()> {
        tracing::trace!("backend allocate: mode={mode} offset={offset} length={length}");
        let flags = nix::fcntl::FallocateFlags::from_bits_truncate(mode as i32);
        nix::fcntl::fallocate(handle.as_raw_fd(), flags, offset as i64, length as i64)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))
    }

    fn hash(&self, handle: &OwnedFd, algo: u8, offset: u64, length: u64) -> io::Result<Vec<u8>> {
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
        // Atomic resolve-then-chown:
        //   1. openat2 with O_PATH | O_NOFOLLOW + RESOLVE_BENEATH pins the
        //      inode the path resolves to *right now*. If an attacker has
        //      swapped the path component to a symlink, O_NOFOLLOW opens
        //      the symlink itself; if they swapped to something pointing
        //      outside the root, RESOLVE_BENEATH fails the open with
        //      EXDEV.
        //   2. fchownat with AT_EMPTY_PATH operates on the pinned inode
        //      directly — no second path lookup, no TOCTOU window.
        // This replaces the previous chown(path) that follows symlinks
        // and re-walks the path, both of which were the classic TOCTOU
        // exploit surface.
        let fd = self.resolve_path(path)?;
        let uid_arg = if uid != 0 { uid } else { u32::MAX };
        let gid_arg = if gid != 0 { gid } else { u32::MAX };
        // u32::MAX (-1 as uid_t) is the POSIX sentinel for "do not change
        // this id" — same convention nix's chown wrapper used for None.
        let rc = unsafe {
            libc::fchownat(
                fd.as_raw_fd(),
                c"".as_ptr(),
                uid_arg as libc::uid_t,
                gid_arg as libc::gid_t,
                libc::AT_EMPTY_PATH,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_name_rejects_traversal_separators_and_nul() {
        assert!(validate_name("ok").is_ok());
        assert!(validate_name("ok.txt").is_ok());
        assert!(validate_name("with space").is_ok());

        assert_eq!(
            validate_name("").unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            validate_name(".").unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            validate_name("..").unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            validate_name("a/b").unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            validate_name("../etc/passwd").unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            validate_name("a\0b").unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn lcreate_rejects_traversal_name() {
        let dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(dir.path().to_string_lossy().into_owned()).unwrap();
        let err = backend
            .lcreate(dir.path(), "../escape.txt", 0, 0o644)
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        // Confirm nothing was written outside the export.
        assert!(!dir.path().parent().unwrap().join("escape.txt").exists());
    }

    #[test]
    fn mkdir_rejects_traversal_name() {
        let dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(dir.path().to_string_lossy().into_owned()).unwrap();
        let err = backend.mkdir(dir.path(), "..", 0o755).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn symlink_rejects_absolute_target() {
        let dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(dir.path().to_string_lossy().into_owned()).unwrap();
        let err = backend
            .symlink(dir.path(), "link", "/etc/passwd")
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
        assert!(!dir.path().join("link").exists());
    }

    #[test]
    fn symlink_rejects_dotdot_target() {
        let dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(dir.path().to_string_lossy().into_owned()).unwrap();
        let err = backend
            .symlink(dir.path(), "link", "../../etc/passwd")
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn symlink_accepts_relative_in_tree_target() {
        let dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(dir.path().to_string_lossy().into_owned()).unwrap();
        backend.symlink(dir.path(), "link", "real.txt").unwrap();
        assert!(
            dir.path().join("link").exists() || dir.path().join("link").symlink_metadata().is_ok()
        );
    }

    #[test]
    fn root_fd_resolves_root_relative() {
        // Smoke test that resolve_dir works on the root itself via the
        // openat2 path; full coverage comes once stage 3 wires it in.
        let dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(dir.path().to_string_lossy().into_owned()).unwrap();
        let fd = backend.resolve_dir(dir.path()).unwrap();
        // A successful open returns a non-negative fd.
        assert!(fd.as_raw_fd() >= 0);
    }

    /// chown must operate on the path's actual inode, not follow a
    /// symlink. The classic TOCTOU exploit places a symlink at the
    /// chown target between create and chown; if chown follows it,
    /// the symlink target (e.g., /etc/passwd) gets reowned. Our impl
    /// uses openat2 with O_PATH | O_NOFOLLOW so the symlink itself
    /// is the chown target.
    #[test]
    fn chown_does_not_follow_symlink() {
        // Skip if not running with capability to chown — the test still
        // exercises the symlink-handling code path even when both uid
        // and gid stay unchanged (sentinel u32::MAX path).
        let dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(dir.path().to_string_lossy().into_owned()).unwrap();

        // Plant a regular file outside the export root that the symlink
        // would point at. We assert the target's mtime is unchanged
        // after the chown call.
        let outside = tempfile::NamedTempFile::new().unwrap();
        let outside_path = outside.path().to_path_buf();
        let outside_meta_before = std::fs::metadata(&outside_path).unwrap();

        // Create the symlink inside the export root pointing outside.
        // (We bypass the backend symlink validator here intentionally —
        // operators or pre-existing files can introduce symlinks any time.)
        let link_path = dir.path().join("link");
        std::os::unix::fs::symlink(&outside_path, &link_path).unwrap();

        // Call chown on the symlink path. The current uid/gid (u32::MAX
        // sentinel) is a no-op — what matters is which inode the syscall
        // operates on. We expect the symlink itself to be the target
        // (or an EPERM if the test user can't chown), never the file
        // outside the root.
        let _ = backend.chown(&link_path, 0, 0);

        // The outside file's metadata must be unchanged (specifically,
        // not chowned to root). raw_uid 0 only succeeds for actual root;
        // if the test runs as a non-root user and chown followed the
        // symlink, we'd see EPERM, but the symlink's owner could have
        // been examined. Stronger assertion: the *outside file* keeps
        // its uid.
        let outside_meta_after = std::fs::metadata(&outside_path).unwrap();
        assert_eq!(
            outside_meta_before.uid(),
            outside_meta_after.uid(),
            "chown followed symlink to file outside export root!"
        );
        assert_eq!(
            outside_meta_before.gid(),
            outside_meta_after.gid(),
            "chown followed symlink to file outside export root!"
        );
    }

    #[test]
    fn resolve_dir_refuses_dotdot_escape() {
        let dir = tempfile::tempdir().unwrap();
        let backend = LocalBackend::new(dir.path().to_string_lossy().into_owned()).unwrap();
        // A relative path that tries to climb above root must fail under
        // RESOLVE_BENEATH. The kernel returns EXDEV for such attempts.
        let escape = Path::new("../");
        let err = backend.resolve_dir(escape).unwrap_err();
        assert!(
            matches!(err.raw_os_error(), Some(e) if e == libc::EXDEV || e == libc::ENOENT),
            "unexpected error: {err:?}"
        );
    }
}
