//! Filesystem backend abstraction.
//!
//! The [`Backend`] trait defines all filesystem operations that the exporter
//! delegates to.  The [`local`] module provides the default implementation
//! backed by a local POSIX filesystem.
//!
//! All trait methods are **synchronous** — handlers call them from within
//! `tokio::task::spawn_blocking`.

pub mod local;

use p9n_proto::wire::{Qid, SetAttr, Stat, StatFs};
use std::io;
use std::path::{Path, PathBuf};

/// Filesystem backend trait.
///
/// Implementations provide the actual I/O operations for the exporter.
/// `Handle` is an opaque type representing an open file or object — for a
/// local filesystem this is `OwnedFd`; for cloud storage it could be a
/// session token, cursor, or presigned URL.
pub trait Backend: Send + Sync + 'static {
    /// Opaque handle for an open file/object.
    type Handle: Send + Sync + 'static;

    // ── Path resolution ──

    /// Return the export root path.
    fn root(&self) -> &Path;

    /// Resolve a path, preventing escape outside the export root.
    /// Symlinks at the final component are preserved (not followed).
    fn resolve(&self, path: &Path) -> io::Result<PathBuf>;

    // ── Attach ──

    /// Ensure the attach root exists and return its (Qid, is_dir).
    fn attach(&self, root: &Path) -> io::Result<(Qid, bool)>;

    // ── Walk ──

    /// Walk one path component: resolve `parent.join(name)` and return
    /// `(resolved_path, qid, is_dir)`.
    fn walk_component(
        &self,
        parent: &Path,
        name: &str,
    ) -> io::Result<(PathBuf, Qid, bool)>;

    // ── Open ──

    /// Open a file or directory, returning `(handle, qid)`.
    /// `flags` are Linux O_* values (0=RDONLY, 1=WRONLY, 2=RDWR, etc.).
    fn open(&self, path: &Path, flags: u32, is_dir: bool) -> io::Result<(Self::Handle, Qid)>;

    // ── Read / Write ──

    /// Read up to `count` bytes at `offset`.
    fn read(&self, handle: &Self::Handle, offset: u64, count: u32) -> io::Result<Vec<u8>>;

    /// Read directly into a caller-provided buffer (zero-copy fast path).
    /// Returns the number of bytes read.
    fn read_into(
        &self,
        handle: &Self::Handle,
        offset: u64,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        let data = self.read(handle, offset, buf.len() as u32)?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    /// Write `data` at `offset`. Returns the number of bytes written.
    fn write(&self, handle: &Self::Handle, offset: u64, data: &[u8]) -> io::Result<usize>;

    /// Flush data to durable storage.
    fn fsync(&self, handle: &Self::Handle) -> io::Result<()>;

    // ── Create ──

    /// Create and open a new file. Returns `(handle, qid, resolved_path)`.
    fn lcreate(
        &self,
        dir: &Path,
        name: &str,
        flags: u32,
        mode: u32,
    ) -> io::Result<(Self::Handle, Qid, PathBuf)>;

    /// Create a symbolic link. Returns `(qid, resolved_path)`.
    fn symlink(&self, dir: &Path, name: &str, target: &str) -> io::Result<(Qid, PathBuf)>;

    /// Create a hard link.
    fn link(&self, target: &Path, dir: &Path, name: &str) -> io::Result<()>;

    /// Create a directory. Returns `(qid, resolved_path)`.
    fn mkdir(&self, parent: &Path, name: &str, mode: u32) -> io::Result<(Qid, PathBuf)>;

    /// Create a device node / FIFO / socket. Returns `(qid, resolved_path)`.
    fn mknod(
        &self,
        parent: &Path,
        name: &str,
        mode: u32,
        major: u32,
        minor: u32,
    ) -> io::Result<(Qid, PathBuf)>;

    // ── Metadata ──

    /// Get file attributes.
    fn getattr(&self, path: &Path) -> io::Result<(Stat, Qid)>;

    /// Set file attributes.
    fn setattr(&self, path: &Path, attr: &SetAttr) -> io::Result<()>;

    /// Get filesystem statistics.
    fn statfs(&self, path: &Path) -> io::Result<StatFs>;

    /// Read symlink target.
    fn readlink(&self, path: &Path) -> io::Result<String>;

    // ── Directory listing ──

    /// Read directory entries in 9P readdir wire format.
    /// `offset` is the entry index to start from, `count` is the maximum
    /// number of bytes to return.
    fn readdir(
        &self,
        path: &Path,
        offset: u64,
        count: u32,
    ) -> io::Result<Vec<u8>>;

    // ── Delete / Rename ──

    /// Remove a file or directory.
    fn unlink(&self, path: &Path, is_dir: bool) -> io::Result<()>;

    /// Rename a file or directory.
    fn rename(&self, old: &Path, new: &Path) -> io::Result<()>;

    // ── Extended attributes ──

    /// Get an extended attribute value.
    fn xattr_get(&self, path: &Path, name: &str) -> io::Result<Vec<u8>>;

    /// Set an extended attribute.
    fn xattr_set(&self, path: &Path, name: &str, data: &[u8], flags: u32) -> io::Result<()>;

    /// List extended attribute names (raw null-separated bytes).
    fn xattr_list(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Get the size of a single xattr value.
    fn xattr_size(&self, path: &Path, name: &str) -> io::Result<u64>;

    /// Get the total size of all xattr names.
    fn xattr_list_size(&self, path: &Path) -> io::Result<u64>;

    // ── File locking ──

    /// Attempt to set a POSIX file lock. Returns P9_LOCK_SUCCESS or
    /// P9_LOCK_BLOCKED.
    fn lock(
        &self,
        handle: &Self::Handle,
        lock_type: u8,
        flags: u32,
        start: u64,
        length: u64,
        proc_id: u32,
    ) -> io::Result<u8>;

    /// Query the current lock state.
    /// Returns `(lock_type, start, length, proc_id)`.
    fn getlock(
        &self,
        handle: &Self::Handle,
        lock_type: u8,
        start: u64,
        length: u64,
        proc_id: u32,
    ) -> io::Result<(u8, u64, u64, u32)>;

    // ── Advanced I/O ──

    /// Server-side copy between two handles. Returns bytes copied.
    fn copy_range(
        &self,
        src: &Self::Handle,
        src_off: u64,
        dst: &Self::Handle,
        dst_off: u64,
        count: u64,
        flags: u32,
    ) -> io::Result<usize>;

    /// Preallocate file space (fallocate).
    fn allocate(
        &self,
        handle: &Self::Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()>;

    /// Compute a content hash. `algo` is one of HASH_* constants.
    /// `length == 0` means hash to EOF.
    fn hash(
        &self,
        handle: &Self::Handle,
        algo: u8,
        offset: u64,
        length: u64,
    ) -> io::Result<Vec<u8>>;

    // ── Ownership ──

    /// Change file ownership. uid/gid of 0 means no change.
    fn chown(&self, path: &Path, uid: u32, gid: u32) -> io::Result<()>;
}
