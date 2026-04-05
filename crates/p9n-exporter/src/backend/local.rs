use p9n_proto::types::*;
use p9n_proto::wire::{Qid, Stat, StatFs};
use std::os::unix::fs::MetadataExt;
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

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a path, preventing escape outside the export root.
    ///
    /// For existing paths, canonicalize to resolve intermediate symlinks.
    /// Symlinks at the final component are **not** followed — the returned path
    /// points at the symlink itself so that readlink works correctly.
    /// For non-existing paths (creation), canonicalize the parent directory
    /// and append the file name.
    pub fn resolve(&self, path: &Path) -> Result<PathBuf, std::io::Error> {
        // Check if the final component is a symlink (don't follow it).
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.is_symlink() {
                if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
                    let canonical_parent = parent.canonicalize()?;
                    if !canonical_parent.starts_with(&self.root) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "path escape",
                        ));
                    }
                    return Ok(canonical_parent.join(name));
                }
            }
        }

        // Not a symlink — canonicalize normally (works for existing paths)
        if let Ok(canonical) = path.canonicalize() {
            if canonical.starts_with(&self.root) {
                return Ok(canonical);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "path escape",
            ));
        }

        // Path doesn't exist yet (creation) — canonicalize parent + append name
        if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
            let canonical_parent = parent.canonicalize().unwrap_or_else(|_| parent.to_path_buf());
            if !canonical_parent.starts_with(&self.root) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "path escape",
                ));
            }
            return Ok(canonical_parent.join(name));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid path",
        ))
    }

    /// Build a Qid from filesystem metadata.
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

    /// Build a Stat from filesystem metadata.
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

    /// Build a StatFs from statvfs.
    pub fn make_statfs(path: &Path) -> Result<StatFs, std::io::Error> {
        let svfs = nix::sys::statvfs::statvfs(path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
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
}
