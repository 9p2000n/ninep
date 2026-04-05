use dashmap::DashMap;
use p9n_proto::wire::Qid;
use std::os::unix::io::OwnedFd;
use std::path::PathBuf;

pub struct FidState {
    pub path: PathBuf,
    pub qid: Qid,
    pub open_fd: Option<OwnedFd>,
    pub is_dir: bool,
}

pub struct FidTable {
    fids: DashMap<u32, FidState>,
}

impl FidTable {
    pub fn new() -> Self {
        Self {
            fids: DashMap::new(),
        }
    }

    pub fn insert(&self, fid: u32, state: FidState) {
        self.fids.insert(fid, state);
    }

    pub fn get(&self, fid: u32) -> Option<dashmap::mapref::one::Ref<'_, u32, FidState>> {
        self.fids.get(&fid)
    }

    pub fn get_mut(&self, fid: u32) -> Option<dashmap::mapref::one::RefMut<'_, u32, FidState>> {
        self.fids.get_mut(&fid)
    }

    pub fn remove(&self, fid: u32) -> Option<(u32, FidState)> {
        self.fids.remove(&fid)
    }

    pub fn contains(&self, fid: u32) -> bool {
        self.fids.contains_key(&fid)
    }

    /// Drop all fids, closing any open file descriptors.
    pub fn clear(&self) {
        self.fids.clear(); // DashMap::clear drops all values, including OwnedFd
    }

    pub fn len(&self) -> usize {
        self.fids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fids.is_empty()
    }
}
