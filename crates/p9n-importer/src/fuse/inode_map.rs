use dashmap::DashMap;
use p9n_proto::wire::Qid;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct InodeMap {
    /// ino -> (fid, qid)
    ino_to_fid: DashMap<u64, (u32, Qid)>,
    /// qid.path -> ino
    qid_to_ino: DashMap<u64, u64>,
    next_ino: AtomicU64,
}

impl InodeMap {
    pub fn new() -> Self {
        Self {
            ino_to_fid: DashMap::new(),
            qid_to_ino: DashMap::new(),
            next_ino: AtomicU64::new(2), // 1 is reserved for root
        }
    }

    pub fn set_root(&self, fid: u32, qid: Qid) {
        self.ino_to_fid.insert(1, (fid, qid.clone()));
        self.qid_to_ino.insert(qid.path, 1);
    }

    /// Get or create an inode for a qid.
    pub fn get_or_insert(&self, fid: u32, qid: &Qid) -> u64 {
        if let Some(ino) = self.qid_to_ino.get(&qid.path) {
            // Update fid mapping
            self.ino_to_fid.insert(*ino, (fid, qid.clone()));
            return *ino;
        }
        let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
        self.ino_to_fid.insert(ino, (fid, qid.clone()));
        self.qid_to_ino.insert(qid.path, ino);
        ino
    }

    pub fn get_fid(&self, ino: u64) -> Option<u32> {
        self.ino_to_fid.get(&ino).map(|r| r.0)
    }

    pub fn get_qid(&self, ino: u64) -> Option<Qid> {
        self.ino_to_fid.get(&ino).map(|r| r.1.clone())
    }

    /// Look up inode by qid path (for push notification cache invalidation).
    pub fn get_ino_by_qid_path(&self, qid_path: u64) -> Option<u64> {
        self.qid_to_ino.get(&qid_path).map(|r| *r)
    }

    pub fn remove(&self, ino: u64) {
        if let Some((_, (_, qid))) = self.ino_to_fid.remove(&ino) {
            self.qid_to_ino.remove(&qid.path);
        }
    }
}
