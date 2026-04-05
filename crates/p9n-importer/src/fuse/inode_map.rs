use dashmap::DashMap;
use p9n_proto::wire::Qid;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsertResult {
    pub ino: u64,
    /// Previous fid that was replaced (must be clunked to avoid server-side leak).
    pub old_fid: Option<u32>,
}

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
    ///
    /// If the qid already has an inode, the fid mapping is updated and the
    /// **previous fid** is returned in `old_fid` so the caller can clunk it.
    /// Without this, the old fid would leak on the server.
    pub fn get_or_insert(&self, fid: u32, qid: &Qid) -> InsertResult {
        if let Some(ino) = self.qid_to_ino.get(&qid.path) {
            let old = self.ino_to_fid.insert(*ino, (fid, qid.clone()));
            let old_fid = old
                .map(|(prev_fid, _)| prev_fid)
                .filter(|&prev| prev != fid);
            return InsertResult { ino: *ino, old_fid };
        }
        let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
        self.ino_to_fid.insert(ino, (fid, qid.clone()));
        self.qid_to_ino.insert(qid.path, ino);
        InsertResult { ino, old_fid: None }
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

    /// Remove and return all fids. Used during graceful shutdown
    /// to send Tclunk for every allocated fid.
    pub fn drain_fids(&self) -> Vec<u32> {
        let fids: Vec<u32> = self.ino_to_fid.iter().map(|r| r.value().0).collect();
        self.ino_to_fid.clear();
        self.qid_to_ino.clear();
        fids
    }

    pub fn remove(&self, ino: u64) {
        if let Some((_, (_, qid))) = self.ino_to_fid.remove(&ino) {
            self.qid_to_ino.remove(&qid.path);
        }
    }
}
