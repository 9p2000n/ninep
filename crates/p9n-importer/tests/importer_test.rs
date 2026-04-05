//! Unit tests for p9n-importer: InodeMap, FidPool, AttrCache, LeaseMap, RpcError.

use p9n_proto::wire::{Qid, Stat};
use p9n_proto::types::*;
use std::time::Duration;

fn make_qid(qtype: u8, path: u64) -> Qid {
    Qid { qtype, version: 1, path }
}

fn make_stat(qid: Qid, size: u64) -> Stat {
    Stat {
        valid: P9_GETATTR_BASIC, qid, mode: 0o644, uid: 1000, gid: 1000,
        nlink: 1, rdev: 0, size, blksize: 4096, blocks: (size + 511) / 512,
        atime_sec: 0, atime_nsec: 0, mtime_sec: 0, mtime_nsec: 0,
        ctime_sec: 0, ctime_nsec: 0, btime_sec: 0, btime_nsec: 0,
        gen: 0, data_version: 0,
    }
}

// ═══════════════════ InodeMap ═══════════════════

mod inode_map_tests {
    use super::*;
    use p9n_importer::fuse::inode_map::InodeMap;

    #[test]
    fn test_root_inode() {
        let map = InodeMap::new();
        let qid = make_qid(QT_DIR, 100);
        map.set_root(0, qid.clone());

        assert_eq!(map.get_fid(1), Some(0));
        assert_eq!(map.get_qid(1).unwrap(), qid);
        assert_eq!(map.get_ino_by_qid_path(100), Some(1));
    }

    #[test]
    fn test_get_or_insert_new() {
        let map = InodeMap::new();
        let qid = make_qid(QT_FILE, 200);
        let r = map.get_or_insert(5, &qid);
        assert!(r.ino >= 2); // 1 reserved for root
        assert!(r.old_fid.is_none());
        assert_eq!(map.get_fid(r.ino), Some(5));
        assert_eq!(map.get_ino_by_qid_path(200), Some(r.ino));
    }

    #[test]
    fn test_get_or_insert_existing_qid() {
        let map = InodeMap::new();
        let qid = make_qid(QT_FILE, 300);
        let r1 = map.get_or_insert(10, &qid);
        let r2 = map.get_or_insert(20, &qid); // same qid.path, different fid
        assert_eq!(r1.ino, r2.ino); // same inode
        assert_eq!(r2.old_fid, Some(10)); // old fid returned for clunk
        assert_eq!(map.get_fid(r1.ino), Some(20)); // fid updated
    }

    #[test]
    fn test_different_qids_get_different_inodes() {
        let map = InodeMap::new();
        let q1 = make_qid(QT_FILE, 400);
        let q2 = make_qid(QT_FILE, 401);
        let r1 = map.get_or_insert(1, &q1);
        let r2 = map.get_or_insert(2, &q2);
        assert_ne!(r1.ino, r2.ino);
    }

    #[test]
    fn test_remove_cleans_both_directions() {
        let map = InodeMap::new();
        let qid = make_qid(QT_FILE, 500);
        let r = map.get_or_insert(7, &qid);

        map.remove(r.ino);
        assert!(map.get_fid(r.ino).is_none());
        assert!(map.get_ino_by_qid_path(500).is_none());
    }

    #[test]
    fn test_remove_nonexistent_is_noop() {
        let map = InodeMap::new();
        map.remove(999); // should not panic
    }

    #[test]
    fn test_monotonic_allocation() {
        let map = InodeMap::new();
        let mut inos = Vec::new();
        for i in 0..10u64 {
            let qid = make_qid(QT_FILE, 1000 + i);
            inos.push(map.get_or_insert(i as u32, &qid).ino);
        }
        // All unique
        let mut sorted = inos.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 10);
    }
}

// ═══════════════════ FidPool ═══════════════════

mod fid_pool_tests {
    use p9n_importer::fuse::fid_pool::FidPool;

    #[test]
    fn test_monotonic_allocation() {
        let pool = FidPool::new();
        let f1 = pool.alloc();
        let f2 = pool.alloc();
        let f3 = pool.alloc();
        assert_eq!(f1, 1);
        assert_eq!(f2, 2);
        assert_eq!(f3, 3);
    }

    #[test]
    fn test_never_allocates_reserved() {
        let pool = FidPool::new();
        let mut fids = Vec::new();
        for _ in 0..100 {
            let fid = pool.alloc();
            assert_ne!(fid, 0xFFFFFFFF, "NO_FID should never be allocated");
            assert_ne!(fid, 0xFFFFFFFE, "reserved fid should never be allocated");
            fids.push(fid);
        }
        // All unique
        fids.sort();
        fids.dedup();
        assert_eq!(fids.len(), 100);
    }

    #[test]
    fn test_starts_at_one() {
        let pool = FidPool::new();
        assert_eq!(pool.alloc(), 1); // fid 0 reserved for root
    }

    #[test]
    fn test_concurrent_allocation() {
        use std::sync::Arc;
        let pool = Arc::new(FidPool::new());
        let mut handles = Vec::new();
        for _ in 0..4 {
            let p = pool.clone();
            handles.push(std::thread::spawn(move || {
                (0..100).map(|_| p.alloc()).collect::<Vec<_>>()
            }));
        }
        let mut all: Vec<u32> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 400, "all fids should be unique across threads");
    }
}

// ═══════════════════ AttrCache ═══════════════════

mod attr_cache_tests {
    use super::*;
    use p9n_importer::fuse::attr_cache::AttrCache;

    #[test]
    fn test_put_and_get() {
        let cache = AttrCache::new(16, Duration::from_secs(10));
        let stat = make_stat(make_qid(QT_FILE, 1), 1024);
        cache.put(42, stat.clone());
        assert_eq!(cache.get(42).unwrap(), stat);
    }

    #[test]
    fn test_get_nonexistent() {
        let cache = AttrCache::new(16, Duration::from_secs(10));
        assert!(cache.get(99).is_none());
    }

    #[test]
    fn test_ttl_expiry() {
        let cache = AttrCache::new(16, Duration::from_millis(50));
        let stat = make_stat(make_qid(QT_FILE, 2), 512);
        cache.put(1, stat);
        assert!(cache.get(1).is_some()); // within TTL
        std::thread::sleep(Duration::from_millis(80));
        assert!(cache.get(1).is_none()); // expired
    }

    #[test]
    fn test_get_leased_ignores_ttl() {
        let cache = AttrCache::new(16, Duration::from_millis(50));
        let stat = make_stat(make_qid(QT_FILE, 3), 256);
        cache.put(1, stat.clone());
        std::thread::sleep(Duration::from_millis(80));
        // Leased get should succeed even after TTL expiry.
        // (Note: must not call get() first — it evicts expired entries.)
        assert_eq!(cache.get_leased(1).unwrap(), stat);
        // Regular get on a different entry to confirm TTL is enforced.
        cache.put(2, make_stat(make_qid(QT_FILE, 4), 128));
        std::thread::sleep(Duration::from_millis(80));
        assert!(cache.get(2).is_none());
    }

    #[test]
    fn test_invalidate() {
        let cache = AttrCache::new(16, Duration::from_secs(10));
        let stat = make_stat(make_qid(QT_FILE, 4), 100);
        cache.put(5, stat);
        cache.invalidate(5);
        assert!(cache.get(5).is_none());
        assert!(cache.get_leased(5).is_none());
    }

    #[test]
    fn test_lru_eviction() {
        let cache = AttrCache::new(2, Duration::from_secs(10)); // capacity=2
        cache.put(1, make_stat(make_qid(QT_FILE, 10), 10));
        cache.put(2, make_stat(make_qid(QT_FILE, 20), 20));
        cache.put(3, make_stat(make_qid(QT_FILE, 30), 30)); // evicts ino=1
        assert!(cache.get(1).is_none(), "oldest entry should be evicted");
        assert!(cache.get(2).is_some());
        assert!(cache.get(3).is_some());
    }
}

// ═══════════════════ LeaseMap ═══════════════════

mod lease_map_tests {
    use p9n_importer::fuse::lease_map::LeaseMap;

    #[test]
    fn test_grant_and_has_lease() {
        let map = LeaseMap::new();
        assert!(!map.has_lease(100));
        map.grant(1, 1000, 100);
        assert!(map.has_lease(100));
    }

    #[test]
    fn test_release_by_fh() {
        let map = LeaseMap::new();
        map.grant(1, 1000, 100);
        let lease_id = map.release_by_fh(1);
        assert_eq!(lease_id, Some(1000));
        assert!(!map.has_lease(100)); // count decremented to 0
    }

    #[test]
    fn test_break_lease() {
        let map = LeaseMap::new();
        map.grant(1, 1000, 100);
        let ino = map.break_lease(1000);
        assert_eq!(ino, Some(100));
        assert!(!map.has_lease(100));
    }

    #[test]
    fn test_release_after_break_returns_none() {
        let map = LeaseMap::new();
        map.grant(1, 1000, 100);
        map.break_lease(1000); // server broke it
        // Client release should return None (already broken, no ack needed)
        assert_eq!(map.release_by_fh(1), None);
    }

    #[test]
    fn test_multiple_leases_per_inode() {
        let map = LeaseMap::new();
        // Two file handles open on the same inode
        map.grant(1, 1000, 100);
        map.grant(2, 1001, 100);
        assert!(map.has_lease(100));

        // Release one — inode still has a lease
        map.release_by_fh(1);
        assert!(map.has_lease(100));

        // Release second — no more leases
        map.release_by_fh(2);
        assert!(!map.has_lease(100));
    }

    #[test]
    fn test_break_unknown_lease() {
        let map = LeaseMap::new();
        assert_eq!(map.break_lease(9999), None);
    }
}

// ═══════════════════ RpcError ═══════════════════

mod rpc_error_tests {
    use p9n_importer::error::RpcError;

    #[test]
    fn test_ninep_errno() {
        let err = RpcError::NineP { ecode: 2 }; // ENOENT
        assert_eq!(err.errno(), Some(2));
    }

    #[test]
    fn test_transport_errno_is_none() {
        let err = RpcError::from("connection lost");
        assert_eq!(err.errno(), None);
    }

    #[test]
    fn test_display_formatting() {
        let e1 = RpcError::NineP { ecode: 13 };
        assert_eq!(format!("{e1}"), "9P error: errno=13");

        let e2 = RpcError::NinePString { ename: "permission denied".into() };
        assert_eq!(format!("{e2}"), "9P error: permission denied");

        let e3 = RpcError::from("timeout");
        assert!(format!("{e3}").contains("timeout"));
    }
}
