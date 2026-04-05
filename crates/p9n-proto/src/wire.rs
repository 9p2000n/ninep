//! Wire-format structures for 9P2000.N messages.

use crate::types::MsgType;

/// QID: 9P file system entity identifier (13 bytes on wire).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Qid {
    pub qtype: u8,
    pub version: u32,
    pub path: u64,
}

/// Stat structure (Rgetattr payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub valid: u64,
    pub qid: Qid,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub rdev: u64,
    pub size: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub atime_sec: u64,
    pub atime_nsec: u64,
    pub mtime_sec: u64,
    pub mtime_nsec: u64,
    pub ctime_sec: u64,
    pub ctime_nsec: u64,
    pub btime_sec: u64,
    pub btime_nsec: u64,
    pub gen: u64,
    pub data_version: u64,
}

/// Setattr request fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAttr {
    pub valid: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime_sec: u64,
    pub atime_nsec: u64,
    pub mtime_sec: u64,
    pub mtime_nsec: u64,
}

/// Directory entry (within Rreaddir).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub qid: Qid,
    pub offset: u64,
    pub dtype: u8,
    pub name: String,
}

/// Statfs response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatFs {
    pub fs_type: u32,
    pub bsize: u32,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub fsid: u64,
    pub namelen: u32,
}

/// Lock request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flock {
    pub lock_type: u8,
    pub flags: u32,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: String,
}

/// Getlock response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Getlock {
    pub lock_type: u8,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: String,
}

/// Sub-operation within a Tcompound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubOp {
    pub msg_type: MsgType,
    pub payload: Vec<u8>,
}

/// Replica entry within Rtopology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replica {
    pub addr: String,
    pub role: u8,
    pub latency_us: u32,
}

/// Metric entry within Rhealth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metric {
    pub name: String,
    pub value: u64,
}

/// ServerStat entry within Rserverstats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStat {
    pub name: String,
    pub stat_type: u8,
    pub value: u64,
}

/// Search result entry within Rsearch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchEntry {
    pub qid: Qid,
    pub name: String,
    pub score: u32,
}
