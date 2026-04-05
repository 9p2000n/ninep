//! Msg enum and Fcall struct for the 9P2000.N protocol.

use crate::types::MsgType;
use crate::wire::{
    Metric, Qid, Replica, SearchEntry, ServerStat, SetAttr, Stat, StatFs, SubOp,
};

/// Message payloads for all 9P2000.N messages.
#[derive(Debug, Clone, PartialEq)]
pub enum Msg {
    // ── Messages with no payload ──
    // Used for: Rstartls, Rflush, Rclunk, Rremove, Rrename, Rsetattr, Rfsync,
    //           Rlink, Rrenameat, Runlinkat, Rxattrcreate, Rauditctl, RstartlsSpiffe,
    //           Rrdmanotify, Rallocate, Rsetacl, Rxattrset, Rleasebreak, Rleaseack,
    //           Rtraceattr, Runwatch, Rstreamdata, Rstreamclose, Rsetquota, Rnotify, etc.
    Empty,

    // ════════════════════════════════════════════════════════════════════════
    // 9P2000 core base messages
    // ════════════════════════════════════════════════════════════════════════

    /// Tversion / Rversion
    Version { msize: u32, version: String },

    /// Tauth
    Auth { afid: u32, uname: String, aname: String },

    /// Rauth
    Rauth { aqid: Qid },

    /// Tattach
    Attach { fid: u32, afid: u32, uname: String, aname: String },

    /// Rattach
    Rattach { qid: Qid },

    /// Rerror (9P2000 string error)
    Error { ename: String },

    /// Rlerror (numeric error)
    Lerror { ecode: u32 },

    /// Tflush
    Flush { oldtag: u16 },

    /// Twalk
    Walk { fid: u32, newfid: u32, wnames: Vec<String> },

    /// Rwalk
    Rwalk { qids: Vec<Qid> },

    /// Tread
    Read { fid: u32, offset: u64, count: u32 },

    /// Rread
    Rread { data: Vec<u8> },

    /// Twrite
    Write { fid: u32, offset: u64, data: Vec<u8> },

    /// Rwrite
    Rwrite { count: u32 },

    /// Tclunk
    Clunk { fid: u32 },

    /// Tremove
    Remove { fid: u32 },

    /// Tlopen
    Lopen { fid: u32, flags: u32 },

    /// Rlopen
    Rlopen { qid: Qid, iounit: u32 },

    /// Tlcreate
    Lcreate { fid: u32, name: String, flags: u32, mode: u32, gid: u32 },

    /// Rlcreate
    Rlcreate { qid: Qid, iounit: u32 },

    /// Tsymlink
    Symlink { fid: u32, name: String, symtgt: String, gid: u32 },

    /// Rsymlink
    Rsymlink { qid: Qid },

    /// Tmknod
    Mknod { dfid: u32, name: String, mode: u32, major: u32, minor: u32, gid: u32 },

    /// Rmknod
    Rmknod { qid: Qid },

    /// Trename
    Rename { fid: u32, dfid: u32, name: String },

    /// Treadlink
    Readlink { fid: u32 },

    /// Rreadlink
    Rreadlink { target: String },

    /// Tgetattr
    Getattr { fid: u32, mask: u64 },

    /// Rgetattr
    Rgetattr { valid: u64, qid: Qid, stat: Stat },

    /// Tsetattr
    Setattr { fid: u32, attr: SetAttr },

    /// Txattrwalk
    Xattrwalk { fid: u32, newfid: u32, name: String },

    /// Rxattrwalk
    Rxattrwalk { size: u64 },

    /// Txattrcreate
    Xattrcreate { fid: u32, name: String, attr_size: u64, flags: u32 },

    /// Treaddir
    Readdir { fid: u32, offset: u64, count: u32 },

    /// Rreaddir (raw readdir data: count[4] + entries)
    Rreaddir { data: Vec<u8> },

    /// Tfsync
    Fsync { fid: u32 },

    /// Tlock
    Lock {
        fid: u32,
        lock_type: u8,
        flags: u32,
        start: u64,
        length: u64,
        proc_id: u32,
        client_id: String,
    },

    /// Rlock
    Rlock { status: u8 },

    /// Tgetlock
    GetlockReq {
        fid: u32,
        lock_type: u8,
        start: u64,
        length: u64,
        proc_id: u32,
        client_id: String,
    },

    /// Rgetlock
    RgetlockResp {
        lock_type: u8,
        start: u64,
        length: u64,
        proc_id: u32,
        client_id: String,
    },

    /// Tlink
    Link { dfid: u32, fid: u32, name: String },

    /// Tmkdir
    Mkdir { dfid: u32, name: String, mode: u32, gid: u32 },

    /// Rmkdir
    Rmkdir { qid: Qid },

    /// Trenameat
    Renameat { olddirfid: u32, oldname: String, newdirfid: u32, newname: String },

    /// Tunlinkat
    Unlinkat { dirfid: u32, name: String, flags: u32 },

    /// Tstatfs
    Statfs { fid: u32 },

    /// Rstatfs
    Rstatfs { stat: StatFs },

    // ════════════════════════════════════════════════════════════════════════
    // 9P2000.N extensions
    // ════════════════════════════════════════════════════════════════════════

    // ── Security: capability negotiation ──

    /// Tcaps / Rcaps
    Caps { caps: Vec<String> },

    /// Tauthneg
    Authneg { mechs: Vec<String> },

    /// Rauthneg
    Rauthneg { mech: String, challenge: Vec<u8> },

    /// Tcapgrant
    Capgrant { fid: u32, rights: u64, expiry: u64, depth: u16 },

    /// Rcapgrant
    Rcapgrant { token: String },

    /// Tcapuse
    Capuse { fid: u32, token: String },

    /// Rcapuse
    Rcapuse { qid: Qid },

    /// Tauditctl
    Auditctl { fid: u32, flags: u32 },

    // ── Security: SPIFFE ──

    /// TstartlsSpiffe
    StartlsSpiffe { spiffe_id: String, trust_domain: String },

    /// Tfetchbundle
    Fetchbundle { trust_domain: String, format: u8 },

    /// Rfetchbundle
    Rfetchbundle { trust_domain: String, format: u8, bundle: Vec<u8> },

    /// Tspiffeverify
    Spiffeverify { svid_type: u8, spiffe_id: String, svid: Vec<u8> },

    /// Rspiffeverify
    Rspiffeverify { status: u8, spiffe_id: String, expiry: u64 },

    // ── Transport: RDMA ──

    /// Trdmatoken
    Rdmatoken { fid: u32, direction: u8, rkey: u32, addr: u64, length: u32 },

    /// Rrdmatoken
    Rrdmatoken { rkey: u32, addr: u64, length: u32 },

    /// Trdmanotify
    Rdmanotify { rkey: u32, addr: u64, length: u32, slots: u16 },

    // ── Transport: QUIC ──

    /// Tquicstream
    Quicstream { stream_type: u8, stream_id: u64 },

    /// Rquicstream
    Rquicstream { stream_id: u64 },

    // ── Transport: CXL ──

    /// Tcxlmap
    Cxlmap { fid: u32, offset: u64, length: u64, prot: u32, flags: u32 },

    /// Rcxlmap
    Rcxlmap { hpa: u64, length: u64, granularity: u32, coherence: u8 },

    /// Tcxlcoherence
    Cxlcoherence { fid: u32, mode: u8 },

    /// Rcxlcoherence
    Rcxlcoherence { mode: u8, snoop_id: u32 },

    // ── Performance: compound operations ──

    /// Tcompound
    Compound { ops: Vec<SubOp> },

    /// Rcompound
    Rcompound { results: Vec<SubOp> },

    // ── Performance: compression ──

    /// Tcompress
    Compress { algo: u8, level: u8 },

    /// Rcompress
    Rcompress { algo: u8 },

    // ── Performance: server-side copy ──

    /// Tcopyrange
    Copyrange {
        src_fid: u32,
        src_off: u64,
        dst_fid: u32,
        dst_off: u64,
        count: u64,
        flags: u32,
    },

    /// Rcopyrange
    Rcopyrange { count: u64 },

    // ── Performance: allocation / seek ──

    /// Tallocate
    Allocate { fid: u32, mode: u32, offset: u64, length: u64 },

    /// Tseekhole
    Seekhole { fid: u32, seek_type: u8, offset: u64 },

    /// Rseekhole
    Rseekhole { offset: u64 },

    // ── Performance: mmap hint ──

    /// Tmmaphint
    Mmaphint { fid: u32, offset: u64, length: u64, prot: u32 },

    /// Rmmaphint
    Rmmaphint { granted: u8 },

    // ── Filesystem: watch / notify ──

    /// Twatch
    Watch { fid: u32, mask: u32, flags: u32 },

    /// Rwatch
    Rwatch { watch_id: u32 },

    /// Tunwatch
    Unwatch { watch_id: u32 },

    /// Rnotify (server push, tag=0xFFFF). Tnotify is reserved and never sent.
    Notify { watch_id: u32, event: u32, name: String, qid: Qid },

    // ── Filesystem: ACL ──

    /// Tgetacl
    Getacl { fid: u32, acl_type: u8 },

    /// Rgetacl
    Rgetacl { data: Vec<u8> },

    /// Tsetacl
    Setacl { fid: u32, acl_type: u8, data: Vec<u8> },

    // ── Filesystem: snapshot / clone ──

    /// Tsnapshot
    Snapshot { fid: u32, name: String, flags: u32 },

    /// Rsnapshot
    Rsnapshot { qid: Qid },

    /// Tclone
    Clone { src_fid: u32, dst_fid: u32, name: String, flags: u32 },

    /// Rclone
    Rclone { qid: Qid },

    // ── Filesystem: extended attributes (9P2000.N style) ──

    /// Txattrget
    Xattrget { fid: u32, name: String },

    /// Rxattrget
    Rxattrget { data: Vec<u8> },

    /// Txattrset
    Xattrset { fid: u32, name: String, data: Vec<u8>, flags: u32 },

    /// Txattrlist
    Xattrlist { fid: u32, cookie: u64, count: u32 },

    /// Rxattrlist
    Rxattrlist { cookie: u64, names: Vec<String> },

    // ── Distributed: leases ──

    /// Tlease
    Lease { fid: u32, lease_type: u8, duration: u32 },

    /// Rlease
    Rlease { lease_id: u64, lease_type: u8, duration: u32 },

    /// Tleaserenew
    Leaserenew { lease_id: u64, duration: u32 },

    /// Rleaserenew
    Rleaserenew { duration: u32 },

    /// Tleasebreak
    Leasebreak { lease_id: u64, new_type: u8 },

    /// Tleaseack
    Leaseack { lease_id: u64 },

    // ── Distributed: session ──

    /// Tsession
    Session { key: [u8; 16], flags: u32 },

    /// Rsession
    Rsession { flags: u32 },

    // ── Distributed: consistency ──

    /// Tconsistency
    Consistency { fid: u32, level: u8 },

    /// Rconsistency
    Rconsistency { level: u8 },

    // ── Distributed: topology ──

    /// Ttopology
    Topology { fid: u32 },

    /// Rtopology
    Rtopology { replicas: Vec<Replica> },

    // ── Observability: trace ──

    /// Ttraceattr
    Traceattr { attrs: Vec<(String, String)> },

    // ── Observability: health ──

    /// Rhealth
    Rhealth { status: u8, load: u32, metrics: Vec<Metric> },

    // ── Observability: stats ──

    /// Tserverstats
    ServerstatsReq { mask: u64 },

    /// Rserverstats
    Rserverstats { stats: Vec<ServerStat> },

    // ── Resources: quota ──

    /// Tgetquota
    Getquota { fid: u32, quota_type: u8 },

    /// Rgetquota
    Rgetquota {
        bytes_used: u64,
        bytes_limit: u64,
        files_used: u64,
        files_limit: u64,
        grace: u32,
    },

    /// Tsetquota
    Setquota {
        fid: u32,
        quota_type: u8,
        bytes_limit: u64,
        files_limit: u64,
        grace: u32,
    },

    // ── Resources: rate limiting ──

    /// Tratelimit
    Ratelimit { fid: u32, iops: u32, bps: u64 },

    /// Rratelimit
    Rratelimit { iops: u32, bps: u64 },

    // ── Streaming: async operations ──

    /// Tasync
    Async { inner_type: MsgType, payload: Vec<u8> },

    /// Rasync
    Rasync { op_id: u64, status: u8 },

    /// Tpoll
    Poll { op_id: u64 },

    /// Rpoll
    Rpoll { status: u8, progress: u32, payload: Vec<u8> },

    // ── Streaming: stream I/O ──

    /// Tstreamopen
    Streamopen { fid: u32, direction: u8, offset: u64, count: u64 },

    /// Rstreamopen
    Rstreamopen { stream_id: u32 },

    /// Tstreamdata
    Streamdata { stream_id: u32, seq: u32, data: Vec<u8> },

    /// Tstreamclose
    Streamclose { stream_id: u32 },

    // ── Content: search ──

    /// Tsearch
    Search { fid: u32, query: String, flags: u32, max_results: u32, cookie: u64 },

    /// Rsearch
    Rsearch { cookie: u64, entries: Vec<SearchEntry> },

    // ── Content: hash ──

    /// Thash
    Hash { fid: u32, algo: u8, offset: u64, length: u64 },

    /// Rhash
    Rhash { algo: u8, hash: Vec<u8> },
}

/// A framed 9P message: header fields plus the decoded payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Fcall {
    /// Total size of the message on the wire (including the 4-byte size field itself).
    pub size: u32,
    /// The message type discriminant.
    pub msg_type: MsgType,
    /// Tag identifying this request/response pair (NO_TAG = 0xFFFF for Tversion/Rversion).
    pub tag: u16,
    /// The decoded message payload.
    pub msg: Msg,
}
