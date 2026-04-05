//! 9P2000.N message type identifiers and protocol constants.

// ── Protocol versions ──
pub const VERSION_9P2000_N: &str = "9P2000.N";
pub const VERSION_9P2000_U: &str = "9P2000.u";
pub const VERSION_9P2000: &str = "9P2000";

// ── Magic numbers ──
pub const NO_TAG: u16 = 0xFFFF;
pub const NO_FID: u32 = 0xFFFFFFFF;
pub const PREV_FID: u32 = 0xFFFFFFFE;

// ── Sizes ──
pub const HEADER_SIZE: usize = 7; // size[4] type[1] tag[2]
pub const SUBOP_HDR_SZ: usize = 5; // opsize[4] type[1]
pub const QID_SIZE: usize = 13; // type[1] version[4] path[8]
pub const MAX_WELEM: usize = 16; // max walk elements

// ── QID types ──
pub const QT_DIR: u8 = 0x80;
pub const QT_APPEND: u8 = 0x40;
pub const QT_EXCL: u8 = 0x20;
pub const QT_AUTH: u8 = 0x08;
pub const QT_TMP: u8 = 0x04;
pub const QT_SYMLINK: u8 = 0x02;
pub const QT_FILE: u8 = 0x00;

// ── Open/Create flags (Linux O_* values) ──
pub const L_O_RDONLY: u32 = 0;
pub const L_O_WRONLY: u32 = 1;
pub const L_O_RDWR: u32 = 2;
pub const L_O_CREAT: u32 = 0o100;
pub const L_O_TRUNC: u32 = 0o1000;
pub const L_O_APPEND: u32 = 0o2000;

// ── Getattr mask bits ──
pub const P9_GETATTR_MODE: u64 = 0x00000001;
pub const P9_GETATTR_NLINK: u64 = 0x00000002;
pub const P9_GETATTR_UID: u64 = 0x00000004;
pub const P9_GETATTR_GID: u64 = 0x00000008;
pub const P9_GETATTR_RDEV: u64 = 0x00000010;
pub const P9_GETATTR_ATIME: u64 = 0x00000020;
pub const P9_GETATTR_MTIME: u64 = 0x00000040;
pub const P9_GETATTR_CTIME: u64 = 0x00000080;
pub const P9_GETATTR_INO: u64 = 0x00000100;
pub const P9_GETATTR_SIZE: u64 = 0x00000200;
pub const P9_GETATTR_BLOCKS: u64 = 0x00000400;
pub const P9_GETATTR_BTIME: u64 = 0x00000800;
pub const P9_GETATTR_GEN: u64 = 0x00001000;
pub const P9_GETATTR_DATA_VERSION: u64 = 0x00002000;
pub const P9_GETATTR_BASIC: u64 = 0x000007FF;
pub const P9_GETATTR_ALL: u64 = 0x00003FFF;

// ── Setattr valid bits ──
pub const P9_SETATTR_MODE: u32 = 0x00000001;
pub const P9_SETATTR_UID: u32 = 0x00000002;
pub const P9_SETATTR_GID: u32 = 0x00000004;
pub const P9_SETATTR_SIZE: u32 = 0x00000008;
pub const P9_SETATTR_ATIME: u32 = 0x00000010;
pub const P9_SETATTR_MTIME: u32 = 0x00000020;
pub const P9_SETATTR_ATIME_SET: u32 = 0x00000080;
pub const P9_SETATTR_MTIME_SET: u32 = 0x00000100;

// ── Lock types ──
pub const P9_LOCK_TYPE_RDLCK: u8 = 0;
pub const P9_LOCK_TYPE_WRLCK: u8 = 1;
pub const P9_LOCK_TYPE_UNLCK: u8 = 2;
pub const P9_LOCK_SUCCESS: u8 = 0;
pub const P9_LOCK_BLOCKED: u8 = 1;
pub const P9_LOCK_ERROR: u8 = 2;
pub const P9_LOCK_GRACE: u8 = 3;
pub const P9_LOCK_FLAGS_BLOCK: u32 = 1;
pub const P9_LOCK_FLAGS_RECLAIM: u32 = 2;

// ── 9P2000.N Capability strings ──
pub const CAP_TLS: &str = "security.tls";
pub const CAP_AUTH: &str = "security.auth";
pub const CAP_SPIFFE: &str = "security.spiffe";
pub const CAP_COMPOUND: &str = "perf.compound";
pub const CAP_LARGEMSG: &str = "perf.largemsg";
pub const CAP_COMPRESS: &str = "perf.compress";
pub const CAP_COPY: &str = "perf.copy";
pub const CAP_ALLOC: &str = "perf.alloc";
pub const CAP_WATCH: &str = "fs.watch";
pub const CAP_ACL: &str = "fs.acl";
pub const CAP_SNAPSHOT: &str = "fs.snapshot";
pub const CAP_XATTR2: &str = "fs.xattr2";
pub const CAP_LEASE: &str = "dist.lease";
pub const CAP_SESSION: &str = "dist.session";
pub const CAP_CONSISTENCY: &str = "dist.consistency";
pub const CAP_TOPOLOGY: &str = "dist.topology";
pub const CAP_TRACE: &str = "obs.trace";
pub const CAP_HEALTH: &str = "obs.health";
pub const CAP_STATS: &str = "obs.stats";
pub const CAP_QUOTA: &str = "res.quota";
pub const CAP_RATELIMIT: &str = "res.ratelimit";
pub const CAP_ASYNC: &str = "stream.async";
pub const CAP_PIPE: &str = "stream.pipe";
pub const CAP_SEARCH: &str = "content.search";
pub const CAP_HASH: &str = "content.hash";
pub const CAP_QUIC: &str = "transport.quic";
pub const CAP_QUIC_MULTI: &str = "transport.quic.multistream";
pub const CAP_RDMA: &str = "transport.rdma";
pub const CAP_CXL: &str = "transport.cxl";

// ── 9P2000.N feature constants ──
pub const CXL_COHERENCE_SOFTWARE: u8 = 0;
pub const CXL_COHERENCE_HARDWARE: u8 = 1;
pub const CXL_COHERENCE_HYBRID: u8 = 2;
pub const CXL_COHERENCE_RELAXED: u8 = 3;
pub const CXL_MAP_SHARED: u32 = 0x01;
pub const CXL_MAP_PRIVATE: u32 = 0x02;
pub const CXL_MAP_DAX: u32 = 0x04;

pub const WATCH_CREATE: u32 = 0x01;
pub const WATCH_REMOVE: u32 = 0x02;
pub const WATCH_MODIFY: u32 = 0x04;
pub const WATCH_ATTRIB: u32 = 0x08;
pub const WATCH_RENAME: u32 = 0x10;
pub const WATCH_RECURSIVE: u32 = 0x01;

pub const LEASE_READ: u8 = 1;
pub const LEASE_WRITE: u8 = 2;
pub const SESSION_FIDS: u32 = 0x01;
pub const SESSION_LEASES: u32 = 0x02;
pub const SESSION_WATCHES: u32 = 0x04;

pub const COMPRESS_LZ4: u8 = 1;
pub const COMPRESS_ZSTD: u8 = 2;
pub const COMPRESS_SNAPPY: u8 = 3;

pub const HASH_XXHASH64: u8 = 0;
pub const HASH_SHA256: u8 = 1;
pub const HASH_BLAKE3: u8 = 2;
pub const HASH_CRC32C: u8 = 3;

pub const COPY_REFLINK: u32 = 0x01;
pub const COPY_DEDUP: u32 = 0x02;

pub const SVID_X509: u8 = 0;
pub const SVID_JWT: u8 = 1;
pub const BUNDLE_X509_CAS: u8 = 0;
pub const BUNDLE_JWT_KEYS: u8 = 1;
pub const SPIFFE_OK: u8 = 0;
pub const SPIFFE_UNTRUSTED: u8 = 1;
pub const SPIFFE_EXPIRED: u8 = 2;
pub const SPIFFE_REVOKED: u8 = 3;
pub const SPIFFE_MISMATCH: u8 = 4;

pub const AUTH_SPIFFE_X509: &str = "SPIFFE-X.509";
pub const AUTH_SPIFFE_JWT: &str = "SPIFFE-JWT";
pub const AUTH_SCRAM_SHA256: &str = "SASL-SCRAM-SHA-256";
pub const AUTH_MTLS: &str = "mTLS";
pub const AUTH_P9ANY: &str = "P9any";

pub const QSTREAM_CONTROL: u8 = 0;
pub const QSTREAM_DATA: u8 = 1;
pub const QSTREAM_PUSH: u8 = 2;
pub const QSTREAM_BULK: u8 = 3;

/// Unified message type enum covering 9P2000 base and 9P2000.N extension messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MsgType {
    // ── base messages ──
    Tlerror = 6,
    Rlerror = 7,
    Tstatfs = 8,
    Rstatfs = 9,
    Tlopen = 12,
    Rlopen = 13,
    Tlcreate = 14,
    Rlcreate = 15,
    Tsymlink = 16,
    Rsymlink = 17,
    Tmknod = 18,
    Rmknod = 19,
    Trename = 20,
    Rrename = 21,
    Treadlink = 22,
    Rreadlink = 23,
    Tgetattr = 24,
    Rgetattr = 25,
    Tsetattr = 26,
    Rsetattr = 27,
    Txattrwalk = 30,
    Rxattrwalk = 31,
    Txattrcreate = 32,
    Rxattrcreate = 33,
    Treaddir = 40,
    Rreaddir = 41,
    Tfsync = 50,
    Rfsync = 51,
    Tlock = 52,
    Rlock = 53,
    Tgetlock = 54,
    Rgetlock = 55,
    Tlink = 70,
    Rlink = 71,
    Tmkdir = 72,
    Rmkdir = 73,
    Trenameat = 74,
    Rrenameat = 75,
    Tunlinkat = 76,
    Runlinkat = 77,
    // ── 9P2000 core messages ──
    Tversion = 100,
    Rversion = 101,
    Tauth = 102,
    Rauth = 103,
    Tattach = 104,
    Rattach = 105,
    // Terror = 106 — unused
    Rerror = 107,
    Tflush = 108,
    Rflush = 109,
    Twalk = 110,
    Rwalk = 111,
    Tread = 116,
    Rread = 117,
    Twrite = 118,
    Rwrite = 119,
    Tclunk = 120,
    Rclunk = 121,
    Tremove = 122,
    Rremove = 123,
    // ── 9P2000.N extensions (128-253) ──
    Tcaps = 128,
    Rcaps = 129,
    Tstartls = 130,
    Rstartls = 131,
    Tauthneg = 132,
    Rauthneg = 133,
    Tcapgrant = 134,
    Rcapgrant = 135,
    Tcapuse = 136,
    Rcapuse = 137,
    Tauditctl = 138,
    Rauditctl = 139,
    TstartlsSpiffe = 140,
    RstartlsSpiffe = 141,
    Tfetchbundle = 142,
    Rfetchbundle = 143,
    Tspiffeverify = 144,
    Rspiffeverify = 145,
    Tcxlmap = 146,
    Rcxlmap = 147,
    Tcxlcoherence = 148,
    Rcxlcoherence = 149,
    Trdmatoken = 150,
    Rrdmatoken = 151,
    Trdmanotify = 152,
    Rrdmanotify = 153,
    Tquicstream = 154,
    Rquicstream = 155,
    Tcompound = 156,
    Rcompound = 157,
    Tcompress = 158,
    Rcompress = 159,
    Tcopyrange = 160,
    Rcopyrange = 161,
    Tallocate = 162,
    Rallocate = 163,
    Tseekhole = 164,
    Rseekhole = 165,
    Tmmaphint = 166,
    Rmmaphint = 167,
    Twatch = 180,
    Rwatch = 181,
    Tunwatch = 182,
    Runwatch = 183,
    Tnotify = 184,
    Rnotify = 185,
    Tgetacl = 186,
    Rgetacl = 187,
    Tsetacl = 188,
    Rsetacl = 189,
    Tsnapshot = 190,
    Rsnapshot = 191,
    Tclone = 192,
    Rclone = 193,
    Txattrget = 194,
    Rxattrget = 195,
    Txattrset = 196,
    Rxattrset = 197,
    Txattrlist = 198,
    Rxattrlist = 199,
    Tlease = 200,
    Rlease = 201,
    Tleaserenew = 202,
    Rleaserenew = 203,
    Tleasebreak = 204,
    Rleasebreak = 205,
    Tleaseack = 206,
    Rleaseack = 207,
    Tsession = 208,
    Rsession = 209,
    Tconsistency = 210,
    Rconsistency = 211,
    Ttopology = 212,
    Rtopology = 213,
    Ttraceattr = 220,
    Rtraceattr = 221,
    Thealth = 222,
    Rhealth = 223,
    Tserverstats = 224,
    Rserverstats = 225,
    Tgetquota = 230,
    Rgetquota = 231,
    Tsetquota = 232,
    Rsetquota = 233,
    Tratelimit = 234,
    Rratelimit = 235,
    Tasync = 240,
    Rasync = 241,
    Tpoll = 242,
    Rpoll = 243,
    Tstreamopen = 244,
    Rstreamopen = 245,
    Tstreamdata = 246,
    Rstreamdata = 247,
    Tstreamclose = 248,
    Rstreamclose = 249,
    Tsearch = 250,
    Rsearch = 251,
    Thash = 252,
    Rhash = 253,
}

impl MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            6..=9 | 12..=27 | 30..=33 | 40..=41 | 50..=55 | 70..=77 |
            100..=109 | 110..=111 | 116..=123 |
            128..=167 | 180..=213 | 220..=235 | 240..=253 => {
                // SAFETY: repr(u8) and we've verified all valid discriminants
                Some(unsafe { std::mem::transmute(v) })
            }
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            // base
            Self::Tlerror => "Tlerror", Self::Rlerror => "Rlerror",
            Self::Tstatfs => "Tstatfs", Self::Rstatfs => "Rstatfs",
            Self::Tlopen => "Tlopen", Self::Rlopen => "Rlopen",
            Self::Tlcreate => "Tlcreate", Self::Rlcreate => "Rlcreate",
            Self::Tsymlink => "Tsymlink", Self::Rsymlink => "Rsymlink",
            Self::Tmknod => "Tmknod", Self::Rmknod => "Rmknod",
            Self::Trename => "Trename", Self::Rrename => "Rrename",
            Self::Treadlink => "Treadlink", Self::Rreadlink => "Rreadlink",
            Self::Tgetattr => "Tgetattr", Self::Rgetattr => "Rgetattr",
            Self::Tsetattr => "Tsetattr", Self::Rsetattr => "Rsetattr",
            Self::Txattrwalk => "Txattrwalk", Self::Rxattrwalk => "Rxattrwalk",
            Self::Txattrcreate => "Txattrcreate", Self::Rxattrcreate => "Rxattrcreate",
            Self::Treaddir => "Treaddir", Self::Rreaddir => "Rreaddir",
            Self::Tfsync => "Tfsync", Self::Rfsync => "Rfsync",
            Self::Tlock => "Tlock", Self::Rlock => "Rlock",
            Self::Tgetlock => "Tgetlock", Self::Rgetlock => "Rgetlock",
            Self::Tlink => "Tlink", Self::Rlink => "Rlink",
            Self::Tmkdir => "Tmkdir", Self::Rmkdir => "Rmkdir",
            Self::Trenameat => "Trenameat", Self::Rrenameat => "Rrenameat",
            Self::Tunlinkat => "Tunlinkat", Self::Runlinkat => "Runlinkat",
            // 9P2000 core
            Self::Tversion => "Tversion", Self::Rversion => "Rversion",
            Self::Tauth => "Tauth", Self::Rauth => "Rauth",
            Self::Tattach => "Tattach", Self::Rattach => "Rattach",
            Self::Rerror => "Rerror",
            Self::Tflush => "Tflush", Self::Rflush => "Rflush",
            Self::Twalk => "Twalk", Self::Rwalk => "Rwalk",
            Self::Tread => "Tread", Self::Rread => "Rread",
            Self::Twrite => "Twrite", Self::Rwrite => "Rwrite",
            Self::Tclunk => "Tclunk", Self::Rclunk => "Rclunk",
            Self::Tremove => "Tremove", Self::Rremove => "Rremove",
            // 9P2000.N extensions
            Self::Tcaps => "Tcaps", Self::Rcaps => "Rcaps",
            Self::Tstartls => "Tstartls", Self::Rstartls => "Rstartls",
            Self::Tauthneg => "Tauthneg", Self::Rauthneg => "Rauthneg",
            Self::Tcapgrant => "Tcapgrant", Self::Rcapgrant => "Rcapgrant",
            Self::Tcapuse => "Tcapuse", Self::Rcapuse => "Rcapuse",
            Self::Tauditctl => "Tauditctl", Self::Rauditctl => "Rauditctl",
            Self::TstartlsSpiffe => "Tstartls_spiffe", Self::RstartlsSpiffe => "Rstartls_spiffe",
            Self::Tfetchbundle => "Tfetchbundle", Self::Rfetchbundle => "Rfetchbundle",
            Self::Tspiffeverify => "Tspiffeverify", Self::Rspiffeverify => "Rspiffeverify",
            Self::Tcxlmap => "Tcxlmap", Self::Rcxlmap => "Rcxlmap",
            Self::Tcxlcoherence => "Tcxlcoherence", Self::Rcxlcoherence => "Rcxlcoherence",
            Self::Trdmatoken => "Trdmatoken", Self::Rrdmatoken => "Rrdmatoken",
            Self::Trdmanotify => "Trdmanotify", Self::Rrdmanotify => "Rrdmanotify",
            Self::Tquicstream => "Tquicstream", Self::Rquicstream => "Rquicstream",
            Self::Tcompound => "Tcompound", Self::Rcompound => "Rcompound",
            Self::Tcompress => "Tcompress", Self::Rcompress => "Rcompress",
            Self::Tcopyrange => "Tcopyrange", Self::Rcopyrange => "Rcopyrange",
            Self::Tallocate => "Tallocate", Self::Rallocate => "Rallocate",
            Self::Tseekhole => "Tseekhole", Self::Rseekhole => "Rseekhole",
            Self::Tmmaphint => "Tmmaphint", Self::Rmmaphint => "Rmmaphint",
            Self::Twatch => "Twatch", Self::Rwatch => "Rwatch",
            Self::Tunwatch => "Tunwatch", Self::Runwatch => "Runwatch",
            Self::Tnotify => "Tnotify", Self::Rnotify => "Rnotify",
            Self::Tgetacl => "Tgetacl", Self::Rgetacl => "Rgetacl",
            Self::Tsetacl => "Tsetacl", Self::Rsetacl => "Rsetacl",
            Self::Tsnapshot => "Tsnapshot", Self::Rsnapshot => "Rsnapshot",
            Self::Tclone => "Tclone", Self::Rclone => "Rclone",
            Self::Txattrget => "Txattrget", Self::Rxattrget => "Rxattrget",
            Self::Txattrset => "Txattrset", Self::Rxattrset => "Rxattrset",
            Self::Txattrlist => "Txattrlist", Self::Rxattrlist => "Rxattrlist",
            Self::Tlease => "Tlease", Self::Rlease => "Rlease",
            Self::Tleaserenew => "Tleaserenew", Self::Rleaserenew => "Rleaserenew",
            Self::Tleasebreak => "Tleasebreak", Self::Rleasebreak => "Rleasebreak",
            Self::Tleaseack => "Tleaseack", Self::Rleaseack => "Rleaseack",
            Self::Tsession => "Tsession", Self::Rsession => "Rsession",
            Self::Tconsistency => "Tconsistency", Self::Rconsistency => "Rconsistency",
            Self::Ttopology => "Ttopology", Self::Rtopology => "Rtopology",
            Self::Ttraceattr => "Ttraceattr", Self::Rtraceattr => "Rtraceattr",
            Self::Thealth => "Thealth", Self::Rhealth => "Rhealth",
            Self::Tserverstats => "Tserverstats", Self::Rserverstats => "Rserverstats",
            Self::Tgetquota => "Tgetquota", Self::Rgetquota => "Rgetquota",
            Self::Tsetquota => "Tsetquota", Self::Rsetquota => "Rsetquota",
            Self::Tratelimit => "Tratelimit", Self::Rratelimit => "Rratelimit",
            Self::Tasync => "Tasync", Self::Rasync => "Rasync",
            Self::Tpoll => "Tpoll", Self::Rpoll => "Rpoll",
            Self::Tstreamopen => "Tstreamopen", Self::Rstreamopen => "Rstreamopen",
            Self::Tstreamdata => "Tstreamdata", Self::Rstreamdata => "Rstreamdata",
            Self::Tstreamclose => "Tstreamclose", Self::Rstreamclose => "Rstreamclose",
            Self::Tsearch => "Tsearch", Self::Rsearch => "Rsearch",
            Self::Thash => "Thash", Self::Rhash => "Rhash",
        }
    }

    /// Returns true if this is a T-message (client request).
    pub fn is_t_message(self) -> bool {
        (self as u8) % 2 == 0
    }

    /// Returns true if this is an R-message (server response).
    pub fn is_r_message(self) -> bool {
        (self as u8) % 2 == 1
    }
}
