//! Round-trip marshal/unmarshal tests for 9P2000.N messages.

use p9n_proto::buf::Buf;
use p9n_proto::codec::{marshal, unmarshal};
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use p9n_proto::wire::*;

fn round_trip(msg_type: MsgType, tag: u16, msg: Msg) -> Msg {
    let fc = Fcall { size: 0, msg_type, tag, msg };
    let mut buf = Buf::new(256);
    marshal(&mut buf, &fc).expect("marshal failed");
    let data = buf.into_vec();
    assert!(data.len() >= HEADER_SIZE, "message too small");
    let mut rbuf = Buf::from_bytes(data);
    let decoded = unmarshal(&mut rbuf).expect("unmarshal failed");
    assert_eq!(decoded.msg_type, msg_type);
    assert_eq!(decoded.tag, tag);
    decoded.msg
}

// ── 9P2000 Core ──

#[test]
fn test_version_round_trip() {
    let msg = Msg::Version { msize: 65536, version: "9P2000.N".to_string() };
    let decoded = round_trip(MsgType::Tversion, 1, msg);
    match decoded {
        Msg::Version { msize, version } => {
            assert_eq!(msize, 65536);
            assert_eq!(version, "9P2000.N");
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_attach_round_trip() {
    let msg = Msg::Attach { fid: 0, afid: NO_FID, uname: "user".into(), aname: "/export".into() };
    let decoded = round_trip(MsgType::Tattach, 2, msg);
    match decoded {
        Msg::Attach { fid, afid, uname, aname } => {
            assert_eq!(fid, 0);
            assert_eq!(afid, NO_FID);
            assert_eq!(uname, "user");
            assert_eq!(aname, "/export");
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_walk_round_trip() {
    let msg = Msg::Walk { fid: 0, newfid: 1, wnames: vec!["a".into(), "b".into(), "c".into()] };
    let decoded = round_trip(MsgType::Twalk, 3, msg);
    match decoded {
        Msg::Walk { fid, newfid, wnames } => {
            assert_eq!(fid, 0);
            assert_eq!(newfid, 1);
            assert_eq!(wnames, vec!["a", "b", "c"]);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_rwalk_round_trip() {
    let qids = vec![
        Qid { qtype: QT_DIR, version: 1, path: 100 },
        Qid { qtype: QT_FILE, version: 2, path: 200 },
    ];
    let decoded = round_trip(MsgType::Rwalk, 3, Msg::Rwalk { qids: qids.clone() });
    match decoded {
        Msg::Rwalk { qids: q } => {
            assert_eq!(q.len(), 2);
            assert_eq!(q[0].qtype, QT_DIR);
            assert_eq!(q[1].path, 200);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_read_write_round_trip() {
    let decoded = round_trip(MsgType::Tread, 4, Msg::Read { fid: 5, offset: 1024, count: 4096 });
    match decoded {
        Msg::Read { fid, offset, count } => {
            assert_eq!(fid, 5);
            assert_eq!(offset, 1024);
            assert_eq!(count, 4096);
        }
        _ => panic!("wrong variant"),
    }

    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let decoded = round_trip(MsgType::Rread, 4, Msg::Rread { data: data.clone() });
    match decoded {
        Msg::Rread { data: d } => assert_eq!(d, data),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_write_round_trip() {
    let data = b"hello world".to_vec();
    let decoded = round_trip(MsgType::Twrite, 5, Msg::Write {
        fid: 7, offset: 0, data: data.clone(),
    });
    match decoded {
        Msg::Write { fid, offset, data: d } => {
            assert_eq!(fid, 7);
            assert_eq!(offset, 0);
            assert_eq!(d, data);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_lerror_round_trip() {
    let decoded = round_trip(MsgType::Rlerror, 6, Msg::Lerror { ecode: 2 });
    match decoded {
        Msg::Lerror { ecode } => assert_eq!(ecode, 2),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_clunk_round_trip() {
    let decoded = round_trip(MsgType::Tclunk, 7, Msg::Clunk { fid: 42 });
    match decoded {
        Msg::Clunk { fid } => assert_eq!(fid, 42),
        _ => panic!("wrong variant"),
    }
}

// ── base messages ──

#[test]
fn test_lopen_round_trip() {
    let decoded = round_trip(MsgType::Tlopen, 10, Msg::Lopen { fid: 3, flags: 2 });
    match decoded {
        Msg::Lopen { fid, flags } => {
            assert_eq!(fid, 3);
            assert_eq!(flags, 2); // O_RDWR
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_getattr_round_trip() {
    let decoded = round_trip(MsgType::Tgetattr, 11, Msg::Getattr { fid: 1, mask: P9_GETATTR_ALL });
    match decoded {
        Msg::Getattr { fid, mask } => {
            assert_eq!(fid, 1);
            assert_eq!(mask, P9_GETATTR_ALL);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_mkdir_round_trip() {
    let decoded = round_trip(MsgType::Tmkdir, 12, Msg::Mkdir {
        dfid: 0, name: "testdir".into(), mode: 0o755, gid: 1000,
    });
    match decoded {
        Msg::Mkdir { dfid, name, mode, gid } => {
            assert_eq!(dfid, 0);
            assert_eq!(name, "testdir");
            assert_eq!(mode, 0o755);
            assert_eq!(gid, 1000);
        }
        _ => panic!("wrong variant"),
    }
}

// ── 9P2000.N Extensions ──

#[test]
fn test_caps_round_trip() {
    let caps = vec!["security.spiffe".into(), "perf.compound".into(), "fs.watch".into()];
    let decoded = round_trip(MsgType::Tcaps, 20, Msg::Caps { caps: caps.clone() });
    match decoded {
        Msg::Caps { caps: c } => assert_eq!(c, caps),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_session_round_trip() {
    let key = [1u8; 16];
    let decoded = round_trip(MsgType::Tsession, 21, Msg::Session {
        key, flags: SESSION_FIDS | SESSION_WATCHES,
    });
    match decoded {
        Msg::Session { key: k, flags } => {
            assert_eq!(k, key);
            assert_eq!(flags, SESSION_FIDS | SESSION_WATCHES);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_watch_round_trip() {
    let decoded = round_trip(MsgType::Twatch, 22, Msg::Watch {
        fid: 5, mask: WATCH_CREATE | WATCH_MODIFY, flags: WATCH_RECURSIVE,
    });
    match decoded {
        Msg::Watch { fid, mask, flags } => {
            assert_eq!(fid, 5);
            assert_eq!(mask, WATCH_CREATE | WATCH_MODIFY);
            assert_eq!(flags, WATCH_RECURSIVE);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_notify_round_trip() {
    let qid = Qid { qtype: QT_FILE, version: 42, path: 12345 };
    let decoded = round_trip(MsgType::Rnotify, NO_TAG, Msg::Notify {
        watch_id: 7, event: WATCH_MODIFY, name: "file.txt".into(), qid: qid.clone(),
    });
    match decoded {
        Msg::Notify { watch_id, event, name, qid: q } => {
            assert_eq!(watch_id, 7);
            assert_eq!(event, WATCH_MODIFY);
            assert_eq!(name, "file.txt");
            assert_eq!(q, qid);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_spiffe_verify_round_trip() {
    let svid = b"fake-cert-data".to_vec();
    let decoded = round_trip(MsgType::Tspiffeverify, 30, Msg::Spiffeverify {
        svid_type: SVID_X509, spiffe_id: "spiffe://example.com/app".into(), svid: svid.clone(),
    });
    match decoded {
        Msg::Spiffeverify { svid_type, spiffe_id, svid: s } => {
            assert_eq!(svid_type, SVID_X509);
            assert_eq!(spiffe_id, "spiffe://example.com/app");
            assert_eq!(s, svid);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn test_capgrant_round_trip() {
    let decoded = round_trip(MsgType::Tcapgrant, 31, Msg::Capgrant {
        fid: 10, rights: 0xFF, expiry: 1712345678, depth: 20,
    });
    match decoded {
        Msg::Capgrant { fid, rights, expiry, depth } => {
            assert_eq!(fid, 10);
            assert_eq!(rights, 0xFF);
            assert_eq!(expiry, 1712345678);
            assert_eq!(depth, 20);
        }
        _ => panic!("wrong variant"),
    }
}

// ── Tag and Buf ──

#[test]
fn test_tag_allocator() {
    let alloc = p9n_proto::tag::TagAllocator::new();
    let mut tags = Vec::new();
    for _ in 0..100 {
        tags.push(alloc.alloc_raw().expect("alloc failed"));
    }
    // All tags should be unique
    let mut sorted = tags.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 100);

    // Free and realloc
    alloc.free(tags[0]);
    let reused = alloc.alloc_raw().expect("alloc failed");
    assert_eq!(reused, tags[0]);
}

#[test]
fn test_tag_guard_raii() {
    let alloc = p9n_proto::tag::TagAllocator::new();
    let tag_val;
    {
        let guard = alloc.alloc_guard().expect("alloc failed");
        tag_val = guard.tag();
        // guard drops here
    }
    // Tag should be free now
    let realloc = alloc.alloc_raw().expect("alloc failed");
    assert_eq!(realloc, tag_val);
}

#[test]
fn test_tag_guard_consume() {
    let alloc = p9n_proto::tag::TagAllocator::new();
    let guard = alloc.alloc_guard().expect("alloc failed");
    let tag_val = guard.consume(); // does NOT free
    // Tag should still be occupied
    // Alloc next should get a different tag
    let next = alloc.alloc_raw().expect("alloc failed");
    assert_ne!(next, tag_val);
    alloc.free(tag_val); // manual free
}

#[test]
fn test_buf_zero_copy() {
    let mut buf = Buf::new(64);
    buf.put_u32(0x12345678);
    buf.put_str("hello");
    let vec = buf.into_vec(); // zero-copy
    assert_eq!(vec[0..4], 0x12345678u32.to_le_bytes());
    assert_eq!(vec[4..6], 5u16.to_le_bytes()); // string length
    assert_eq!(&vec[6..11], b"hello");
}

// ── Classify ──

#[test]
fn test_message_classification() {
    use p9n_proto::classify::{classify, MessageClass};

    // Metadata
    assert_eq!(classify(MsgType::Tversion), MessageClass::Metadata);
    assert_eq!(classify(MsgType::Tcaps), MessageClass::Metadata);
    assert_eq!(classify(MsgType::Tsession), MessageClass::Metadata);
    assert_eq!(classify(MsgType::Thealth), MessageClass::Metadata);
    assert_eq!(classify(MsgType::Tflush), MessageClass::Metadata);
    assert_eq!(classify(MsgType::Rerror), MessageClass::Metadata);

    // Data
    assert_eq!(classify(MsgType::Twalk), MessageClass::Data);
    assert_eq!(classify(MsgType::Tread), MessageClass::Data);
    assert_eq!(classify(MsgType::Twrite), MessageClass::Data);
    assert_eq!(classify(MsgType::Tgetattr), MessageClass::Data);
    assert_eq!(classify(MsgType::Treaddir), MessageClass::Data);

    // Push
    assert_eq!(classify(MsgType::Rnotify), MessageClass::Push);
    assert_eq!(classify(MsgType::Rleasebreak), MessageClass::Push);
    assert_eq!(classify(MsgType::Rstreamdata), MessageClass::Push);

    // Reserved
    assert_eq!(classify(MsgType::Tnotify), MessageClass::Metadata);
}

// ── CapSet ──

#[test]
fn test_capset() {
    use p9n_proto::caps::{CapSet, intersect};

    let mut client = CapSet::new();
    client.add(CAP_SPIFFE);
    client.add(CAP_WATCH);
    client.add(CAP_SESSION);
    client.add("custom.feature");

    let mut server = CapSet::new();
    server.add(CAP_SPIFFE);
    server.add(CAP_COMPOUND);
    server.add(CAP_SESSION);

    let result = intersect(&client, &server);
    assert!(result.has(CAP_SPIFFE));
    assert!(result.has(CAP_SESSION));
    assert!(!result.has(CAP_WATCH));
    assert!(!result.has(CAP_COMPOUND));
    assert!(!result.has("custom.feature"));
    assert_eq!(result.count(), 2);
}
