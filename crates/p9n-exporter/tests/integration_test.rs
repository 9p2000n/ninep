//! Integration tests: exporter ↔ direct QUIC client over loopback.
//!
//! Tests the full exporter stack without needing fuse3 or p9n-importer.
//! Uses rcgen for self-signed certs, tempfile for export dirs.

use p9n_proto::buf::Buf;
use p9n_proto::codec;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use std::sync::Arc;

// ── Test Helpers ──

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn generate_test_certs() -> (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    ensure_crypto_provider();
    use rcgen::{CertificateParams, KeyPair, SanType};
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.subject_alt_names.push(SanType::URI(
        "spiffe://test.local/exporter".try_into().unwrap(),
    ));
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (
        vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            key_pair.serialize_der(),
        )),
    )
}

async fn start_exporter(
    export_path: &str,
) -> (
    std::net::SocketAddr,
    Vec<rustls::pki_types::CertificateDer<'static>>,
) {
    start_exporter_with_config(export_path, p9n_exporter::config::ExporterConfig::default()).await
}

async fn start_exporter_with_config(
    export_path: &str,
    config: p9n_exporter::config::ExporterConfig,
) -> (
    std::net::SocketAddr,
    Vec<rustls::pki_types::CertificateDer<'static>>,
) {
    let (certs, key) = generate_test_certs();
    let certs_clone = certs.clone();

    let server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();

    let quic_server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
    ));

    let endpoint = quinn::Endpoint::server(quic_server, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();

    let export = export_path.to_string();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let export = export.clone();
            let config = config.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let ctx = Arc::new(p9n_exporter::shared::SharedCtx {
                    backend: p9n_exporter::backend::local::LocalBackend::new(export.clone())
                        .unwrap(),
                    access: p9n_exporter::access::AccessControl::new(export.into()),
                    session_store: p9n_exporter::session_store::SessionStore::new(
                        std::time::Duration::from_secs(60),
                    ),
                    watch_mgr: p9n_exporter::watch_manager::WatchManager::new().unwrap(),
                    lease_mgr: p9n_exporter::lease_manager::LeaseManager::new(),
                    trust_store: p9n_auth::spiffe::trust_bundle::TrustBundleStore::new(),
                    server_spiffe_id: "spiffe://test.local/exporter".into(),
                    server_trust_domain: "test.local".into(),
                    cap_signing_key: [0x42; 32],
                    config,
                });
                let mut handler = p9n_exporter::quic_connection::QuicConnectionHandler::new(conn, ctx);
                let _ = handler.run().await;
            });
        }
    });

    (addr, certs_clone)
}

/// Simple RPC: send a Fcall on a QUIC stream and read the response.
async fn rpc(
    conn: &quinn::Connection,
    msg_type: MsgType,
    tag: u16,
    msg: Msg,
) -> Result<Fcall, Box<dyn std::error::Error + Send + Sync>> {
    let fc = Fcall { size: 0, msg_type, tag, msg };
    let mut buf = Buf::new(256);
    codec::marshal(&mut buf, &fc)?;
    let wire = buf.into_vec();

    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&wire).await?;
    send.finish()?;

    // Read response
    let mut size_buf = [0u8; 4];
    recv.read_exact(&mut size_buf).await?;
    let size = u32::from_le_bytes(size_buf) as usize;
    let mut msg_buf = vec![0u8; size];
    msg_buf[..4].copy_from_slice(&size_buf);
    recv.read_exact(&mut msg_buf[4..]).await?;

    let mut rbuf = Buf::from_bytes(msg_buf);
    let response = codec::unmarshal(&mut rbuf)?;

    // Check for error
    match &response.msg {
        Msg::Lerror { ecode } => Err(format!("9P error: errno={ecode}").into()),
        _ => Ok(response),
    }
}

async fn connect(
    addr: std::net::SocketAddr,
    certs: &[rustls::pki_types::CertificateDer<'static>],
) -> quinn::Connection {
    let mut root_store = rustls::RootCertStore::empty();
    for c in certs {
        let _ = root_store.add(c.clone());
    }
    let client_tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let mut cc = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
    ));
    let mut tc = quinn::TransportConfig::default();
    tc.datagram_receive_buffer_size(Some(65536));
    cc.transport_config(Arc::new(tc));

    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(cc);
    ep.connect(addr, "localhost").unwrap().await.unwrap()
}

async fn setup(
    export_path: &str,
) -> (
    quinn::Connection,
    Vec<rustls::pki_types::CertificateDer<'static>>,
) {
    let (addr, certs) = start_exporter(export_path).await;
    let conn = connect(addr, &certs).await;

    // Version
    let r = rpc(&conn, MsgType::Tversion, 0, Msg::Version {
        msize: 65536, version: VERSION_9P2000_N.into(),
    }).await.unwrap();
    assert!(matches!(r.msg, Msg::Version { .. }));

    // Attach
    let r = rpc(&conn, MsgType::Tattach, 1, Msg::Attach {
        fid: 0, afid: NO_FID, uname: "test".into(), aname: "".into(),
    }).await.unwrap();
    assert!(matches!(r.msg, Msg::Rattach { .. }));

    (conn, certs)
}

// ═══════════════════ Tests ═══════════════════

#[tokio::test]
async fn test_version_negotiation() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, certs) = start_exporter(dir.path().to_str().unwrap()).await;
    let conn = connect(addr, &certs).await;

    // 9P2000.N
    let r = rpc(&conn, MsgType::Tversion, 0, Msg::Version {
        msize: 65536, version: "9P2000.N".into(),
    }).await.unwrap();
    match r.msg {
        Msg::Version { msize, version } => {
            assert_eq!(version, "9P2000.N");
            assert!(msize <= 4 * 1024 * 1024);
        }
        _ => panic!("expected Version"),
    }

    // Non-9P2000.N version is rejected
    let r = rpc(&conn, MsgType::Tversion, 0, Msg::Version {
        msize: 8192, version: "9P2000.L".into(),
    }).await.unwrap();
    match r.msg {
        Msg::Version { version, .. } => assert_eq!(version, "unknown"),
        _ => panic!("expected Version"),
    }
}

#[tokio::test]
async fn test_walk_and_getattr() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.txt"), "content").unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    let r = rpc(&conn, MsgType::Twalk, 2, Msg::Walk {
        fid: 0, newfid: 1, wnames: vec!["test.txt".into()],
    }).await.unwrap();
    match &r.msg {
        Msg::Rwalk { qids } => {
            assert_eq!(qids.len(), 1);
            assert_eq!(qids[0].qtype, QT_FILE);
        }
        _ => panic!("expected Rwalk"),
    }

    let r = rpc(&conn, MsgType::Tgetattr, 3, Msg::Getattr {
        fid: 1, mask: P9_GETATTR_ALL,
    }).await.unwrap();
    match r.msg {
        Msg::Rgetattr { stat, .. } => assert_eq!(stat.size, 7),
        _ => panic!("expected Rgetattr"),
    }
}

#[tokio::test]
async fn test_read_file() {
    let dir = tempfile::tempdir().unwrap();
    let content = b"Hello, 9P2000.N!\n";
    std::fs::write(dir.path().join("hello.txt"), content).unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    rpc(&conn, MsgType::Twalk, 2, Msg::Walk {
        fid: 0, newfid: 1, wnames: vec!["hello.txt".into()],
    }).await.unwrap();
    rpc(&conn, MsgType::Tlopen, 3, Msg::Lopen { fid: 1, flags: 0 }).await.unwrap();

    let r = rpc(&conn, MsgType::Tread, 4, Msg::Read {
        fid: 1, offset: 0, count: 4096,
    }).await.unwrap();
    match r.msg {
        Msg::Rread { data } => assert_eq!(data, content.to_vec()),
        _ => panic!("expected Rread"),
    }

    // Read at offset
    let r = rpc(&conn, MsgType::Tread, 5, Msg::Read {
        fid: 1, offset: 7, count: 8,
    }).await.unwrap();
    match r.msg {
        Msg::Rread { data } => assert_eq!(data, b"9P2000.N"),
        _ => panic!("expected Rread"),
    }
}

#[tokio::test]
async fn test_write_file() {
    let dir = tempfile::tempdir().unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    rpc(&conn, MsgType::Tlcreate, 2, Msg::Lcreate {
        fid: 0, name: "new.txt".into(), flags: L_O_RDWR | L_O_CREAT, mode: 0o644, gid: 0,
    }).await.unwrap();

    let data = b"written by test".to_vec();
    let r = rpc(&conn, MsgType::Twrite, 3, Msg::Write {
        fid: 0, offset: 0, data: data.clone(),
    }).await.unwrap();
    match r.msg {
        Msg::Rwrite { count } => assert_eq!(count, data.len() as u32),
        _ => panic!("expected Rwrite"),
    }

    rpc(&conn, MsgType::Tclunk, 4, Msg::Clunk { fid: 0 }).await.unwrap();
    assert_eq!(std::fs::read(dir.path().join("new.txt")).unwrap(), b"written by test");
}

#[tokio::test]
async fn test_mkdir_and_readdir() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "a").unwrap();
    std::fs::write(dir.path().join("b.txt"), "b").unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    rpc(&conn, MsgType::Tmkdir, 2, Msg::Mkdir {
        dfid: 0, name: "sub".into(), mode: 0o755, gid: 0,
    }).await.unwrap();
    assert!(dir.path().join("sub").is_dir());

    // Clone fid, open, readdir
    rpc(&conn, MsgType::Twalk, 3, Msg::Walk { fid: 0, newfid: 10, wnames: vec![] }).await.unwrap();
    rpc(&conn, MsgType::Tlopen, 4, Msg::Lopen { fid: 10, flags: L_O_RDONLY }).await.unwrap();
    let r = rpc(&conn, MsgType::Treaddir, 5, Msg::Readdir {
        fid: 10, offset: 0, count: 65536,
    }).await.unwrap();

    match r.msg {
        Msg::Rreaddir { data } => {
            let names = extract_names(&data);
            assert!(names.contains(&"a.txt".into()), "missing a.txt in {names:?}");
            assert!(names.contains(&"b.txt".into()), "missing b.txt in {names:?}");
            assert!(names.contains(&"sub".into()), "missing sub in {names:?}");
        }
        _ => panic!("expected Rreaddir"),
    }
}

#[tokio::test]
async fn test_unlink_and_rename() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("del.txt"), "gone").unwrap();
    std::fs::write(dir.path().join("old.txt"), "move").unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    rpc(&conn, MsgType::Tunlinkat, 2, Msg::Unlinkat {
        dirfid: 0, name: "del.txt".into(), flags: 0,
    }).await.unwrap();
    assert!(!dir.path().join("del.txt").exists());

    rpc(&conn, MsgType::Trenameat, 3, Msg::Renameat {
        olddirfid: 0, oldname: "old.txt".into(), newdirfid: 0, newname: "new.txt".into(),
    }).await.unwrap();
    assert!(!dir.path().join("old.txt").exists());
    assert_eq!(std::fs::read(dir.path().join("new.txt")).unwrap(), b"move");
}

#[tokio::test]
async fn test_walk_nonexistent() {
    let dir = tempfile::tempdir().unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    let r = rpc(&conn, MsgType::Twalk, 2, Msg::Walk {
        fid: 0, newfid: 1, wnames: vec!["nonexistent".into()],
    }).await;
    assert!(r.is_err());
}

#[tokio::test]
async fn test_statfs() {
    let dir = tempfile::tempdir().unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    let r = rpc(&conn, MsgType::Tstatfs, 2, Msg::Statfs { fid: 0 }).await.unwrap();
    match r.msg {
        Msg::Rstatfs { stat } => {
            assert!(stat.blocks > 0);
            assert!(stat.bsize > 0);
        }
        _ => panic!("expected Rstatfs"),
    }
}

#[tokio::test]
async fn test_concurrent_reads() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..5 {
        std::fs::write(dir.path().join(format!("f{i}.txt")), format!("data{i}")).unwrap();
    }
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;
    let conn = Arc::new(conn);

    let mut handles = Vec::new();
    for i in 0..5u32 {
        let conn = conn.clone();
        handles.push(tokio::spawn(async move {
            let fid = 10 + i;
            let tag_base = (i * 10 + 100) as u16;
            rpc(&conn, MsgType::Twalk, tag_base, Msg::Walk {
                fid: 0, newfid: fid, wnames: vec![format!("f{i}.txt")],
            }).await.unwrap();
            rpc(&conn, MsgType::Tlopen, tag_base + 1, Msg::Lopen { fid, flags: 0 }).await.unwrap();
            let r = rpc(&conn, MsgType::Tread, tag_base + 2, Msg::Read {
                fid, offset: 0, count: 4096,
            }).await.unwrap();
            match r.msg {
                Msg::Rread { data } => assert_eq!(data, format!("data{i}").into_bytes()),
                _ => panic!("concurrent read {i} failed"),
            }
            rpc(&conn, MsgType::Tclunk, tag_base + 3, Msg::Clunk { fid }).await.unwrap();
        }));
    }
    for h in handles { h.await.unwrap(); }
}

// ═══════════════════ New Tests ═══════════════════

#[tokio::test]
async fn test_symlink_and_readlink() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("target.txt"), "real").unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // Create symlink with relative target path
    let r = rpc(&conn, MsgType::Tsymlink, 2, Msg::Symlink {
        fid: 0, name: "link.txt".into(),
        symtgt: "target.txt".to_string(), gid: 0,
    }).await.unwrap();
    assert!(matches!(r.msg, Msg::Rsymlink { .. }));
    assert!(dir.path().join("link.txt").is_symlink());

    // Walk to symlink — should give a fid for the symlink itself, not the target
    rpc(&conn, MsgType::Twalk, 3, Msg::Walk {
        fid: 0, newfid: 2, wnames: vec!["link.txt".into()],
    }).await.unwrap();

    // Readlink
    let r = rpc(&conn, MsgType::Treadlink, 4, Msg::Readlink { fid: 2 }).await.unwrap();
    match r.msg {
        Msg::Rreadlink { target } => {
            assert_eq!(target, "target.txt", "readlink should return symlink target");
        }
        _ => panic!("expected Rreadlink"),
    }
}

#[tokio::test]
async fn test_remove() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("victim.txt"), "data").unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // Walk to file
    rpc(&conn, MsgType::Twalk, 2, Msg::Walk {
        fid: 0, newfid: 1, wnames: vec!["victim.txt".into()],
    }).await.unwrap();

    // Tremove: removes file AND clunks fid
    let r = rpc(&conn, MsgType::Tremove, 3, Msg::Remove { fid: 1 }).await.unwrap();
    assert!(matches!(r.msg, Msg::Empty));
    assert!(!dir.path().join("victim.txt").exists());

    // fid should be clunked — using it again should fail
    let r = rpc(&conn, MsgType::Tgetattr, 4, Msg::Getattr { fid: 1, mask: P9_GETATTR_ALL }).await;
    assert!(r.is_err(), "fid should be clunked after Tremove");
}

#[tokio::test]
async fn test_session_zero_key_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // Zero key should be rejected
    let r = rpc(&conn, MsgType::Tsession, 2, Msg::Session {
        key: [0u8; 16], flags: SESSION_FIDS,
    }).await;
    assert!(r.is_err(), "zero session key should be rejected");
}

#[tokio::test]
async fn test_session_duplicate_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // First Tsession should succeed
    let r = rpc(&conn, MsgType::Tsession, 2, Msg::Session {
        key: [0x42u8; 16], flags: SESSION_FIDS,
    }).await.unwrap();
    assert!(matches!(r.msg, Msg::Rsession { .. }));

    // Second Tsession on same connection should fail
    let r = rpc(&conn, MsgType::Tsession, 3, Msg::Session {
        key: [0x99u8; 16], flags: SESSION_FIDS,
    }).await;
    assert!(r.is_err(), "duplicate Tsession should be rejected");
}

#[tokio::test]
async fn test_caps_negotiation() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, certs) = start_exporter(dir.path().to_str().unwrap()).await;
    let conn = connect(addr, &certs).await;

    rpc(&conn, MsgType::Tversion, 0, Msg::Version {
        msize: 65536, version: VERSION_9P2000_N.into(),
    }).await.unwrap();

    // Negotiate caps
    let r = rpc(&conn, MsgType::Tcaps, 1, Msg::Caps {
        caps: vec![
            CAP_SPIFFE.into(), CAP_WATCH.into(), CAP_SESSION.into(),
            "nonexistent.feature".into(),
        ],
    }).await.unwrap();

    match r.msg {
        Msg::Caps { caps } => {
            assert!(caps.contains(&CAP_SPIFFE.to_string()));
            assert!(caps.contains(&CAP_SESSION.to_string()));
            assert!(caps.contains(&CAP_WATCH.to_string()));
            assert!(!caps.contains(&"nonexistent.feature".to_string()),
                "unknown caps should be filtered out");
        }
        _ => panic!("expected Rcaps"),
    }
}

#[tokio::test]
async fn test_compound_walk_getattr() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("comp.txt"), "compound").unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // Build compound: walk + getattr
    use p9n_proto::wire::SubOp;

    // SubOp 1: Twalk { fid:0, newfid:5, wnames:["comp.txt"] }
    let walk_fc = Fcall { size: 0, msg_type: MsgType::Twalk, tag: 0,
        msg: Msg::Walk { fid: 0, newfid: 5, wnames: vec!["comp.txt".into()] } };
    let mut walk_buf = Buf::new(64);
    codec::marshal(&mut walk_buf, &walk_fc).unwrap();
    let walk_wire = walk_buf.into_vec();
    let walk_payload = walk_wire[HEADER_SIZE..].to_vec();

    // SubOp 2: Tgetattr { fid:5, mask:ALL }
    let attr_fc = Fcall { size: 0, msg_type: MsgType::Tgetattr, tag: 0,
        msg: Msg::Getattr { fid: 5, mask: P9_GETATTR_ALL } };
    let mut attr_buf = Buf::new(64);
    codec::marshal(&mut attr_buf, &attr_fc).unwrap();
    let attr_wire = attr_buf.into_vec();
    let attr_payload = attr_wire[HEADER_SIZE..].to_vec();

    let r = rpc(&conn, MsgType::Tcompound, 2, Msg::Compound {
        ops: vec![
            SubOp { msg_type: MsgType::Twalk, payload: walk_payload },
            SubOp { msg_type: MsgType::Tgetattr, payload: attr_payload },
        ],
    }).await.unwrap();

    match r.msg {
        Msg::Rcompound { results } => {
            assert_eq!(results.len(), 2, "compound should return 2 results");
        }
        _ => panic!("expected Rcompound"),
    }
}

#[tokio::test]
async fn test_hash_blake3() {
    let dir = tempfile::tempdir().unwrap();
    let content = b"hash me please";
    std::fs::write(dir.path().join("hashme.txt"), content).unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // Walk + open
    rpc(&conn, MsgType::Twalk, 2, Msg::Walk {
        fid: 0, newfid: 1, wnames: vec!["hashme.txt".into()],
    }).await.unwrap();
    rpc(&conn, MsgType::Tlopen, 3, Msg::Lopen { fid: 1, flags: 0 }).await.unwrap();

    // Hash
    let r = rpc(&conn, MsgType::Thash, 4, Msg::Hash {
        fid: 1, algo: HASH_BLAKE3, offset: 0, length: 0,
    }).await.unwrap();

    match r.msg {
        Msg::Rhash { algo, hash } => {
            assert_eq!(algo, HASH_BLAKE3);
            assert_eq!(hash.len(), 32, "BLAKE3 hash should be 32 bytes");
            // Verify against known hash
            let expected = blake3::hash(content);
            assert_eq!(hash, expected.as_bytes().to_vec());
        }
        _ => panic!("expected Rhash"),
    }
}

// ═══════════════════ P3: Lease/Session/Stale-fid Tests ═══════════════════

#[tokio::test]
async fn test_lease_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("leased.txt"), "data").unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // Walk to file
    rpc(&conn, MsgType::Twalk, 2, Msg::Walk {
        fid: 0, newfid: 1, wnames: vec!["leased.txt".into()],
    }).await.unwrap();

    // Grant lease
    let r = rpc(&conn, MsgType::Tlease, 3, Msg::Lease {
        fid: 1, lease_type: 1, duration: 60,
    }).await.unwrap();
    let lease_id = match r.msg {
        Msg::Rlease { lease_id, lease_type, duration } => {
            assert_eq!(lease_type, 1);
            assert!(duration <= 300);
            lease_id
        }
        _ => panic!("expected Rlease"),
    };

    // Renew lease
    let r = rpc(&conn, MsgType::Tleaserenew, 4, Msg::Leaserenew {
        lease_id, duration: 120,
    }).await.unwrap();
    match r.msg {
        Msg::Rleaserenew { duration } => assert!(duration <= 300),
        _ => panic!("expected Rleaserenew"),
    }

    // Renew nonexistent lease should fail
    let r = rpc(&conn, MsgType::Tleaserenew, 5, Msg::Leaserenew {
        lease_id: 99999, duration: 60,
    }).await;
    assert!(r.is_err(), "renewing nonexistent lease should fail");

    // Ack (release) lease
    let r = rpc(&conn, MsgType::Tleaseack, 6, Msg::Leaseack { lease_id }).await.unwrap();
    assert!(matches!(r.msg, Msg::Empty));
}

#[tokio::test]
async fn test_stale_fid_rejected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), "data").unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // Walk to file
    rpc(&conn, MsgType::Twalk, 2, Msg::Walk {
        fid: 0, newfid: 1, wnames: vec!["file.txt".into()],
    }).await.unwrap();

    // Clunk fid 1
    rpc(&conn, MsgType::Tclunk, 3, Msg::Clunk { fid: 1 }).await.unwrap();

    // Using stale fid should fail
    let r = rpc(&conn, MsgType::Tgetattr, 4, Msg::Getattr {
        fid: 1, mask: P9_GETATTR_ALL,
    }).await;
    assert!(r.is_err(), "stale fid should be rejected");
}

#[tokio::test]
async fn test_consistency_invalid_level() {
    let dir = tempfile::tempdir().unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // Valid level
    let r = rpc(&conn, MsgType::Tconsistency, 2, Msg::Consistency {
        fid: 0, level: 2,
    }).await.unwrap();
    match r.msg {
        Msg::Rconsistency { level } => assert_eq!(level, 3), // single node = linearizable
        _ => panic!("expected Rconsistency"),
    }

    // Invalid level (>3) should fail
    let r = rpc(&conn, MsgType::Tconsistency, 3, Msg::Consistency {
        fid: 0, level: 99,
    }).await;
    assert!(r.is_err(), "level > 3 should be rejected");
}

#[tokio::test]
async fn test_serverstats() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "a").unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // Walk to create a fid
    rpc(&conn, MsgType::Twalk, 2, Msg::Walk {
        fid: 0, newfid: 1, wnames: vec!["a.txt".into()],
    }).await.unwrap();

    let r = rpc(&conn, MsgType::Tserverstats, 3, Msg::ServerstatsReq { mask: 0 })
        .await.unwrap();
    match r.msg {
        Msg::Rserverstats { stats } => {
            assert!(stats.len() >= 3, "should have at least 3 stats, got {}", stats.len());
            let names: Vec<&str> = stats.iter().map(|s| s.name.as_str()).collect();
            assert!(names.contains(&"uptime_sec"), "missing uptime: {names:?}");
            assert!(names.contains(&"fids_open"), "missing fids_open: {names:?}");

            // Check fids_open reflects our 2 fids (root + a.txt)
            let fids_stat = stats.iter().find(|s| s.name == "fids_open").unwrap();
            assert!(fids_stat.value >= 2, "should have at least 2 fids open");
        }
        _ => panic!("expected Rserverstats"),
    }
}

#[tokio::test]
async fn test_lock_and_getlock() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("lockme.txt"), "data").unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // Walk + open
    rpc(&conn, MsgType::Twalk, 2, Msg::Walk {
        fid: 0, newfid: 1, wnames: vec!["lockme.txt".into()],
    }).await.unwrap();
    rpc(&conn, MsgType::Tlopen, 3, Msg::Lopen { fid: 1, flags: 2 }).await.unwrap(); // O_RDWR

    // Lock (non-blocking write lock)
    let r = rpc(&conn, MsgType::Tlock, 4, Msg::Lock {
        fid: 1, lock_type: 1, flags: 0, start: 0, length: 0, proc_id: 1, client_id: "test".into(),
    }).await.unwrap();
    match r.msg {
        Msg::Rlock { status } => assert_eq!(status, P9_LOCK_SUCCESS),
        _ => panic!("expected Rlock"),
    }

    // Getlock should show no conflicting lock (our own lock)
    let r = rpc(&conn, MsgType::Tgetlock, 5, Msg::GetlockReq {
        fid: 1, lock_type: 1, start: 0, length: 0, proc_id: 1, client_id: "test".into(),
    }).await.unwrap();
    assert!(matches!(r.msg, Msg::RgetlockResp { .. }));

    // Unlock
    let r = rpc(&conn, MsgType::Tlock, 6, Msg::Lock {
        fid: 1, lock_type: 2, flags: 0, start: 0, length: 0, proc_id: 1, client_id: "test".into(),
    }).await.unwrap();
    match r.msg {
        Msg::Rlock { status } => assert_eq!(status, P9_LOCK_SUCCESS),
        _ => panic!("expected Rlock unlock"),
    }
}

#[tokio::test]
async fn test_stream_write() {
    let dir = tempfile::tempdir().unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // Create and open a file for writing
    rpc(&conn, MsgType::Tlcreate, 2, Msg::Lcreate {
        fid: 0, name: "streamed.txt".into(), flags: L_O_RDWR | L_O_CREAT, mode: 0o644, gid: 0,
    }).await.unwrap();

    // Open a write stream on the file (direction=1 is write, offset=0)
    let r = rpc(&conn, MsgType::Tstreamopen, 3, Msg::Streamopen {
        fid: 0, direction: 1, offset: 0, count: 0,
    }).await.unwrap();
    let stream_id = match r.msg {
        Msg::Rstreamopen { stream_id } => stream_id,
        _ => panic!("expected Rstreamopen"),
    };

    // Write three chunks sequentially
    for (seq, chunk) in ["Hello, ", "streaming ", "world!"].iter().enumerate() {
        let r = rpc(&conn, MsgType::Tstreamdata, 10 + seq as u16, Msg::Streamdata {
            stream_id, seq: seq as u32, data: chunk.as_bytes().to_vec(),
        }).await.unwrap();
        match r.msg {
            Msg::Streamdata { stream_id: sid, seq: s, data } => {
                assert_eq!(sid, stream_id);
                assert_eq!(s, seq as u32);
                assert!(data.is_empty(), "write ack should have empty data");
            }
            _ => panic!("expected Rstreamdata"),
        }
    }

    // Close the stream (triggers fsync for write streams)
    let r = rpc(&conn, MsgType::Tstreamclose, 20, Msg::Streamclose { stream_id }).await.unwrap();
    assert!(matches!(r.msg, Msg::Empty));

    // Verify file contents
    rpc(&conn, MsgType::Tclunk, 21, Msg::Clunk { fid: 0 }).await.unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("streamed.txt")).unwrap(),
        b"Hello, streaming world!"
    );
}

#[tokio::test]
async fn test_stream_read() {
    let dir = tempfile::tempdir().unwrap();
    let content = b"Read me in a stream";
    std::fs::write(dir.path().join("readable.txt"), content).unwrap();
    let (conn, _) = setup(dir.path().to_str().unwrap()).await;

    // Walk + open
    rpc(&conn, MsgType::Twalk, 2, Msg::Walk {
        fid: 0, newfid: 1, wnames: vec!["readable.txt".into()],
    }).await.unwrap();
    rpc(&conn, MsgType::Tlopen, 3, Msg::Lopen { fid: 1, flags: 0 }).await.unwrap();

    // Open a read stream (direction=0 is read, offset=0)
    let r = rpc(&conn, MsgType::Tstreamopen, 4, Msg::Streamopen {
        fid: 1, direction: 0, offset: 0, count: 0,
    }).await.unwrap();
    let stream_id = match r.msg {
        Msg::Rstreamopen { stream_id } => stream_id,
        _ => panic!("expected Rstreamopen"),
    };

    // Read first chunk
    let r = rpc(&conn, MsgType::Tstreamdata, 5, Msg::Streamdata {
        stream_id, seq: 0, data: Vec::new(),
    }).await.unwrap();
    let data = match r.msg {
        Msg::Streamdata { data, .. } => data,
        _ => panic!("expected Rstreamdata"),
    };
    assert_eq!(data, content.to_vec());

    // Second read should return empty (EOF)
    let r = rpc(&conn, MsgType::Tstreamdata, 6, Msg::Streamdata {
        stream_id, seq: 1, data: Vec::new(),
    }).await.unwrap();
    match r.msg {
        Msg::Streamdata { data, .. } => assert!(data.is_empty(), "should be EOF"),
        _ => panic!("expected Rstreamdata"),
    }

    // Close stream
    rpc(&conn, MsgType::Tstreamclose, 7, Msg::Streamclose { stream_id }).await.unwrap();
}

#[tokio::test]
async fn test_rate_limit_throttles_reads() {
    let dir = tempfile::tempdir().unwrap();
    let content = vec![0xAAu8; 1024];
    std::fs::write(dir.path().join("data.bin"), &content).unwrap();

    // Start exporter with rate limiting enabled: 10 IOPS, unlimited BPS.
    let mut config = p9n_exporter::config::ExporterConfig::default();
    config.enable_rate_limit = true;
    let (addr, certs) = start_exporter_with_config(
        dir.path().to_str().unwrap(), config,
    ).await;
    let conn = connect(addr, &certs).await;

    // Version + Attach
    rpc(&conn, MsgType::Tversion, 0, Msg::Version {
        msize: 65536, version: VERSION_9P2000_N.into(),
    }).await.unwrap();
    rpc(&conn, MsgType::Tattach, 1, Msg::Attach {
        fid: 0, afid: NO_FID, uname: "test".into(), aname: "".into(),
    }).await.unwrap();

    // Walk + open
    rpc(&conn, MsgType::Twalk, 2, Msg::Walk {
        fid: 0, newfid: 1, wnames: vec!["data.bin".into()],
    }).await.unwrap();
    rpc(&conn, MsgType::Tlopen, 3, Msg::Lopen { fid: 1, flags: 0 }).await.unwrap();

    // Set rate limit: 10 IOPS on fid 1
    let r = rpc(&conn, MsgType::Tratelimit, 4, Msg::Ratelimit {
        fid: 1, iops: 10, bps: 0,
    }).await.unwrap();
    match r.msg {
        Msg::Rratelimit { iops, .. } => assert_eq!(iops, 10),
        _ => panic!("expected Rratelimit"),
    }

    // First read should succeed immediately (bucket starts full).
    let start = std::time::Instant::now();
    let r = rpc(&conn, MsgType::Tread, 5, Msg::Read {
        fid: 1, offset: 0, count: 1024,
    }).await.unwrap();
    match r.msg {
        Msg::Rread { data } => assert_eq!(data.len(), 1024),
        _ => panic!("expected Rread"),
    }
    let first_elapsed = start.elapsed();

    // Drain the IOPS bucket: 9 more rapid reads (bucket had 10 tokens).
    for i in 0..9u16 {
        rpc(&conn, MsgType::Tread, 10 + i, Msg::Read {
            fid: 1, offset: 0, count: 64,
        }).await.unwrap();
    }

    // 11th read should be delayed (~100ms at 10 IOPS).
    let before = std::time::Instant::now();
    rpc(&conn, MsgType::Tread, 30, Msg::Read {
        fid: 1, offset: 0, count: 64,
    }).await.unwrap();
    let delay = before.elapsed();

    assert!(
        delay >= std::time::Duration::from_millis(50),
        "11th read should be throttled, but completed in {delay:?}"
    );
    // First read should have been fast (no throttling).
    assert!(
        first_elapsed < std::time::Duration::from_millis(50),
        "first read should be fast, but took {first_elapsed:?}"
    );
}

fn extract_names(data: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if pos + 24 > data.len() { break; }
        pos += 13 + 8 + 1; // qid + offset + dtype
        if pos + 2 > data.len() { break; }
        let nl = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + nl > data.len() { break; }
        names.push(String::from_utf8_lossy(&data[pos..pos + nl]).into());
        pos += nl;
    }
    names
}
