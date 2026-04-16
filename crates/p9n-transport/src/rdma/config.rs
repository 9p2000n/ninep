//! RDMA connection establishment via TCP+TLS bootstrap.
//!
//! The authentication flow:
//! 1. TCP connect to exporter's RDMA listen address
//! 2. TLS handshake (SPIFFE mTLS, same as TCP transport)
//! 3. Exchange RDMA QP parameters over TLS stream
//! 4. Derive session key via `export_keying_material()`
//! 5. Create QP and transition to RTR/RTS
//! 6. Close TCP connection; all data flows over RDMA verbs

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::debug;

use super::mr_pool::MrPool;
use super::verbs::{
    CompletionChannel, CompletionQueue, ProtectionDomain, QpEndpoint, QueuePair,
    RdmaContext,
};
use crate::error::TransportError;

/// Default RDMA parameters.
pub const DEFAULT_MAX_SEND_WR: u32 = 128;
pub const DEFAULT_MAX_RECV_WR: u32 = 128;
pub const DEFAULT_MAX_SGE: u32 = 1;
pub const DEFAULT_CQ_SIZE: i32 = 256;
pub const DEFAULT_SLOT_SIZE: usize = 4 * 1024 * 1024; // 4 MB (matches 9P msize)
/// Send pool: 32 slots for concurrent sends.
pub const DEFAULT_SEND_POOL_COUNT: usize = 32;
/// Recv pool: 64 slots posted to the receive queue.
pub const DEFAULT_RECV_POOL_COUNT: usize = 64;
pub const DEFAULT_PORT: u8 = 1;
pub const DEFAULT_GID_INDEX: u8 = 0;

/// All RDMA resources for one connection.
pub struct RdmaConnection {
    pub ctx: Arc<RdmaContext>,
    pub pd: Arc<ProtectionDomain>,
    pub send_cq: Arc<CompletionQueue>,
    pub recv_cq: Arc<CompletionQueue>,
    pub qp: Arc<QueuePair>,
    /// Pre-registered send buffer pool. Each slot is `DEFAULT_SLOT_SIZE` bytes.
    pub send_pool: MrPool,
    /// Pre-registered recv buffer pool. Each slot is `DEFAULT_SLOT_SIZE` bytes.
    pub recv_pool: MrPool,
    pub local_endpoint: QpEndpoint,
    pub port: u8,
    pub gid_index: u8,
}

/// Serialize QP endpoint parameters for exchange over TLS.
fn encode_endpoint(ep: &QpEndpoint) -> [u8; 26] {
    let mut buf = [0u8; 26];
    buf[0..4].copy_from_slice(&ep.qp_num.to_le_bytes());
    buf[4..6].copy_from_slice(&ep.lid.to_le_bytes());
    buf[6..22].copy_from_slice(&ep.gid);
    buf[22..26].copy_from_slice(&ep.psn.to_le_bytes());
    buf
}

/// Deserialize QP endpoint parameters.
fn decode_endpoint(buf: &[u8; 26]) -> QpEndpoint {
    QpEndpoint {
        qp_num: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
        lid: u16::from_le_bytes(buf[4..6].try_into().unwrap()),
        gid: buf[6..22].try_into().unwrap(),
        psn: u32::from_le_bytes(buf[22..26].try_into().unwrap()),
    }
}

/// Server-side: create a TCP listener for RDMA bootstrap connections.
pub async fn server_listener(addr: SocketAddr) -> Result<TcpListener, TransportError> {
    TcpListener::bind(addr)
        .await
        .map_err(TransportError::Io)
}

/// Server-side: accept one RDMA connection.
///
/// Performs TLS handshake, exchanges QP parameters, sets up RDMA resources.
/// Returns the fully-connected `RdmaConnection` and the session key.
pub async fn accept(
    tcp_stream: TcpStream,
    tls_acceptor: &TlsAcceptor,
    device_name: Option<&str>,
) -> Result<(RdmaConnection, [u8; 16], Vec<Vec<u8>>), TransportError> {
    let peer = tcp_stream.peer_addr().map_err(TransportError::Io)?;
    debug!(?peer, "RDMA bootstrap: accepting TLS");

    let mut tls = tls_acceptor.accept(tcp_stream).await.map_err(|e| {
        TransportError::Rdma(format!("TLS accept failed: {e}"))
    })?;

    // Extract peer certificates and session key before the TLS stream
    // is consumed. The certificates are needed for SPIFFE ID extraction.
    let (session_key, peer_certs) = {
        let (_, server_conn) = tls.get_ref();
        let mut key = [0u8; 16];
        server_conn
            .export_keying_material(&mut key, b"9P2000.N-session", None)
            .map_err(|e| TransportError::Rdma(format!("export_keying_material: {e}")))?;
        let certs = server_conn
            .peer_certificates()
            .map(|c| c.iter().map(|d| d.to_vec()).collect::<Vec<_>>())
            .unwrap_or_default();
        (key, certs)
    };

    // Set up RDMA resources.
    let conn = setup_rdma_resources(device_name)?;

    // Send our QP endpoint to the client.
    let our_ep = encode_endpoint(&conn.local_endpoint);
    tls.write_all(&our_ep).await.map_err(TransportError::Io)?;

    // Read the client's QP endpoint.
    let mut their_ep_buf = [0u8; 26];
    tls.read_exact(&mut their_ep_buf).await.map_err(TransportError::Io)?;
    let remote = decode_endpoint(&their_ep_buf);

    // Transition QP: INIT → RTR → RTS.
    conn.qp.to_rtr(&remote, conn.port, conn.gid_index)?;
    conn.qp.to_rts(conn.local_endpoint.psn)?;

    // Pre-post receive buffers from the recv pool.
    for _ in 0..DEFAULT_RECV_POOL_COUNT {
        let slot = conn.recv_pool.checkout()
            .ok_or_else(|| TransportError::Rdma("recv pool exhausted on init".into()))?;
        slot.post_recv(&conn.qp)?;
        slot.leak(); // Leased to the QP; returned on CQ completion.
    }

    debug!(?peer, "RDMA connection established (server)");

    // TLS stream dropped here — TCP connection closes.
    Ok((conn, session_key, peer_certs))
}

/// Client-side: connect to an RDMA-enabled exporter.
///
/// Opens TCP, does TLS handshake, exchanges QP parameters.
pub async fn client_connect(
    addr: SocketAddr,
    tls_connector: &tokio_rustls::TlsConnector,
    server_name: rustls::pki_types::ServerName<'static>,
    device_name: Option<&str>,
) -> Result<(RdmaConnection, [u8; 16]), TransportError> {
    debug!(?addr, "RDMA bootstrap: connecting");

    let tcp = TcpStream::connect(addr).await.map_err(TransportError::Io)?;
    let mut tls = tls_connector.connect(server_name, tcp).await.map_err(|e| {
        TransportError::Rdma(format!("TLS connect failed: {e}"))
    })?;

    // Derive session key.
    let session_key = {
        let (_, client_conn) = tls.get_ref();
        let mut key = [0u8; 16];
        client_conn
            .export_keying_material(&mut key, b"9P2000.N-session", None)
            .map_err(|e| TransportError::Rdma(format!("export_keying_material: {e}")))?;
        key
    };

    // Set up RDMA resources.
    let conn = setup_rdma_resources(device_name)?;

    // Read server's QP endpoint.
    let mut their_ep_buf = [0u8; 26];
    tls.read_exact(&mut their_ep_buf).await.map_err(TransportError::Io)?;
    let remote = decode_endpoint(&their_ep_buf);

    // Send our QP endpoint to the server.
    let our_ep = encode_endpoint(&conn.local_endpoint);
    tls.write_all(&our_ep).await.map_err(TransportError::Io)?;

    // Transition QP: INIT → RTR → RTS.
    conn.qp.to_rtr(&remote, conn.port, conn.gid_index)?;
    conn.qp.to_rts(conn.local_endpoint.psn)?;

    // Pre-post receive buffers from the recv pool.
    for _ in 0..DEFAULT_RECV_POOL_COUNT {
        let slot = conn.recv_pool.checkout()
            .ok_or_else(|| TransportError::Rdma("recv pool exhausted on init".into()))?;
        slot.post_recv(&conn.qp)?;
        slot.leak(); // Leased to the QP; returned on CQ completion.
    }

    debug!(?addr, "RDMA connection established (client)");
    Ok((conn, session_key))
}

/// Common: allocate all RDMA resources for a connection.
fn setup_rdma_resources(device_name: Option<&str>) -> Result<RdmaConnection, TransportError> {
    let port = DEFAULT_PORT;
    let gid_index = DEFAULT_GID_INDEX;

    let ctx = Arc::new(RdmaContext::open(device_name)?);
    let pd = Arc::new(ProtectionDomain::new(ctx.clone())?);

    let send_cc = Arc::new(CompletionChannel::new(ctx.clone())?);
    let recv_cc = Arc::new(CompletionChannel::new(ctx.clone())?);
    let send_cq = Arc::new(CompletionQueue::new(&ctx, DEFAULT_CQ_SIZE, send_cc)?);
    let recv_cq = Arc::new(CompletionQueue::new(&ctx, DEFAULT_CQ_SIZE, recv_cc)?);

    let qp = Arc::new(QueuePair::new(
        pd.clone(),
        &send_cq,
        &recv_cq,
        DEFAULT_MAX_SEND_WR,
        DEFAULT_MAX_RECV_WR,
        DEFAULT_MAX_SGE,
        DEFAULT_MAX_SGE,
    )?);

    // Transition QP to INIT (must happen before RTR).
    qp.to_init(port)?;

    // Query local endpoint info.
    let port_attr = ctx.query_port(port)?;
    let gid = ctx.query_gid(port, gid_index as i32)?;
    let psn: u32 = rand_psn();

    let local_endpoint = QpEndpoint {
        qp_num: qp.qp_num(),
        lid: port_attr.lid,
        gid: unsafe { gid.raw },
        psn,
    };

    // Allocate send pool (single MR, multiple slots).
    let send_pool = MrPool::new(&pd, DEFAULT_SLOT_SIZE, DEFAULT_SEND_POOL_COUNT)?;

    // Allocate recv pool (single MR, multiple slots).
    let recv_pool = MrPool::new(&pd, DEFAULT_SLOT_SIZE, DEFAULT_RECV_POOL_COUNT)?;

    Ok(RdmaConnection {
        ctx,
        pd,
        send_cq,
        recv_cq,
        qp,
        send_pool,
        recv_pool,
        local_endpoint,
        port,
        gid_index,
    })
}

/// Generate a random 24-bit packet sequence number.
fn rand_psn() -> u32 {
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    t & 0xFFFFFF
}
