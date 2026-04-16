use crate::error::RpcError;
use crate::quic_rpc::QuicRpcClient;
use crate::tcp_rpc::TcpRpcClient;
#[cfg(feature = "rdma")]
use crate::rdma_rpc::RdmaRpcClient;
use p9n_proto::caps::CapSet;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use p9n_proto::wire::Qid;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tracing::Instrument;

/// Monotonic connection id — bumped on every successful (re)connect so that
/// logs from before/after a reconnect can be distinguished by `conn_id`.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a new connection id. Exposed so the reconnect wrapper uses the
/// same counter as the initial connect path.
pub fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

/// Unified RPC handle that delegates to QUIC, TCP+TLS, or RDMA transport.
pub enum RpcHandle {
    Quic(Arc<QuicRpcClient>),
    Tcp(Arc<TcpRpcClient<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>),
    #[cfg(feature = "rdma")]
    Rdma(Arc<RdmaRpcClient>),
}

impl RpcHandle {
    /// Send a request and wait for the matching response.
    pub async fn call(
        &self,
        msg_type: MsgType,
        msg: Msg,
    ) -> Result<Fcall, RpcError> {
        match self {
            Self::Quic(rpc) => rpc.call(msg_type, msg).await,
            Self::Tcp(rpc) => rpc.call(msg_type, msg).await,
            #[cfg(feature = "rdma")]
            Self::Rdma(rpc) => rpc.call(msg_type, msg).await,
        }
    }

    /// Check whether the underlying connection is still alive.
    pub fn is_alive(&self) -> bool {
        match self {
            Self::Quic(rpc) => rpc.is_alive(),
            Self::Tcp(rpc) => rpc.is_alive(),
            #[cfg(feature = "rdma")]
            Self::Rdma(rpc) => rpc.is_alive(),
        }
    }

    /// Gracefully close the transport connection.
    pub async fn close(&self) {
        match self {
            Self::Quic(rpc) => rpc.close(),
            Self::Tcp(rpc) => rpc.close().await,
            #[cfg(feature = "rdma")]
            Self::Rdma(rpc) => rpc.close(),
        }
    }

    /// The monotonic conn_id of the underlying transport client.
    pub fn conn_id(&self) -> u64 {
        match self {
            Self::Quic(rpc) => rpc.conn_id(),
            Self::Tcp(rpc) => rpc.conn_id(),
            #[cfg(feature = "rdma")]
            Self::Rdma(rpc) => rpc.conn_id(),
        }
    }

    /// Register an RDMA token for a fid (no-op for QUIC/TCP).
    ///
    /// When using RDMA transport, this allocates a buffer and tells the
    /// server to use one-sided RDMA operations for this fid's I/O.
    pub async fn register_rdma_token(&self, fid: u32, direction: u8) {
        #[cfg(feature = "rdma")]
        if let Self::Rdma(rpc) = self {
            if let Err(e) = rpc.register_rdma_token(fid, direction).await {
                tracing::debug!(fid, direction, error = %e, "RDMA token registration failed");
            }
        }
        let _ = (fid, direction); // suppress unused warnings for non-rdma builds
    }

    /// Deregister RDMA token for a fid (no-op for QUIC/TCP).
    pub fn deregister_rdma_token(&self, fid: u32) {
        #[cfg(feature = "rdma")]
        if let Self::Rdma(rpc) = self {
            rpc.deregister_rdma_token(fid);
        }
        let _ = fid;
    }
}

pub struct Importer {
    pub rpc: Arc<RpcHandle>,
    pub msize: u32,
    pub caps: CapSet,
    pub root_qid: Qid,
    pub root_fid: u32,
    /// Session key for reconnection (derived from TLS keying material).
    pub session_key: Option<[u8; 16]>,
    /// Sender half of the push channel. Retained so it can be cloned into
    /// new connections on reconnect.
    pub push_tx: mpsc::Sender<p9n_proto::fcall::Fcall>,
    pub push_rx: mpsc::Receiver<p9n_proto::fcall::Fcall>,
    /// QUIC endpoint, retained so the same UDP socket is reused across
    /// reconnections.
    pub endpoint: Option<quinn::Endpoint>,
}

/// Options for connecting to a 9P server.
pub struct ConnectOpts {
    pub addr: String,
    pub hostname: String,
    pub uname: String,
    pub aname: String,
}

impl Default for ConnectOpts {
    fn default() -> Self {
        Self {
            addr: String::new(),
            hostname: "localhost".to_string(),
            uname: "nobody".to_string(),
            aname: String::new(),
        }
    }
}

impl Importer {
    /// Connect over QUIC (requires SPIFFE auth).
    ///
    /// Creates a new QUIC endpoint. The endpoint is stored in the returned
    /// `Importer` so that the same UDP socket can be reused on reconnect.
    pub async fn connect_quic(
        addr: &str,
        hostname: &str,
        auth: p9n_auth::SpiffeAuth,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = p9n_transport::quic::config::client_endpoint(&auth)?;
        Self::connect_quic_with_endpoint(&endpoint, addr, hostname).await
    }

    /// Connect over QUIC using an existing endpoint.
    ///
    /// Always performs a full 1-RTT handshake. 0-RTT is deliberately not
    /// attempted — see `docs/ARCH_DESIGN_DECISION.md` for the rationale.
    pub async fn connect_quic_with_endpoint(
        endpoint: &quinn::Endpoint,
        addr: &str,
        hostname: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let conn_id = next_conn_id();
        let server_addr: std::net::SocketAddr = addr.parse()?;
        tracing::info!(conn_id, %addr, hostname, "connecting via QUIC");
        let conn = p9n_transport::quic::connect::connect(endpoint, server_addr, hostname).await?;
        tracing::info!(conn_id, %addr, hostname, transport = "quic", "connected");

        let (push_tx, push_rx) = mpsc::channel(64);
        let rpc = Arc::new(QuicRpcClient::new(conn.clone(), push_tx.clone(), conn_id));

        let opts = ConnectOpts {
            addr: addr.to_string(),
            hostname: hostname.to_string(),
            ..Default::default()
        };

        let root_fid = 0u32;
        let (msize, negotiated_caps, root_qid, session_key) = async {
            let msize = negotiate_version(&*rpc, &opts).await?;
            let caps = negotiate_caps(&*rpc, true).await?;
            if caps.has(CAP_QUIC_MULTI) {
                let _ = bind_push_stream(&*rpc).await;
            }
            let root_qid = do_attach(&*rpc, root_fid, &opts).await?;
            let session_key = if caps.has(CAP_SESSION) {
                let key = derive_session_key(&conn)?;
                establish_session(&*rpc, key).await?
            } else {
                tracing::debug!("skipping Tsession (CAP_SESSION not negotiated)");
                None
            };
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((msize, caps, root_qid, session_key))
        }
        .instrument(tracing::info_span!(
            "handshake",
            conn_id,
            transport = "quic",
            addr = %addr,
            hostname,
        ))
        .await?;

        Ok(Self {
            rpc: Arc::new(RpcHandle::Quic(rpc)),
            msize,
            caps: negotiated_caps,
            root_qid,
            root_fid,
            session_key,
            push_tx,
            push_rx,
            endpoint: Some(endpoint.clone()),
        })
    }

    /// Connect over TCP+TLS (requires SPIFFE auth).
    pub async fn connect_tcp(
        addr: &str,
        hostname: &str,
        auth: p9n_auth::SpiffeAuth,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let conn_id = next_conn_id();
        let tls_config = p9n_auth::spiffe::tls_config::client_config(
            &auth.identity,
            &auth.trust_store,
        )?;
        let server_addr: std::net::SocketAddr = addr.parse()?;
        tracing::info!(conn_id, %addr, hostname, "connecting via TCP+TLS");
        let stream = p9n_transport::tcp::config::client_connect(
            server_addr, hostname, tls_config,
        ).await?;
        tracing::info!(conn_id, %addr, hostname, transport = "tcp", "connected");

        // Derive session key from TLS connection BEFORE splitting the stream
        let session_key_bytes = {
            let (_, tls_conn) = stream.get_ref();
            let mut key = [0u8; 16];
            tls_conn
                .export_keying_material(&mut key, b"9P2000.N session", None)
                .map_err(|_| "TLS export_keying_material failed")?;
            key
        };

        let (push_tx, push_rx) = mpsc::channel(64);
        let rpc = Arc::new(TcpRpcClient::new(stream, push_tx.clone(), conn_id));

        let opts = ConnectOpts {
            addr: addr.to_string(),
            hostname: hostname.to_string(),
            ..Default::default()
        };

        let root_fid = 0u32;
        let (msize, negotiated_caps, root_qid, session_key) = async {
            let msize = negotiate_version(&*rpc, &opts).await?;
            let caps = negotiate_caps(&*rpc, false).await?;
            let root_qid = do_attach(&*rpc, root_fid, &opts).await?;
            let session_key = if caps.has(CAP_SESSION) {
                establish_session(&*rpc, session_key_bytes).await?
            } else {
                tracing::debug!("skipping Tsession (CAP_SESSION not negotiated)");
                None
            };
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((msize, caps, root_qid, session_key))
        }
        .instrument(tracing::info_span!(
            "handshake",
            conn_id,
            transport = "tcp",
            addr = %addr,
            hostname,
        ))
        .await?;

        Ok(Self {
            rpc: Arc::new(RpcHandle::Tcp(rpc)),
            msize,
            caps: negotiated_caps,
            root_qid,
            root_fid,
            session_key,
            push_tx,
            push_rx,
            endpoint: None,
        })
    }

    /// Connect over RDMA (requires SPIFFE auth + RDMA hardware/SoftRoCE).
    #[cfg(feature = "rdma")]
    pub async fn connect_rdma(
        addr: &str,
        hostname: &str,
        auth: p9n_auth::SpiffeAuth,
        device_name: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let conn_id = next_conn_id();
        let tls_config = p9n_auth::spiffe::tls_config::client_config(
            &auth.identity,
            &auth.trust_store,
        )?;
        let server_addr: std::net::SocketAddr = addr.parse()?;
        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())?;

        tracing::info!(conn_id, %addr, hostname, device = ?device_name, "connecting via RDMA");

        let (rdma_conn, session_key_bytes) =
            p9n_transport::rdma::config::client_connect(
                server_addr, &tls_connector, server_name, device_name,
            )
            .await?;
        tracing::info!(conn_id, %addr, hostname, transport = "rdma", "connected");

        let (push_tx, push_rx) = mpsc::channel(64);
        let rpc = Arc::new(RdmaRpcClient::new(rdma_conn, push_tx.clone(), conn_id));

        let opts = ConnectOpts {
            addr: addr.to_string(),
            hostname: hostname.to_string(),
            ..Default::default()
        };

        let root_fid = 0u32;
        let (msize, negotiated_caps, root_qid, session_key) = async {
            let msize = negotiate_version(&*rpc, &opts).await?;
            let caps = negotiate_caps(&*rpc, false).await?;
            let root_qid = do_attach(&*rpc, root_fid, &opts).await?;
            let session_key = if caps.has(CAP_SESSION) {
                establish_session(&*rpc, session_key_bytes).await?
            } else {
                tracing::debug!("skipping Tsession (CAP_SESSION not negotiated)");
                None
            };
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((msize, caps, root_qid, session_key))
        }
        .instrument(tracing::info_span!(
            "handshake",
            conn_id,
            transport = "rdma",
            addr = %addr,
            hostname,
        ))
        .await?;

        Ok(Self {
            rpc: Arc::new(RpcHandle::Rdma(rpc)),
            msize,
            caps: negotiated_caps,
            root_qid,
            root_fid,
            session_key,
            push_tx,
            push_rx,
            endpoint: None,
        })
    }
}

// ── Reconnect helpers ──

/// Reconnect result: new RPC handle + updated session key.
pub struct ReconnectResult {
    pub rpc: Arc<RpcHandle>,
    pub session_key: Option<[u8; 16]>,
    pub conn_id: u64,
}

/// Re-establish a QUIC connection using an existing endpoint.
///
/// Performs the full 1-RTT handshake: version → caps → attach → session.
/// The `push_tx` is cloned into the new `QuicRpcClient` so that push messages
/// continue to flow into the same channel used before the disconnect.
pub async fn reconnect_quic(
    endpoint: &quinn::Endpoint,
    addr: &str,
    hostname: &str,
    push_tx: mpsc::Sender<Fcall>,
) -> Result<ReconnectResult, Box<dyn std::error::Error + Send + Sync>> {
    let conn_id = next_conn_id();
    let server_addr: std::net::SocketAddr = addr.parse()?;
    tracing::info!(conn_id, %addr, hostname, "reconnecting via QUIC");
    let conn = p9n_transport::quic::connect::connect(endpoint, server_addr, hostname).await?;
    tracing::info!(conn_id, %addr, hostname, transport = "quic", "reconnected");

    let rpc = Arc::new(QuicRpcClient::new(conn.clone(), push_tx, conn_id));

    let opts = ConnectOpts {
        addr: addr.to_string(),
        hostname: hostname.to_string(),
        ..Default::default()
    };

    let session_key = async {
        negotiate_version(&*rpc, &opts).await?;
        let caps = negotiate_caps(&*rpc, true).await?;
        if caps.has(CAP_QUIC_MULTI) {
            let _ = bind_push_stream(&*rpc).await;
        }
        do_attach(&*rpc, 0, &opts).await?;
        let key = derive_session_key(&conn)?;
        establish_session(&*rpc, key).await
    }
    .instrument(tracing::info_span!(
        "handshake",
        conn_id,
        transport = "quic",
        addr = %addr,
        hostname,
        reconnect = true,
    ))
    .await?;

    Ok(ReconnectResult {
        rpc: Arc::new(RpcHandle::Quic(rpc)),
        session_key,
        conn_id,
    })
}

/// Re-establish a TCP+TLS connection.
///
/// Same handshake as `reconnect_quic` but over a new TCP+TLS stream.
pub async fn reconnect_tcp(
    addr: &str,
    hostname: &str,
    identity: &p9n_auth::spiffe::SpiffeIdentity,
    trust_store: &p9n_auth::spiffe::trust_bundle::TrustBundleStore,
    push_tx: mpsc::Sender<Fcall>,
) -> Result<ReconnectResult, Box<dyn std::error::Error + Send + Sync>> {
    let conn_id = next_conn_id();
    let tls_config = p9n_auth::spiffe::tls_config::client_config(identity, trust_store)?;
    let server_addr: std::net::SocketAddr = addr.parse()?;
    tracing::info!(conn_id, %addr, hostname, "reconnecting via TCP+TLS");
    let stream = p9n_transport::tcp::config::client_connect(server_addr, hostname, tls_config).await?;
    tracing::info!(conn_id, %addr, hostname, transport = "tcp", "reconnected");

    let session_key_bytes = {
        let (_, tls_conn) = stream.get_ref();
        let mut key = [0u8; 16];
        tls_conn
            .export_keying_material(&mut key, b"9P2000.N session", None)
            .map_err(|_| "TLS export_keying_material failed")?;
        key
    };

    let rpc = Arc::new(TcpRpcClient::new(stream, push_tx, conn_id));

    let opts = ConnectOpts {
        addr: addr.to_string(),
        hostname: hostname.to_string(),
        ..Default::default()
    };

    let session_key = async {
        negotiate_version(&*rpc, &opts).await?;
        negotiate_caps(&*rpc, false).await?;
        do_attach(&*rpc, 0, &opts).await?;
        establish_session(&*rpc, session_key_bytes).await
    }
    .instrument(tracing::info_span!(
        "handshake",
        conn_id,
        transport = "tcp",
        addr = %addr,
        hostname,
        reconnect = true,
    ))
    .await?;

    Ok(ReconnectResult {
        rpc: Arc::new(RpcHandle::Tcp(rpc)),
        session_key,
        conn_id,
    })
}

/// Re-establish an RDMA connection.
#[cfg(feature = "rdma")]
pub async fn reconnect_rdma(
    addr: &str,
    hostname: &str,
    identity: &p9n_auth::spiffe::SpiffeIdentity,
    trust_store: &p9n_auth::spiffe::trust_bundle::TrustBundleStore,
    push_tx: mpsc::Sender<Fcall>,
    device_name: Option<&str>,
) -> Result<ReconnectResult, Box<dyn std::error::Error + Send + Sync>> {
    let conn_id = next_conn_id();
    let tls_config = p9n_auth::spiffe::tls_config::client_config(identity, trust_store)?;
    let server_addr: std::net::SocketAddr = addr.parse()?;
    let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())?;

    tracing::info!(conn_id, %addr, hostname, device = ?device_name, "reconnecting via RDMA");

    let (rdma_conn, session_key_bytes) =
        p9n_transport::rdma::config::client_connect(
            server_addr, &tls_connector, server_name, device_name,
        )
        .await?;
    tracing::info!(conn_id, %addr, hostname, transport = "rdma", "reconnected");

    let rpc = Arc::new(RdmaRpcClient::new(rdma_conn, push_tx, conn_id));

    let opts = ConnectOpts {
        addr: addr.to_string(),
        hostname: hostname.to_string(),
        ..Default::default()
    };

    let session_key = async {
        negotiate_version(&*rpc, &opts).await?;
        negotiate_caps(&*rpc, false).await?;
        do_attach(&*rpc, 0, &opts).await?;
        establish_session(&*rpc, session_key_bytes).await
    }
    .instrument(tracing::info_span!(
        "handshake",
        conn_id,
        transport = "rdma",
        addr = %addr,
        hostname,
        reconnect = true,
    ))
    .await?;

    Ok(ReconnectResult {
        rpc: Arc::new(RpcHandle::Rdma(rpc)),
        session_key,
        conn_id,
    })
}

// ── Shared handshake helpers ──

/// Trait for calling 9P RPCs — implemented by both QuicRpcClient and TcpRpcClient<W>.
trait RpcCaller {
    fn call(
        &self,
        msg_type: MsgType,
        msg: Msg,
    ) -> impl std::future::Future<Output = Result<Fcall, RpcError>> + Send;
}

impl RpcCaller for QuicRpcClient {
    fn call(
        &self,
        msg_type: MsgType,
        msg: Msg,
    ) -> impl std::future::Future<Output = Result<Fcall, RpcError>> + Send {
        QuicRpcClient::call(self, msg_type, msg)
    }
}

impl<W: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> RpcCaller
    for TcpRpcClient<W>
{
    fn call(
        &self,
        msg_type: MsgType,
        msg: Msg,
    ) -> impl std::future::Future<Output = Result<Fcall, RpcError>> + Send {
        TcpRpcClient::call(self, msg_type, msg)
    }
}

#[cfg(feature = "rdma")]
impl RpcCaller for RdmaRpcClient {
    fn call(
        &self,
        msg_type: MsgType,
        msg: Msg,
    ) -> impl std::future::Future<Output = Result<Fcall, RpcError>> + Send {
        RdmaRpcClient::call(self, msg_type, msg)
    }
}

// Handshake helpers. Each log event inherits `conn_id` / `transport` / `addr`
// / `hostname` from the surrounding `handshake` span — see the .instrument()
// wrappers at the call sites in connect_* / reconnect_*.

/// Negotiate protocol version. Returns msize. Fails if server does not support 9P2000.N.
async fn negotiate_version(
    rpc: &impl RpcCaller,
    _opts: &ConnectOpts,
) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
    let requested_msize = 65536u32;
    tracing::debug!(
        requested_msize,
        requested_version = VERSION_9P2000_N,
        "handshake: sending Tversion",
    );
    let ver_resp = rpc
        .call(MsgType::Tversion, Msg::Version {
            msize: requested_msize,
            version: VERSION_9P2000_N.to_string(),
        })
        .await?;

    match &ver_resp.msg {
        Msg::Version { msize, version } => {
            if version == VERSION_9P2000_N {
                tracing::info!(
                    msize,
                    clamped = *msize < requested_msize,
                    version = %version,
                    "handshake: version negotiated",
                );
                Ok(*msize)
            } else {
                tracing::error!(
                    got = %version,
                    want = VERSION_9P2000_N,
                    "handshake: server does not support 9P2000.N",
                );
                Err(format!("server does not support 9P2000.N (got {version})").into())
            }
        }
        _ => Err("unexpected version response".into()),
    }
}

/// Negotiate capabilities (9P2000.N only).
async fn negotiate_caps(
    rpc: &impl RpcCaller,
    want_quic_multi: bool,
) -> Result<CapSet, Box<dyn std::error::Error + Send + Sync>> {
    let mut caps = CapSet::new();
    caps.add(CAP_COMPOUND);
    caps.add(CAP_WATCH);
    caps.add(CAP_XATTR2);
    caps.add(CAP_SESSION);
    caps.add(CAP_HEALTH);
    if want_quic_multi {
        caps.add(CAP_QUIC_MULTI);
    }

    let requested: Vec<String> = caps.caps().to_vec();
    tracing::debug!(
        n_requested = requested.len(),
        requested = ?requested,
        "handshake: sending Tcaps",
    );

    let caps_resp = rpc
        .call(MsgType::Tcaps, Msg::Caps {
            caps: requested.clone(),
        })
        .await?;

    match caps_resp.msg {
        Msg::Caps { caps: server_caps } => {
            let dropped: Vec<&String> = requested.iter().filter(|c| !server_caps.contains(c)).collect();
            tracing::info!(
                n_requested = requested.len(),
                n_granted = server_caps.len(),
                granted = ?server_caps,
                dropped = ?dropped,
                "handshake: caps negotiated",
            );
            let mut result = CapSet::new();
            for c in server_caps {
                result.add(&c);
            }
            Ok(result)
        }
        _ => {
            tracing::warn!("handshake: unexpected Tcaps response; assuming empty cap set");
            Ok(CapSet::new())
        }
    }
}

/// Send Tquicstream(stream_type=2) to bind a persistent push stream.
/// Called only after CAP_QUIC_MULTI has been negotiated. Failure is not
/// fatal: the server may still use the legacy ephemeral push path. See
/// docs/QUICSTREAM.md.
async fn bind_push_stream(rpc: &impl RpcCaller) -> Option<u64> {
    tracing::debug!("handshake: sending Tquicstream(push)");
    let resp = match rpc
        .call(
            MsgType::Tquicstream,
            Msg::Quicstream { stream_type: 2, stream_id: 0 },
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(error = %e, "Tquicstream bind failed, falling back to ephemeral push");
            return None;
        }
    };
    match resp.msg {
        Msg::Rquicstream { stream_id } => {
            tracing::info!(alias = stream_id, "Tquicstream bound");
            Some(stream_id)
        }
        Msg::Lerror { ecode } => {
            tracing::info!(ecode, "Tquicstream rejected; using ephemeral push");
            None
        }
        _ => {
            tracing::warn!("Tquicstream: unexpected response");
            None
        }
    }
}

/// Send Tattach and return root QID.
async fn do_attach(
    rpc: &impl RpcCaller,
    root_fid: u32,
    opts: &ConnectOpts,
) -> Result<Qid, Box<dyn std::error::Error + Send + Sync>> {
    tracing::debug!(
        root_fid,
        uname = %opts.uname,
        aname = %opts.aname,
        "handshake: sending Tattach",
    );
    let attach_resp = rpc
        .call(MsgType::Tattach, Msg::Attach {
            fid: root_fid,
            afid: NO_FID,
            uname: opts.uname.clone(),
            aname: opts.aname.clone(),
        })
        .await?;

    match attach_resp.msg {
        Msg::Rattach { qid } => {
            tracing::info!(
                root_fid,
                qid_path = qid.path,
                qid_version = qid.version,
                qid_type = qid.qtype,
                "handshake: attached",
            );
            Ok(qid)
        }
        _ => Err("unexpected attach response".into()),
    }
}

/// Establish a 9P2000.N session. Returns session key on success.
async fn establish_session(
    rpc: &impl RpcCaller,
    key: [u8; 16],
) -> Result<Option<[u8; 16]>, Box<dyn std::error::Error + Send + Sync>> {
    let key_prefix = hex_prefix(&key);
    let requested_flags = SESSION_FIDS | SESSION_WATCHES;
    tracing::debug!(
        key_prefix = %key_prefix,
        requested_flags = format_args!("{:#x}", requested_flags),
        "handshake: sending Tsession",
    );
    let session_resp = rpc
        .call(MsgType::Tsession, Msg::Session {
            key,
            flags: requested_flags,
        })
        .await?;

    match session_resp.msg {
        Msg::Rsession { flags } => {
            tracing::info!(
                key_prefix = %key_prefix,
                requested_flags = format_args!("{:#x}", requested_flags),
                effective_flags = format_args!("{:#x}", flags),
                dropped_flags = format_args!("{:#x}", requested_flags & !flags),
                "handshake: session established",
            );
            Ok(Some(key))
        }
        _ => {
            tracing::warn!("handshake: unexpected Tsession response");
            Ok(None)
        }
    }
}

/// 8-char hex prefix of a byte slice, for opaque-identifier logging.
fn hex_prefix(bytes: &[u8]) -> String {
    let n = bytes.len().min(4);
    let mut s = String::with_capacity(n * 2);
    for b in &bytes[..n] {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Derive a 128-bit session key from the QUIC/TLS connection's keying material.
fn derive_session_key(
    conn: &quinn::Connection,
) -> Result<[u8; 16], Box<dyn std::error::Error + Send + Sync>> {
    let mut key = [0u8; 16];
    conn.export_keying_material(&mut key, b"9P2000.N session", b"")
        .map_err(|_| "TLS export_keying_material failed")?;
    Ok(key)
}
