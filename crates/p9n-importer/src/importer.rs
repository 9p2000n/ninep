use crate::error::RpcError;
use crate::quic_rpc::QuicRpcClient;
use crate::tcp_rpc::TcpRpcClient;
use p9n_proto::caps::CapSet;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::*;
use p9n_proto::wire::Qid;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Unified RPC handle that delegates to QUIC or TCP+TLS transport.
pub enum RpcHandle {
    Quic(Arc<QuicRpcClient>),
    Tcp(Arc<TcpRpcClient<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>),
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
        }
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
    pub push_rx: mpsc::Receiver<p9n_proto::fcall::Fcall>,
    /// QUIC endpoint, retained so session tickets survive across reconnections
    /// (required for 0-RTT).
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
    /// `Importer` so that session tickets persist — pass it to
    /// [`reconnect()`] to benefit from 0-RTT on subsequent connections.
    pub async fn connect(
        addr: &str,
        hostname: &str,
        auth: p9n_auth::SpiffeAuth,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let endpoint = p9n_transport::quic::config::client_endpoint(&auth)?;
        Self::connect_with_endpoint(&endpoint, addr, hostname).await
    }

    /// Connect over QUIC using an existing endpoint.
    ///
    /// Reusing the endpoint across reconnections enables 0-RTT: the rustls
    /// session store inside the endpoint caches session tickets from previous
    /// connections, allowing quinn to skip the TLS handshake round-trip.
    pub async fn connect_with_endpoint(
        endpoint: &quinn::Endpoint,
        addr: &str,
        hostname: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let server_addr: std::net::SocketAddr = addr.parse()?;
        let result = p9n_transport::quic::zero_rtt::connect(endpoint, server_addr, hostname).await?;
        let conn = result.conn;

        if result.used_0rtt {
            tracing::info!("connected to {addr} (0-RTT)");
        } else {
            tracing::info!("connected to {addr}");
        }

        let (push_tx, push_rx) = mpsc::channel(64);
        let rpc = Arc::new(QuicRpcClient::new(conn.clone(), push_tx));

        let opts = ConnectOpts {
            addr: addr.to_string(),
            hostname: hostname.to_string(),
            ..Default::default()
        };

        // Version negotiation
        let msize = negotiate_version(&*rpc, &opts).await?;

        // Capability negotiation
        let negotiated_caps = negotiate_caps(&*rpc).await?;

        // Attach
        let root_fid = 0u32;
        let root_qid = do_attach(&*rpc, root_fid, &opts).await?;

        // Session
        let session_key = if negotiated_caps.has(CAP_SESSION) {
            let key = derive_session_key(&conn)?;
            establish_session(&*rpc, key).await?
        } else {
            None
        };

        Ok(Self {
            rpc: Arc::new(RpcHandle::Quic(rpc)),
            msize,
            caps: negotiated_caps,
            root_qid,
            root_fid,
            session_key,
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
        let tls_config = p9n_auth::spiffe::tls_config::client_config(
            &auth.identity,
            &auth.trust_store,
        )?;
        let server_addr: std::net::SocketAddr = addr.parse()?;
        let stream = p9n_transport::tcp::config::client_connect(
            server_addr, hostname, tls_config,
        ).await?;
        tracing::info!("TCP+TLS connected to {addr}");

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
        let rpc = Arc::new(TcpRpcClient::new(stream, push_tx));

        let opts = ConnectOpts {
            addr: addr.to_string(),
            hostname: hostname.to_string(),
            ..Default::default()
        };

        let msize = negotiate_version(&*rpc, &opts).await?;

        let negotiated_caps = negotiate_caps(&*rpc).await?;

        let root_fid = 0u32;
        let root_qid = do_attach(&*rpc, root_fid, &opts).await?;

        let session_key = if negotiated_caps.has(CAP_SESSION) {
            establish_session(&*rpc, session_key_bytes).await?
        } else {
            None
        };

        Ok(Self {
            rpc: Arc::new(RpcHandle::Tcp(rpc)),
            msize,
            caps: negotiated_caps,
            root_qid,
            root_fid,
            session_key,
            push_rx,
            endpoint: None,
        })
    }
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

/// Negotiate protocol version. Returns msize. Fails if server does not support 9P2000.N.
async fn negotiate_version(
    rpc: &impl RpcCaller,
    _opts: &ConnectOpts,
) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
    let ver_resp = rpc
        .call(MsgType::Tversion, Msg::Version {
            msize: 65536,
            version: VERSION_9P2000_N.to_string(),
        })
        .await?;

    match &ver_resp.msg {
        Msg::Version { msize, version } => {
            if version == VERSION_9P2000_N {
                tracing::info!("negotiated 9P2000.N, msize={msize}");
                Ok(*msize)
            } else {
                Err(format!("server does not support 9P2000.N (got {version})").into())
            }
        }
        _ => Err("unexpected version response".into()),
    }
}

/// Negotiate capabilities (9P2000.N only).
async fn negotiate_caps(
    rpc: &impl RpcCaller,
) -> Result<CapSet, Box<dyn std::error::Error + Send + Sync>> {
    let mut caps = CapSet::new();
    caps.add(CAP_COMPOUND);
    caps.add(CAP_WATCH);
    caps.add(CAP_XATTR2);
    caps.add(CAP_SESSION);
    caps.add(CAP_HEALTH);

    let caps_resp = rpc
        .call(MsgType::Tcaps, Msg::Caps {
            caps: caps.caps().to_vec(),
        })
        .await?;

    match caps_resp.msg {
        Msg::Caps { caps: server_caps } => {
            let mut result = CapSet::new();
            for c in server_caps {
                result.add(&c);
            }
            Ok(result)
        }
        _ => Ok(CapSet::new()),
    }
}

/// Send Tattach and return root QID.
async fn do_attach(
    rpc: &impl RpcCaller,
    root_fid: u32,
    opts: &ConnectOpts,
) -> Result<Qid, Box<dyn std::error::Error + Send + Sync>> {
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
            tracing::info!("attached, root qid={:?}", qid);
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
    let session_resp = rpc
        .call(MsgType::Tsession, Msg::Session {
            key,
            flags: SESSION_FIDS | SESSION_WATCHES,
        })
        .await?;

    match session_resp.msg {
        Msg::Rsession { flags } => {
            tracing::info!("session established, flags={flags:#x}");
            Ok(Some(key))
        }
        _ => Ok(None),
    }
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
