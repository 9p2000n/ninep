use crate::access::AccessControl;
use crate::backend::local::LocalBackend;
use crate::lease_manager::LeaseManager;
use crate::quic_connection::QuicConnectionHandler;
use crate::tcp_connection::TcpConnectionHandler;
use crate::session_store::SessionStore;
use crate::shared::SharedCtx;
use crate::watch_manager::WatchManager;
use p9n_auth::SpiffeAuth;
use p9n_auth::spiffe::tls_config;
use p9n_transport::quic::config;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

pub struct Exporter {
    endpoint: quinn::Endpoint,
    ctx: Arc<SharedCtx>,
    tcp_listener: Option<tokio::net::TcpListener>,
    tcp_acceptor: Option<TlsAcceptor>,
    shutdown_token: CancellationToken,
}

impl Exporter {
    pub fn new(
        listen: SocketAddr,
        export: String,
        auth: SpiffeAuth,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_config(listen, export, auth, crate::config::ExporterConfig::default())
    }

    pub fn with_config(
        listen: SocketAddr,
        export: String,
        auth: SpiffeAuth,
        cfg: crate::config::ExporterConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let endpoint = config::server_endpoint(listen, &auth)?;
        let backend = LocalBackend::new(export.clone())?;
        let access = AccessControl::new(backend.root().to_path_buf());
        let session_store = SessionStore::new(cfg.session_ttl);
        let watch_mgr = WatchManager::new()?;
        let lease_mgr = LeaseManager::new();

        let server_spiffe_id = auth.identity.spiffe_id.clone();
        let server_trust_domain = auth.identity.trust_domain.clone();
        let trust_store = auth.trust_store.clone();
        let cap_signing_key = generate_hmac_key();

        let ctx = Arc::new(SharedCtx {
            backend,
            access,
            session_store,
            watch_mgr,
            lease_mgr,
            trust_store,
            server_spiffe_id,
            server_trust_domain,
            cap_signing_key,
            config: cfg,
        });

        tracing::info!("9P2000.N exporter listening on {listen}");
        Ok(Self {
            endpoint,
            ctx,
            tcp_listener: None,
            tcp_acceptor: None,
            shutdown_token: CancellationToken::new(),
        })
    }

    /// Enable TCP+TLS listening on the given address.
    ///
    /// Uses the same TLS configuration as the QUIC endpoint (mTLS with SPIFFE).
    /// Takes identity and trust store references to build the TLS config.
    pub async fn enable_tcp(
        &mut self,
        addr: SocketAddr,
        identity: &p9n_auth::spiffe::SpiffeIdentity,
        trust_store: &p9n_auth::spiffe::trust_bundle::TrustBundleStore,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tls_config = tls_config::server_config(identity, trust_store)
            .map_err(|e| format!("TCP TLS config: {e}"))?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("TCP+TLS listener on {addr}");
        self.tcp_listener = Some(listener);
        self.tcp_acceptor = Some(acceptor);
        Ok(())
    }

    pub fn access_mut(&mut self) -> &mut AccessControl {
        &mut Arc::get_mut(&mut self.ctx)
            .expect("shared context already cloned")
            .access
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.spawn_gc_task();

        let mut handlers = JoinSet::new();
        let mut sigterm = signal(SignalKind::terminate())
            .expect("failed to register SIGTERM handler");

        loop {
            tokio::select! {
                incoming = self.endpoint.accept() => {
                    match incoming {
                        Some(incoming) => {
                            let ctx = self.ctx.clone();
                            handlers.spawn(async move {
                                match incoming.await {
                                    Ok(conn) => {
                                        let remote = conn.remote_address();
                                        tracing::info!("accepted QUIC connection from {remote}");
                                        let mut handler = QuicConnectionHandler::new(conn, ctx);
                                        if let Err(e) = handler.run().await {
                                            tracing::warn!("QUIC connection {remote} error: {e}");
                                        }
                                    }
                                    Err(e) => tracing::warn!("QUIC incoming failed: {e}"),
                                }
                            });
                        }
                        None => break,
                    }
                }
                result = tcp_accept(&self.tcp_listener, &self.tcp_acceptor) => {
                    match result {
                        Ok((tls_stream, remote)) => {
                            let ctx = self.ctx.clone();
                            handlers.spawn(async move {
                                tracing::info!("accepted TCP+TLS connection from {remote}");
                                let mut handler = TcpConnectionHandler::new(tls_stream, ctx);
                                if let Err(e) = handler.run().await {
                                    tracing::warn!("TCP connection {remote} error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("TCP accept error: {e}");
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("received SIGINT, shutting down...");
                    break;
                }
                _ = sigterm.recv() => {
                    tracing::info!("received SIGTERM, shutting down...");
                    break;
                }
            }
        }

        self.shutdown(handlers).await;
        Ok(())
    }

    /// Ordered shutdown: stop new connections → drain active handlers → stop GC → idle.
    async fn shutdown(&self, mut handlers: JoinSet<()>) {
        // Step 1: Stop accepting new connections.
        self.endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");

        // Step 2: Wait for active connection handlers to finish cleanup.
        // endpoint.close() triggers CONNECTION_CLOSE on all QUIC connections,
        // causing each handler's select! to exit and call cleanup().
        let active = handlers.len();
        if active > 0 {
            tracing::info!("waiting for {active} connection(s) to drain...");
            let drain = async { while handlers.join_next().await.is_some() {} };
            if tokio::time::timeout(Duration::from_secs(10), drain).await.is_err() {
                tracing::warn!("drain timed out after 10s, aborting remaining handlers");
                handlers.abort_all();
            }
        }

        // Step 3: Stop the GC background task.
        self.shutdown_token.cancel();

        // Step 4: Wait for QUIC endpoint to become idle (ensures
        // CONNECTION_CLOSE frames are acknowledged by peers).
        self.endpoint.wait_idle().await;

        tracing::info!("clean shutdown complete");
    }

    /// Spawn a background task that periodically garbage-collects expired sessions.
    fn spawn_gc_task(&self) {
        let token = self.shutdown_token.clone();
        let ctx = self.ctx.clone();
        let interval = self.ctx.config.session_gc_interval;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => ctx.session_store.gc(),
                    _ = token.cancelled() => break,
                }
            }
        });
    }
}

/// Accept a TCP+TLS connection if a TCP listener is configured.
///
/// If no TCP listener is present, this future never completes (pends forever),
/// so the `select!` arm is effectively disabled.
async fn tcp_accept(
    listener: &Option<tokio::net::TcpListener>,
    acceptor: &Option<TlsAcceptor>,
) -> Result<
    (tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::net::SocketAddr),
    Box<dyn std::error::Error>,
> {
    let (listener, acceptor) = match (listener, acceptor) {
        (Some(l), Some(a)) => (l, a),
        _ => {
            // No TCP listener configured — pend forever so this arm never fires.
            std::future::pending::<()>().await;
            unreachable!()
        }
    };
    let (stream, addr) = listener.accept().await?;
    let tls_stream = acceptor.accept(stream).await?;
    Ok((tls_stream, addr))
}

/// Generate a 256-bit HMAC key from system entropy.
fn generate_hmac_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    // Use time + stack address as entropy source.
    // In production, use getrandom or ring::rand.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.as_nanos();
    key[..16].copy_from_slice(&nanos.to_le_bytes());
    let addr = &key as *const _ as u64;
    key[16..24].copy_from_slice(&addr.to_le_bytes());
    let pid = std::process::id();
    key[24..28].copy_from_slice(&pid.to_le_bytes());
    // Mix with a simple hash
    for i in 0..32 {
        key[i] = key[i].wrapping_mul(31).wrapping_add(key[(i + 7) % 32]);
    }
    key
}
