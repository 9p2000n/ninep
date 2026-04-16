use crate::access::AccessControl;
use crate::backend::Backend;
use crate::backend::local::LocalBackend;
use crate::lease_manager::LeaseManager;
use crate::quic_connection::QuicConnectionHandler;
use crate::tcp_connection::TcpConnectionHandler;
#[cfg(feature = "rdma")]
use crate::rdma_connection::RdmaConnectionHandler;
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

/// 9P2000.N file exporter, generic over the filesystem backend.
pub struct Exporter<B: Backend = LocalBackend> {
    endpoint: quinn::Endpoint,
    ctx: Arc<SharedCtx<B>>,
    tcp_listener: Option<tokio::net::TcpListener>,
    tcp_acceptor: Option<TlsAcceptor>,
    #[cfg(feature = "rdma")]
    rdma_listener: Option<tokio::net::TcpListener>,
    #[cfg(feature = "rdma")]
    rdma_acceptor: Option<TlsAcceptor>,
    #[cfg(feature = "rdma")]
    rdma_device: Option<String>,
    shutdown_token: CancellationToken,
}

impl Exporter<LocalBackend> {
    /// Create an exporter with the default local filesystem backend.
    pub fn new(
        listen: SocketAddr,
        export: String,
        auth: SpiffeAuth,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_config(listen, export, auth, crate::config::ExporterConfig::default())
    }

    /// Create an exporter with the default local filesystem backend and custom config.
    pub fn with_config(
        listen: SocketAddr,
        export: String,
        auth: SpiffeAuth,
        cfg: crate::config::ExporterConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let endpoint = config::server_endpoint(listen, &auth)?;
        let backend = LocalBackend::new(export.clone())?;
        let access = AccessControl::new(backend.root().to_path_buf());
        Self::with_backend(endpoint, backend, access, auth, cfg)
    }
}

impl<B: Backend> Exporter<B> {
    /// Create an exporter with a custom backend.
    pub fn with_backend(
        endpoint: quinn::Endpoint,
        backend: B,
        access: AccessControl,
        auth: SpiffeAuth,
        cfg: crate::config::ExporterConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let session_store = SessionStore::new(cfg.session_ttl);
        let watch_mgr = WatchManager::new()?;
        let lease_mgr = LeaseManager::new();

        let server_spiffe_id = auth.identity.spiffe_id.clone();
        let server_trust_domain = auth.identity.trust_domain.clone();
        let trust_store = auth.trust_store.clone();
        let cap_signing_key = generate_hmac_key()
            .map_err(|e| format!("HMAC key generation failed: {e}"))?;

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

        tracing::info!("9P2000.N exporter listening on {}", endpoint.local_addr()?);
        Ok(Self {
            endpoint,
            ctx,
            tcp_listener: None,
            tcp_acceptor: None,
            #[cfg(feature = "rdma")]
            rdma_listener: None,
            #[cfg(feature = "rdma")]
            rdma_acceptor: None,
            #[cfg(feature = "rdma")]
            rdma_device: None,
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

    /// Enable RDMA listening on the given address.
    ///
    /// The RDMA bootstrap uses TCP+TLS for authentication (same SPIFFE mTLS),
    /// then exchanges QP parameters and transitions to RDMA verbs for data.
    #[cfg(feature = "rdma")]
    pub async fn enable_rdma(
        &mut self,
        addr: SocketAddr,
        identity: &p9n_auth::spiffe::SpiffeIdentity,
        trust_store: &p9n_auth::spiffe::trust_bundle::TrustBundleStore,
        device_name: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tls_config = tls_config::server_config(identity, trust_store)
            .map_err(|e| format!("RDMA TLS config: {e}"))?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("RDMA listener on {addr} (TCP+TLS bootstrap)");
        self.rdma_listener = Some(listener);
        self.rdma_acceptor = Some(acceptor);
        self.rdma_device = device_name;
        Ok(())
    }

    pub fn access_mut(&mut self) -> &mut AccessControl {
        &mut Arc::get_mut(&mut self.ctx)
            .expect("shared context already cloned")
            .access
    }

    /// Accept an RDMA connection (or pend forever if RDMA is not enabled).
    #[cfg(feature = "rdma")]
    async fn accept_rdma(
        &self,
    ) -> Result<
        (p9n_transport::rdma::config::RdmaConnection, Option<String>, std::net::SocketAddr),
        Box<dyn std::error::Error>,
    > {
        rdma_accept(
            &self.rdma_listener,
            &self.rdma_acceptor,
            self.rdma_device.as_deref(),
        )
        .await
    }

    #[cfg(not(feature = "rdma"))]
    async fn accept_rdma(&self) -> Result<(), Box<dyn std::error::Error>> {
        std::future::pending::<()>().await;
        unreachable!()
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
                result = self.accept_rdma() => {
                    #[cfg(feature = "rdma")]
                    match result {
                        Ok((rdma_conn, spiffe_id, remote)) => {
                            let ctx = self.ctx.clone();
                            handlers.spawn(async move {
                                tracing::info!("accepted RDMA connection from {remote}");
                                let mut handler = RdmaConnectionHandler::new(rdma_conn, ctx, spiffe_id);
                                if let Err(e) = handler.run().await {
                                    tracing::warn!("RDMA connection {remote} error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("RDMA accept error: {e}");
                        }
                    }
                    #[cfg(not(feature = "rdma"))]
                    { let _ = result; }
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

        // Step 4: Wait for QUIC endpoint to become idle.
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
                    _ = tokio::time::sleep(interval) => {
                        tracing::trace!("session GC tick");
                        ctx.session_store.gc();
                    }
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

/// Accept an RDMA connection if an RDMA listener is configured.
///
/// Accepts a TCP+TLS bootstrap connection, exchanges QP parameters,
/// and returns the established RDMA connection.
#[cfg(feature = "rdma")]
async fn rdma_accept(
    listener: &Option<tokio::net::TcpListener>,
    acceptor: &Option<TlsAcceptor>,
    device_name: Option<&str>,
) -> Result<
    (p9n_transport::rdma::config::RdmaConnection, Option<String>, std::net::SocketAddr),
    Box<dyn std::error::Error>,
> {
    let (listener, acceptor) = match (listener, acceptor) {
        (Some(l), Some(a)) => (l, a),
        _ => {
            std::future::pending::<()>().await;
            unreachable!()
        }
    };
    let (tcp_stream, addr) = listener.accept().await?;

    // Extract SPIFFE ID from the TLS peer certificate during bootstrap.
    let (rdma_conn, _session_key, peer_certs) =
        p9n_transport::rdma::config::accept(tcp_stream, acceptor, device_name).await?;

    let spiffe_id = crate::util::spiffe_id_from_certs(&peer_certs);

    Ok((rdma_conn, spiffe_id, addr))
}

/// Generate a 256-bit HMAC signing key from the OS CSPRNG.
fn generate_hmac_key() -> Result<[u8; 32], getrandom::Error> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_key_is_random_and_nonzero() {
        let k1 = generate_hmac_key().expect("csprng available");
        let k2 = generate_hmac_key().expect("csprng available");
        assert_ne!(k1, [0u8; 32], "key must not be all zeros");
        assert_ne!(k1, k2, "successive keys must differ (CSPRNG, not deterministic)");
    }
}
