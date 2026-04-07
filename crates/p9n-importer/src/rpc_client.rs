//! Reconnecting RPC client.
//!
//! Wraps [`RpcHandle`] with transparent reconnection: when a transport error
//! is detected, the client re-establishes the QUIC or TCP connection, replays
//! the 9P handshake (version/caps/attach/session), and retries the failed call.
//!
//! Concurrent FUSE operations that all observe the same connection failure are
//! serialised through a `Mutex` so that only one reconnection attempt happens.

use crate::error::RpcError;
use crate::importer::{self, RpcHandle};
use arc_swap::ArcSwap;
use p9n_proto::fcall::{Fcall, Msg};
use p9n_proto::types::MsgType;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

/// Transport type, determines reconnection path.
#[derive(Clone)]
pub enum Transport {
    Quic,
    Tcp,
}

/// State needed to re-establish a connection after disconnect.
struct ReconnectCtx {
    addr: String,
    hostname: String,
    transport: Transport,
    push_tx: mpsc::Sender<Fcall>,
    /// QUIC endpoint (preserves session tickets for 0-RTT).
    endpoint: Option<quinn::Endpoint>,
    /// SPIFFE identity for TLS client cert (both QUIC and TCP reconnect).
    identity: p9n_auth::spiffe::SpiffeIdentity,
    /// Trust bundle for TLS verification.
    trust_store: p9n_auth::spiffe::trust_bundle::TrustBundleStore,
}

/// A reconnecting RPC client.
///
/// All FUSE filesystem operations go through `call()`. On transport failure
/// the client automatically reconnects and retries the request once.
pub struct RpcClient {
    inner: ArcSwap<RpcHandle>,
    reconnect_lock: Mutex<()>,
    ctx: ReconnectCtx,
}

impl RpcClient {
    pub fn new(
        rpc: Arc<RpcHandle>,
        transport: Transport,
        endpoint: Option<quinn::Endpoint>,
        addr: String,
        hostname: String,
        push_tx: mpsc::Sender<Fcall>,
        identity: p9n_auth::spiffe::SpiffeIdentity,
        trust_store: p9n_auth::spiffe::trust_bundle::TrustBundleStore,
    ) -> Self {
        Self {
            inner: ArcSwap::from(rpc),
            reconnect_lock: Mutex::new(()),
            ctx: ReconnectCtx {
                addr,
                hostname,
                transport,
                push_tx,
                endpoint,
                identity,
                trust_store,
            },
        }
    }

    /// Send a 9P request. On transport failure, reconnect and retry once.
    pub async fn call(
        &self,
        msg_type: MsgType,
        msg: Msg,
    ) -> Result<Fcall, RpcError> {
        tracing::trace!("rpc_client call: type={}", msg_type.name());
        let rpc = self.inner.load();
        match rpc.call(msg_type, msg.clone()).await {
            Ok(fc) => Ok(fc),
            Err(e) if e.is_transport() => {
                tracing::warn!("RPC transport error, attempting reconnect...");
                self.reconnect().await;
                // Retry once with the (potentially) new connection.
                self.inner.load().call(msg_type, msg).await
            }
            Err(e) => Err(e),
        }
    }

    /// Close the underlying transport (for graceful shutdown).
    pub async fn close(&self) {
        self.inner.load().close().await;
    }

    /// Attempt to reconnect. Only one task performs the reconnect;
    /// concurrent callers wait for it to finish.
    async fn reconnect(&self) {
        let _guard = self.reconnect_lock.lock().await;

        // Double-check: another task may have already reconnected while we waited
        // for the lock. is_alive() is synchronous (no I/O, no timeout risk).
        if self.inner.load().is_alive() {
            return;
        }

        // Close the old connection to release resources (background reader tasks,
        // keep-alive timers). Without this, failed reconnect attempts would leave
        // zombie QUIC connections sending keep-alive PINGs indefinitely.
        self.inner.load().close().await;

        let result = match self.ctx.transport {
            Transport::Quic => {
                let Some(ref ep) = self.ctx.endpoint else {
                    tracing::error!("cannot reconnect QUIC: no endpoint");
                    return;
                };
                importer::reconnect_quic(
                    ep,
                    &self.ctx.addr,
                    &self.ctx.hostname,
                    self.ctx.push_tx.clone(),
                ).await
            }
            Transport::Tcp => {
                importer::reconnect_tcp(
                    &self.ctx.addr,
                    &self.ctx.hostname,
                    &self.ctx.identity,
                    &self.ctx.trust_store,
                    self.ctx.push_tx.clone(),
                ).await
            }
        };

        match result {
            Ok(r) => {
                self.inner.store(r.rpc);
                tracing::info!("reconnected successfully");
            }
            Err(e) => {
                tracing::error!("reconnect failed: {e}");
            }
        }
    }
}
