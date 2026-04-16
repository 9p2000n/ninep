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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::{Mutex, mpsc};

/// Transport type, determines reconnection path.
#[derive(Clone)]
pub enum Transport {
    Quic,
    Tcp,
    #[cfg(feature = "rdma")]
    Rdma,
}

/// State needed to re-establish a connection after disconnect.
struct ReconnectCtx {
    addr: String,
    hostname: String,
    transport: Transport,
    push_tx: mpsc::Sender<Fcall>,
    /// QUIC endpoint (reused across reconnects to keep the same UDP socket).
    endpoint: Option<quinn::Endpoint>,
    /// SPIFFE identity for TLS client cert (both QUIC and TCP reconnect).
    identity: p9n_auth::spiffe::SpiffeIdentity,
    /// Trust bundle for TLS verification.
    trust_store: p9n_auth::spiffe::trust_bundle::TrustBundleStore,
    /// RDMA device name (None = auto-detect first device).
    #[cfg(feature = "rdma")]
    rdma_device: Option<String>,
}

/// Reconnect activity counters. Mutation goes through `record_*`; logs and
/// metrics export read via `snapshot()`.
#[derive(Default)]
struct ReconnectCounters {
    successes: AtomicU64,
    failures: AtomicU64,
}

impl ReconnectCounters {
    fn record_success(&self) -> u64 {
        self.successes.fetch_add(1, Ordering::Relaxed) + 1
    }
    fn record_failure(&self) -> u64 {
        self.failures.fetch_add(1, Ordering::Relaxed) + 1
    }
    #[allow(dead_code)] // used by the pending /metrics endpoint
    fn snapshot(&self) -> (u64, u64) {
        (
            self.successes.load(Ordering::Relaxed),
            self.failures.load(Ordering::Relaxed),
        )
    }
}

/// A reconnecting RPC client.
///
/// All FUSE filesystem operations go through `call()`. On transport failure
/// the client automatically reconnects and retries the request once.
pub struct RpcClient {
    inner: ArcSwap<RpcHandle>,
    reconnect_lock: Mutex<()>,
    ctx: ReconnectCtx,
    /// The conn_id of the currently active underlying RpcHandle. Updated on
    /// each successful reconnect, logged in every call so events before/after
    /// a disconnect can be distinguished.
    current_conn_id: AtomicU64,
    counters: ReconnectCounters,
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
        initial_conn_id: u64,
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
                #[cfg(feature = "rdma")]
                rdma_device: None,
            },
            current_conn_id: AtomicU64::new(initial_conn_id),
            counters: ReconnectCounters::default(),
        }
    }

    /// Set the RDMA device name for reconnection.
    #[cfg(feature = "rdma")]
    pub fn set_rdma_device(&mut self, device: Option<String>) {
        self.ctx.rdma_device = device;
    }

    /// The conn_id currently in use by the underlying RPC handle.
    pub fn conn_id(&self) -> u64 {
        self.current_conn_id.load(Ordering::Relaxed)
    }

    /// Send a 9P request. On transport failure, reconnect and retry once.
    pub async fn call(
        &self,
        msg_type: MsgType,
        msg: Msg,
    ) -> Result<Fcall, RpcError> {
        let conn_id = self.current_conn_id.load(Ordering::Relaxed);
        tracing::trace!(conn_id, msg_type = msg_type.name(), "rpc_client call");
        let rpc = self.inner.load();
        match rpc.call(msg_type, msg.clone()).await {
            Ok(fc) => Ok(fc),
            Err(e) if e.is_transport() => {
                tracing::warn!(
                    conn_id,
                    msg_type = msg_type.name(),
                    error = %e,
                    "RPC transport error; attempting reconnect",
                );
                self.reconnect().await;
                // Retry once with the (potentially) new connection.
                let new_conn_id = self.current_conn_id.load(Ordering::Relaxed);
                tracing::debug!(
                    old_conn_id = conn_id,
                    new_conn_id,
                    msg_type = msg_type.name(),
                    "retrying RPC after reconnect",
                );
                self.inner.load().call(msg_type, msg).await
            }
            Err(e) => Err(e),
        }
    }

    /// Close the underlying transport (for graceful shutdown).
    pub async fn close(&self) {
        self.inner.load().close().await;
    }

    /// Register an RDMA token for a fid (no-op for QUIC/TCP).
    pub async fn register_rdma_token(&self, fid: u32, direction: u8) {
        self.inner.load().register_rdma_token(fid, direction).await;
    }

    /// Deregister RDMA token for a fid (no-op for QUIC/TCP).
    pub fn deregister_rdma_token(&self, fid: u32) {
        self.inner.load().deregister_rdma_token(fid);
    }

    /// Attempt to reconnect. Only one task performs the reconnect;
    /// concurrent callers wait for it to finish.
    async fn reconnect(&self) {
        let _guard = self.reconnect_lock.lock().await;

        let old_conn_id = self.current_conn_id.load(Ordering::Relaxed);

        // Double-check: another task may have already reconnected while we waited
        // for the lock. is_alive() is synchronous (no I/O, no timeout risk).
        if self.inner.load().is_alive() {
            let now_conn_id = self.current_conn_id.load(Ordering::Relaxed);
            if now_conn_id != old_conn_id {
                tracing::debug!(
                    old_conn_id,
                    now_conn_id,
                    "reconnect skipped: another task already reconnected",
                );
            } else {
                tracing::debug!(conn_id = old_conn_id, "reconnect skipped: connection still alive");
            }
            return;
        }

        let transport_name = match self.ctx.transport {
            Transport::Quic => "quic",
            Transport::Tcp => "tcp",
            #[cfg(feature = "rdma")]
            Transport::Rdma => "rdma",
        };
        tracing::info!(
            old_conn_id,
            transport = transport_name,
            addr = %self.ctx.addr,
            hostname = %self.ctx.hostname,
            "reconnect: closing old connection",
        );
        let started = Instant::now();

        // Close the old connection to release resources (background reader tasks,
        // keep-alive timers). Without this, failed reconnect attempts would leave
        // zombie QUIC connections sending keep-alive PINGs indefinitely.
        self.inner.load().close().await;

        let result = match self.ctx.transport {
            Transport::Quic => {
                let Some(ref ep) = self.ctx.endpoint else {
                    tracing::error!(old_conn_id, "cannot reconnect QUIC: no endpoint stored");
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
            #[cfg(feature = "rdma")]
            Transport::Rdma => {
                importer::reconnect_rdma(
                    &self.ctx.addr,
                    &self.ctx.hostname,
                    &self.ctx.identity,
                    &self.ctx.trust_store,
                    self.ctx.push_tx.clone(),
                    self.ctx.rdma_device.as_deref(),
                ).await
            }
        };

        let elapsed_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok(r) => {
                self.current_conn_id.store(r.conn_id, Ordering::Relaxed);
                self.inner.store(r.rpc);
                let reconnects_total = self.counters.record_success();
                tracing::info!(
                    old_conn_id,
                    new_conn_id = r.conn_id,
                    transport = transport_name,
                    elapsed_ms,
                    reconnects_total,
                    "reconnect succeeded",
                );
            }
            Err(e) => {
                let failures_total = self.counters.record_failure();
                tracing::error!(
                    old_conn_id,
                    transport = transport_name,
                    elapsed_ms,
                    failures_total,
                    error = %e,
                    "reconnect failed",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_default_and_snapshot() {
        let c = ReconnectCounters::default();
        assert_eq!(c.snapshot(), (0, 0));
    }

    #[test]
    fn counters_record_returns_running_total() {
        let c = ReconnectCounters::default();
        assert_eq!(c.record_success(), 1);
        assert_eq!(c.record_success(), 2);
        assert_eq!(c.record_failure(), 1);
        assert_eq!(c.record_failure(), 2);
        assert_eq!(c.snapshot(), (2, 2));
    }
}
