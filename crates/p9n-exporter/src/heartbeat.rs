//! Periodic heartbeat task that polls registered sources and emits one
//! structured log line per source per tick — even when idle.
//!
//! The previous implementation hard-coded every subsystem's fields in a
//! single central log statement. Adding a new subsystem required editing
//! that central statement AND knowing the existing field set. Here each
//! source owns its own log call, so growth is additive:
//!
//! ```ignore
//! Heartbeat::new(Duration::from_secs(30))
//!     .add({
//!         let ctx = ctx.clone();
//!         move |tick| {
//!             let s = ctx.lease_mgr.stats();
//!             tracing::debug!(tick, leases = s.leases, ..., "lease heartbeat");
//!         }
//!     })
//!     .add({ /* another subsystem */ })
//!     .spawn(shutdown_token);
//! ```
//!
//! Heartbeat sources are `Fn(u64)` closures, so they can capture any data
//! they need (typically an `Arc<T>` to the subsystem being observed).

use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

type Source = Box<dyn Fn(u64) + Send + Sync>;

/// Builder + runner for the periodic heartbeat task.
pub struct Heartbeat {
    interval: Duration,
    sources: Vec<Source>,
}

impl Heartbeat {
    /// Create a heartbeat that ticks every `interval`. No sources attached
    /// until `add()` is called.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            sources: Vec::new(),
        }
    }

    /// Register a closure to be called on every tick with the monotonic
    /// tick number. The closure is expected to emit its own structured
    /// `tracing` event (so the source, not the runner, controls the log
    /// format).
    pub fn add<F>(mut self, source: F) -> Self
    where
        F: Fn(u64) + Send + Sync + 'static,
    {
        self.sources.push(Box::new(source));
        self
    }

    /// Number of sources currently registered. Useful in tests.
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Whether no sources are registered.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Consume the builder and spawn the heartbeat task. The task exits
    /// when `shutdown` is cancelled.
    pub fn spawn(self, shutdown: CancellationToken) -> JoinHandle<()> {
        let Self { interval, sources } = self;
        let interval_secs = interval.as_secs();
        let n_sources = sources.len();
        tokio::spawn(async move {
            tracing::info!(
                interval_secs,
                n_sources,
                "heartbeat task starting",
            );
            let mut tick: u64 = 0;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {
                        tick = tick.wrapping_add(1);
                        for src in &sources {
                            src(tick);
                        }
                    }
                    _ = shutdown.cancelled() => {
                        tracing::debug!(ticks = tick, "heartbeat task exiting (shutdown)");
                        break;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn new_and_builder_is_empty() {
        let hb = Heartbeat::new(Duration::from_secs(1));
        assert!(hb.is_empty());
        assert_eq!(hb.len(), 0);
    }

    #[test]
    fn add_grows_source_count() {
        let hb = Heartbeat::new(Duration::from_secs(1))
            .add(|_| {})
            .add(|_| {});
        assert_eq!(hb.len(), 2);
    }

    #[tokio::test]
    async fn spawn_ticks_all_sources_and_monotonic() {
        let counter_a = Arc::new(AtomicU64::new(0));
        let counter_b = Arc::new(AtomicU64::new(0));
        let observed = Arc::new(parking_lot::Mutex::new(Vec::<u64>::new()));
        let token = CancellationToken::new();
        let handle = Heartbeat::new(Duration::from_millis(30))
            .add({
                let c = counter_a.clone();
                let o = observed.clone();
                move |tick| {
                    c.fetch_add(1, Ordering::Relaxed);
                    o.lock().push(tick);
                }
            })
            .add({
                let c = counter_b.clone();
                move |_tick| { c.fetch_add(1, Ordering::Relaxed); }
            })
            .spawn(token.clone());

        tokio::time::sleep(Duration::from_millis(120)).await;
        token.cancel();
        let _ = handle.await;

        let a = counter_a.load(Ordering::Relaxed);
        let b = counter_b.load(Ordering::Relaxed);
        assert!(a >= 2, "expected at least 2 ticks, got {}", a);
        assert_eq!(a, b, "both sources should tick the same number of times");

        let got = observed.lock().clone();
        assert_eq!(got[0], 1, "first tick should be 1");
        for pair in got.windows(2) {
            assert_eq!(pair[1], pair[0] + 1, "tick numbers must be monotonic");
        }
    }
}
