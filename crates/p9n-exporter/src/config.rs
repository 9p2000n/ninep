//! Runtime configuration with sane defaults.
//!
//! All previously hardcoded values are now configurable.

use std::time::Duration;

/// Exporter runtime configuration.
#[derive(Debug, Clone)]
pub struct ExporterConfig {
    /// Maximum 9P message size (default: 4 MiB).
    pub max_msize: u32,
    /// Session store TTL — how long saved sessions can be resumed (default: 5 min).
    pub session_ttl: Duration,
    /// Session store GC interval (default: 60s).
    pub session_gc_interval: Duration,
    /// Background heartbeat interval for subsystem stats logging (default: 30s).
    /// A single tokio task ticks at this interval and emits a log line for the
    /// session store, lease manager, and watch manager — even when idle. Set
    /// log filter to `p9n_exporter=debug` to see them.
    pub heartbeat_interval: Duration,
    /// Watch event channel capacity per connection (default: 256).
    pub watch_channel_capacity: usize,
    /// Maximum lease duration in seconds (default: 300).
    pub max_lease_duration: u32,
    /// Maximum capability token lifetime in seconds (default: 86400 = 24h).
    pub max_cap_token_ttl: u64,
    /// Enable per-fid rate limiting via Tratelimit (default: false).
    /// When disabled, Tratelimit is acknowledged but not enforced.
    pub enable_rate_limit: bool,
    /// Maximum IOPS a client may request per fid (default: 100_000).
    /// Only effective when `enable_rate_limit` is true.
    pub max_iops: u32,
    /// Maximum bytes/sec a client may request per fid (default: 1 GiB/s).
    /// Only effective when `enable_rate_limit` is true.
    pub max_bps: u64,
    /// Maximum number of OS threads in the tokio blocking pool
    /// (used by `spawn_blocking` for filesystem I/O). Default: 256.
    ///
    /// Each thread consumes ~8 MB stack. On slow backends (NFS, spinning
    /// disk) with high concurrency, the pool can fill up — further
    /// `spawn_blocking` calls will queue until a thread frees up.
    /// Tune up for high-concurrency NFS exports, down for memory-
    /// constrained environments.
    pub max_blocking_threads: usize,
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            max_msize: 4 * 1024 * 1024,
            session_ttl: Duration::from_secs(300),
            session_gc_interval: Duration::from_secs(60),
            heartbeat_interval: Duration::from_secs(30),
            watch_channel_capacity: 256,
            max_lease_duration: 300,
            max_cap_token_ttl: 86400,
            enable_rate_limit: false,
            max_iops: 100_000,
            max_bps: 1024 * 1024 * 1024, // 1 GiB/s
            max_blocking_threads: 256,
        }
    }
}
