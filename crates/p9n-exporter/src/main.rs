use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser)]
#[command(name = "p9n-exporter", about = "9P2000.N file exporter")]
struct Args {
    /// Address to listen on
    #[arg(short, long, default_value = "[::]:5640")]
    listen: SocketAddr,

    /// Directory to export
    #[arg(short, long, default_value = "/tmp/9p-export")]
    export: String,

    /// TCP+TLS listen address (optional, alternative to QUIC)
    #[arg(long)]
    tcp_listen: Option<SocketAddr>,

    /// RDMA listen address (optional, TCP+TLS bootstrap for RDMA)
    #[cfg(feature = "rdma")]
    #[arg(long)]
    rdma_listen: Option<SocketAddr>,

    /// RDMA device name (auto-detect if not set)
    #[cfg(feature = "rdma")]
    #[arg(long)]
    rdma_device: Option<String>,

    /// SPIFFE X.509-SVID certificate (PEM)
    #[arg(long)]
    cert: String,

    /// SPIFFE private key (PEM)
    #[arg(long)]
    key: String,

    /// CA bundle (PEM)
    #[arg(long)]
    ca: String,

    /// JWT JWK Set files for remote trust domains (format: domain=path)
    /// Example: --jwt-keys partner.com=/etc/spiffe/partner-jwks.json
    #[arg(long, value_name = "DOMAIN=PATH")]
    jwt_keys: Vec<String>,

    /// Path to the signed POSIX mapping bundle (JWS Compact, see
    /// docs/POSIX_IDENTITY.md §3). When set together with
    /// --posix-mapping-jwks, peer SPIFFE IDs resolve to (uid, gid,
    /// groups) through the bundle in preference to the v1 X.509
    /// extension path. Bundle load failure is fail-closed: the
    /// exporter exits with an error.
    #[arg(long, value_name = "PATH")]
    posix_mapping_bundle: Option<String>,

    /// Path to the JWK Set file containing the mapping-authority
    /// public key(s) used to verify --posix-mapping-bundle. Typically
    /// a slice of the SPIFFE trust bundle filtered to JWKs whose
    /// `use` field equals "p9n-mapping". MUST be set when
    /// --posix-mapping-bundle is set.
    #[arg(long, value_name = "PATH")]
    posix_mapping_jwks: Option<String>,

    /// Enable per-fid rate limiting via Tratelimit
    #[arg(long)]
    enable_rate_limit: bool,

    /// Allow Tattach from peers without a SPIFFE identity.
    ///
    /// By default (and recommended for any multi-tenant deployment),
    /// anonymous peers are rejected at attach time because per-workload
    /// root isolation requires a SPIFFE identity to derive the correct
    /// subtree. Enable only for legacy single-tenant deployments where
    /// SPIFFE auth is intentionally not used.
    #[arg(long)]
    allow_anonymous: bool,

    /// Maximum OS threads for blocking filesystem I/O (default: 256).
    /// Each thread uses ~8 MB stack. Tune up for NFS/high-concurrency,
    /// down for memory-constrained environments.
    #[arg(long, default_value = "256")]
    blocking_threads: usize,

    /// SPIRE Agent socket path for SPIFFE Workload API
    /// (e.g., /run/spire/agent.sock). When set, --cert/--key/--ca are not required.
    #[cfg(feature = "workload-api")]
    #[arg(long, value_name = "PATH")]
    spiffe_agent_socket: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init();
    let args = Args::parse();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(args.blocking_threads)
        .build()?;

    rt.block_on(async_main(args))
}

async fn async_main(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let auth = load_auth(&args).await?;
    load_jwt_keys(&auth, &args.jwt_keys)?;

    let identity = auth.identity.clone();
    let trust_store = auth.trust_store.clone();

    let mut config = p9n_exporter::config::ExporterConfig::default();
    config.enable_rate_limit = args.enable_rate_limit;
    config.max_blocking_threads = args.blocking_threads;
    config.allow_anonymous_attach = args.allow_anonymous;

    // Load (and verify) the POSIX mapping bundle before constructing the
    // exporter so any failure is fail-closed and surfaces before we bind
    // the listening sockets.
    let mapping_state = load_posix_mapping(&args, &identity)?;

    let mut exporter =
        p9n_exporter::exporter::Exporter::with_config(args.listen, args.export, auth, config)?;

    if let Some(state) = mapping_state {
        exporter.set_posix_mapping(std::sync::Arc::new(state));
    }

    if let Some(tcp_addr) = args.tcp_listen {
        exporter
            .enable_tcp(tcp_addr, &identity, &trust_store)
            .await?;
    }

    #[cfg(feature = "rdma")]
    if let Some(rdma_addr) = args.rdma_listen {
        exporter
            .enable_rdma(rdma_addr, &identity, &trust_store, args.rdma_device)
            .await?;
    }

    tracing::info!(
        blocking_threads = args.blocking_threads,
        "tokio runtime configured"
    );

    exporter.run().await
}

// ── Initialization ──

fn init() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");
    p9n_exporter::logging::init();
}

// ── Authentication ──

async fn load_auth(args: &Args) -> Result<p9n_auth::SpiffeAuth, Box<dyn std::error::Error>> {
    #[cfg(feature = "workload-api")]
    if let Some(ref socket) = args.spiffe_agent_socket {
        return Ok(p9n_auth::SpiffeAuth::from_workload_api(socket)
            .await
            .map_err(|e| format!("workload API: {e}"))?);
    }
    Ok(
        p9n_auth::SpiffeAuth::from_pem_files(&args.cert, &args.key, &args.ca)
            .map_err(|e| format!("auth: {e}"))?,
    )
}

// ── JWT trust bundles ──

// ── POSIX mapping bundle ──

fn load_posix_mapping(
    args: &Args,
    identity: &p9n_auth::spiffe::SpiffeIdentity,
) -> Result<Option<p9n_exporter::posix_mapping_state::PosixMappingState>, Box<dyn std::error::Error>>
{
    match (&args.posix_mapping_bundle, &args.posix_mapping_jwks) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => {
            Err("--posix-mapping-bundle and --posix-mapping-jwks must be set together".into())
        }
        (Some(bundle), Some(jwks)) => {
            let state = p9n_exporter::posix_mapping_state::PosixMappingState::load_from_files(
                std::path::Path::new(bundle),
                std::path::Path::new(jwks),
                &identity.trust_domain,
            )
            .map_err(|e| format!("posix-mapping bundle: {e}"))?;
            Ok(Some(state))
        }
    }
}

fn load_jwt_keys(
    auth: &p9n_auth::SpiffeAuth,
    entries: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in entries {
        let (domain, path) = entry
            .split_once('=')
            .ok_or_else(|| format!("invalid --jwt-keys format: {entry} (expected domain=path)"))?;
        let json = std::fs::read(path).map_err(|e| format!("read JWK file {path}: {e}"))?;
        let jwk_set = p9n_auth::spiffe::jwt_svid::JwkSet::from_json(&json)
            .map_err(|e| format!("parse JWK file {path}: {e}"))?;
        auth.trust_store.set_jwt_keys(domain, jwk_set);
        tracing::info!("loaded JWT JWK Set for domain: {domain}");
    }
    Ok(())
}
