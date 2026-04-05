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

    /// Enable per-fid rate limiting via Tratelimit
    #[arg(long)]
    enable_rate_limit: bool,

    /// SPIRE Agent socket path for SPIFFE Workload API
    /// (e.g., /run/spire/agent.sock). When set, --cert/--key/--ca are not required.
    #[cfg(feature = "workload-api")]
    #[arg(long, value_name = "PATH")]
    spiffe_agent_socket: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    #[cfg(feature = "workload-api")]
    let auth = if let Some(ref socket) = args.spiffe_agent_socket {
        p9n_auth::SpiffeAuth::from_workload_api(socket).await
            .map_err(|e| format!("workload API: {e}"))?
    } else {
        p9n_auth::SpiffeAuth::from_pem_files(&args.cert, &args.key, &args.ca)
            .map_err(|e| format!("auth: {e}"))?
    };
    #[cfg(not(feature = "workload-api"))]
    let auth = p9n_auth::SpiffeAuth::from_pem_files(&args.cert, &args.key, &args.ca)
        .map_err(|e| format!("auth: {e}"))?;

    // Load JWT JWK Sets for remote trust domains
    for entry in &args.jwt_keys {
        let (domain, path) = entry.split_once('=')
            .ok_or_else(|| format!("invalid --jwt-keys format: {entry} (expected domain=path)"))?;
        let json = std::fs::read(path)
            .map_err(|e| format!("read JWK file {path}: {e}"))?;
        let jwk_set = p9n_auth::spiffe::jwt_svid::JwkSet::from_json(&json)
            .map_err(|e| format!("parse JWK file {path}: {e}"))?;
        auth.trust_store.set_jwt_keys(domain, jwk_set);
        tracing::info!("loaded JWT JWK Set for domain: {domain}");
    }

    // Clone identity/trust_store before auth is consumed by Exporter::new()
    let identity = auth.identity.clone();
    let trust_store = auth.trust_store.clone();

    let mut config = p9n_exporter::config::ExporterConfig::default();
    config.enable_rate_limit = args.enable_rate_limit;

    let mut exporter = p9n_exporter::exporter::Exporter::with_config(
        args.listen, args.export, auth, config,
    )?;

    if let Some(tcp_addr) = args.tcp_listen {
        exporter.enable_tcp(tcp_addr, &identity, &trust_store).await?;
    }

    exporter.run().await
}
