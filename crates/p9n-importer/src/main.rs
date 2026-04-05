use clap::Parser;
use fuse3::raw::Session;
use fuse3::MountOptions;

#[derive(Parser)]
#[command(name = "p9n-importer", about = "9P2000.N file importer")]
struct Args {
    /// Exporter address (host:port)
    #[arg(short, long)]
    exporter: String,

    /// Mount point
    #[arg(short, long)]
    mount: String,

    /// Server hostname for TLS SNI
    #[arg(long, default_value = "localhost")]
    hostname: String,

    /// SPIFFE certificate (PEM)
    #[arg(long)]
    cert: String,

    /// Private key (PEM)
    #[arg(long)]
    key: String,

    /// CA bundle (PEM)
    #[arg(long)]
    ca: String,

    /// Transport protocol: "quic" or "tcp" (TLS)
    #[arg(long, default_value = "quic")]
    transport: String,

    /// Username for attach (default: current user or "nobody")
    #[arg(long)]
    uname: Option<String>,

    /// Attach name (remote path)
    #[arg(long, default_value = "")]
    aname: String,

    /// SPIRE Agent socket path for SPIFFE Workload API
    /// (e.g., /run/spire/agent.sock). When set, --cert/--key/--ca are not required.
    #[cfg(feature = "workload-api")]
    #[arg(long, value_name = "PATH")]
    spiffe_agent_socket: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    #[cfg(feature = "workload-api")]
    let auth = if let Some(ref socket) = args.spiffe_agent_socket {
        p9n_auth::SpiffeAuth::from_workload_api(socket).await?
    } else {
        p9n_auth::SpiffeAuth::from_pem_files(&args.cert, &args.key, &args.ca)?
    };
    #[cfg(not(feature = "workload-api"))]
    let auth = p9n_auth::SpiffeAuth::from_pem_files(&args.cert, &args.key, &args.ca)?;

    let importer = if args.transport == "tcp" {
        p9n_importer::importer::Importer::connect_tcp(
            &args.exporter, &args.hostname, auth,
        ).await?
    } else {
        p9n_importer::importer::Importer::connect(
            &args.exporter, &args.hostname, auth,
        ).await?
    };

    let fs = p9n_importer::fuse::filesystem::P9Filesystem::new(importer);

    let mut mount_options = MountOptions::default();
    mount_options.fs_name("9p");

    tracing::info!("mounting at {}", args.mount);

    let mut mount_handle = Session::new(mount_options)
        .mount_with_unprivileged(fs, &args.mount)
        .await?;

    tokio::select! {
        res = &mut mount_handle => {
            if let Err(e) = res {
                tracing::error!("FUSE session error: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("unmounting...");
        }
    }

    Ok(())
}
