use clap::Parser;
use fuse3::raw::Session;
use fuse3::MountOptions;
use p9n_importer::fuse::filesystem::P9Filesystem;
use p9n_importer::rpc_client::{RpcClient, Transport};
use p9n_importer::shutdown::ShutdownHandle;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};

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

    /// Transport protocol: "quic", "tcp", or "rdma"
    #[arg(long, default_value = "quic")]
    transport: String,

    /// RDMA device name (auto-detect if not set)
    #[cfg(feature = "rdma")]
    #[arg(long)]
    rdma_device: Option<String>,

    /// Username for attach (default: current user or "nobody")
    #[arg(long)]
    uname: Option<String>,

    /// Attach name (remote path)
    #[arg(long, default_value = "")]
    aname: String,

    /// Maximum OS threads for blocking I/O (default: 64)
    #[arg(long, default_value = "64")]
    blocking_threads: usize,

    /// SPIRE Agent socket path for SPIFFE Workload API
    /// (e.g., /run/spire/agent.sock). When set, --cert/--key/--ca are not required.
    #[cfg(feature = "workload-api")]
    #[arg(long, value_name = "PATH")]
    spiffe_agent_socket: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init();
    let args = Args::parse();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(args.blocking_threads)
        .build()?;

    rt.block_on(async_main(args))
}

async fn async_main(args: Args) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let auth = load_auth(&args).await?;
    let identity = auth.identity.clone();
    let trust_store = auth.trust_store.clone();

    let mut importer = connect(&args, auth).await?;

    let endpoint = importer.endpoint.take();
    let transport = match args.transport.as_str() {
        "tcp" => Transport::Tcp,
        #[cfg(feature = "rdma")]
        "rdma" => Transport::Rdma,
        _ => Transport::Quic,
    };

    // Build the reconnecting RPC client. The push_tx is shared: on reconnect
    // a clone is passed to the new QuicRpcClient/TcpRpcClient, so the push
    // receiver task keeps working across reconnections without restarting.
    let initial_conn_id = importer.rpc.conn_id();
    let rpc = Arc::new(RpcClient::new(
        importer.rpc.clone(),
        transport,
        endpoint.clone(),
        args.exporter.clone(),
        args.hostname.clone(),
        importer.push_tx.clone(),
        identity,
        trust_store,
        initial_conn_id,
    ));

    let (fs, shutdown_handle) = P9Filesystem::new(rpc, importer);
    let mut mount_handle = mount(fs, &args.mount).await?;

    let fuse_exited = serve(&mut mount_handle).await;
    shutdown(fuse_exited, mount_handle, shutdown_handle, endpoint, &args.mount).await;

    Ok(())
}

// ── Initialization ──

fn init() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");
    p9n_importer::logging::init();
}

// ── Authentication ──

async fn load_auth(
    args: &Args,
) -> Result<p9n_auth::SpiffeAuth, Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(feature = "workload-api")]
    if let Some(ref socket) = args.spiffe_agent_socket {
        return Ok(p9n_auth::SpiffeAuth::from_workload_api(socket).await?);
    }
    Ok(p9n_auth::SpiffeAuth::from_pem_files(&args.cert, &args.key, &args.ca)?)
}

// ── Transport ──

async fn connect(
    args: &Args,
    auth: p9n_auth::SpiffeAuth,
) -> Result<p9n_importer::importer::Importer, Box<dyn std::error::Error + Send + Sync>> {
    match args.transport.as_str() {
        "tcp" => {
            p9n_importer::importer::Importer::connect_tcp(
                &args.exporter, &args.hostname, auth,
            ).await
        }
        #[cfg(feature = "rdma")]
        "rdma" => {
            p9n_importer::importer::Importer::connect_rdma(
                &args.exporter, &args.hostname, auth,
                args.rdma_device.as_deref(),
            ).await
        }
        _ => {
            p9n_importer::importer::Importer::connect_quic(
                &args.exporter, &args.hostname, auth,
            ).await
        }
    }
}

// ── FUSE mount ──

async fn mount(
    fs: P9Filesystem,
    path: &str,
) -> Result<fuse3::raw::MountHandle, Box<dyn std::error::Error + Send + Sync>> {
    let mut mount_options = MountOptions::default();
    mount_options.fs_name("9p");

    let euid = unsafe { libc::geteuid() };
    let privileged = euid == 0;
    tracing::info!(path, euid, privileged, "FUSE mounting");

    let session = Session::new(mount_options);
    // root can mount directly via /dev/fuse; non-root needs fusermount3
    let handle = if privileged {
        session.mount(fs, path).await?
    } else {
        session.mount_with_unprivileged(fs, path).await?
    };
    tracing::info!(path, "FUSE mount succeeded");
    Ok(handle)
}

// ── Serve (wait for FUSE session or signal) ──

/// Returns `true` if the FUSE session ended on its own (external unmount or error).
async fn serve(mount_handle: &mut fuse3::raw::MountHandle) -> bool {
    let mut sigterm = signal(SignalKind::terminate())
        .expect("failed to register SIGTERM handler");

    tokio::select! {
        res = mount_handle => {
            if let Err(e) = res {
                tracing::error!("FUSE session error: {e}");
            }
            true
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received SIGINT, shutting down...");
            false
        }
        _ = sigterm.recv() => {
            tracing::info!("received SIGTERM, shutting down...");
            false
        }
    }
}

// ── Graceful shutdown ──

async fn shutdown(
    fuse_exited: bool,
    mount_handle: fuse3::raw::MountHandle,
    shutdown_handle: ShutdownHandle,
    endpoint: Option<quinn::Endpoint>,
    mount_path: &str,
) {
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        if !fuse_exited {
            tracing::info!("unmounting {mount_path}...");
            if let Err(e) = mount_handle.unmount().await {
                tracing::warn!("FUSE unmount error: {e}");
            }
        }

        shutdown_handle.run().await;

        if let Some(ep) = endpoint {
            ep.wait_idle().await;
        }
    })
    .await;

    match result {
        Ok(()) => tracing::info!("clean shutdown complete"),
        Err(_) => tracing::warn!("shutdown timed out after 10s"),
    }
}
