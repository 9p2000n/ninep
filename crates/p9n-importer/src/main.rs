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

    /// Path to the JWK Set containing the mapping-authority public
    /// key(s) used to verify the signed POSIX mapping bundle (see
    /// docs/POSIX_IDENTITY.md §6.2). When set, the importer fetches
    /// the bundle from the exporter via Tfetchbundle after mTLS and
    /// uses its own SPIFFE ID's entry to derive (uid, gid, groups).
    /// When unset, the importer runs without a resolved POSIX
    /// identity (`stat` returns whatever uid/gid the exporter wrote).
    #[arg(long, value_name = "PATH")]
    posix_mapping_jwks: Option<String>,

    /// Fail at startup if the mapping bundle does not produce a POSIX
    /// identity for the importer's own SPIFFE ID. Implies
    /// `--posix-mapping-jwks` must be set.
    #[arg(long)]
    require_posix_mapping: bool,

    /// Drop privileges to the bundle-derived `(uid, gid, groups)`
    /// before mounting FUSE. Requires the importer to start as root
    /// or with `CAP_SETUID`/`CAP_SETGID` and `--posix-mapping-jwks`
    /// to be set. Irreversible.
    #[arg(long)]
    setuid_from_mapping: bool,
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

    // Optional: load the JWK Set used to verify a signed mapping bundle
    // fetched from the exporter post-mTLS. Loading at startup means a
    // missing or malformed JWK file fails fast, before any network I/O.
    let mapping_jwks = load_mapping_jwks(args.posix_mapping_jwks.as_deref())?;

    let mut importer = connect(&args, auth).await?;

    // Resolve the importer's POSIX identity from the signed mapping
    // bundle (fetched via Tfetchbundle after mTLS). The doc (§7.1)
    // places Tfetchbundle before Tattach; in this implementation
    // Tattach is already inside connect(). The deviation is safe
    // because Tattach is SVID-authenticated, not uid-authenticated:
    // the importer's pre-setuid uid does not affect server-side
    // identity resolution.
    let posix = resolve_posix_identity(
        &args,
        &identity,
        mapping_jwks.as_ref(),
        &importer,
    )
    .await?;

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

    let posix_gid = posix.as_ref().map(|p| p.gid);
    let (fs, shutdown_handle) = P9Filesystem::new(rpc, importer, posix_gid);

    // Drop privileges *before* the FUSE mount. After the transition, the
    // mount() path falls through to the unprivileged `fusermount3` helper
    // because euid is no longer 0. See docs/POSIX_IDENTITY.md §7.1.
    if args.setuid_from_mapping {
        let p = posix.as_ref().expect(
            "resolve_posix_identity guarantees Some when --setuid-from-mapping is set",
        );
        p9n_importer::posix_bootstrap::apply_setuid(p)
            .map_err(|e| format!("setuid bootstrap failed: {e}"))?;
    }

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

// ── POSIX identity resolution ──

fn load_mapping_jwks(
    path: Option<&str>,
) -> Result<Option<p9n_auth::spiffe::jwt_svid::JwkSet>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(path) = path else { return Ok(None) };
    let bytes = std::fs::read(path)
        .map_err(|e| format!("read --posix-mapping-jwks {path}: {e}"))?;
    let jwks = p9n_auth::spiffe::jwt_svid::JwkSet::from_json(&bytes)
        .map_err(|e| format!("parse --posix-mapping-jwks {path}: {e}"))?;
    tracing::info!(path, keys = jwks.keys.len(), "loaded mapping-bundle JWK Set");
    Ok(Some(jwks))
}

/// Resolve `(uid, gid, groups)` for the importer's own SPIFFE ID by
/// fetching the signed mapping bundle from the exporter.
///
/// - With no JWK Set configured (`--posix-mapping-jwks` unset),
///   returns `Ok(None)`. `--require-posix-mapping` or
///   `--setuid-from-mapping` then surface this as a startup error.
/// - With a JWK Set: a Tfetchbundle failure (e.g. exporter has no
///   bundle loaded for our trust domain) is treated as `None`.
/// - A bundle that fetches but fails verification is fatal — never
///   silently downgraded to "fall through", since a signed-but-
///   invalid bundle is a security event.
async fn resolve_posix_identity(
    args: &Args,
    identity: &p9n_auth::spiffe::SpiffeIdentity,
    jwks: Option<&p9n_auth::spiffe::jwt_svid::JwkSet>,
    importer: &p9n_importer::importer::Importer,
) -> Result<Option<p9n_auth::PosixIdentity>, Box<dyn std::error::Error + Send + Sync>> {
    let mut posix: Option<p9n_auth::PosixIdentity> = None;

    if let Some(jwks) = jwks {
        match importer
            .fetch_posix_mapping_bundle(&identity.trust_domain)
            .await
        {
            Ok(jws_bytes) => {
                let now = unix_now();
                match p9n_importer::posix_bootstrap::extract_from_bundle(
                    &identity.spiffe_id,
                    &jws_bytes,
                    jwks,
                    &identity.trust_domain,
                    now,
                ) {
                    Ok(Some(p)) => {
                        tracing::info!(
                            uid = p.uid,
                            gid = p.gid,
                            spiffe_id = %identity.spiffe_id,
                            "POSIX identity resolved from mapping bundle",
                        );
                        posix = Some(p);
                    }
                    Ok(None) => {
                        tracing::warn!(
                            spiffe_id = %identity.spiffe_id,
                            trust_domain = %identity.trust_domain,
                            "mapping bundle has no entry for this SPIFFE ID",
                        );
                    }
                    Err(e) => {
                        // Verified-but-invalid is a security event —
                        // never silently downgrade. Caller exits.
                        return Err(format!("mapping bundle verification: {e}").into());
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "exporter has no POSIX mapping bundle for our trust domain",
                );
            }
        }
    }

    if posix.is_none() && (args.require_posix_mapping || args.setuid_from_mapping) {
        return Err(format!(
            "--{} requires a bundle-resolved POSIX identity",
            if args.setuid_from_mapping {
                "setuid-from-mapping"
            } else {
                "require-posix-mapping"
            },
        )
        .into());
    }

    Ok(posix)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
