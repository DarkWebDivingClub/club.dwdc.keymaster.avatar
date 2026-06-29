use anyhow::Result;
use avatar_protocol::{read_line_message, write_line_message, JsonRpcRequest, JsonRpcResponse};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(2); // start at 2; 1 is used by connect

fn next_request_id() -> u64 {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[derive(Parser, Debug)]
#[command(
    name = "km-gpg-sa",
    version,
    about = "GPG Service Avatar - GPG environment setup and Assuan-to-JSON-RPC proxy"
)]
struct Cli {
    /// Path to TOML config file
    #[arg(long)]
    config: Option<PathBuf>,

    /// Avatar local API socket path
    #[arg(long, default_value = "/tmp/keymaster-avatar.sock")]
    avatar_socket: PathBuf,

    /// GPG proxy socket path (scd-shim connects here)
    #[arg(long, default_value = "/tmp/keymaster-avatar-gpg.sock")]
    gpg_socket: PathBuf,

    /// GnuPG home directory
    #[arg(long, env = "GNUPGHOME", default_value = "/tmp/gnupg-home")]
    gnupg_home: PathBuf,

    /// Path to scd-shim binary (used in gpg-agent.conf).
    /// Requires a symlink or absolute path; gpg-agent won't resolve PATH.
    #[arg(long)]
    scdaemon_program: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Deserialize, Default)]
struct Config {
    avatar_socket: Option<PathBuf>,
    gpg_socket: Option<PathBuf>,
    gnupg_home: Option<PathBuf>,
    scdaemon_program: Option<PathBuf>,
    log_level: Option<String>,
}

/// Resolve the scd-shim binary path.
///
/// Search order:
/// 1. `--scdaemon-program` CLI flag
/// 2. `scdaemon_program` from config file
/// 3. Sibling of the current executable
/// 4. Fallback: `/usr/local/bin/scd-shim`
fn resolve_scdaemon_program(cli_value: Option<&str>, config_value: Option<&std::path::Path>) -> PathBuf {
    // 1. CLI flag
    if let Some(v) = cli_value {
        return PathBuf::from(v);
    }

    // 2. Config
    if let Some(v) = config_value {
        return v.to_path_buf();
    }

    // 3. Sibling
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let path = dir.join("scd-shim");
            if path.exists() {
                return path;
            }
        }
    }

    // 4. Legacy fallback
    PathBuf::from("/usr/local/bin/scd-shim")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load config file (CLI > config > default)
    let config: Config = avatar_protocol::config::load_config(
        "km-gpg-sa",
        cli.config.as_deref(),
    )
    .unwrap_or_default();

    let log_level = if cli.log_level != "info" {
        cli.log_level.clone()
    } else {
        config.log_level.unwrap_or_else(|| cli.log_level.clone())
    };
    let avatar_socket = if cli.avatar_socket != PathBuf::from("/tmp/keymaster-avatar.sock") {
        cli.avatar_socket.clone()
    } else {
        config
            .avatar_socket
            .unwrap_or_else(|| cli.avatar_socket.clone())
    };
    let gpg_socket = if cli.gpg_socket != PathBuf::from("/tmp/keymaster-avatar-gpg.sock") {
        cli.gpg_socket.clone()
    } else {
        config
            .gpg_socket
            .unwrap_or_else(|| cli.gpg_socket.clone())
    };
    let gnupg_home = if cli.gnupg_home != PathBuf::from("/tmp/gnupg-home") {
        cli.gnupg_home.clone()
    } else {
        config
            .gnupg_home
            .unwrap_or_else(|| cli.gnupg_home.clone())
    };
    let scdaemon_program = resolve_scdaemon_program(
        cli.scdaemon_program.as_deref(),
        config.scdaemon_program.as_deref(),
    );

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log_level)),
        )
        .init();

    // Step 1: Connect to avatar local API
    info!(
        "Connecting to avatar local API: {}",
        avatar_socket.display()
    );
    let avatar_stream = UnixStream::connect(&avatar_socket).await?;
    let (reader, mut avatar_writer) = avatar_stream.into_split();
    let mut avatar_reader = BufReader::new(reader);
    info!("Connected to avatar local API");

    // Send connect message (JSON-RPC 2.0)
    let connect_req = JsonRpcRequest::new(
        "connect",
        serde_json::json!({
            "type": "gpg",
        }),
        1,
    );
    write_line_message(&mut avatar_writer, &connect_req).await?;
    let connect_resp: JsonRpcResponse = read_line_message(&mut avatar_reader).await?;
    if connect_resp.error.is_some() {
        let err = connect_resp.error.unwrap();
        anyhow::bail!("connect failed: {} (code {})", err.message, err.code);
    }
    info!("Connected to avatar, service type: gpg");

    // Step 2: Fetch GPG public cert from avatar
    info!("Fetching GPG public cert from avatar...");
    let cert_req = JsonRpcRequest::new(
        "gpg.get_public_cert",
        serde_json::json!({}),
        next_request_id(),
    );
    let cert_resp = send_and_receive(&mut avatar_writer, &mut avatar_reader, &cert_req).await?;
    let cert_armor = cert_resp
        .result
        .as_ref()
        .and_then(|r| r.get("public_cert_armor"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing public_cert_armor in response"))?
        .to_string();
    info!("Got GPG public cert ({} bytes)", cert_armor.len());

    // Step 3: Setup GNUPGHOME
    let scdaemon_str = scdaemon_program.to_string_lossy().to_string();
    setup_gnupg_home(&gnupg_home, &cert_armor, &scdaemon_str, &gpg_socket)?;
    info!("GNUPGHOME configured at {}", gnupg_home.display());

    // Step 4: Start proxy listener BEFORE LEARN (scd-shim connects back during LEARN)
    let avatar_writer = Arc::new(Mutex::new(avatar_writer));
    let avatar_reader = Arc::new(Mutex::new(avatar_reader));

    // Remove stale socket if it exists
    let _ = std::fs::remove_file(&gpg_socket);
    let listener = UnixListener::bind(&gpg_socket)?;
    info!("GPG proxy listening on: {}", gpg_socket.display());

    let proxy_writer = avatar_writer.clone();
    let proxy_reader = avatar_reader.clone();
    let proxy_handle = tokio::spawn(async move {
        proxy_loop(listener, proxy_writer, proxy_reader).await;
    });

    // Step 5: Kill stale gpg-agent
    info!("Killing stale gpg-agent...");
    let kill_status = tokio::process::Command::new("gpgconf")
        .arg("--homedir")
        .arg(&gnupg_home)
        .arg("--kill")
        .arg("gpg-agent")
        .status()
        .await;
    debug!("gpgconf --kill gpg-agent: {:?}", kill_status);

    // Step 6: LEARN — triggers gpg-agent → scd-shim → connects to our proxy
    info!("Running SCD LEARN...");
    let learn_output = tokio::process::Command::new("gpg-connect-agent")
        .arg("--homedir")
        .arg(&gnupg_home)
        .arg("LEARN --sendinfo --force")
        .arg("/bye")
        .output()
        .await?;
    if !learn_output.status.success() {
        let stderr = String::from_utf8_lossy(&learn_output.stderr);
        let stdout = String::from_utf8_lossy(&learn_output.stdout);
        warn!(
            "SCD LEARN exited with {}: stdout={}, stderr={}",
            learn_output.status, stdout, stderr
        );
    } else {
        info!("SCD LEARN completed successfully");
    }

    // Step 7: Import cert
    info!("Importing GPG public cert...");
    let cert_path = gnupg_home.join("keymaster-public.asc");
    let import_output = tokio::process::Command::new("gpg")
        .arg("--homedir")
        .arg(&gnupg_home)
        .arg("--batch")
        .arg("--import")
        .arg(&cert_path)
        .output()
        .await?;
    if !import_output.status.success() {
        let stderr = String::from_utf8_lossy(&import_output.stderr);
        warn!("GPG import failed: {}", stderr);
    } else {
        info!("GPG cert imported");
    }

    // Step 8: Set ownertrust to ultimate
    info!("Setting ownertrust...");
    let ownertrust_output = tokio::process::Command::new("bash")
        .arg("-c")
        .arg(format!(
            "gpg --homedir {} --batch --with-colons --list-keys 2>/dev/null \
             | awk -F: '/^fpr:/{{print $10 \":6:\"}}' \
             | gpg --homedir {} --batch --import-ownertrust",
            gnupg_home.display(),
            gnupg_home.display()
        ))
        .output()
        .await?;
    if !ownertrust_output.status.success() {
        let stderr = String::from_utf8_lossy(&ownertrust_output.stderr);
        warn!("ownertrust import failed: {}", stderr);
    } else {
        info!("Ownertrust set to ultimate");
    }

    // Step 8.5: Create shadow key stubs in private-keys-v1.d/
    info!("Creating shadow key stubs...");
    let privkeys_dir = gnupg_home.join("private-keys-v1.d");
    std::fs::create_dir_all(&privkeys_dir)?;

    let list_output = tokio::process::Command::new("gpg")
        .arg("--homedir")
        .arg(&gnupg_home)
        .arg("--batch")
        .arg("--with-colons")
        .arg("--with-keygrip")
        .arg("--list-keys")
        .output()
        .await?;

    if list_output.status.success() {
        let stdout = String::from_utf8_lossy(&list_output.stdout);
        for line in stdout.lines() {
            if line.starts_with("grp:") {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() > 9 {
                    let keygrip = fields[9];
                    if keygrip.len() == 40 {
                        let stub_path = privkeys_dir.join(format!("{}.key", keygrip));
                        if !stub_path.exists() {
                            std::fs::write(&stub_path, "(shadowed-private-key)\n")?;
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                std::fs::set_permissions(
                                    &stub_path,
                                    std::fs::Permissions::from_mode(0o600),
                                )?;
                            }
                            info!("Created stub: {}.key", keygrip);
                        }
                    }
                }
            }
        }
    }

    // Restart gpg-agent to pick up stubs, then re-learn card keys
    let _ = tokio::process::Command::new("gpgconf")
        .arg("--homedir")
        .arg(&gnupg_home)
        .arg("--kill")
        .arg("gpg-agent")
        .status()
        .await;

    let learn2 = tokio::process::Command::new("gpg-connect-agent")
        .arg("--homedir")
        .arg(&gnupg_home)
        .arg("LEARN --sendinfo --force")
        .arg("/bye")
        .output()
        .await?;
    if learn2.status.success() {
        info!("Re-learned card keys after stub creation");
    } else {
        warn!(
            "Re-learn failed: {}",
            String::from_utf8_lossy(&learn2.stderr)
        );
    }

    // Step 9: Ready
    info!("GPG ready — proxy active on {}", gpg_socket.display());

    // Step 10: Wait for proxy to end (killed by avatar kill_on_drop)
    let _ = proxy_handle.await;

    // Cleanup on shutdown
    info!("Shutting down, killing gpg-agent...");
    let _ = tokio::process::Command::new("gpgconf")
        .arg("--homedir")
        .arg(&gnupg_home)
        .arg("--kill")
        .arg("gpg-agent")
        .status()
        .await;
    let _ = std::fs::remove_file(&gpg_socket);

    Ok(())
}

/// Set up GNUPGHOME with config files for gpg-agent + scd-shim.
fn setup_gnupg_home(
    gnupg_home: &std::path::Path,
    cert_armor: &str,
    scdaemon_program: &str,
    gpg_socket: &std::path::Path,
) -> Result<()> {
    // Create directory with restricted permissions
    std::fs::create_dir_all(gnupg_home)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(gnupg_home, std::fs::Permissions::from_mode(0o700))?;
    }

    // Write public cert
    let cert_path = gnupg_home.join("keymaster-public.asc");
    std::fs::write(&cert_path, cert_armor)?;
    info!("Wrote cert to {}", cert_path.display());

    // Write gpg-agent.conf
    let agent_conf = format!(
        "scdaemon-program {}\n\
         allow-loopback-pinentry\n\
         pinentry-program {}/pinentry-iz.sh\n\
         log-file {}/gpg-agent.log\n\
         verbose\n",
        scdaemon_program,
        gnupg_home.display(),
        gnupg_home.display(),
    );
    std::fs::write(gnupg_home.join("gpg-agent.conf"), &agent_conf)?;
    info!("Wrote gpg-agent.conf");

    // Write dummy pinentry script
    let pinentry = "#!/bin/bash\n\
        echo \"OK Pleased to meet you\"\n\
        while IFS= read -r cmd; do\n\
          case \"${cmd%% *}\" in\n\
            GETPIN) echo \"D\"; echo \"OK\";;\n\
            BYE) echo \"OK\"; exit 0;;\n\
            *) echo \"OK\";;\n\
          esac\n\
        done\n";
    let pinentry_path = gnupg_home.join("pinentry-iz.sh");
    std::fs::write(&pinentry_path, pinentry)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pinentry_path, std::fs::Permissions::from_mode(0o755))?;
    }
    info!("Wrote pinentry-iz.sh");

    // Write socket path file for scd-shim to discover
    let socket_file = gnupg_home.join("km-gpg-sa.socket");
    std::fs::write(&socket_file, gpg_socket.to_string_lossy().as_bytes())?;
    info!("Wrote km-gpg-sa.socket ({})", gpg_socket.display());

    Ok(())
}

/// Proxy loop: accept connections from scd-shim, forward JSON-RPC to avatar.
async fn proxy_loop(
    listener: UnixListener,
    avatar_writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    avatar_reader: Arc<Mutex<BufReader<tokio::net::unix::OwnedReadHalf>>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                debug!("Accepted proxy connection from scd-shim");
                let w = avatar_writer.clone();
                let r = avatar_reader.clone();
                tokio::spawn(handle_shim_connection(stream, w, r));
            }
            Err(e) => {
                error!("Proxy accept error: {}", e);
                break;
            }
        }
    }
}

/// Handle a single scd-shim connection: read JSON-RPC requests, forward to
/// avatar, return responses. Requests are serial within a connection.
async fn handle_shim_connection(
    stream: UnixStream,
    avatar_writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    avatar_reader: Arc<Mutex<BufReader<tokio::net::unix::OwnedReadHalf>>>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    loop {
        // Read one JSON-RPC request from scd-shim
        let request: JsonRpcRequest = match read_line_message(&mut reader).await {
            Ok(req) => req,
            Err(e) => {
                debug!("Shim connection closed: {}", e);
                break;
            }
        };

        debug!("Proxy: {} (id={:?})", request.method, request.id);

        // Forward to avatar (serialized access via mutex)
        let response: JsonRpcResponse = {
            let mut aw = avatar_writer.lock().await;
            let mut ar = avatar_reader.lock().await;
            match send_and_receive_locked(&mut aw, &mut ar, &request).await {
                Ok(resp) => resp,
                Err(e) => {
                    error!("Proxy forward error: {}", e);
                    let id = request.id.unwrap_or(serde_json::Value::Null);
                    JsonRpcResponse::error(id, -32603, format!("proxy error: {}", e))
                }
            }
        };

        // Send response back to scd-shim
        if let Err(e) = write_line_message(&mut writer, &response).await {
            error!("Proxy write error: {}", e);
            break;
        }
    }
}

/// Send a JSON-RPC request and wait for the response (unlocked variant for startup).
async fn send_and_receive(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    req: &JsonRpcRequest,
) -> Result<JsonRpcResponse> {
    write_line_message(writer, req).await?;
    let resp: JsonRpcResponse = read_line_message(reader).await?;
    Ok(resp)
}

/// Send a JSON-RPC request and wait for the response (locked variant for proxy).
async fn send_and_receive_locked(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    req: &JsonRpcRequest,
) -> Result<JsonRpcResponse> {
    write_line_message(writer, req).await?;
    let resp: JsonRpcResponse = read_line_message(reader).await?;
    Ok(resp)
}
