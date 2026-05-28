use anyhow::Result;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

/// A request from the GPG agent to the Avatar main loop
#[derive(Debug)]
pub enum GpgAgentRequest {
    /// Fetch available keys from KM
    RequestKeys {
        reply: oneshot::Sender<RequestKeysReply>,
    },
    /// Sign a hash with a specific key
    PkSign {
        keygrip: String,
        hash_algo: u32,
        hash_hex: String,
        reply: oneshot::Sender<PkSignReply>,
    },
}

#[derive(Debug)]
pub struct RequestKeysReply {
    /// Each key: (keygrip, n_b64, e_b64)
    pub keys: Vec<GpgKeyInfo>,
}

#[derive(Debug, Clone)]
pub struct GpgKeyInfo {
    pub keygrip: String,
    pub n_b64: String,
    pub e_b64: String,
}

#[derive(Debug)]
pub struct PkSignReply {
    /// Raw RSA signature bytes
    pub signature: Option<Vec<u8>>,
}

/// Connection state for a single GPG agent client
struct ConnectionState {
    current_sigkey: Option<String>,
    current_hash_algo: Option<u32>,
    current_hash_hex: Option<String>,
    cached_keys: Option<Vec<GpgKeyInfo>>,
}

impl ConnectionState {
    fn new() -> Self {
        Self {
            current_sigkey: None,
            current_hash_algo: None,
            current_hash_hex: None,
            cached_keys: None,
        }
    }

    fn reset(&mut self) {
        self.current_sigkey = None;
        self.current_hash_algo = None;
        self.current_hash_hex = None;
    }
}

/// Start the GPG agent Unix socket listener.
/// Returns the socket path and a receiver for agent requests.
pub async fn start_gpg_agent(
    socket_path: &Path,
) -> Result<(PathBuf, mpsc::Receiver<GpgAgentRequest>)> {
    // Remove stale socket if it exists
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    info!("GPG agent listening on: {}", socket_path.display());

    let (tx, rx) = mpsc::channel::<GpgAgentRequest>(32);
    let path = socket_path.to_path_buf();

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    debug!("GPG agent: new connection");
                    let tx = tx.clone();
                    tokio::spawn(handle_gpg_connection(stream, tx));
                }
                Err(e) => {
                    error!("GPG agent accept error: {}", e);
                }
            }
        }
    });

    Ok((path, rx))
}

async fn handle_gpg_connection(
    stream: tokio::net::UnixStream,
    tx: mpsc::Sender<GpgAgentRequest>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut state = ConnectionState::new();

    // Send greeting
    if let Err(e) = writer
        .write_all(b"OK Pleased to meet you\n")
        .await
    {
        error!("GPG agent: write greeting error: {}", e);
        return;
    }

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                debug!("GPG agent: connection closed");
                return;
            }
            Ok(_) => {}
            Err(e) => {
                debug!("GPG agent: read error ({})", e);
                return;
            }
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        debug!("GPG agent: received: {}", trimmed);

        let response = handle_assuan_command(trimmed, &tx, &mut state).await;

        match response {
            AssuanResponse::Ok(msg) => {
                let resp = if msg.is_empty() {
                    "OK\n".to_string()
                } else {
                    format!("OK {}\n", msg)
                };
                if let Err(e) = writer.write_all(resp.as_bytes()).await {
                    error!("GPG agent: write error: {}", e);
                    return;
                }
            }
            AssuanResponse::Data(lines) => {
                for data_line in &lines {
                    let resp = format!("D {}\n", data_line);
                    if let Err(e) = writer.write_all(resp.as_bytes()).await {
                        error!("GPG agent: write error: {}", e);
                        return;
                    }
                }
                if let Err(e) = writer.write_all(b"OK\n").await {
                    error!("GPG agent: write error: {}", e);
                    return;
                }
            }
            AssuanResponse::Status(lines) => {
                for status_line in &lines {
                    let resp = format!("{}\n", status_line);
                    if let Err(e) = writer.write_all(resp.as_bytes()).await {
                        error!("GPG agent: write error: {}", e);
                        return;
                    }
                }
                if let Err(e) = writer.write_all(b"OK\n").await {
                    error!("GPG agent: write error: {}", e);
                    return;
                }
            }
            AssuanResponse::Error(code, msg) => {
                let resp = format!("ERR {} {}\n", code, msg);
                if let Err(e) = writer.write_all(resp.as_bytes()).await {
                    error!("GPG agent: write error: {}", e);
                    return;
                }
            }
            AssuanResponse::Bye => {
                let _ = writer.write_all(b"OK closing connection\n").await;
                return;
            }
        }
    }
}

enum AssuanResponse {
    Ok(String),
    Data(Vec<String>),
    /// Status lines (S <keyword> <data>) followed by OK
    Status(Vec<String>),
    Error(u32, &'static str),
    Bye,
}

async fn handle_assuan_command(
    line: &str,
    tx: &mpsc::Sender<GpgAgentRequest>,
    state: &mut ConnectionState,
) -> AssuanResponse {
    let parts: Vec<&str> = line.splitn(2, ' ').collect();
    let cmd = parts[0].to_uppercase();
    let args = if parts.len() > 1 { parts[1] } else { "" };

    match cmd.as_str() {
        "RESET" => {
            state.reset();
            AssuanResponse::Ok(String::new())
        }
        "OPTION" => {
            // Accept all options silently
            AssuanResponse::Ok(String::new())
        }
        "GETINFO" => {
            handle_getinfo(args)
        }
        "HAVEKEY" => {
            handle_havekey(args, tx, state).await
        }
        "KEYINFO" => {
            handle_keyinfo(args, tx, state).await
        }
        "SIGKEY" => {
            state.current_sigkey = Some(args.trim().to_string());
            debug!("GPG agent: SIGKEY set to {}", args.trim());
            AssuanResponse::Ok(String::new())
        }
        "SETHASH" => {
            handle_sethash(args, state)
        }
        "PKSIGN" => {
            handle_pksign(tx, state).await
        }
        "BYE" => {
            AssuanResponse::Bye
        }
        "SCD" => {
            // No smartcard daemon — return appropriate error
            AssuanResponse::Error(67108883, "No SmartCard daemon")
        }
        "AGENT_ID" | "SETKEYDESC" | "SETKEY" => {
            // Silently accept
            AssuanResponse::Ok(String::new())
        }
        _ => {
            warn!("GPG agent: unsupported command: {}", cmd);
            AssuanResponse::Error(276, "unknown IPC command")
        }
    }
}

fn handle_getinfo(args: &str) -> AssuanResponse {
    match args.trim() {
        "version" => AssuanResponse::Data(vec!["2.4.4".to_string()]),
        "pid" => AssuanResponse::Data(vec![std::process::id().to_string()]),
        "socket_name" => AssuanResponse::Data(vec!["/tmp/iz-avatar-gpg-agent.sock".to_string()]),
        _ => AssuanResponse::Ok(String::new()),
    }
}

async fn ensure_keys_cached(
    tx: &mpsc::Sender<GpgAgentRequest>,
    state: &mut ConnectionState,
) -> bool {
    if state.cached_keys.is_some() {
        return true;
    }

    let (reply_tx, reply_rx) = oneshot::channel();
    if tx.send(GpgAgentRequest::RequestKeys { reply: reply_tx }).await.is_err() {
        error!("GPG agent: channel closed");
        return false;
    }

    match tokio::time::timeout(std::time::Duration::from_secs(30), reply_rx).await {
        Ok(Ok(reply)) => {
            info!("GPG agent: cached {} keys from KM", reply.keys.len());
            state.cached_keys = Some(reply.keys);
            true
        }
        Ok(Err(_)) => {
            error!("GPG agent: reply channel dropped");
            false
        }
        Err(_) => {
            error!("GPG agent: timeout waiting for keys");
            false
        }
    }
}

async fn handle_havekey(
    args: &str,
    tx: &mpsc::Sender<GpgAgentRequest>,
    state: &mut ConnectionState,
) -> AssuanResponse {
    if !ensure_keys_cached(tx, state).await {
        return AssuanResponse::Error(1, "failed to fetch keys");
    }

    // Handle --list=N option: return binary keygrips as D line data.
    // GPG's agent_probe_any_secret_key reads binary 20-byte keygrips via DATA callback
    // and compares them with memcmp against keyring keygrips.
    if args.contains("--list") {
        if let Some(ref keys) = state.cached_keys {
            let mut binary_grips: Vec<u8> = Vec::new();
            for key in keys {
                if let Ok(bytes) = hex_to_bytes_keygrip(&key.keygrip) {
                    binary_grips.extend_from_slice(&bytes);
                }
            }
            info!("GPG agent: HAVEKEY --list → returning {} keys ({} bytes)", keys.len(), binary_grips.len());
            let encoded = percent_encode_sexp(&binary_grips);
            return AssuanResponse::Data(vec![encoded]);
        }
        return AssuanResponse::Ok(String::new());
    }

    let requested_keygrips: Vec<&str> = args.split_whitespace().collect();
    if let Some(ref keys) = state.cached_keys {
        let available: Vec<&str> = keys.iter().map(|k| k.keygrip.as_str()).collect();
        debug!("GPG agent: HAVEKEY requested={:?} available={:?}", requested_keygrips, available);
        for grip in &requested_keygrips {
            if keys.iter().any(|k| k.keygrip.eq_ignore_ascii_case(grip)) {
                info!("GPG agent: HAVEKEY {} → found", grip);
                return AssuanResponse::Ok(String::new());
            }
        }
    }

    info!("GPG agent: HAVEKEY {:?} → not found", requested_keygrips);
    AssuanResponse::Error(67108881, "No secret key")
}

async fn handle_keyinfo(
    args: &str,
    tx: &mpsc::Sender<GpgAgentRequest>,
    state: &mut ConnectionState,
) -> AssuanResponse {
    if !ensure_keys_cached(tx, state).await {
        return AssuanResponse::Error(1, "failed to fetch keys");
    }

    let requested_keygrip = args.split_whitespace().next().unwrap_or("").to_uppercase();
    if let Some(ref keys) = state.cached_keys {
        for key in keys {
            if key.keygrip.eq_ignore_ascii_case(&requested_keygrip) {
                // S KEYINFO <keygrip> D - - - P - - -
                let info_line = format!("S KEYINFO {} D - - - P - - -", key.keygrip);
                return AssuanResponse::Status(vec![info_line]);
            }
        }
    }

    AssuanResponse::Error(67108881, "No secret key")
}

fn handle_sethash(args: &str, state: &mut ConnectionState) -> AssuanResponse {
    // SETHASH <algo> <hex-hash>
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 2 {
        return AssuanResponse::Error(1, "invalid SETHASH arguments");
    }

    let algo: u32 = match parts[0].parse() {
        Ok(a) => a,
        Err(_) => return AssuanResponse::Error(1, "invalid hash algorithm"),
    };
    let hash_hex = parts[1].to_string();

    state.current_hash_algo = Some(algo);
    state.current_hash_hex = Some(hash_hex.clone());
    debug!("GPG agent: SETHASH algo={} hash={}", algo, hash_hex);

    AssuanResponse::Ok(String::new())
}

async fn handle_pksign(
    tx: &mpsc::Sender<GpgAgentRequest>,
    state: &mut ConnectionState,
) -> AssuanResponse {
    let keygrip = match &state.current_sigkey {
        Some(k) => k.clone(),
        None => return AssuanResponse::Error(1, "no key set (use SIGKEY first)"),
    };
    let hash_algo = match state.current_hash_algo {
        Some(a) => a,
        None => return AssuanResponse::Error(1, "no hash set (use SETHASH first)"),
    };
    let hash_hex = match &state.current_hash_hex {
        Some(h) => h.clone(),
        None => return AssuanResponse::Error(1, "no hash set"),
    };

    info!(
        "GPG agent: PKSIGN keygrip={} algo={} hash={}",
        keygrip, hash_algo, hash_hex
    );

    let (reply_tx, reply_rx) = oneshot::channel();
    if tx
        .send(GpgAgentRequest::PkSign {
            keygrip: keygrip.clone(),
            hash_algo,
            hash_hex: hash_hex.clone(),
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        error!("GPG agent: channel closed");
        return AssuanResponse::Error(1, "internal error");
    }

    match tokio::time::timeout(std::time::Duration::from_secs(30), reply_rx).await {
        Ok(Ok(reply)) => {
            match reply.signature {
                Some(sig_bytes) => {
                    info!("GPG agent: got signature ({} bytes)", sig_bytes.len());
                    // Build canonical S-expression: (7:sig-val(3:rsa(1:s<len>:<sig>)))
                    let sexp = build_sig_sexp(&sig_bytes);
                    // Percent-encode for Assuan D line
                    let encoded = percent_encode_sexp(&sexp);
                    AssuanResponse::Data(vec![encoded])
                }
                None => {
                    error!("GPG agent: signing failed");
                    AssuanResponse::Error(1, "signing failed")
                }
            }
        }
        Ok(Err(_)) => {
            error!("GPG agent: reply channel dropped");
            AssuanResponse::Error(1, "internal error")
        }
        Err(_) => {
            error!("GPG agent: timeout waiting for signature");
            AssuanResponse::Error(1, "timeout")
        }
    }
}

/// Build canonical S-expression for RSA signature:
/// (7:sig-val(3:rsa(1:s<len>:<raw-sig>)))
fn build_sig_sexp(sig: &[u8]) -> Vec<u8> {
    let s_token = format!("{}:", sig.len());
    let prefix = format!("(7:sig-val(3:rsa(1:s{}", s_token);

    let mut sexp = Vec::with_capacity(prefix.len() + sig.len() + 3);
    sexp.extend_from_slice(prefix.as_bytes());
    sexp.extend_from_slice(sig);
    sexp.extend_from_slice(b")))");
    sexp
}

/// Percent-encode binary data for Assuan D line.
/// Encodes bytes that are not printable ASCII, plus '%', CR, LF.
fn percent_encode_sexp(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 3);
    for &b in data {
        if b == b'%' || b == b'\r' || b == b'\n' || b < 0x20 || b > 0x7e {
            result.push_str(&format!("%{:02X}", b));
        } else {
            result.push(b as char);
        }
    }
    result
}

/// Convert a 40-character hex keygrip string to 20 bytes.
fn hex_to_bytes_keygrip(hex: &str) -> Result<[u8; 20], ()> {
    if hex.len() != 40 {
        return Err(());
    }
    let mut bytes = [0u8; 20];
    for i in 0..20 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(bytes)
}
