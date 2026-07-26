#[cfg(test)]
mod tests;

use anyhow::{bail, Result};
use avatar_protocol::{read_line_message, write_line_message, JsonRpcRequest, JsonRpcResponse};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(2); // 1 is reserved for connect

fn next_request_id() -> u64 {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MiB

#[derive(Parser, Debug)]
#[command(
    name = "km-nostr-sa",
    version,
    about = "Nostr Service Avatar - JSON-RPC to Avatar local API bridge"
)]
struct Cli {
    /// Avatar local API socket path
    #[arg(long, default_value = "/tmp/keymaster-avatar.sock")]
    avatar_socket: PathBuf,

    /// Nostr SA listen socket path
    #[arg(long, default_value = "/tmp/keymaster-nostr-sa.sock")]
    listen_socket: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

// ---------------------------------------------------------------------------
// Client request type — sent from per-connection handlers to the main loop
// ---------------------------------------------------------------------------

struct ClientRequest {
    method: String,
    params: Value,
    client_id: Value,
    reply: oneshot::Sender<JsonRpcResponse>,
}

// ---------------------------------------------------------------------------
// 4-byte length-prefix framed I/O (client-facing side)
// ---------------------------------------------------------------------------

async fn read_framed_message(
    reader: &mut (impl AsyncReadExt + Unpin),
) -> Result<Value> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_MESSAGE_SIZE {
        bail!("invalid message length: {}", len);
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    let msg: Value = serde_json::from_slice(&buf)?;
    Ok(msg)
}

async fn write_framed_message(
    writer: &mut (impl AsyncWriteExt + Unpin),
    msg: &Value,
) -> Result<()> {
    let data = serde_json::to_vec(msg)?;
    let len = (data.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Hex ↔ Base64 encoding translation
// ---------------------------------------------------------------------------

/// Convert a hex-encoded string field to base64.
fn hex_to_base64_field(obj: &mut Value, field: &str) {
    if let Some(hex_str) = obj.get(field).and_then(|v| v.as_str()) {
        if let Ok(bytes) = hex::decode(hex_str) {
            obj[field] = Value::String(BASE64.encode(&bytes));
        }
    }
}

/// Convert a base64-encoded string field to hex.
fn base64_to_hex_field(obj: &mut Value, field: &str) {
    if let Some(b64_str) = obj.get(field).and_then(|v| v.as_str()) {
        if let Ok(bytes) = BASE64.decode(b64_str) {
            obj[field] = Value::String(hex::encode(&bytes));
        }
    }
}

/// Translate client request params: hex → base64 for byte fields.
fn translate_request_params(method: &str, params: &mut Value) {
    match method {
        "get_public_keys" => { /* no byte fields */ }
        "sign_event" => {
            hex_to_base64_field(params, "public_key");
            hex_to_base64_field(params, "event_hash");
        }
        "nip04_encrypt" | "nip04_decrypt" | "nip44_encrypt" | "nip44_decrypt" => {
            hex_to_base64_field(params, "public_key");
            hex_to_base64_field(params, "peer_public_key");
        }
        "get_mls_pubkey" => {
            hex_to_base64_field(params, "nostr_pubkey");
        }
        "mls_sign" => {
            hex_to_base64_field(params, "mls_pubkey");
            hex_to_base64_field(params, "data");
        }
        "sign_account_identity_proof" => {
            hex_to_base64_field(params, "account_identity");
            hex_to_base64_field(params, "mls_signature_public_key");
        }
        "mls_hpke_pubkey_at" => {
            hex_to_base64_field(params, "mls_pubkey");
        }
        "mls_hpke_dh" | "mls_hpke_decap" => {
            hex_to_base64_field(params, "hpke_pubkey");
            hex_to_base64_field(params, "peer_public");
        }
        "mls_next_hpke_init_key" => {
            hex_to_base64_field(params, "mls_pubkey");
            hex_to_base64_field(params, "current_hpke_pubkey");
        }
        _ => {}
    }
}

/// Translate avatar response result: base64 → hex for byte fields.
fn translate_response_result(method: &str, result: &mut Value) {
    match method {
        "get_public_keys" => {
            // Result is an array of {public_key: base64}
            if let Some(arr) = result.as_array_mut() {
                for item in arr {
                    base64_to_hex_field(item, "public_key");
                }
            }
        }
        "sign_event" => {
            base64_to_hex_field(result, "signature");
        }
        "get_mls_pubkey" => {
            base64_to_hex_field(result, "mls_pubkey");
        }
        "mls_sign" | "sign_account_identity_proof" => {
            base64_to_hex_field(result, "signature");
        }
        "mls_hpke_pubkey_at" | "mls_next_hpke_init_key" => {
            base64_to_hex_field(result, "hpke_pubkey");
        }
        "mls_hpke_dh" | "mls_hpke_decap" => {
            base64_to_hex_field(result, "dh_result");
        }
        // encrypt/decrypt responses contain string fields — no translation needed
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Client connection handler
// ---------------------------------------------------------------------------

async fn handle_client(
    stream: UnixStream,
    tx: mpsc::Sender<ClientRequest>,
) {
    let (reader, writer) = stream.into_split();
    let mut reader = reader;
    let mut writer = writer;

    loop {
        // Read 4-byte framed JSON-RPC request from client
        let msg = match read_framed_message(&mut reader).await {
            Ok(msg) => msg,
            Err(e) => {
                debug!("Client disconnected: {}", e);
                return;
            }
        };

        // Extract method, params, and id
        let method = match msg.get("method").and_then(|v| v.as_str()) {
            Some(m) => m.to_string(),
            None => {
                let err_resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "missing method"},
                    "id": msg.get("id").cloned().unwrap_or(Value::Null)
                });
                if write_framed_message(&mut writer, &err_resp).await.is_err() {
                    return;
                }
                continue;
            }
        };

        let params = msg.get("params").cloned().unwrap_or(serde_json::json!({}));
        let client_id = msg.get("id").cloned().unwrap_or(Value::Null);

        // Send request to main loop and wait for response
        let (reply_tx, reply_rx) = oneshot::channel();
        let req = ClientRequest {
            method,
            params,
            client_id: client_id.clone(),
            reply: reply_tx,
        };

        if tx.send(req).await.is_err() {
            error!("Main loop channel closed");
            return;
        }

        match reply_rx.await {
            Ok(resp) => {
                let resp_value = serde_json::to_value(&resp).unwrap_or(serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": "internal serialization error"},
                    "id": client_id
                }));
                if write_framed_message(&mut writer, &resp_value).await.is_err() {
                    return;
                }
            }
            Err(_) => {
                let err_resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": "request dropped"},
                    "id": client_id
                });
                if write_framed_message(&mut writer, &err_resp).await.is_err() {
                    return;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Avatar connection with exponential backoff
// ---------------------------------------------------------------------------

async fn connect_with_retry(socket_path: &std::path::Path) -> UnixStream {
    let mut delay = std::time::Duration::from_secs(1);
    let max_delay = std::time::Duration::from_secs(30);

    loop {
        match UnixStream::connect(socket_path).await {
            Ok(stream) => {
                info!("Connected to avatar local API: {}", socket_path.display());
                return stream;
            }
            Err(e) => {
                warn!(
                    "Cannot connect to {}: {} — retrying in {:?}",
                    socket_path.display(),
                    e,
                    delay
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(max_delay);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Send JSON-RPC request to avatar and receive response (NDJSON framing)
// ---------------------------------------------------------------------------

async fn send_and_receive(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    req: &JsonRpcRequest,
) -> Result<JsonRpcResponse> {
    write_line_message(writer, req).await?;
    let resp: JsonRpcResponse = read_line_message(reader).await?;
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .init();

    // Start client listener (persists across avatar reconnects)
    if cli.listen_socket.exists() {
        std::fs::remove_file(&cli.listen_socket)?;
    }
    let listener = UnixListener::bind(&cli.listen_socket)?;
    info!(
        "Nostr SA listening on: {}",
        cli.listen_socket.display()
    );
    println!("NOSTR_SA_SOCK={}", cli.listen_socket.display());

    // Channel for client requests
    let (tx, mut rx) = mpsc::channel::<ClientRequest>(32);

    // Spawn client acceptor
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    debug!("Client connected");
                    let tx = tx.clone();
                    tokio::spawn(handle_client(stream, tx));
                }
                Err(e) => {
                    error!("Accept failed: {}", e);
                }
            }
        }
    });

    // Outer reconnection loop
    loop {
        // Connect to avatar with retry
        let avatar_stream = connect_with_retry(&cli.avatar_socket).await;
        let (reader, mut avatar_writer) = avatar_stream.into_split();
        let mut avatar_reader = BufReader::new(reader);

        // Send connect message (JSON-RPC 2.0)
        let connect_req = JsonRpcRequest::new(
            "connect",
            serde_json::json!({ "type": "nostr" }),
            1,
        );
        if let Err(e) = write_line_message(&mut avatar_writer, &connect_req).await {
            error!("Failed to send connect: {} — reconnecting", e);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }
        match read_line_message::<JsonRpcResponse>(&mut avatar_reader).await {
            Ok(resp) if resp.error.is_some() => {
                let err = resp.error.unwrap();
                error!(
                    "connect rejected: {} (code {}) — reconnecting",
                    err.message, err.code
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            Ok(_) => {
                info!("Connected to avatar, service type: nostr");
            }
            Err(e) => {
                error!("Failed to read connect response: {} — reconnecting", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        }

        // Bridge loop: process client requests one at a time
        let mut connection_ok = true;
        while connection_ok {
            let request = match rx.recv().await {
                Some(req) => req,
                None => {
                    info!("All client channels closed, exiting");
                    return Ok(());
                }
            };

            let method = &request.method;
            let req_id = next_request_id();

            // Translate request params: hex → base64
            let mut params = request.params.clone();
            translate_request_params(method, &mut params);

            // Build avatar-side JSON-RPC request with "nostr." prefix
            let avatar_method = format!("nostr.{}", method);
            let rpc_req = JsonRpcRequest::new(&avatar_method, params, req_id);

            match send_and_receive(&mut avatar_writer, &mut avatar_reader, &rpc_req).await {
                Ok(mut resp) => {
                    // Translate response result: base64 → hex
                    if let Some(ref mut result) = resp.result {
                        translate_response_result(method, result);
                    }

                    info!("[Nostr] {}: ok", method);

                    // Send response back to client with original ID
                    let client_resp = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: resp.result,
                        error: resp.error,
                        id: request.client_id,
                    };
                    let _ = request.reply.send(client_resp);
                }
                Err(e) => {
                    error!("[Nostr] {} failed: {} — reconnecting", method, e);
                    let err_resp = JsonRpcResponse::error(
                        request.client_id,
                        -32603,
                        format!("avatar connection error: {}", e),
                    );
                    let _ = request.reply.send(err_resp);
                    connection_ok = false;
                }
            }
        }

        warn!("Avatar connection lost, reconnecting...");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
