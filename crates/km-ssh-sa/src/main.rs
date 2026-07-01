mod ssh_agent;

use anyhow::Result;
use avatar_protocol::{read_line_message, write_line_message, JsonRpcRequest, JsonRpcResponse};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::BufReader;
use tokio::net::UnixStream;
use tracing::{error, info, warn};

use crate::ssh_agent::{AgentIdentitiesReply, AgentRequest, AgentSignReply};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(2); // start at 2; 1 is used by connect

fn next_request_id() -> u64 {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[derive(Parser, Debug)]
#[command(
    name = "km-ssh-sa",
    version,
    about = "SSH Service Avatar - SSH-agent to Avatar local API bridge (JSON-RPC 2.0)"
)]
struct Cli {
    /// Avatar local API socket path
    #[arg(long, default_value = "/tmp/keymaster-avatar.sock")]
    avatar_socket: PathBuf,

    /// SSH agent socket path
    #[arg(long, default_value = "/tmp/keymaster-avatar-ssh-agent.sock")]
    agent_socket: PathBuf,

    /// Service npub (used to identify this service channel)
    #[arg(long, default_value = "")]
    npub: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// Connect to the avatar socket with exponential backoff.
/// Retries until the connection succeeds.
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .init();

    // Start SSH agent listener (persists across reconnects)
    let (_agent_path, mut agent_rx) = ssh_agent::start_agent(&cli.agent_socket).await?;
    info!("SSH agent listening on: {}", cli.agent_socket.display());
    println!("SSH_AUTH_SOCK={}", cli.agent_socket.display());

    // Outer reconnection loop
    loop {
        // Connect to avatar with retry
        let avatar_stream = connect_with_retry(&cli.avatar_socket).await;
        let (reader, mut avatar_writer) = avatar_stream.into_split();
        let mut avatar_reader = BufReader::new(reader);

        // Send connect message (JSON-RPC 2.0)
        let connect_req = JsonRpcRequest::new(
            "connect",
            serde_json::json!({
                "npub": &cli.npub,
                "type": "ssh",
            }),
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
                error!("connect rejected: {} (code {}) — reconnecting", err.message, err.code);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            Ok(_) => {
                info!("Connected to avatar, service type: ssh");
            }
            Err(e) => {
                error!("Failed to read connect response: {} — reconnecting", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        }

        // Bridge loop: read AgentRequest from SSH agent, translate to JSON-RPC
        let mut connection_ok = true;
        while connection_ok {
            let request = match agent_rx.recv().await {
                Some(req) => req,
                None => {
                    info!("SSH agent channel closed, exiting");
                    return Ok(());
                }
            };

            match request {
                AgentRequest::RequestIdentities { reply } => {
                    let req_id = next_request_id();
                    let rpc_req = JsonRpcRequest::new(
                        "ssh.request_identities",
                        serde_json::json!({}),
                        req_id,
                    );

                    match send_and_receive(&mut avatar_writer, &mut avatar_reader, &rpc_req).await {
                        Ok(resp) if resp.error.is_none() => {
                            let mut identities = Vec::new();
                            if let Some(ref result) = resp.result {
                                if let Some(idents) =
                                    result.get("identities").and_then(|v| v.as_array())
                                {
                                    for ident in idents {
                                        let key_blob_b64 = ident
                                            .get("key_blob")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("");
                                        let comment = ident
                                            .get("comment")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("");
                                        if let Ok(key_blob) = BASE64.decode(key_blob_b64) {
                                            identities.push((key_blob, comment.to_string()));
                                        }
                                    }
                                }
                            }
                            info!("[SSH] Got {} identities", identities.len());
                            let _ = reply.send(AgentIdentitiesReply { identities });
                        }
                        Ok(resp) => {
                            let err_msg = resp
                                .error
                                .as_ref()
                                .map(|e| e.message.as_str())
                                .unwrap_or("unknown error");
                            warn!("[SSH] request_identities error: {}", err_msg);
                            let _ = reply.send(AgentIdentitiesReply { identities: vec![] });
                        }
                        Err(e) => {
                            error!("[SSH] request_identities failed: {} — reconnecting", e);
                            let _ = reply.send(AgentIdentitiesReply { identities: vec![] });
                            connection_ok = false;
                        }
                    }
                }
                AgentRequest::SignRequest {
                    key_blob,
                    data,
                    flags,
                    reply,
                } => {
                    let req_id = next_request_id();
                    let rpc_req = JsonRpcRequest::new(
                        "ssh.sign_request",
                        serde_json::json!({
                            "key_blob": BASE64.encode(&key_blob),
                            "data": BASE64.encode(&data),
                            "flags": flags,
                        }),
                        req_id,
                    );

                    match send_and_receive(&mut avatar_writer, &mut avatar_reader, &rpc_req).await {
                        Ok(resp) if resp.error.is_none() => {
                            let sig = resp
                                .result
                                .as_ref()
                                .and_then(|r| r.get("signature"))
                                .and_then(|v| v.as_str())
                                .and_then(|s| BASE64.decode(s).ok());
                            let key_type = resp
                                .result
                                .as_ref()
                                .and_then(|r| r.get("key_type"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("ssh-ed25519")
                                .to_string();
                            if sig.is_some() {
                                info!("[SSH] Got signature from avatar");
                            } else {
                                error!("[SSH] Invalid signature in response");
                            }
                            let _ = reply.send(AgentSignReply {
                                signature: sig,
                                key_type,
                            });
                        }
                        Ok(resp) => {
                            let err_msg = resp
                                .error
                                .as_ref()
                                .map(|e| e.message.as_str())
                                .unwrap_or("unknown error");
                            warn!("[SSH] sign_request error: {}", err_msg);
                            let _ = reply.send(AgentSignReply {
                                signature: None,
                                key_type: "ssh-ed25519".to_string(),
                            });
                        }
                        Err(e) => {
                            error!("[SSH] sign_request failed: {} — reconnecting", e);
                            let _ = reply.send(AgentSignReply {
                                signature: None,
                                key_type: "ssh-ed25519".to_string(),
                            });
                            connection_ok = false;
                        }
                    }
                }
            }
        }

        warn!("Avatar connection lost, reconnecting...");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Send a JSON-RPC request and wait for the response.
/// Sequential: one request at a time over the single avatar connection.
async fn send_and_receive(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    req: &JsonRpcRequest,
) -> Result<JsonRpcResponse> {
    write_line_message(writer, req).await?;
    let resp: JsonRpcResponse = read_line_message(reader).await?;
    Ok(resp)
}
