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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .init();

    info!(
        "Connecting to avatar local API: {}",
        cli.avatar_socket.display()
    );
    let avatar_stream = UnixStream::connect(&cli.avatar_socket).await?;
    let (reader, mut avatar_writer) = avatar_stream.into_split();
    let mut avatar_reader = BufReader::new(reader);
    info!("Connected to avatar local API");

    // Send connect message (JSON-RPC 2.0)
    let connect_req = JsonRpcRequest::new(
        "connect",
        serde_json::json!({
            "npub": &cli.npub,
            "type": "ssh",
        }),
        1,
    );
    write_line_message(&mut avatar_writer, &connect_req).await?;
    let connect_resp: JsonRpcResponse = read_line_message(&mut avatar_reader).await?;
    if connect_resp.error.is_some() {
        let err = connect_resp.error.unwrap();
        anyhow::bail!("connect failed: {} (code {})", err.message, err.code);
    }
    info!("Connected to avatar, service type: ssh");

    // Start SSH agent listener
    let (_agent_path, mut agent_rx) = ssh_agent::start_agent(&cli.agent_socket).await?;
    info!("SSH agent listening on: {}", cli.agent_socket.display());
    println!("SSH_AUTH_SOCK={}", cli.agent_socket.display());

    // Bridge loop: read AgentRequest from SSH agent, translate to JSON-RPC request,
    // send to avatar, read JSON-RPC response, translate back to AgentReply
    while let Some(request) = agent_rx.recv().await {
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
                        error!("[SSH] request_identities failed: {}", e);
                        let _ = reply.send(AgentIdentitiesReply { identities: vec![] });
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
                        error!("[SSH] sign_request failed: {}", e);
                        let _ = reply.send(AgentSignReply {
                            signature: None,
                            key_type: "ssh-ed25519".to_string(),
                        });
                    }
                }
            }
        }
    }

    info!("SSH agent channel closed, exiting");
    Ok(())
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
