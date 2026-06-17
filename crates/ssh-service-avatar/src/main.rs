mod ssh_agent;

use anyhow::Result;
use avatar_protocol::{read_message, write_message, LocalRequest, LocalResponse};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UnixStream;
use tracing::{error, info, warn};

use crate::ssh_agent::{AgentIdentitiesReply, AgentRequest, AgentSignReply};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_request_id() -> u64 {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[derive(Parser, Debug)]
#[command(
    name = "ssh-service-avatar",
    version,
    about = "SSH Service Avatar - SSH-agent to Avatar local API bridge"
)]
struct Cli {
    /// Avatar local API socket path
    #[arg(long, default_value = "/tmp/keymaster-avatar.sock")]
    avatar_socket: PathBuf,

    /// SSH agent socket path
    #[arg(long, default_value = "/tmp/keymaster-avatar-ssh-agent.sock")]
    agent_socket: PathBuf,

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

    info!("Connecting to avatar local API: {}", cli.avatar_socket.display());
    let avatar_stream = UnixStream::connect(&cli.avatar_socket).await?;
    let (mut avatar_reader, mut avatar_writer) = avatar_stream.into_split();
    info!("Connected to avatar local API");

    // Start SSH agent listener
    let (_agent_path, mut agent_rx) = ssh_agent::start_agent(&cli.agent_socket).await?;
    info!("SSH agent listening on: {}", cli.agent_socket.display());
    println!("SSH_AUTH_SOCK={}", cli.agent_socket.display());

    // Bridge loop: read AgentRequest from SSH agent, translate to LocalRequest,
    // send to avatar, read LocalResponse, translate back to AgentReply
    while let Some(request) = agent_rx.recv().await {
        match request {
            AgentRequest::RequestIdentities { reply } => {
                let req_id = next_request_id();
                let local_req = LocalRequest {
                    service: "ssh".to_string(),
                    request_id: req_id,
                    operation: "request_identities".to_string(),
                    payload: serde_json::json!({}),
                };

                match send_and_receive(&mut avatar_writer, &mut avatar_reader, &local_req).await {
                    Ok(resp) if resp.status == "ok" => {
                        let mut identities = Vec::new();
                        if let Some(payload) = &resp.payload {
                            if let Some(idents) = payload.get("identities").and_then(|v| v.as_array()) {
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
                        warn!("[SSH] request_identities error: {:?}", resp.error);
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
                let local_req = LocalRequest {
                    service: "ssh".to_string(),
                    request_id: req_id,
                    operation: "sign_request".to_string(),
                    payload: serde_json::json!({
                        "key_blob": BASE64.encode(&key_blob),
                        "data": BASE64.encode(&data),
                        "flags": flags,
                    }),
                };

                match send_and_receive(&mut avatar_writer, &mut avatar_reader, &local_req).await {
                    Ok(resp) if resp.status == "ok" => {
                        let sig = resp.payload
                            .as_ref()
                            .and_then(|p| p.get("signature"))
                            .and_then(|v| v.as_str())
                            .and_then(|s| BASE64.decode(s).ok());
                        let key_type = resp.payload
                            .as_ref()
                            .and_then(|p| p.get("key_type"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("ssh-ed25519")
                            .to_string();
                        if sig.is_some() {
                            info!("[SSH] Got signature from avatar");
                        } else {
                            error!("[SSH] Invalid signature in response");
                        }
                        let _ = reply.send(AgentSignReply { signature: sig, key_type });
                    }
                    Ok(resp) => {
                        warn!("[SSH] sign_request error: {:?}", resp.error);
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

/// Send a LocalRequest and wait for the LocalResponse.
/// Sequential: one request at a time over the single avatar connection.
async fn send_and_receive(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    reader: &mut tokio::net::unix::OwnedReadHalf,
    req: &LocalRequest,
) -> Result<LocalResponse> {
    write_message(writer, req).await?;
    let resp: LocalResponse = read_message(reader).await?;
    Ok(resp)
}
