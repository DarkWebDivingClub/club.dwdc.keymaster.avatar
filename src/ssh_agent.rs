use anyhow::Result;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, debug, error, warn};

// SSH agent protocol message types
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENT_FAILURE: u8 = 5;

/// A request from the SSH agent to the Avatar main loop
#[derive(Debug)]
pub enum AgentRequest {
    RequestIdentities {
        reply: oneshot::Sender<AgentIdentitiesReply>,
    },
    SignRequest {
        key_blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
        reply: oneshot::Sender<AgentSignReply>,
    },
}

#[derive(Debug)]
pub struct AgentIdentitiesReply {
    /// Each identity: (key_blob, comment)
    pub identities: Vec<(Vec<u8>, String)>,
}

#[derive(Debug)]
pub struct AgentSignReply {
    /// Raw signature bytes
    pub signature: Option<Vec<u8>>,
    /// Key type for the signature response (e.g. "ssh-ed25519", "ssh-rsa")
    pub key_type: String,
}

/// Start the SSH agent Unix socket listener.
/// Returns the socket path and a receiver for agent requests.
pub async fn start_agent(
    socket_path: &Path,
) -> Result<(PathBuf, mpsc::Receiver<AgentRequest>)> {
    // Remove stale socket if it exists
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;
    info!("SSH agent listening on: {}", socket_path.display());

    let (tx, rx) = mpsc::channel::<AgentRequest>(32);
    let path = socket_path.to_path_buf();

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    debug!("SSH agent: new connection");
                    let tx = tx.clone();
                    tokio::spawn(handle_connection(stream, tx));
                }
                Err(e) => {
                    error!("SSH agent accept error: {}", e);
                }
            }
        }
    });

    Ok((path, rx))
}

async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    tx: mpsc::Sender<AgentRequest>,
) {
    loop {
        // Read message: 4-byte big-endian length, then payload
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) => {
                debug!("SSH agent: connection closed ({})", e);
                return;
            }
        }

        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 256 * 1024 {
            warn!("SSH agent: invalid message length: {}", msg_len);
            return;
        }

        let mut payload = vec![0u8; msg_len];
        if let Err(e) = stream.read_exact(&mut payload).await {
            debug!("SSH agent: read error ({})", e);
            return;
        }

        let msg_type = payload[0];
        let msg_body = &payload[1..];

        debug!("SSH agent: received message type {} ({} bytes)", msg_type, msg_len);

        let response = match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => {
                handle_request_identities(&tx).await
            }
            SSH_AGENTC_SIGN_REQUEST => {
                handle_sign_request(msg_body, &tx).await
            }
            _ => {
                warn!("SSH agent: unsupported message type {}", msg_type);
                vec![SSH_AGENT_FAILURE]
            }
        };

        // Write response: 4-byte length + payload
        let resp_len = (response.len() as u32).to_be_bytes();
        if let Err(e) = stream.write_all(&resp_len).await {
            error!("SSH agent: write error: {}", e);
            return;
        }
        if let Err(e) = stream.write_all(&response).await {
            error!("SSH agent: write error: {}", e);
            return;
        }
    }
}

async fn handle_request_identities(tx: &mpsc::Sender<AgentRequest>) -> Vec<u8> {
    let (reply_tx, reply_rx) = oneshot::channel();
    if tx.send(AgentRequest::RequestIdentities { reply: reply_tx }).await.is_err() {
        error!("SSH agent: channel closed");
        return vec![SSH_AGENT_FAILURE];
    }

    match tokio::time::timeout(std::time::Duration::from_secs(30), reply_rx).await {
        Ok(Ok(reply)) => {
            build_identities_answer(&reply.identities)
        }
        Ok(Err(_)) => {
            error!("SSH agent: reply channel dropped");
            vec![SSH_AGENT_FAILURE]
        }
        Err(_) => {
            error!("SSH agent: timeout waiting for identities");
            vec![SSH_AGENT_FAILURE]
        }
    }
}

async fn handle_sign_request(body: &[u8], tx: &mpsc::Sender<AgentRequest>) -> Vec<u8> {
    // Parse: string key_blob, string data, uint32 flags
    let mut offset = 0;

    let key_blob = match read_string(body, &mut offset) {
        Some(b) => b,
        None => return vec![SSH_AGENT_FAILURE],
    };

    let data = match read_string(body, &mut offset) {
        Some(d) => d,
        None => return vec![SSH_AGENT_FAILURE],
    };

    let flags = if offset + 4 <= body.len() {
        u32::from_be_bytes([body[offset], body[offset+1], body[offset+2], body[offset+3]])
    } else {
        0
    };

    debug!("SSH agent: sign_request key_blob={} bytes, data={} bytes, flags={}",
           key_blob.len(), data.len(), flags);

    let (reply_tx, reply_rx) = oneshot::channel();
    if tx.send(AgentRequest::SignRequest {
        key_blob: key_blob.to_vec(),
        data: data.to_vec(),
        flags,
        reply: reply_tx,
    }).await.is_err() {
        error!("SSH agent: channel closed");
        return vec![SSH_AGENT_FAILURE];
    }

    match tokio::time::timeout(std::time::Duration::from_secs(30), reply_rx).await {
        Ok(Ok(reply)) => {
            match reply.signature {
                Some(sig) => build_sign_response(&sig, &reply.key_type),
                None => vec![SSH_AGENT_FAILURE],
            }
        }
        Ok(Err(_)) => {
            error!("SSH agent: reply channel dropped");
            vec![SSH_AGENT_FAILURE]
        }
        Err(_) => {
            error!("SSH agent: timeout waiting for signature");
            vec![SSH_AGENT_FAILURE]
        }
    }
}

fn build_identities_answer(identities: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(SSH_AGENT_IDENTITIES_ANSWER);

    // nkeys (u32 BE)
    let nkeys = identities.len() as u32;
    buf.extend_from_slice(&nkeys.to_be_bytes());

    for (key_blob, comment) in identities {
        // string key_blob
        buf.extend_from_slice(&(key_blob.len() as u32).to_be_bytes());
        buf.extend_from_slice(key_blob);
        // string comment
        let comment_bytes = comment.as_bytes();
        buf.extend_from_slice(&(comment_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(comment_bytes);
    }

    buf
}

fn build_sign_response(raw_signature: &[u8], key_type: &str) -> Vec<u8> {
    // SSH signature format: string signature_blob
    // where signature_blob = string algorithm_name + string signature
    let algo = key_type.as_bytes();

    let mut sig_blob = Vec::new();
    sig_blob.extend_from_slice(&(algo.len() as u32).to_be_bytes());
    sig_blob.extend_from_slice(algo);
    sig_blob.extend_from_slice(&(raw_signature.len() as u32).to_be_bytes());
    sig_blob.extend_from_slice(raw_signature);

    let mut buf = Vec::new();
    buf.push(SSH_AGENT_SIGN_RESPONSE);
    buf.extend_from_slice(&(sig_blob.len() as u32).to_be_bytes());
    buf.extend_from_slice(&sig_blob);

    buf
}

fn read_string<'a>(buf: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    if *offset + 4 > buf.len() {
        return None;
    }
    let len = u32::from_be_bytes([buf[*offset], buf[*offset+1], buf[*offset+2], buf[*offset+3]]) as usize;
    *offset += 4;
    if *offset + len > buf.len() {
        return None;
    }
    let data = &buf[*offset..*offset + len];
    *offset += len;
    Some(data)
}
