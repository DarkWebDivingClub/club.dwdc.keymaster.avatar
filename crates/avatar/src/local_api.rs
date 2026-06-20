use anyhow::Result;
use avatar_protocol::{
    read_line_message, write_line_message, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse,
    JSONRPC_INTERNAL_ERROR, JSONRPC_NO_SESSION, JSONRPC_SEND_FAILED,
    JSONRPC_TIMEOUT, JSONRPC_CHANNEL_DROPPED,
};
use nostr::prelude::*;
use nostr_sdk::prelude::*;
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, RwLock};
use tracing::{debug, error, info, warn};

use crate::protocol::PROTOCOL_KIND;
use crate::session::SessionManager;
use crate::PendingResponses;

/// Start the local API Unix socket listener.
/// Accepts connections from service avatar processes and forwards their
/// requests to the appropriate Nostr service channel.
pub async fn start_listener(
    socket_path: &Path,
    avatar_keys: Arc<Keys>,
    client: Arc<Client>,
    session_mgr: Arc<RwLock<SessionManager>>,
    pending: PendingResponses,
) -> Result<()> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    info!("Local API listening on: {}", socket_path.display());

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    debug!("Local API: new connection");
                    let keys = avatar_keys.clone();
                    let cli = client.clone();
                    let mgr = session_mgr.clone();
                    let pend = pending.clone();
                    tokio::spawn(handle_connection(stream, keys, cli, mgr, pend));
                }
                Err(e) => {
                    error!("Local API accept error: {}", e);
                }
            }
        }
    });

    Ok(())
}

async fn handle_connection(
    stream: UnixStream,
    avatar_keys: Arc<Keys>,
    client: Arc<Client>,
    session_mgr: Arc<RwLock<SessionManager>>,
    pending: PendingResponses,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut bound_service: Option<String> = None;

    loop {
        let msg: JsonRpcMessage = match read_line_message(&mut reader).await {
            Ok(r) => r,
            Err(e) => {
                debug!("Local API: connection closed ({})", e);
                return;
            }
        };

        // Must be a request (has method)
        if !msg.is_request() {
            debug!("Local API: ignoring non-request message");
            continue;
        }

        let method = msg.method.as_deref().unwrap_or("");
        let id = msg.id.clone().unwrap_or(Value::Null);
        let params = msg.params.clone();

        debug!("Local API: method={} id={}", method, id);

        // Handle connect (first message — binds this connection to a service)
        if method == "connect" {
            let svc_type = params
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let npub = params
                .get("npub")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if svc_type.is_empty() {
                let resp = JsonRpcResponse::error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    "connect requires 'type' param",
                );
                if write_line_message(&mut writer, &resp).await.is_err() {
                    return;
                }
                continue;
            }

            info!(
                "Local API: connect type={} npub={}",
                svc_type,
                if npub.is_empty() { "<none>" } else { &npub }
            );
            bound_service = Some(svc_type.clone());

            let resp = JsonRpcResponse::success(
                id,
                serde_json::json!({
                    "npub": npub,
                }),
            );
            if write_line_message(&mut writer, &resp).await.is_err() {
                return;
            }
            continue;
        }

        // All other methods require a prior connect
        let service_type = match &bound_service {
            Some(s) => s.clone(),
            None => {
                let resp = JsonRpcResponse::error(
                    id,
                    JSONRPC_INTERNAL_ERROR,
                    "must send 'connect' first",
                );
                if write_line_message(&mut writer, &resp).await.is_err() {
                    return;
                }
                continue;
            }
        };

        // Forward the JSON-RPC request to Nostr as-is
        let resp = forward_to_nostr(
            &service_type,
            &JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: method.to_string(),
                params,
                id: Some(id.clone()),
            },
            &avatar_keys,
            &client,
            &session_mgr,
            &pending,
        )
        .await;

        if write_line_message(&mut writer, &resp).await.is_err() {
            error!("Local API: write error");
            return;
        }
    }
}

/// Forward a JSON-RPC request to the Nostr service channel and wait for the response.
async fn forward_to_nostr(
    service_type: &str,
    request: &JsonRpcRequest,
    _avatar_keys: &Keys,
    client: &Client,
    session_mgr: &Arc<RwLock<SessionManager>>,
    pending: &PendingResponses,
) -> JsonRpcResponse {
    let id = request.id.clone().unwrap_or(Value::Null);

    // Find the service channel
    let channel_info = {
        let mgr = session_mgr.read().await;
        mgr.find_service_channel(service_type)
    };

    let (service_keys, km_service_pubkey) = match channel_info {
        Some(info) => info,
        None => {
            warn!(
                "Local API: no service channel for '{}' (not yet established?)",
                service_type
            );
            return JsonRpcResponse::error(id, JSONRPC_NO_SESSION, "no service channel available");
        }
    };

    // Send the JSON-RPC request as-is (encrypted) on the service channel
    let request_json = match serde_json::to_string(request) {
        Ok(j) => j,
        Err(e) => {
            return JsonRpcResponse::error(
                id,
                JSONRPC_INTERNAL_ERROR,
                format!("serialize error: {}", e),
            );
        }
    };

    let event_id = match send_service_request(&service_keys, client, &km_service_pubkey, &request_json)
        .await
    {
        Ok(eid) => eid,
        Err(e) => {
            error!("Local API: send error: {}", e);
            return JsonRpcResponse::error(id, JSONRPC_SEND_FAILED, "failed to send request");
        }
    };

    // Wait for the response
    let (tx, rx) = oneshot::channel();
    {
        let mut p = pending.write().await;
        p.insert(event_id, tx);
    }

    match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
        Ok(Ok(response_json)) => {
            // The response is already a complete JSON-RPC response string from KM.
            // Parse it and forward as-is.
            match serde_json::from_str::<JsonRpcResponse>(&response_json) {
                Ok(resp) => {
                    debug!("Local API: got response for id={}", id);
                    resp
                }
                Err(_) => {
                    // If it's not a valid JSON-RPC response, wrap the raw value
                    match serde_json::from_str::<Value>(&response_json) {
                        Ok(val) => {
                            if val.get("result").is_some() || val.get("error").is_some() {
                                // Looks like a response but didn't parse cleanly, forward the raw value
                                JsonRpcResponse::success(id, val)
                            } else {
                                JsonRpcResponse::success(id, val)
                            }
                        }
                        Err(e) => JsonRpcResponse::error(
                            id,
                            JSONRPC_INTERNAL_ERROR,
                            format!("invalid response: {}", e),
                        ),
                    }
                }
            }
        }
        Ok(Err(_)) => {
            error!("Local API: response channel dropped");
            JsonRpcResponse::error(id, JSONRPC_CHANNEL_DROPPED, "response channel dropped")
        }
        Err(_) => {
            error!("Local API: timeout waiting for response");
            let mut p = pending.write().await;
            p.remove(&event_id);
            JsonRpcResponse::error(id, JSONRPC_TIMEOUT, "timeout")
        }
    }
}

/// Send an encrypted JSON-RPC request on the service channel.
async fn send_service_request(
    service_keys: &Keys,
    client: &Client,
    km_service_pubkey: &PublicKey,
    request_json: &str,
) -> Result<EventId> {
    let encrypted = nip44::encrypt(
        service_keys.secret_key(),
        km_service_pubkey,
        request_json,
        nip44::Version::V2,
    )?;

    let event = EventBuilder::new(Kind::Custom(PROTOCOL_KIND), &encrypted)
        .tag(Tag::public_key(*km_service_pubkey))
        .sign_with_keys(service_keys)?;

    let event_id = event.id;
    client.send_event(event).await?;
    debug!(
        "Sent service request {} to {}",
        event_id,
        km_service_pubkey.to_hex()
    );
    Ok(event_id)
}
