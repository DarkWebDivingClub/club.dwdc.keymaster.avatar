use anyhow::Result;
use avatar_protocol::{read_message, write_message, LocalRequest, LocalResponse};
use nostr::prelude::*;
use nostr_sdk::prelude::*;
use std::path::Path;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, RwLock};
use tracing::{debug, error, info, warn};

use crate::protocol::{Request, PROTOCOL_KIND};
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
    let (mut reader, mut writer) = stream.into_split();
    let mut bound_service: Option<String> = None;

    loop {
        let req: LocalRequest = match read_message(&mut reader).await {
            Ok(r) => r,
            Err(e) => {
                debug!("Local API: connection closed ({})", e);
                return;
            }
        };

        debug!(
            "Local API: request_id={} service={} op={}",
            req.request_id, req.service, req.operation
        );

        // First-request-allocates: bind the connection to a service type
        match &bound_service {
            None => {
                info!("Local API: binding connection to service '{}'", req.service);
                bound_service = Some(req.service.clone());
            }
            Some(svc) if *svc != req.service => {
                let resp = LocalResponse::error(
                    req.request_id,
                    format!("connection bound to '{}', got '{}'", svc, req.service),
                );
                if write_message(&mut writer, &resp).await.is_err() {
                    return;
                }
                continue;
            }
            _ => {}
        }

        let resp =
            handle_local_request(&req, &avatar_keys, &client, &session_mgr, &pending).await;

        if write_message(&mut writer, &resp).await.is_err() {
            error!("Local API: write error");
            return;
        }
    }
}

async fn handle_local_request(
    req: &LocalRequest,
    _avatar_keys: &Keys,
    client: &Client,
    session_mgr: &Arc<RwLock<SessionManager>>,
    pending: &PendingResponses,
) -> LocalResponse {
    // Find the service channel for the requested service type
    let channel_info = {
        let mgr = session_mgr.read().await;
        mgr.find_service_channel(&req.service)
    };

    let (service_keys, km_service_pubkey) = match channel_info {
        Some(info) => info,
        None => {
            warn!(
                "Local API: no service channel for '{}' (not yet established?)",
                req.service
            );
            return LocalResponse::error(req.request_id, "no service channel available");
        }
    };

    // Build a Nostr Request from the local API request
    let nostr_req = Request {
        method: req.operation.clone(),
        params: if req.payload.is_null() {
            vec![]
        } else {
            vec![req.payload.clone()]
        },
    };

    // Send the request on the service channel
    let event_id = match send_service_request(&service_keys, client, &km_service_pubkey, &nostr_req)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("Local API: send error: {}", e);
            return LocalResponse::error(req.request_id, "failed to send request");
        }
    };

    // Wait for the response
    let (tx, rx) = oneshot::channel();
    {
        let mut p = pending.write().await;
        p.insert(event_id, tx);
    }

    match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
        Ok(Ok(result)) => {
            debug!("Local API: got response for request_id={}", req.request_id);
            LocalResponse::success(req.request_id, result)
        }
        Ok(Err(_)) => {
            error!("Local API: response channel dropped");
            LocalResponse::error(req.request_id, "response channel dropped")
        }
        Err(_) => {
            error!("Local API: timeout waiting for response");
            // Clean up the pending entry
            let mut p = pending.write().await;
            p.remove(&event_id);
            LocalResponse::error(req.request_id, "timeout")
        }
    }
}

/// Send a service channel request from Avatar's service keypair to KM's service keypair.
async fn send_service_request(
    service_keys: &Keys,
    client: &Client,
    km_service_pubkey: &PublicKey,
    request: &Request,
) -> Result<EventId> {
    let request_json = serde_json::to_string(request)?;
    let encrypted = nip44::encrypt(
        service_keys.secret_key(),
        km_service_pubkey,
        &request_json,
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
