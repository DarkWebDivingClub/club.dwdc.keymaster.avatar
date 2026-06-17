mod gpg_agent;
mod local_api;
mod protocol;
mod session;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use nostr::prelude::*;
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};
use tracing::{debug, error, info, warn};

use crate::gpg_agent::{GpgAgentRequest, GpgKeyInfo, PkSignReply, RequestKeysReply};
use crate::protocol::{Request, Response, PROTOCOL_KIND};
use crate::session::SessionManager;

#[derive(Parser, Debug)]
#[command(
    name = "keymaster-avatar",
    version,
    about = "KeyMaster Avatar - Nostr-based key service relay agent"
)]
struct Cli {
    /// Nostr relay URL to connect to
    #[arg(long, default_value = "ws://localhost:7000")]
    relay: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// GPG agent socket path
    #[arg(long, default_value = "/tmp/keymaster-avatar-gpg-agent.sock")]
    gpg_agent_socket: PathBuf,

    /// Local API socket path (for service avatar processes)
    #[arg(long, default_value = "/tmp/keymaster-avatar.sock")]
    local_api_socket: PathBuf,
}

/// Pending response futures for service channel requests sent to KM
pub type PendingResponses = Arc<RwLock<HashMap<EventId, oneshot::Sender<serde_json::Value>>>>;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .init();

    // Generate avatar keypair
    let avatar_keys = Keys::generate();
    let avatar_pubkey = avatar_keys.public_key();
    info!("Avatar pubkey: {}", avatar_pubkey.to_hex());

    // Display QR bootstrap payload
    let qr_payload = serde_json::json!({
        "v": 1,
        "relay": &cli.relay,
        "avatar_pubkey": avatar_pubkey.to_hex()
    });
    let qr_json = serde_json::to_string(&qr_payload)?;
    display_qr(&qr_json);
    println!("\nQR Payload: {}", qr_json);
    println!("Relay: {}", cli.relay);
    println!("Avatar pubkey: {}", avatar_pubkey.to_hex());
    println!("\nWaiting for KeyMaster attach...\n");

    // Create session manager and pending response tracker
    let session_mgr = Arc::new(RwLock::new(SessionManager::new()));
    let pending_responses: PendingResponses = Arc::new(RwLock::new(HashMap::new()));

    // Start GPG agent (legacy — stays bundled)
    let (_gpg_agent_path, mut gpg_agent_rx) =
        gpg_agent::start_gpg_agent(&cli.gpg_agent_socket).await?;
    println!("GPG_AGENT_SOCK={}", cli.gpg_agent_socket.display());

    // Connect to relay
    let client = Client::new(avatar_keys.clone());
    client.add_relay(&cli.relay).await?;
    client.connect().await;
    info!("Connected to relay: {}", cli.relay);

    // Subscribe to events addressed to us
    let filter = Filter::new()
        .kind(Kind::Custom(PROTOCOL_KIND))
        .pubkey(avatar_pubkey)
        .since(Timestamp::now());

    client.subscribe(vec![filter], None).await?;
    info!("Subscribed to kind {} events for our pubkey", PROTOCOL_KIND);

    // Start local API listener for service avatar processes
    let avatar_keys_arc = Arc::new(avatar_keys.clone());
    let client_arc = Arc::new(client.clone());
    local_api::start_listener(
        &cli.local_api_socket,
        avatar_keys_arc,
        client_arc,
        session_mgr.clone(),
        pending_responses.clone(),
    )
    .await?;
    println!("LOCAL_API_SOCK={}", cli.local_api_socket.display());

    // Spawn the GPG agent bridge task (legacy — stays bundled)
    let gpg_session_mgr = session_mgr.clone();
    let gpg_pending = pending_responses.clone();
    let gpg_keys = avatar_keys.clone();
    let gpg_client = client.clone();

    tokio::spawn(async move {
        while let Some(request) = gpg_agent_rx.recv().await {
            let session_mgr = gpg_session_mgr.clone();
            let pending = gpg_pending.clone();
            let keys = gpg_keys.clone();
            let client = gpg_client.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    handle_gpg_agent_request(request, &keys, &client, &session_mgr, &pending).await
                {
                    error!("Error handling GPG agent request: {}", e);
                }
            });
        }
    });

    // Event loop
    let event_pending = pending_responses.clone();
    client
        .handle_notifications(|notification| {
            let avatar_keys = avatar_keys.clone();
            let client_clone = client.clone();
            let session_mgr = session_mgr.clone();
            let pending = event_pending.clone();

            async move {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::Custom(PROTOCOL_KIND) {
                        if let Err(e) = handle_event(
                            &avatar_keys,
                            &client_clone,
                            &session_mgr,
                            &pending,
                            &event,
                        )
                        .await
                        {
                            error!("Error handling event {}: {}", event.id, e);
                        }
                    }
                }
                Ok(false) // continue listening
            }
        })
        .await?;

    Ok(())
}

async fn handle_gpg_agent_request(
    request: GpgAgentRequest,
    _avatar_keys: &Keys,
    client: &Client,
    session_mgr: &Arc<RwLock<SessionManager>>,
    pending: &PendingResponses,
) -> Result<()> {
    // Find GPG service channel
    let channel_info = {
        let mgr = session_mgr.read().await;
        mgr.find_gpg_channel()
    };

    let (service_keys, km_service_pubkey) = match channel_info {
        Some(info) => info,
        None => {
            warn!("No GPG service channel available");
            match request {
                GpgAgentRequest::RequestKeys { reply } => {
                    let _ = reply.send(RequestKeysReply { keys: vec![] });
                }
                GpgAgentRequest::PkSign { reply, .. } => {
                    let _ = reply.send(PkSignReply { signature: None });
                }
            }
            return Ok(());
        }
    };

    match request {
        GpgAgentRequest::RequestKeys { reply } => {
            info!("[GPG Agent] request_keys → forwarding to KM");
            let req = Request {
                method: "request_keys".to_string(),
                params: vec![],
            };
            let event_id =
                send_service_request(&service_keys, client, &km_service_pubkey, &req).await?;

            let (tx, rx) = oneshot::channel();
            {
                let mut p = pending.write().await;
                p.insert(event_id, tx);
            }

            match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
                Ok(Ok(result)) => {
                    let mut keys = Vec::new();
                    if let Some(key_arr) = result.get("keys").and_then(|v| v.as_array()) {
                        for k in key_arr {
                            let keygrip = k
                                .get("keygrip")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let n_b64 = k
                                .get("n_b64")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let e_b64 = k
                                .get("e_b64")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            keys.push(GpgKeyInfo {
                                keygrip,
                                n_b64,
                                e_b64,
                            });
                        }
                    }
                    info!("[GPG Agent] Got {} keys from KM", keys.len());
                    let _ = reply.send(RequestKeysReply { keys });
                }
                Ok(Err(_)) => {
                    error!("[GPG Agent] Response channel dropped");
                    let _ = reply.send(RequestKeysReply { keys: vec![] });
                }
                Err(_) => {
                    error!("[GPG Agent] Timeout waiting for keys from KM");
                    let _ = reply.send(RequestKeysReply { keys: vec![] });
                }
            }
        }
        GpgAgentRequest::PkSign {
            keygrip,
            hash_algo,
            hash_hex,
            reply,
        } => {
            info!(
                "[GPG Agent] pksign → forwarding to KM (keygrip={}, algo={})",
                keygrip, hash_algo
            );
            let req = Request {
                method: "pksign".to_string(),
                params: vec![serde_json::json!({
                    "keygrip": keygrip,
                    "hash_algo": hash_algo,
                    "hash_data": hash_hex,
                })],
            };
            let event_id =
                send_service_request(&service_keys, client, &km_service_pubkey, &req).await?;

            let (tx, rx) = oneshot::channel();
            {
                let mut p = pending.write().await;
                p.insert(event_id, tx);
            }

            match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
                Ok(Ok(result)) => {
                    let sig = result
                        .get("signature")
                        .and_then(|v| v.as_str())
                        .and_then(|s| BASE64.decode(s).ok());
                    if sig.is_some() {
                        info!("[GPG Agent] Got signature from KM");
                    } else {
                        error!("[GPG Agent] Invalid signature from KM");
                    }
                    let _ = reply.send(PkSignReply { signature: sig });
                }
                Ok(Err(_)) => {
                    error!("[GPG Agent] Response channel dropped");
                    let _ = reply.send(PkSignReply { signature: None });
                }
                Err(_) => {
                    error!("[GPG Agent] Timeout waiting for signature from KM");
                    let _ = reply.send(PkSignReply { signature: None });
                }
            }
        }
    }

    Ok(())
}

/// Send a service channel request from Avatar's service keypair to KM's service keypair
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

async fn handle_event(
    avatar_keys: &Keys,
    client: &Client,
    session_mgr: &Arc<RwLock<SessionManager>>,
    pending: &PendingResponses,
    event: &Event,
) -> Result<()> {
    let sender_pubkey = event.pubkey;
    debug!(
        "Received event {} from {}",
        event.id,
        sender_pubkey.to_hex()
    );

    // Try to decrypt with avatar root keys first
    let plaintext = match nip44::decrypt(avatar_keys.secret_key(), &sender_pubkey, &event.content) {
        Ok(pt) => pt,
        Err(_) => {
            // Try to decrypt with service channel keys
            let mgr = session_mgr.read().await;
            match mgr.try_decrypt_with_service_keys(&sender_pubkey, &event.content) {
                Some(pt) => pt,
                None => {
                    debug!("Could not decrypt event {} from {}", event.id, sender_pubkey.to_hex());
                    return Ok(());
                }
            }
        }
    };

    debug!("Decrypted content: {}", plaintext);

    // Try parsing as response first (has result or error)
    let json: serde_json::Value = serde_json::from_str(&plaintext)?;

    if json.get("result").is_some() || json.get("error").is_some() {
        // This is a response — check if it's a service.spawn response or a service channel response
        handle_response(session_mgr, pending, event, &json).await
    } else if json.get("method").is_some() {
        // This is a request
        let request: Request = serde_json::from_value(json)?;
        info!(
            "Received method: {} from {}",
            request.method,
            sender_pubkey.to_hex()
        );

        match request.method.as_str() {
            "attach" => {
                handle_attach(
                    avatar_keys,
                    client,
                    session_mgr,
                    event,
                    &sender_pubkey,
                    &request,
                )
                .await
            }
            "detach" => {
                handle_detach(avatar_keys, client, session_mgr, event, &sender_pubkey).await
            }
            _ => {
                warn!("Unknown method: {}", request.method);
                let response = Response::error("unknown method");
                send_response(avatar_keys, client, &sender_pubkey, &event.id, &response).await
            }
        }
    } else {
        warn!("Unknown message format");
        Ok(())
    }
}

async fn handle_response(
    session_mgr: &Arc<RwLock<SessionManager>>,
    pending: &PendingResponses,
    event: &Event,
    json: &serde_json::Value,
) -> Result<()> {
    // Find the reply-to event ID from e tags
    let reply_to = event.tags.iter().find_map(|tag| {
        let vec = tag.as_slice();
        if vec.len() >= 4 && vec[0] == "e" && vec[3] == "reply" {
            EventId::from_hex(&vec[1]).ok()
        } else {
            None
        }
    });

    if let Some(reply_to_id) = reply_to {
        // Check if this is a response to a service.spawn request
        {
            let mut mgr = session_mgr.write().await;
            if let Some(result) = json.get("result") {
                if let Some(service_pubkey_hex) = result.get("service_pubkey").and_then(|v| v.as_str()) {
                    // This is a service.spawn response — store KM's service pubkey
                    if let Ok(km_svc_pk) = PublicKey::from_hex(service_pubkey_hex) {
                        mgr.set_km_service_pubkey(&reply_to_id, km_svc_pk);
                        info!(
                            "Service channel established. KM service pubkey: {}",
                            service_pubkey_hex
                        );
                        return Ok(());
                    }
                }
            }
        }

        // Check if this is a response to a pending service channel request
        let tx = {
            let mut p = pending.write().await;
            p.remove(&reply_to_id)
        };

        if let Some(tx) = tx {
            if let Some(result) = json.get("result") {
                let _ = tx.send(result.clone());
                debug!("Delivered response for {}", reply_to_id);
            } else if let Some(err) = json.get("error") {
                error!("Service error response: {}", err);
                let _ = tx.send(serde_json::json!({}));
            }
        } else {
            debug!("Response to {} with no pending handler", reply_to_id);
        }
    }

    Ok(())
}

async fn handle_attach(
    avatar_keys: &Keys,
    client: &Client,
    session_mgr: &Arc<RwLock<SessionManager>>,
    event: &Event,
    km_pubkey: &PublicKey,
    request: &Request,
) -> Result<()> {
    info!("=== ATTACH from KeyMaster {} ===", km_pubkey.to_hex());

    let params = request
        .params
        .first()
        .ok_or_else(|| anyhow::anyhow!("attach: missing params"))?;

    // Parse services: accept both flat strings ["ssh"] and objects [{"service_type":"ssh"}]
    let services = params
        .get("services")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    // Try object format first: {"service_type": "ssh"}
                    s.get("service_type")
                        .and_then(|t| t.as_str())
                        .map(String::from)
                        // Fall back to flat string format: "ssh"
                        .or_else(|| s.as_str().map(String::from))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let identity = params
        .get("identity")
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();

    let alt_ids: Vec<String> = params
        .get("alt_id")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    info!("  Services: {:?}", services);
    info!("  Identity: {}", identity);
    info!("  Alt IDs: {:?}", alt_ids);

    let attached_session_event_id = event.id;
    {
        let mut mgr = session_mgr.write().await;
        mgr.create_root_session(
            attached_session_event_id,
            *km_pubkey,
            services.clone(),
            identity.clone(),
            alt_ids.clone(),
        );
    }

    let response = Response::ok();
    send_response(avatar_keys, client, km_pubkey, &event.id, &response).await?;
    info!(
        "Attach response sent. Session established: {}",
        attached_session_event_id
    );

    for service_type in &services {
        info!("Spawning service channel for: {}", service_type);
        spawn_service_channel(
            avatar_keys,
            client,
            session_mgr,
            km_pubkey,
            &attached_session_event_id,
            service_type,
            &identity,
            &alt_ids,
        )
        .await?;
    }

    Ok(())
}

async fn spawn_service_channel(
    avatar_keys: &Keys,
    client: &Client,
    session_mgr: &Arc<RwLock<SessionManager>>,
    km_pubkey: &PublicKey,
    attached_session_event_id: &EventId,
    service_type: &str,
    identity: &str,
    alt_ids: &[String],
) -> Result<()> {
    let service_avatar_keys = Keys::generate();
    let service_avatar_pubkey = service_avatar_keys.public_key();

    info!(
        "  Service Avatar pubkey for {}: {}",
        service_type,
        service_avatar_pubkey.to_hex()
    );

    let mut allowed_identity = vec![identity.to_string()];
    allowed_identity.extend(alt_ids.iter().cloned());

    let methods: Vec<&str> = match service_type {
        "ssh" => vec!["request_identities", "sign_request"],
        "gpg" => vec!["request_keys", "pksign", "pksign_raw"],
        "nostr" => vec![
            "get_public_key",
            "sign_event",
            "nip44_encrypt",
            "nip44_decrypt",
        ],
        _ => vec![],
    };

    let spawn_request = Request {
        method: "service.spawn".to_string(),
        params: vec![serde_json::json!({
            "service_avatar_pubkey": service_avatar_pubkey.to_hex(),
            "service_type": service_type,
            "allowed_identity": allowed_identity,
            "methods": methods,
        })],
    };

    let request_json = serde_json::to_string(&spawn_request)?;
    let encrypted = nip44::encrypt(
        avatar_keys.secret_key(),
        km_pubkey,
        &request_json,
        nip44::Version::V2,
    )?;

    let event = EventBuilder::new(Kind::Custom(PROTOCOL_KIND), &encrypted)
        .tag(Tag::public_key(*km_pubkey))
        .tag(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E)),
            vec![
                attached_session_event_id.to_hex(),
                String::new(),
                "session".to_string(),
            ],
        ))
        .sign_with_keys(avatar_keys)?;

    let spawn_event_id = event.id;
    client.send_event(event).await?;
    info!("  Sent service.spawn request (event: {})", spawn_event_id);

    {
        let mut mgr = session_mgr.write().await;
        mgr.add_service_channel(
            *attached_session_event_id,
            service_type.to_string(),
            service_avatar_keys,
            spawn_event_id,
        );
    }

    let svc_filter = Filter::new()
        .kind(Kind::Custom(PROTOCOL_KIND))
        .pubkey(service_avatar_pubkey)
        .since(Timestamp::now());
    client.subscribe(vec![svc_filter], None).await?;

    info!(
        "  Subscribed to service channel events for {}",
        service_avatar_pubkey.to_hex()
    );

    Ok(())
}

async fn handle_detach(
    avatar_keys: &Keys,
    client: &Client,
    session_mgr: &Arc<RwLock<SessionManager>>,
    event: &Event,
    km_pubkey: &PublicKey,
) -> Result<()> {
    info!("=== DETACH from KeyMaster {} ===", km_pubkey.to_hex());

    let session_id = {
        let mgr = session_mgr.read().await;
        mgr.find_session_by_km_pubkey(km_pubkey)
    };

    if let Some(sid) = session_id {
        let mut mgr = session_mgr.write().await;
        mgr.remove_session(&sid);
        info!("Session {} removed", sid);
    } else {
        warn!("No active session found for {}", km_pubkey.to_hex());
    }

    let response = Response::ok();
    send_response(avatar_keys, client, km_pubkey, &event.id, &response).await?;
    info!("Detach response sent");

    Ok(())
}

async fn send_response(
    avatar_keys: &Keys,
    client: &Client,
    recipient: &PublicKey,
    reply_to: &EventId,
    response: &Response,
) -> Result<()> {
    let response_json = serde_json::to_string(response)?;
    let encrypted = nip44::encrypt(
        avatar_keys.secret_key(),
        recipient,
        &response_json,
        nip44::Version::V2,
    )?;

    let event = EventBuilder::new(Kind::Custom(PROTOCOL_KIND), &encrypted)
        .tag(Tag::public_key(*recipient))
        .tag(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E)),
            vec![reply_to.to_hex(), String::new(), "reply".to_string()],
        ))
        .sign_with_keys(avatar_keys)?;

    client.send_event(event).await?;
    debug!(
        "Sent response to {} (reply to {})",
        recipient.to_hex(),
        reply_to
    );
    Ok(())
}

fn display_qr(data: &str) {
    use qrcode::QrCode;

    if let Ok(code) = QrCode::new(data) {
        let string = code
            .render::<char>()
            .quiet_zone(true)
            .module_dimensions(2, 1)
            .build();
        println!("{}", string);
    } else {
        eprintln!("Failed to generate QR code");
    }
}
