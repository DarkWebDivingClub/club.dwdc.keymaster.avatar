mod local_api;
mod protocol;
mod seed;
mod session;

use anyhow::Result;
use avatar_protocol::{JsonRpcMessage, JsonRpcResponse};
use bitcoin::bip32::{Xpriv, Xpub};
use clap::Parser;
use nostr::prelude::*;
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};
use tracing::{debug, error, info, warn};

use crate::protocol::PROTOCOL_KIND;
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

    /// Local API socket path (for service avatar processes)
    #[arg(long, default_value = "/tmp/keymaster-avatar.sock")]
    local_api_socket: PathBuf,

    /// Path to the persistent seed file
    #[arg(long, default_value = "~/.config/keymaster-avatar/seed")]
    seed_file: String,
}

/// Pending response futures for service channel requests sent to KM.
/// Value is the raw JSON-RPC response string from KM.
pub type PendingResponses = Arc<RwLock<HashMap<EventId, oneshot::Sender<String>>>>;

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs_next_home() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn dirs_next_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
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

    // Load or create persistent seed
    let seed_path = expand_tilde(&cli.seed_file);
    let seed = seed::load_or_create_seed(&seed_path)?;
    info!("Seed loaded from: {}", seed_path.display());

    // Derive login keys at m/0
    let login_keys = seed::derive_login_keys(&seed, 0)?;
    let avatar_keys = login_keys.nostr_keys.clone();
    let avatar_pubkey = avatar_keys.public_key();
    let login_xpub = login_keys.xpub;
    info!("Avatar pubkey: {}", avatar_pubkey.to_hex());
    info!("Login xpub: {}", login_xpub);

    // Display QR bootstrap payload
    let qr_payload = serde_json::json!({
        "relay": &cli.relay,
        "login_xpub": login_xpub.to_string(),
        "services": ["ssh"]
    });
    let qr_json = serde_json::to_string(&qr_payload)?;
    display_qr(&qr_json);
    println!("\nQR Payload: {}", qr_json);
    println!("Relay: {}", cli.relay);
    println!("Avatar pubkey: {}", avatar_pubkey.to_hex());
    println!("Login xpub: {}", login_xpub);
    println!("\nWaiting for KeyMaster attach...\n");

    // Create session manager and pending response tracker
    let session_mgr = Arc::new(RwLock::new(SessionManager::new()));
    let pending_responses: PendingResponses = Arc::new(RwLock::new(HashMap::new()));

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

    // Store login xpriv in an Arc for use in the event loop
    let login_xpriv = Arc::new(login_keys.xpriv);

    // Event loop
    let event_pending = pending_responses.clone();
    client
        .handle_notifications(|notification| {
            let avatar_keys = avatar_keys.clone();
            let client_clone = client.clone();
            let session_mgr = session_mgr.clone();
            let pending = event_pending.clone();
            let login_xpriv = login_xpriv.clone();

            async move {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::Custom(PROTOCOL_KIND) {
                        if let Err(e) = handle_event(
                            &avatar_keys,
                            &client_clone,
                            &session_mgr,
                            &pending,
                            &login_xpriv,
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

async fn handle_event(
    avatar_keys: &Keys,
    client: &Client,
    session_mgr: &Arc<RwLock<SessionManager>>,
    pending: &PendingResponses,
    login_xpriv: &Xpriv,
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
                    debug!(
                        "Could not decrypt event {} from {}",
                        event.id,
                        sender_pubkey.to_hex()
                    );
                    return Ok(());
                }
            }
        }
    };

    debug!("Decrypted content: {}", plaintext);

    // Parse as a generic JSON-RPC message
    let msg: JsonRpcMessage = match serde_json::from_str(&plaintext) {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to parse JSON-RPC message: {}", e);
            return Ok(());
        }
    };

    if msg.is_response() {
        // This is a response from KM — forward to waiting local API handler
        handle_response(pending, event, &plaintext, &msg).await
    } else if msg.is_request() {
        let method = msg.method.as_deref().unwrap_or("");
        info!(
            "Received method: {} from {}",
            method,
            sender_pubkey.to_hex()
        );

        match method {
            "attach" => {
                handle_attach(
                    avatar_keys,
                    client,
                    session_mgr,
                    login_xpriv,
                    event,
                    &sender_pubkey,
                    &msg,
                )
                .await
            }
            "detach" => {
                handle_detach(avatar_keys, client, session_mgr, event, &sender_pubkey).await
            }
            _ => {
                warn!("Unknown method: {}", method);
                let id = msg.id.clone().unwrap_or(serde_json::Value::Null);
                let response = JsonRpcResponse::error(id, -32601, "unknown method");
                send_response(avatar_keys, client, &sender_pubkey, &event.id, &response).await
            }
        }
    } else {
        warn!("Unknown message format");
        Ok(())
    }
}

async fn handle_response(
    pending: &PendingResponses,
    event: &Event,
    plaintext: &str,
    _msg: &JsonRpcMessage,
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
        // Forward the raw JSON-RPC response to the pending local API handler
        let tx = {
            let mut p = pending.write().await;
            p.remove(&reply_to_id)
        };

        if let Some(tx) = tx {
            let _ = tx.send(plaintext.to_string());
            debug!("Delivered response for {}", reply_to_id);
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
    login_xpriv: &Xpriv,
    event: &Event,
    km_pubkey: &PublicKey,
    msg: &JsonRpcMessage,
) -> Result<()> {
    info!("=== ATTACH from KeyMaster {} ===", km_pubkey.to_hex());

    let params = if msg.params.is_array() {
        msg.params
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
    } else if msg.params.is_object() {
        msg.params.clone()
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };

    // Parse services from attach params
    let services: Vec<(String, u32)> = params
        .get("services")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    // Object format: {"type": "ssh", "seq": 0}
                    if let Some(t) = s.get("type").and_then(|v| v.as_str()) {
                        let seq = s.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
                        Some((t.to_string(), seq as u32))
                    } else if let Some(t) = s.as_str() {
                        // Flat string format: "ssh"
                        Some((t.to_string(), 0))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    // Extract connector if present
    let identity = params
        .get("connector")
        .and_then(|c| c.get("identity_npub"))
        .and_then(|v| v.as_str())
        .or_else(|| params.get("identity").and_then(|v| v.as_str()))
        .unwrap_or("default")
        .to_string();

    let service_types: Vec<String> = services.iter().map(|(t, _)| t.clone()).collect();
    info!("  Services: {:?}", services);
    info!("  Identity: {}", identity);

    let attached_session_event_id = event.id;
    {
        let mut mgr = session_mgr.write().await;
        mgr.create_root_session(
            attached_session_event_id,
            *km_pubkey,
            service_types.clone(),
            identity.clone(),
            vec![],
        );
    }

    // Try to extract realm_xpub from connector params for BIP-32 channel derivation.
    // Fall back to using event pubkey directly for backwards compat.
    let realm_xpub: Option<Xpub> = params
        .get("connector")
        .and_then(|c| c.get("realm_xpub"))
        .and_then(|v| v.as_str())
        .and_then(|s| {
            Xpub::from_str(s)
                .map_err(|e| warn!("Failed to parse realm_xpub: {}", e))
                .ok()
        });

    // Derive and register service channels
    for (service_type, seq) in &services {
        // Derive avatar-side service keys from login_xpriv
        let avatar_svc_keys = seed::derive_service_keys(login_xpriv, service_type, *seq)?;
        let avatar_svc_pubkey = avatar_svc_keys.public_key();

        // Derive KM-side service pubkey
        let km_svc_pubkey = if let Some(ref rxpub) = realm_xpub {
            // BIP-32 derivation: realm_xpub / protocol_index(type) / seq
            seed::derive_service_pubkey(rxpub, service_type, *seq)?
        } else {
            // Backwards compat: use the event sender pubkey directly
            warn!(
                "No realm_xpub — using event pubkey for {} service channel (legacy mode)",
                service_type
            );
            *km_pubkey
        };

        info!(
            "  Service channel {}: avatar_svc_pk={}, km_svc_pk={}",
            service_type,
            avatar_svc_pubkey.to_hex(),
            km_svc_pubkey.to_hex()
        );

        {
            let mut mgr = session_mgr.write().await;
            mgr.add_service_channel(
                attached_session_event_id,
                service_type.clone(),
                avatar_svc_keys,
                km_svc_pubkey,
            );
        }

        // Subscribe to service channel events
        let svc_filter = Filter::new()
            .kind(Kind::Custom(PROTOCOL_KIND))
            .pubkey(avatar_svc_pubkey)
            .since(Timestamp::now());
        client.subscribe(vec![svc_filter], None).await?;
        info!(
            "  Subscribed to service channel events for {}",
            avatar_svc_pubkey.to_hex()
        );
    }

    // Build accepted list
    let accepted: Vec<serde_json::Value> = services
        .iter()
        .map(|(t, seq)| {
            serde_json::json!({
                "type": t,
                "seq": seq,
            })
        })
        .collect();

    let id = msg.id.clone().unwrap_or(serde_json::Value::Number(1.into()));
    let response = JsonRpcResponse::success(
        id,
        serde_json::json!({
            "accepted": accepted,
        }),
    );
    send_response(avatar_keys, client, km_pubkey, &event.id, &response).await?;
    info!(
        "Attach response sent. Session established: {}",
        attached_session_event_id
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

    let id = serde_json::Value::Null;
    let response = JsonRpcResponse::success(id, serde_json::json!({"status": "ok"}));
    send_response(avatar_keys, client, km_pubkey, &event.id, &response).await?;
    info!("Detach response sent");

    Ok(())
}

async fn send_response(
    avatar_keys: &Keys,
    client: &Client,
    recipient: &PublicKey,
    reply_to: &EventId,
    response: &JsonRpcResponse,
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
