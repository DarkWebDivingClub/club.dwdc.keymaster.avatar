mod local_api;
mod protocol;
mod seed;
mod session;

use anyhow::Result;
use avatar_protocol::{JsonRpcMessage, JsonRpcResponse};
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{Secp256k1, schnorr::Signature as SchnorrSignature};
use clap::Parser;
use nostr::prelude::*;
use nostr_sdk::prelude::*;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{oneshot, watch, RwLock};
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
    /// Path to TOML config file
    #[arg(long)]
    config: Option<PathBuf>,

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

    /// Path to identity allowlist file (one hex npub per line)
    #[arg(long, default_value = "~/.config/keymaster-avatar/allowlist")]
    allowlist: String,
}

#[derive(Deserialize, Default)]
struct Config {
    relay: Option<String>,
    log_level: Option<String>,
    local_api_socket: Option<PathBuf>,
    seed_file: Option<String>,
    allowlist: Option<String>,
    service_avatar_dir: Option<PathBuf>,
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

/// Load identity allowlist from file.
/// One hex npub per line; empty lines and lines starting with '#' are skipped.
/// If the file is missing or empty, returns an empty set (allow all).
fn load_allowlist(path: &std::path::Path) -> HashSet<String> {
    let mut set = HashSet::new();
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return set,
    };
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        set.insert(trimmed.to_string());
    }
    set
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load config file (CLI > config > default)
    let config: Config = avatar_protocol::config::load_config(
        "avatar",
        cli.config.as_deref(),
    )
    .unwrap_or_default();

    let relay = if cli.relay != "ws://localhost:7000" {
        cli.relay.clone()
    } else {
        config.relay.unwrap_or_else(|| cli.relay.clone())
    };
    let log_level = if cli.log_level != "info" {
        cli.log_level.clone()
    } else {
        config.log_level.unwrap_or_else(|| cli.log_level.clone())
    };
    let local_api_socket = if cli.local_api_socket != PathBuf::from("/tmp/keymaster-avatar.sock") {
        cli.local_api_socket.clone()
    } else {
        config
            .local_api_socket
            .unwrap_or_else(|| cli.local_api_socket.clone())
    };
    let seed_file = if cli.seed_file != "~/.config/keymaster-avatar/seed" {
        cli.seed_file.clone()
    } else {
        config.seed_file.unwrap_or_else(|| cli.seed_file.clone())
    };
    let allowlist_str = if cli.allowlist != "~/.config/keymaster-avatar/allowlist" {
        cli.allowlist.clone()
    } else {
        config.allowlist.unwrap_or_else(|| cli.allowlist.clone())
    };
    let service_avatar_dir = config.service_avatar_dir;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log_level)),
        )
        .init();

    // Load identity allowlist
    let allowlist_path = expand_tilde(&allowlist_str);
    let allowlist = load_allowlist(&allowlist_path);
    if allowlist.is_empty() {
        info!("No identity allowlist (all identities accepted)");
    } else {
        info!("Identity allowlist loaded: {} entries from {}", allowlist.len(), allowlist_path.display());
    }
    let allowlist = Arc::new(allowlist);

    // Load or create persistent seed
    let seed_path = expand_tilde(&seed_file);
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
        "relay": &relay,
        "login_xpub": login_xpub.to_string(),
        "services": ["ssh", "gpg"]
    });
    let qr_json = serde_json::to_string(&qr_payload)?;
    display_qr(&qr_json);
    println!("\nQR Payload: {}", qr_json);
    println!("Relay: {}", relay);
    println!("Avatar pubkey: {}", avatar_pubkey.to_hex());
    println!("Login xpub: {}", login_xpub);
    println!("\nWaiting for KeyMaster attach...\n");

    // Create session manager and pending response tracker
    let session_mgr = Arc::new(RwLock::new(SessionManager::new()));
    let pending_responses: PendingResponses = Arc::new(RwLock::new(HashMap::new()));

    // Connect to relay
    let client = Client::new(avatar_keys.clone());
    client.add_relay(&relay).await?;
    client.connect().await;
    info!("Connected to relay: {}", relay);

    // Subscribe to events addressed to us via explicit #p filter.
    // With "login" marker p tags on all KM→Avatar service responses,
    // this single subscription catches both root and service channel events.
    let filter = Filter::new()
        .kind(Kind::Custom(PROTOCOL_KIND))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::P), [avatar_pubkey.to_hex()])
        .since(Timestamp::now());

    client.subscribe(vec![filter], None).await?;
    info!("Subscribed to kind {} events for #p={}", PROTOCOL_KIND, avatar_pubkey.to_hex());

    // Start local API listener for service avatar processes
    let avatar_keys_arc = Arc::new(avatar_keys.clone());
    let client_arc = Arc::new(client.clone());
    local_api::start_listener(
        &local_api_socket,
        avatar_keys_arc,
        client_arc,
        session_mgr.clone(),
        pending_responses.clone(),
    )
    .await?;
    println!("LOCAL_API_SOCK={}", local_api_socket.display());

    // Store login keys in Arcs for use in the event loop
    let login_xpriv = Arc::new(login_keys.xpriv);
    let login_xpub_arc = Arc::new(login_xpub);
    let service_avatar_dir = Arc::new(service_avatar_dir);
    let local_api_socket = Arc::new(local_api_socket);

    // Event loop
    let event_pending = pending_responses.clone();
    client
        .handle_notifications(|notification| {
            let avatar_keys = avatar_keys.clone();
            let client_clone = client.clone();
            let session_mgr = session_mgr.clone();
            let pending = event_pending.clone();
            let login_xpriv = login_xpriv.clone();
            let login_xpub = login_xpub_arc.clone();
            let allowlist = allowlist.clone();
            let local_api_socket = local_api_socket.clone();
            let service_avatar_dir = service_avatar_dir.clone();

            async move {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::Custom(PROTOCOL_KIND) {
                        if let Err(e) = handle_event(
                            &avatar_keys,
                            &client_clone,
                            &session_mgr,
                            &pending,
                            &login_xpriv,
                            &login_xpub,
                            &allowlist,
                            &local_api_socket,
                            service_avatar_dir.as_deref(),
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
    login_xpub: &Xpub,
    allowlist: &HashSet<String>,
    local_api_socket: &std::path::Path,
    service_avatar_dir: Option<&std::path::Path>,
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
                    login_xpub,
                    allowlist,
                    local_api_socket,
                    service_avatar_dir,
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
    login_xpub: &Xpub,
    allowlist: &HashSet<String>,
    local_api_socket: &std::path::Path,
    service_avatar_dir: Option<&std::path::Path>,
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

    // --- Connector signature verification ---
    if let Some(connector) = params.get("connector") {
        // Verify login_xpub matches ours
        if let Some(login_xpub_str) = connector.get("login_xpub").and_then(|v| v.as_str()) {
            if login_xpub_str != login_xpub.to_string() {
                warn!(
                    "Connector login_xpub mismatch: got {} expected {}",
                    login_xpub_str, login_xpub
                );
                let id = msg.id.clone().unwrap_or(serde_json::Value::Null);
                let response = JsonRpcResponse::error(id, -32602, "login_xpub mismatch");
                send_response(avatar_keys, client, km_pubkey, &event.id, &response).await?;
                return Ok(());
            }
        }

        // Verify realm_xpub sender matches event pubkey
        if let Some(realm_xpub_str) = connector.get("realm_xpub").and_then(|v| v.as_str()) {
            if let Ok(rxpub) = Xpub::from_str(realm_xpub_str) {
                let realm_pk_bytes = &rxpub.public_key.serialize()[1..]; // x-only from compressed
                let sender_bytes = event.pubkey.serialize();
                if realm_pk_bytes != sender_bytes {
                    warn!("Connector realm_xpub does not match event sender");
                    let id = msg.id.clone().unwrap_or(serde_json::Value::Null);
                    let response =
                        JsonRpcResponse::error(id, -32602, "realm_xpub sender mismatch");
                    send_response(avatar_keys, client, km_pubkey, &event.id, &response).await?;
                    return Ok(());
                }
            }
        }

        // Verify Schnorr signature over canonical connector
        if let Some(sig_hex) = params.get("connector_sig").and_then(|v| v.as_str()) {
            let canonical = canonicalize_json(connector);
            let hash = sha256::Hash::hash(canonical.as_bytes());
            let msg_obj =
                secp256k1::Message::from_digest(*hash.as_ref());

            let sig_bytes = match Vec::<u8>::from_hex(sig_hex) {
                Ok(b) if b.len() == 64 => b,
                _ => {
                    warn!("Invalid connector_sig hex");
                    let id = msg.id.clone().unwrap_or(serde_json::Value::Null);
                    let response =
                        JsonRpcResponse::error(id, -32602, "invalid connector_sig");
                    send_response(avatar_keys, client, km_pubkey, &event.id, &response).await?;
                    return Ok(());
                }
            };

            let sig = match SchnorrSignature::from_slice(&sig_bytes) {
                Ok(s) => s,
                Err(_) => {
                    warn!("Failed to parse connector_sig");
                    let id = msg.id.clone().unwrap_or(serde_json::Value::Null);
                    let response =
                        JsonRpcResponse::error(id, -32602, "invalid connector_sig");
                    send_response(avatar_keys, client, km_pubkey, &event.id, &response).await?;
                    return Ok(());
                }
            };

            let identity_npub_hex = connector
                .get("identity_npub")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let identity_pk_bytes = match Vec::<u8>::from_hex(identity_npub_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => {
                    warn!("Invalid identity_npub in connector");
                    let id = msg.id.clone().unwrap_or(serde_json::Value::Null);
                    let response =
                        JsonRpcResponse::error(id, -32602, "invalid identity_npub");
                    send_response(avatar_keys, client, km_pubkey, &event.id, &response).await?;
                    return Ok(());
                }
            };

            let secp = Secp256k1::verification_only();
            let xonly =
                bitcoin::secp256k1::XOnlyPublicKey::from_slice(&identity_pk_bytes)?;
            if secp.verify_schnorr(&sig, &msg_obj, &xonly).is_err() {
                warn!("Connector signature verification FAILED");
                let id = msg.id.clone().unwrap_or(serde_json::Value::Null);
                let response =
                    JsonRpcResponse::error(id, -32602, "connector signature verification failed");
                send_response(avatar_keys, client, km_pubkey, &event.id, &response).await?;
                return Ok(());
            }
            info!("  Connector signature verified OK");
        } else {
            warn!("No connector_sig present — legacy attach (unverified)");
        }
    }

    // --- Identity allowlist check ---
    if !allowlist.is_empty() && !allowlist.contains(&identity) {
        warn!("Identity {} not in allowlist — rejecting attach", identity);
        let id = msg.id.clone().unwrap_or(serde_json::Value::Null);
        let response = JsonRpcResponse::error(id, -32602, "identity not in allowlist");
        send_response(avatar_keys, client, km_pubkey, &event.id, &response).await?;
        return Ok(());
    }

    // Create shutdown channel for service process monitors
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let attached_session_event_id = event.id;
    {
        let mut mgr = session_mgr.write().await;
        mgr.create_root_session(
            attached_session_event_id,
            *km_pubkey,
            service_types.clone(),
            identity.clone(),
            vec![],
            Some(shutdown_tx),
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
                *km_pubkey,
            );
        }

        // No per-service subscription needed — root #p subscription catches
        // all events via "login" marker p tag on KM→Avatar responses.
    }

    // Spawn service process monitors for each service (km-{type}-sa binaries).
    for (service_type, _seq) in &services {
        let svc = service_type.clone();
        let socket = local_api_socket.to_path_buf();
        let rx = shutdown_rx.clone();
        let sa_dir = service_avatar_dir.map(|p| p.to_path_buf());
        tokio::spawn(service_monitor(svc, socket, sa_dir, rx));
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

/// Resolve the path to a service avatar binary.
///
/// Search order:
/// 1. `service_avatar_dir` from config — look for the binary there
/// 2. Sibling of the current executable
/// 3. Fall back to bare name (resolved via PATH)
fn resolve_service_binary(service_type: &str, service_avatar_dir: Option<&std::path::Path>) -> PathBuf {
    let name = format!("km-{}-sa", service_type);

    // 1. Config override
    if let Some(dir) = service_avatar_dir {
        let path = dir.join(&name);
        if path.exists() {
            return path;
        }
    }

    // 2. Sibling lookup
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let path = dir.join(&name);
            if path.exists() {
                return path;
            }
        }
    }

    // 3. PATH fallback
    PathBuf::from(name)
}

/// Spawn a service avatar process (e.g. km-ssh-sa).
async fn spawn_service_avatar(
    service_type: &str,
    avatar_socket: &std::path::Path,
    service_avatar_dir: Option<&std::path::Path>,
) -> Result<tokio::process::Child> {
    let binary = resolve_service_binary(service_type, service_avatar_dir);
    info!("Spawning service process: {} (socket: {})", binary.display(), avatar_socket.display());
    let mut cmd = tokio::process::Command::new(&binary);
    cmd.arg("--avatar-socket")
        .arg(avatar_socket)
        .arg("--log-level")
        .arg("debug")
        .kill_on_drop(true);
    // Pass GNUPGHOME so km-gpg-sa knows where to set up GPG
    if let Ok(gnupg_home) = std::env::var("GNUPGHOME") {
        cmd.env("GNUPGHOME", &gnupg_home);
    }
    let child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn {}: {}", binary.display(), e))?;
    Ok(child)
}

/// Monitor a service process: respawn on crash, stop on shutdown signal.
async fn service_monitor(
    service_type: String,
    avatar_socket: PathBuf,
    service_avatar_dir: Option<PathBuf>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let mut child = match spawn_service_avatar(&service_type, &avatar_socket, service_avatar_dir.as_deref()).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to spawn {}: {}", service_type, e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        tokio::select! {
            status = child.wait() => {
                match status {
                    Ok(s) => warn!("Service process {} exited: {}", service_type, s),
                    Err(e) => error!("Service process {} error: {}", service_type, e),
                }
                // Respawn after brief delay
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            _ = shutdown.changed() => {
                info!("Shutdown signal for service {}, killing process", service_type);
                let _ = child.kill().await;
                return;
            }
        }
    }
}

/// Canonical JSON: sort keys lexicographically, compact output.
/// Must match Java `canonicalizeJson()` byte-for-byte.
fn canonicalize_json(obj: &serde_json::Value) -> String {
    if let Some(map) = obj.as_object() {
        let sorted: std::collections::BTreeMap<&String, &serde_json::Value> =
            map.iter().collect();
        let parts: Vec<String> = sorted
            .iter()
            .map(|(k, v)| {
                let key = serde_json::to_string(*k).unwrap();
                let val = match v {
                    serde_json::Value::Object(_) => canonicalize_json(v),
                    _ => serde_json::to_string(v).unwrap(),
                };
                format!("{}:{}", key, val)
            })
            .collect();
        format!("{{{}}}", parts.join(","))
    } else {
        serde_json::to_string(obj).unwrap()
    }
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
