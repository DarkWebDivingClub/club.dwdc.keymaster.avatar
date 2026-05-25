mod protocol;
mod session;

use anyhow::Result;
use clap::Parser;
use nostr::prelude::*;
use nostr_sdk::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

use crate::session::SessionManager;
use crate::protocol::{PROTOCOL_KIND, Request, Response};

#[derive(Parser, Debug)]
#[command(name = "iz-avatar", version, about = "IZ Avatar - Nostr-based key service relay agent")]
struct Cli {
    /// Nostr relay URL to connect to
    #[arg(long, default_value = "ws://localhost:7000")]
    relay: String,

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

    // Create session manager
    let session_mgr = Arc::new(RwLock::new(SessionManager::new()));

    // Connect to relay
    let client = Client::new(avatar_keys.clone());
    client.add_relay(&cli.relay).await?;
    client.connect().await;
    info!("Connected to relay: {}", cli.relay);

    // Subscribe to events addressed to us (kind 27235 with p tag matching our pubkey)
    let filter = Filter::new()
        .kind(Kind::Custom(PROTOCOL_KIND))
        .pubkey(avatar_pubkey)
        .since(Timestamp::now());

    client.subscribe(vec![filter], None).await?;
    info!("Subscribed to kind {} events for our pubkey", PROTOCOL_KIND);

    // Event loop
    client
        .handle_notifications(|notification| {
            let avatar_keys = avatar_keys.clone();
            let client_clone = client.clone();
            let session_mgr = session_mgr.clone();

            async move {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::Custom(PROTOCOL_KIND) {
                        if let Err(e) = handle_event(
                            &avatar_keys,
                            &client_clone,
                            &session_mgr,
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
    event: &Event,
) -> Result<()> {
    let sender_pubkey = event.pubkey;
    debug!("Received event {} from {}", event.id, sender_pubkey.to_hex());

    // Decrypt NIP-44 content
    let plaintext = nip44::decrypt(
        avatar_keys.secret_key(),
        &sender_pubkey,
        &event.content,
    )?;
    debug!("Decrypted content: {}", plaintext);

    let request: Request = serde_json::from_str(&plaintext)?;
    info!("Received method: {} from {}", request.method, sender_pubkey.to_hex());

    match request.method.as_str() {
        "attach" => {
            handle_attach(avatar_keys, client, session_mgr, event, &sender_pubkey, &request).await
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

    // Parse attach params
    let params = request.params.first()
        .ok_or_else(|| anyhow::anyhow!("attach: missing params"))?;

    let services = params.get("services")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.get("service_type").and_then(|t| t.as_str()).map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let identity = params.get("identity")
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();

    let alt_ids: Vec<String> = params.get("alt_id")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_default();

    info!("  Services: {:?}", services);
    info!("  Identity: {}", identity);
    info!("  Alt IDs: {:?}", alt_ids);

    // Store session — the attach event ID becomes the session anchor
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

    // Send attach response
    let response = Response::ok();
    send_response(avatar_keys, client, km_pubkey, &event.id, &response).await?;
    info!("Attach response sent. Session established: {}", attached_session_event_id);

    // Now initiate service.spawn for each service the KM advertised
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
    // Generate a service-channel keypair for the Avatar side
    let service_avatar_keys = Keys::generate();
    let service_avatar_pubkey = service_avatar_keys.public_key();

    info!(
        "  Service Avatar pubkey for {}: {}",
        service_type,
        service_avatar_pubkey.to_hex()
    );

    // Build allowed_identity list
    let mut allowed_identity = vec![identity.to_string()];
    allowed_identity.extend(alt_ids.iter().cloned());

    // Determine methods based on service type
    let methods: Vec<&str> = match service_type {
        "ssh" => vec!["request_identities", "sign_request"],
        "nostr" => vec!["get_public_key", "sign_event", "nip44_encrypt", "nip44_decrypt"],
        _ => vec![],
    };

    // Send service.spawn request to KM
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

    // Build event with session tag
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

    // Store the service channel in session manager
    {
        let mut mgr = session_mgr.write().await;
        mgr.add_service_channel(
            *attached_session_event_id,
            service_type.to_string(),
            service_avatar_keys,
            spawn_event_id,
        );
    }

    // Subscribe to events for the service channel keypair
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

    // Find and remove the session
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

    // Send detach response
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
    debug!("Sent response to {} (reply to {})", recipient.to_hex(), reply_to);
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
