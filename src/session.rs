use nostr::prelude::*;
use std::collections::HashMap;
use tracing::info;

/// A service channel within a session
pub struct ServiceChannel {
    pub service_type: String,
    pub service_avatar_keys: Keys,
    pub spawn_event_id: EventId,
    /// Set once KM responds with the service pubkey
    pub km_service_pubkey: Option<PublicKey>,
    /// Set once KM confirms spawn — the service session event ID
    pub service_session_event_id: Option<EventId>,
}

/// A root session anchored by an attach event
pub struct RootSession {
    pub attached_session_event_id: EventId,
    pub keymaster_pubkey: PublicKey,
    pub services: Vec<String>,
    pub identity: String,
    pub alt_ids: Vec<String>,
    pub channels: HashMap<String, ServiceChannel>,
}

/// Manages active sessions
pub struct SessionManager {
    sessions: HashMap<EventId, RootSession>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn create_root_session(
        &mut self,
        attached_session_event_id: EventId,
        keymaster_pubkey: PublicKey,
        services: Vec<String>,
        identity: String,
        alt_ids: Vec<String>,
    ) {
        let session = RootSession {
            attached_session_event_id,
            keymaster_pubkey,
            services,
            identity,
            alt_ids,
            channels: HashMap::new(),
        };
        self.sessions.insert(attached_session_event_id, session);
        info!("Root session created: {}", attached_session_event_id);
    }

    pub fn add_service_channel(
        &mut self,
        session_id: EventId,
        service_type: String,
        service_avatar_keys: Keys,
        spawn_event_id: EventId,
    ) {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            let channel = ServiceChannel {
                service_type: service_type.clone(),
                service_avatar_keys,
                spawn_event_id,
                km_service_pubkey: None,
                service_session_event_id: None,
            };
            session.channels.insert(service_type, channel);
        }
    }

    pub fn find_session_by_km_pubkey(&self, km_pubkey: &PublicKey) -> Option<EventId> {
        self.sessions
            .values()
            .find(|s| s.keymaster_pubkey == *km_pubkey)
            .map(|s| s.attached_session_event_id)
    }

    pub fn remove_session(&mut self, session_id: &EventId) -> Option<RootSession> {
        let session = self.sessions.remove(session_id);
        if let Some(ref s) = session {
            info!(
                "Removed session {} with {} service channels",
                session_id,
                s.channels.len()
            );
        }
        session
    }

    pub fn get_session(&self, session_id: &EventId) -> Option<&RootSession> {
        self.sessions.get(session_id)
    }

    pub fn get_session_mut(&mut self, session_id: &EventId) -> Option<&mut RootSession> {
        self.sessions.get_mut(session_id)
    }
}
