use nostr::prelude::*;
use nostr::nips::nip44;
use std::collections::HashMap;
use tokio::sync::watch;
use tracing::{info, debug};

/// A service channel within a session.
/// Keys are deterministically derived from xpubs — no spawn round-trip needed.
pub struct ServiceChannel {
    pub service_type: String,
    pub service_avatar_keys: Keys,
    pub km_service_pubkey: PublicKey,
    /// KM realm pubkey — used for "realm" marker p tag on service requests.
    pub km_realm_pubkey: PublicKey,
}

/// A root session anchored by an attach event
pub struct RootSession {
    pub attached_session_event_id: EventId,
    pub keymaster_pubkey: PublicKey,
    pub services: Vec<String>,
    pub identity: String,
    pub alt_ids: Vec<String>,
    pub channels: HashMap<String, ServiceChannel>,
    /// Shutdown signal sender for service process monitors
    pub shutdown: Option<watch::Sender<bool>>,
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
        shutdown: Option<watch::Sender<bool>>,
    ) {
        let session = RootSession {
            attached_session_event_id,
            keymaster_pubkey,
            services,
            identity,
            alt_ids,
            channels: HashMap::new(),
            shutdown,
        };
        self.sessions.insert(attached_session_event_id, session);
        info!("Root session created: {}", attached_session_event_id);
    }

    pub fn add_service_channel(
        &mut self,
        session_id: EventId,
        service_type: String,
        service_avatar_keys: Keys,
        km_service_pubkey: PublicKey,
        km_realm_pubkey: PublicKey,
    ) {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            info!(
                "Adding service channel: type={}, avatar_svc_pk={}, km_svc_pk={}",
                service_type,
                service_avatar_keys.public_key().to_hex(),
                km_service_pubkey.to_hex()
            );
            let channel = ServiceChannel {
                service_type: service_type.clone(),
                service_avatar_keys,
                km_service_pubkey,
                km_realm_pubkey,
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

    /// Signal shutdown for a session's service monitors and remove the session.
    pub fn remove_session(&mut self, session_id: &EventId) -> Option<RootSession> {
        // Signal service monitors to stop before removing session
        if let Some(session) = self.sessions.get(session_id) {
            if let Some(ref shutdown) = session.shutdown {
                let _ = shutdown.send(true);
                info!("Sent shutdown signal to service monitors for session {}", session_id);
            }
        }
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

    /// Find any service channel by type — returns the avatar keys, KM service pubkey, and KM realm pubkey.
    pub fn find_service_channel(&self, service_type: &str) -> Option<(Keys, PublicKey, PublicKey)> {
        for session in self.sessions.values() {
            if let Some(channel) = session.channels.get(service_type) {
                return Some((
                    channel.service_avatar_keys.clone(),
                    channel.km_service_pubkey,
                    channel.km_realm_pubkey,
                ));
            }
        }
        None
    }

    /// Try to decrypt an event with any service channel keys
    pub fn try_decrypt_with_service_keys(&self, sender_pubkey: &PublicKey, content: &str) -> Option<String> {
        for session in self.sessions.values() {
            for channel in session.channels.values() {
                match nip44::decrypt(
                    channel.service_avatar_keys.secret_key(),
                    sender_pubkey,
                    content,
                ) {
                    Ok(plaintext) => {
                        debug!("Decrypted with service channel key for {}", channel.service_type);
                        return Some(plaintext);
                    }
                    Err(_) => continue,
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::prelude::*;
    use tokio::sync::watch;

    /// Helper: generate a random EventId for testing.
    fn random_event_id() -> EventId {
        let keys = Keys::generate();
        let event = EventBuilder::text_note("test")
            .sign_with_keys(&keys)
            .unwrap();
        event.id
    }

    #[test]
    fn test_evict_stale_session_on_duplicate_km_pubkey() {
        let mut mgr = SessionManager::new();
        let km_keys = Keys::generate();
        let km_pubkey = km_keys.public_key();

        let sid1 = random_event_id();
        let sid2 = random_event_id();

        // Create first session
        mgr.create_root_session(
            sid1,
            km_pubkey,
            vec!["ssh".to_string()],
            "alice".to_string(),
            vec![],
            None,
        );
        assert!(mgr.find_session_by_km_pubkey(&km_pubkey).is_some());

        // Evict stale session and create second
        if let Some(old_sid) = mgr.find_session_by_km_pubkey(&km_pubkey) {
            mgr.remove_session(&old_sid);
        }
        mgr.create_root_session(
            sid2,
            km_pubkey,
            vec!["ssh".to_string()],
            "alice".to_string(),
            vec![],
            None,
        );

        // Only the second session should remain
        let found = mgr.find_session_by_km_pubkey(&km_pubkey);
        assert_eq!(found, Some(sid2));
        assert!(mgr.find_service_channel("ssh").is_none()); // no channels added yet
    }

    #[test]
    fn test_find_service_channel_returns_latest() {
        let mut mgr = SessionManager::new();

        let keys_a = Keys::generate();
        let keys_b = Keys::generate();
        let svc_keys = Keys::generate();
        let km_svc_pk = Keys::generate().public_key();

        let sid_a = random_event_id();
        let sid_b = random_event_id();

        // Session A with ssh channel
        mgr.create_root_session(
            sid_a,
            keys_a.public_key(),
            vec!["ssh".to_string()],
            "alice".to_string(),
            vec![],
            None,
        );
        mgr.add_service_channel(
            sid_a,
            "ssh".to_string(),
            svc_keys.clone(),
            km_svc_pk,
            keys_a.public_key(),
        );

        // Session B with ssh channel (different keys)
        let svc_keys_b = Keys::generate();
        mgr.create_root_session(
            sid_b,
            keys_b.public_key(),
            vec!["ssh".to_string()],
            "bob".to_string(),
            vec![],
            None,
        );
        mgr.add_service_channel(
            sid_b,
            "ssh".to_string(),
            svc_keys_b.clone(),
            km_svc_pk,
            keys_b.public_key(),
        );

        // Remove session A
        mgr.remove_session(&sid_a);

        // find_service_channel should return session B's channel
        let result = mgr.find_service_channel("ssh");
        assert!(result.is_some());
        let (found_keys, _, _) = result.unwrap();
        assert_eq!(found_keys.public_key(), svc_keys_b.public_key());
    }

    #[test]
    fn test_remove_session_sends_shutdown() {
        let mut mgr = SessionManager::new();
        let km_keys = Keys::generate();
        let sid = random_event_id();

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        mgr.create_root_session(
            sid,
            km_keys.public_key(),
            vec!["ssh".to_string()],
            "alice".to_string(),
            vec![],
            Some(shutdown_tx),
        );

        // Remove session — should send shutdown signal
        mgr.remove_session(&sid);

        // The receiver should see the shutdown signal
        assert_eq!(*shutdown_rx.borrow(), true);
    }
}
