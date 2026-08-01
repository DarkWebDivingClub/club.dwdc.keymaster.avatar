use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::info;

/// A resolved user entry mapping a Nostr pubkey to a Unix user.
#[derive(Debug, Clone)]
pub struct UserEntry {
    pub unix_user: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

/// Maps Nostr hex pubkeys to Unix users.
pub struct UserMap {
    entries: HashMap<String, UserEntry>,
}

#[derive(Deserialize)]
struct UsersFile {
    #[serde(default)]
    user: Vec<RawUserEntry>,
}

#[derive(Deserialize)]
struct RawUserEntry {
    npub: String,
    unix_user: String,
}

impl UserMap {
    /// Load user mappings from a TOML file and resolve each unix_user
    /// to uid/gid/home via the system user database.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading users file: {}", path.display()))?;
        let file: UsersFile = toml::from_str(&content)
            .with_context(|| format!("parsing users file: {}", path.display()))?;

        let mut entries = HashMap::new();
        for raw in &file.user {
            let user = nix::unistd::User::from_name(&raw.unix_user)
                .with_context(|| format!("looking up user '{}'", raw.unix_user))?
                .ok_or_else(|| {
                    anyhow::anyhow!("unix user '{}' not found", raw.unix_user)
                })?;

            let entry = UserEntry {
                unix_user: raw.unix_user.clone(),
                uid: user.uid.as_raw(),
                gid: user.gid.as_raw(),
                home: user.dir,
            };
            info!(
                "User mapping: npub={}... -> {}(uid={}, gid={})",
                &raw.npub[..8.min(raw.npub.len())],
                entry.unix_user,
                entry.uid,
                entry.gid
            );
            entries.insert(raw.npub.clone(), entry);
        }

        Ok(UserMap { entries })
    }

    /// Look up a user entry by Nostr hex pubkey.
    pub fn lookup(&self, npub: &str) -> Option<&UserEntry> {
        self.entries.get(npub)
    }
}
