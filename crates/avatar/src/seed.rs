use anyhow::{Context, Result};
use avatar_protocol::protocol_index;
use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use nostr::prelude::*;
use std::path::Path;
use tracing::info;

pub const DEFAULT_SEED_PATH: &str = "/var/lib/keymaster-avatar/seed";

/// Login keys derived from the master seed at m/0.
pub struct LoginKeys {
    pub xpriv: Xpriv,
    pub xpub: Xpub,
    pub nostr_keys: Keys,
}

/// Load the avatar seed from `seed_path`.
///
/// If the file exists, read and return it. If it does not exist,
/// generate a random 32-byte seed and try to write it. Fails with
/// a clear error if the parent directory does not exist or is not
/// writable.
pub fn resolve_seed(seed_path: &Path) -> Result<[u8; 32]> {
    if seed_path.exists() {
        let seed = read_seed(seed_path)?;
        info!("Seed loaded from {}", seed_path.display());
        return Ok(seed);
    }

    // Verify parent directory exists and is writable before generating
    let parent = seed_path.parent()
        .ok_or_else(|| anyhow::anyhow!("seed path has no parent directory: {}", seed_path.display()))?;

    if !parent.exists() {
        anyhow::bail!(
            "seed directory does not exist: {} — create it or check seed_file config",
            parent.display()
        );
    }

    // Check writability by attempting to create a temp file
    let probe = parent.join(".seed-probe");
    std::fs::write(&probe, b"")
        .with_context(|| format!(
            "seed directory is not writable: {} — check ownership/permissions",
            parent.display()
        ))?;
    let _ = std::fs::remove_file(&probe);

    // Generate and persist
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).context("generating random seed")?;

    std::fs::write(seed_path, &seed)
        .with_context(|| format!("writing seed file: {}", seed_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(seed_path, std::fs::Permissions::from_mode(0o600))
            .context("setting seed file permissions")?;
    }

    info!("Generated new seed at {}", seed_path.display());
    Ok(seed)
}

fn read_seed(path: &Path) -> Result<[u8; 32]> {
    let data = std::fs::read(path)
        .with_context(|| format!("reading seed file: {}", path.display()))?;
    if data.len() != 32 {
        anyhow::bail!(
            "seed file {} has {} bytes, expected 32",
            path.display(),
            data.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data);
    Ok(seed)
}

/// Derive login keys at m/`login_seq` from the master seed.
pub fn derive_login_keys(seed: &[u8; 32], login_seq: u32) -> Result<LoginKeys> {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Bitcoin, seed)
        .context("creating master xpriv")?;
    let login_xpriv = master
        .derive_priv(&secp, &[ChildNumber::from_normal_idx(login_seq)?])
        .context("deriving login xpriv")?;
    let login_xpub = Xpub::from_priv(&secp, &login_xpriv);

    // Extract the 32-byte secret key from the login xpriv
    let secret_bytes = login_xpriv.private_key.secret_bytes();
    let nostr_secret = SecretKey::from_slice(&secret_bytes)
        .context("creating nostr secret key from login xpriv")?;
    let nostr_keys = Keys::new(nostr_secret);

    Ok(LoginKeys {
        xpriv: login_xpriv,
        xpub: login_xpub,
        nostr_keys,
    })
}

/// Derive service-channel Nostr keys from the login xpriv.
///
/// Path: `login_xpriv / protocol_index(protocol) / seq` (non-hardened)
pub fn derive_service_keys(login_xpriv: &Xpriv, protocol: &str, seq: u32) -> Result<Keys> {
    let secp = Secp256k1::new();
    let h = ChildNumber::from_normal_idx(protocol_index(protocol))?;
    let s = ChildNumber::from_normal_idx(seq)?;
    let child = login_xpriv
        .derive_priv(&secp, &[h, s])
        .context("deriving service xpriv")?;

    let secret_bytes = child.private_key.secret_bytes();
    let nostr_secret = SecretKey::from_slice(&secret_bytes)
        .context("creating nostr secret key from service xpriv")?;
    Ok(Keys::new(nostr_secret))
}

/// Derive a service-channel Nostr public key from a peer's xpub (public-only derivation).
///
/// Path: `xpub / protocol_index(protocol) / seq` (non-hardened)
pub fn derive_service_pubkey(
    xpub: &Xpub,
    protocol: &str,
    seq: u32,
) -> Result<nostr::PublicKey> {
    let secp = Secp256k1::new();
    let h = ChildNumber::from_normal_idx(protocol_index(protocol))?;
    let s = ChildNumber::from_normal_idx(seq)?;
    let child_xpub = xpub
        .derive_pub(&secp, &[h, s])
        .context("deriving service xpub")?;

    // BIP-32 public key is a compressed SEC1 key (33 bytes).
    // Nostr uses the x-only (32-byte) representation (BIP-340).
    let compressed = child_xpub.public_key.serialize();
    // x-only key is bytes [1..33] of the compressed key
    let x_only = &compressed[1..33];
    let nostr_pk = nostr::PublicKey::from_slice(x_only)
        .context("creating nostr pubkey from derived xpub")?;
    Ok(nostr_pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const TEST_SEED: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    #[test]
    fn t3_round_trip_login_keys() {
        let login = derive_login_keys(&TEST_SEED, 0).unwrap();
        // xpub derived from xpriv should be consistent
        let secp = Secp256k1::new();
        let check_xpub = Xpub::from_priv(&secp, &login.xpriv);
        assert_eq!(login.xpub, check_xpub);
    }

    #[test]
    fn t4_stability() {
        // Same seed + seq must produce same keys
        let a = derive_login_keys(&TEST_SEED, 0).unwrap();
        let b = derive_login_keys(&TEST_SEED, 0).unwrap();
        assert_eq!(a.xpub, b.xpub);
        assert_eq!(
            a.nostr_keys.public_key(),
            b.nostr_keys.public_key()
        );
    }

    #[test]
    fn t5_xpub_format() {
        let login = derive_login_keys(&TEST_SEED, 0).unwrap();
        let xpub_str = login.xpub.to_string();
        // Standard xpub starts with "xpub"
        assert!(xpub_str.starts_with("xpub"), "xpub string: {}", xpub_str);
        // Should round-trip through string
        let parsed = Xpub::from_str(&xpub_str).unwrap();
        assert_eq!(login.xpub, parsed);
    }

    #[test]
    fn t6_npub_derivation() {
        let login = derive_login_keys(&TEST_SEED, 0).unwrap();
        // Derive service keys from xpriv
        let svc_keys = derive_service_keys(&login.xpriv, "ssh", 0).unwrap();
        // Should produce a valid nostr pubkey
        let pk = svc_keys.public_key();
        assert_eq!(pk.to_hex().len(), 64);
    }

    #[test]
    fn t7_xpriv_vs_xpub_same_pubkey() {
        let login = derive_login_keys(&TEST_SEED, 0).unwrap();

        // Derive service pubkey from xpriv (private derivation)
        let svc_keys = derive_service_keys(&login.xpriv, "ssh", 0).unwrap();
        let from_priv = svc_keys.public_key();

        // Derive service pubkey from xpub (public-only derivation)
        let from_pub = derive_service_pubkey(&login.xpub, "ssh", 0).unwrap();

        assert_eq!(from_priv, from_pub,
            "xpriv-derived pubkey must match xpub-derived pubkey");
    }

    #[test]
    fn t7_different_protocols_different_keys() {
        let login = derive_login_keys(&TEST_SEED, 0).unwrap();
        let ssh_keys = derive_service_keys(&login.xpriv, "ssh", 0).unwrap();
        let gpg_keys = derive_service_keys(&login.xpriv, "gpg", 0).unwrap();
        assert_ne!(ssh_keys.public_key(), gpg_keys.public_key());
    }

    #[test]
    fn t7_different_seq_different_keys() {
        let login = derive_login_keys(&TEST_SEED, 0).unwrap();
        let k0 = derive_service_keys(&login.xpriv, "ssh", 0).unwrap();
        let k1 = derive_service_keys(&login.xpriv, "ssh", 1).unwrap();
        assert_ne!(k0.public_key(), k1.public_key());
    }

    #[test]
    fn t_read_configured_seed() {
        let dir = std::env::temp_dir().join("keymaster-avatar-test-seed");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seed");

        std::fs::write(&path, &TEST_SEED).unwrap();
        let loaded = read_seed(&path).unwrap();
        assert_eq!(loaded, TEST_SEED);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn t_read_seed_missing_is_error() {
        let path = std::env::temp_dir().join("keymaster-avatar-test-seed-missing");
        let _ = std::fs::remove_file(&path);
        assert!(read_seed(&path).is_err());
    }

    #[test]
    fn t_read_seed_rejects_wrong_size() {
        let dir = std::env::temp_dir().join("keymaster-avatar-test-seed-bad");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seed");

        std::fs::write(&path, b"too short").unwrap();
        assert!(read_seed(&path).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
