//! Client library for `km-nostr-sa` — the KeyMaster Nostr Service Avatar.
//!
//! Provides a typed Rust API over the length-prefixed JSON-RPC Unix socket
//! protocol. All byte arrays are passed as fixed-size arrays; hex encoding
//! is handled internally.
//!
//! # Example
//!
//! ```no_run
//! use km_nostr_client::KmNostrClient;
//!
//! let mut client = KmNostrClient::connect_default().unwrap();
//! let keys = client.get_public_keys().unwrap();
//! let mls_pub = client.get_mls_pubkey(&keys[0]).unwrap();
//! let sig = client.mls_sign(&mls_pub, b"hello").unwrap();
//! ```

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde_json::{json, Value};

/// Errors returned by the client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("RPC error {code}: {message}")]
    Rpc { code: i64, message: String },

    #[error("unexpected response shape: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Client for the km-nostr-sa Unix socket.
///
/// Each method opens a fresh connection (the socket supports both
/// single-shot and persistent connections; fresh connections avoid
/// stale-state issues after service restarts).
pub struct KmNostrClient {
    path: std::path::PathBuf,
}

impl KmNostrClient {
    /// Connect using the default socket path:
    /// `/run/user/{uid}/keymaster-nostr-sa.sock`
    pub fn connect_default() -> Result<Self> {
        let uid = unsafe { libc::getuid() };
        let path = format!("/run/user/{uid}/keymaster-nostr-sa.sock");
        Self::connect(Path::new(&path))
    }

    /// Connect to a specific socket path.
    pub fn connect(path: &Path) -> Result<Self> {
        // Verify the socket exists at construction time
        if !path.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("socket not found: {}", path.display()),
            )));
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    /// List all Nostr public keys available on the connected KeyMaster.
    pub fn get_public_keys(&self) -> Result<Vec<[u8; 32]>> {
        let resp = self.call("get_public_keys", json!({}))?;
        let arr = resp
            .as_array()
            .ok_or_else(|| Error::Protocol("expected array".into()))?;
        arr.iter()
            .map(|item| {
                let hex_str = item
                    .get("public_key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::Protocol("missing public_key".into()))?;
                hex_to_32(hex_str)
            })
            .collect()
    }

    /// Schnorr-sign a 32-byte event hash with the given Nostr key.
    pub fn sign_event(&self, pubkey: &[u8; 32], event_hash: &[u8; 32]) -> Result<[u8; 64]> {
        let resp = self.call(
            "sign_event",
            json!({
                "public_key": hex::encode(pubkey),
                "event_hash": hex::encode(event_hash),
            }),
        )?;
        hex_to_64(get_str(&resp, "signature")?)
    }

    /// NIP-44 encrypt plaintext for a peer.
    pub fn nip44_encrypt(
        &self,
        pubkey: &[u8; 32],
        peer_public_key: &[u8; 32],
        plaintext: &str,
    ) -> Result<String> {
        let resp = self.call(
            "nip44_encrypt",
            json!({
                "public_key": hex::encode(pubkey),
                "peer_public_key": hex::encode(peer_public_key),
                "plaintext": plaintext,
            }),
        )?;
        get_str(&resp, "ciphertext").map(|s| s.to_string())
    }

    /// NIP-44 decrypt ciphertext from a peer.
    pub fn nip44_decrypt(
        &self,
        pubkey: &[u8; 32],
        peer_public_key: &[u8; 32],
        ciphertext: &str,
    ) -> Result<String> {
        let resp = self.call(
            "nip44_decrypt",
            json!({
                "public_key": hex::encode(pubkey),
                "peer_public_key": hex::encode(peer_public_key),
                "ciphertext": ciphertext,
            }),
        )?;
        get_str(&resp, "plaintext").map(|s| s.to_string())
    }

    /// Get the MLS Ed25519 signing public key for a Nostr identity.
    ///
    /// Must be called before `mls_sign` — populates the server-side cache.
    pub fn get_mls_pubkey(&self, nostr_pubkey: &[u8; 32]) -> Result<[u8; 32]> {
        let resp = self.call(
            "get_mls_pubkey",
            json!({
                "nostr_pubkey": hex::encode(nostr_pubkey),
                "device_id": null,
            }),
        )?;
        hex_to_32(get_str(&resp, "mls_pubkey")?)
    }

    /// Ed25519 sign arbitrary data with the MLS signing key.
    ///
    /// Requires a prior `get_mls_pubkey` call for the same identity.
    pub fn mls_sign(&self, mls_pubkey: &[u8; 32], data: &[u8]) -> Result<[u8; 64]> {
        let resp = self.call(
            "mls_sign",
            json!({
                "mls_pubkey": hex::encode(mls_pubkey),
                "data": hex::encode(data),
            }),
        )?;
        hex_to_64(get_str(&resp, "signature")?)
    }

    /// Sign a Kind 450 account identity proof (links Nostr identity to MLS key).
    pub fn sign_account_identity_proof(
        &self,
        account_identity: &[u8; 32],
        mls_signature_public_key: &[u8; 32],
        ciphersuite: u32,
        signature_scheme: u32,
    ) -> Result<[u8; 64]> {
        let resp = self.call(
            "sign_account_identity_proof",
            json!({
                "account_identity": hex::encode(account_identity),
                "mls_signature_public_key": hex::encode(mls_signature_public_key),
                "ciphersuite": ciphersuite,
                "signature_scheme": signature_scheme,
            }),
        )?;
        hex_to_64(get_str(&resp, "signature")?)
    }

    /// Get the X25519 HPKE public key at a specific index.
    ///
    /// Must be called before `mls_hpke_dh`/`mls_hpke_decap` for the
    /// returned key — populates the server-side HPKE cache.
    pub fn mls_hpke_pubkey_at(
        &self,
        mls_pubkey: &[u8; 32],
        key_type: u32,
        index: u32,
    ) -> Result<[u8; 32]> {
        let resp = self.call(
            "mls_hpke_pubkey_at",
            json!({
                "mls_pubkey": hex::encode(mls_pubkey),
                "key_type": key_type,
                "index": index,
            }),
        )?;
        hex_to_32(get_str(&resp, "hpke_pubkey")?)
    }

    /// X25519 Diffie-Hellman key agreement.
    ///
    /// Requires a prior `mls_hpke_pubkey_at` call that returned `hpke_pubkey`.
    pub fn mls_hpke_dh(
        &self,
        hpke_pubkey: &[u8; 32],
        peer_public: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let resp = self.call(
            "mls_hpke_dh",
            json!({
                "hpke_pubkey": hex::encode(hpke_pubkey),
                "peer_public": hex::encode(peer_public),
            }),
        )?;
        hex_to_32(get_str(&resp, "dh_result")?)
    }

    /// X25519 HPKE decapsulation (same operation as `mls_hpke_dh`).
    pub fn mls_hpke_decap(
        &self,
        hpke_pubkey: &[u8; 32],
        peer_public: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let resp = self.call(
            "mls_hpke_decap",
            json!({
                "hpke_pubkey": hex::encode(hpke_pubkey),
                "peer_public": hex::encode(peer_public),
            }),
        )?;
        hex_to_32(get_str(&resp, "dh_result")?)
    }

    /// Get the next unused HPKE init key for key package publishing.
    ///
    /// Pass `None` for `current_hpke_pubkey` to get index 0.
    pub fn mls_next_hpke_init_key(
        &self,
        mls_pubkey: &[u8; 32],
        current_hpke_pubkey: Option<&[u8; 32]>,
    ) -> Result<([u8; 32], u32)> {
        let resp = self.call(
            "mls_next_hpke_init_key",
            json!({
                "mls_pubkey": hex::encode(mls_pubkey),
                "current_hpke_pubkey": current_hpke_pubkey.map(hex::encode),
            }),
        )?;
        let pubkey = hex_to_32(get_str(&resp, "hpke_pubkey")?)?;
        let index = resp
            .get("index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Protocol("missing index".into()))? as u32;
        Ok((pubkey, index))
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut stream = UnixStream::connect(&self.path)?;

        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let payload = serde_json::to_vec(&req)?;

        // Write: 4-byte big-endian length + payload
        let len_bytes = (payload.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes)?;
        stream.write_all(&payload)?;

        // Read: 4-byte big-endian length + payload
        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr)?;
        let resp_len = u32::from_be_bytes(hdr) as usize;

        let mut buf = vec![0u8; resp_len];
        stream.read_exact(&mut buf)?;

        let resp: Value = serde_json::from_slice(&buf)?;

        // Check for JSON-RPC error
        if let Some(err) = resp.get("error") {
            let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
            let message = err
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
                .to_string();
            return Err(Error::Rpc { code, message });
        }

        resp.get("result")
            .cloned()
            .ok_or_else(|| Error::Protocol("missing result field".into()))
    }
}

// Helper: extract a string field from a JSON object.
fn get_str<'a>(obj: &'a Value, field: &str) -> Result<&'a str> {
    obj.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Protocol(format!("missing field: {field}")))
}

// Helper: decode a 32-byte hex string.
fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| Error::Protocol(format!("expected 32 bytes, got {}", v.len())))
}

// Helper: decode a 64-byte hex string.
fn hex_to_64(s: &str) -> Result<[u8; 64]> {
    let bytes = hex::decode(s)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| Error::Protocol(format!("expected 64 bytes, got {}", v.len())))
}

// libc for getuid — avoid pulling in a full libc crate just for this.
mod libc {
    extern "C" {
        pub fn getuid() -> u32;
    }
}
