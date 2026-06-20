// Local API client for keymaster-avatar (synchronous, blocking I/O).
// Speaks the avatar-protocol framing: 4-byte BE length + JSON payload.
// Replaces the SSH agent protocol used by the old PKCS#11 lib.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Deserialize;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// An identity returned by the avatar's request_identities operation.
#[derive(Debug, Deserialize)]
pub struct Identity {
    pub key_type: String,
    pub public_key: String, // base64-encoded
    pub label: String,
}

pub struct LocalClient {
    stream: UnixStream,
    next_id: u64,
}

impl LocalClient {
    pub fn connect(socket_path: &Path) -> Result<Self, String> {
        let stream = UnixStream::connect(socket_path)
            .map_err(|e| format!("connect to {}: {}", socket_path.display(), e))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("set_read_timeout: {}", e))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| format!("set_write_timeout: {}", e))?;
        Ok(LocalClient { stream, next_id: 1 })
    }

    /// Send a LocalRequest and receive a LocalResponse (blocking).
    fn request(
        &mut self,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let req = serde_json::json!({
            "service": "gpg",
            "request_id": self.next_id,
            "operation": operation,
            "payload": payload,
        });
        let req_id = self.next_id;
        self.next_id += 1;

        let data = serde_json::to_vec(&req).map_err(|e| format!("serialize: {}", e))?;

        // Write: 4-byte BE length + JSON
        let len_bytes = (data.len() as u32).to_be_bytes();
        self.stream
            .write_all(&len_bytes)
            .map_err(|e| format!("write len: {}", e))?;
        self.stream
            .write_all(&data)
            .map_err(|e| format!("write payload: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("flush: {}", e))?;

        // Read: 4-byte BE length + JSON
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .map_err(|e| format!("read response len: {}", e))?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > 1024 * 1024 {
            return Err(format!("invalid response length: {}", resp_len));
        }
        let mut resp_buf = vec![0u8; resp_len];
        self.stream
            .read_exact(&mut resp_buf)
            .map_err(|e| format!("read response: {}", e))?;

        let resp: serde_json::Value =
            serde_json::from_slice(&resp_buf).map_err(|e| format!("parse response: {}", e))?;

        // Validate request_id matches
        if resp.get("request_id").and_then(|v| v.as_u64()) != Some(req_id) {
            return Err("response request_id mismatch".into());
        }

        let status = resp
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("error");
        if status != "ok" {
            let err_msg = resp
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(format!("avatar error: {}", err_msg));
        }

        Ok(resp
            .get("payload")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// Request identities from the avatar (GPG keys).
    pub fn request_identities(&mut self) -> Result<Vec<Identity>, String> {
        let payload = self.request("request_identities", serde_json::json!({}))?;

        let identities_val = payload
            .get("identities")
            .ok_or("missing 'identities' in response")?;

        let identities: Vec<Identity> = serde_json::from_value(identities_val.clone())
            .map_err(|e| format!("parse identities: {}", e))?;

        Ok(identities)
    }

    /// Fetch the GPG public cert armor from the keymaster.
    pub fn get_public_cert(&mut self) -> Result<String, String> {
        let payload = self.request("get_public_cert", serde_json::json!({}))?;

        let cert_armor = payload
            .get("public_cert_armor")
            .and_then(|v| v.as_str())
            .ok_or("missing 'public_cert_armor' in response")?;

        Ok(cert_armor.to_string())
    }

    /// Sign data with the given key (Ed25519).
    pub fn sign(
        &mut self,
        key_index: usize,
        public_key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let payload = self.request(
            "sign_request",
            serde_json::json!({
                "key_index": key_index,
                "public_key": BASE64.encode(public_key),
                "data": BASE64.encode(data),
                "mechanism": "eddsa",
            }),
        )?;

        let sig_b64 = payload
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or("missing 'signature' in response")?;

        let sig = BASE64
            .decode(sig_b64)
            .map_err(|e| format!("decode signature: {}", e))?;

        Ok(sig)
    }
}
