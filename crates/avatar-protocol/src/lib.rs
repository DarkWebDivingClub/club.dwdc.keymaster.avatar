use anyhow::{bail, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Maximum line size: 1 MiB
const MAX_LINE_SIZE: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Protocol index: SHA-256(name) → 31-bit unsigned integer
// Same algorithm as Java Bip32KeyDerivator.mangle()
// ---------------------------------------------------------------------------

/// Compute a 31-bit non-hardened BIP-32 child index from a protocol name.
///
/// Algorithm: SHA-256(name as UTF-8) → take first 4 bytes as big-endian u32 → clear MSB.
/// This matches the Java `Bip32KeyDerivator.mangle()` function exactly.
pub fn protocol_index(name: &str) -> u32 {
    let hash = Sha256::digest(name.as_bytes());
    let raw = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    raw & 0x7FFF_FFFF
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 message types
// ---------------------------------------------------------------------------

/// JSON-RPC 2.0 request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

impl JsonRpcRequest {
    pub fn new(method: impl Into<String>, params: Value, id: impl Into<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
            id: Some(id.into()),
        }
    }

    pub fn notification(method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
            id: None,
        }
    }
}

/// JSON-RPC 2.0 error object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// JSON-RPC 2.0 response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }
}

// Standard JSON-RPC error codes
pub const JSONRPC_PARSE_ERROR: i64 = -32700;
pub const JSONRPC_INVALID_REQUEST: i64 = -32600;
pub const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
pub const JSONRPC_INVALID_PARAMS: i64 = -32602;
pub const JSONRPC_INTERNAL_ERROR: i64 = -32603;

// Application error codes
pub const JSONRPC_NO_SESSION: i64 = -32001;
pub const JSONRPC_SEND_FAILED: i64 = -32002;
pub const JSONRPC_TIMEOUT: i64 = -32003;
pub const JSONRPC_CHANNEL_DROPPED: i64 = -32004;

// ---------------------------------------------------------------------------
// A generic JSON-RPC message that can be either request or response.
// Used when we don't know the direction yet (e.g. reading from Nostr).
// ---------------------------------------------------------------------------

/// A raw JSON-RPC 2.0 message — could be request or response.
/// Use `is_request()` / `is_response()` to distinguish.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcMessage {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub params: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

impl JsonRpcMessage {
    pub fn is_request(&self) -> bool {
        self.method.is_some()
    }

    pub fn is_response(&self) -> bool {
        self.result.is_some() || self.error.is_some()
    }
}

// ---------------------------------------------------------------------------
// NDJSON framing: newline-delimited JSON
// ---------------------------------------------------------------------------

/// Read one newline-delimited JSON message from a buffered reader.
pub async fn read_line_message<T: DeserializeOwned>(
    reader: &mut BufReader<impl tokio::io::AsyncRead + Unpin>,
) -> Result<T> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        bail!("connection closed");
    }
    if n > MAX_LINE_SIZE {
        bail!("line too long: {} bytes", n);
    }
    let msg = serde_json::from_str(line.trim_end())?;
    Ok(msg)
}

/// Write a JSON message as a newline-terminated line.
pub async fn write_line_message<T: Serialize>(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    msg: &T,
) -> Result<()> {
    let mut data = serde_json::to_vec(msg)?;
    data.push(b'\n');
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t1_golden_value_alice() {
        // Must match Java: Bip32KeyDerivator.mangle("alice@atlanta.com") == 0x748b0a69
        assert_eq!(protocol_index("alice@atlanta.com"), 0x748b0a69);
    }

    #[test]
    fn t1_deterministic() {
        let a = protocol_index("ssh");
        let b = protocol_index("ssh");
        assert_eq!(a, b);
    }

    #[test]
    fn t1_case_sensitive() {
        assert_ne!(protocol_index("SSH"), protocol_index("ssh"));
        assert_ne!(protocol_index("Ssh"), protocol_index("ssh"));
    }

    #[test]
    fn t1_31_bit_range() {
        // MSB must always be clear (non-hardened BIP-32 index)
        for name in &["ssh", "gpg", "nostr", "alice@atlanta.com", "", "x"] {
            let idx = protocol_index(name);
            assert_eq!(idx & 0x8000_0000, 0, "MSB set for '{}'", name);
        }
    }

    #[test]
    fn t1_empty_string() {
        // Must not panic, must produce a valid 31-bit value
        let idx = protocol_index("");
        assert_eq!(idx & 0x8000_0000, 0);
        // SHA-256("") is well-known: e3b0c44298fc1c14...
        // first 4 bytes: 0xe3b0c442 & 0x7FFFFFFF = 0x63b0c442
        assert_eq!(idx, 0x63b0c442);
    }

    #[test]
    fn t1_different_inputs_differ() {
        assert_ne!(protocol_index("ssh"), protocol_index("gpg"));
        assert_ne!(protocol_index("ssh"), protocol_index("nostr"));
    }

    // Cross-language golden values (T2) — must match Java MangleTest.t2_*
    #[test]
    fn t2_cross_language_ssh() {
        assert_eq!(protocol_index("ssh"), 0x7f5a55cf);
    }

    #[test]
    fn t2_cross_language_gpg() {
        assert_eq!(protocol_index("gpg"), 0x6858a423);
    }

    #[test]
    fn t2_cross_language_nostr() {
        assert_eq!(protocol_index("nostr"), 0x0f5392e4);
    }
}
