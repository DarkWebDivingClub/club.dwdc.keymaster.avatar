use anyhow::{bail, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum frame size: 1 MiB
const MAX_FRAME_SIZE: u32 = 1024 * 1024;

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Service avatar → Avatar request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalRequest {
    /// Service type (e.g. "ssh", "gpg")
    pub service: String,
    /// Unique request identifier (monotonic counter)
    pub request_id: u64,
    /// Operation name (e.g. "request_identities", "sign_request")
    pub operation: String,
    /// Operation-specific payload (may be empty object)
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// Avatar → service avatar response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalResponse {
    /// Matches the request_id from LocalRequest
    pub request_id: u64,
    /// "ok" or "error"
    pub status: String,
    /// Result payload on success
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    /// Error message on failure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl LocalResponse {
    pub fn success(request_id: u64, payload: serde_json::Value) -> Self {
        Self {
            request_id,
            status: "ok".to_string(),
            payload: Some(payload),
            error: None,
        }
    }

    pub fn error(request_id: u64, msg: impl Into<String>) -> Self {
        Self {
            request_id,
            status: "error".to_string(),
            payload: None,
            error: Some(msg.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Framing: 4-byte big-endian length prefix + payload
// ---------------------------------------------------------------------------

/// Read a length-prefixed frame from the stream.
pub async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > MAX_FRAME_SIZE {
        bail!("invalid frame length: {}", len);
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a length-prefixed frame to the stream.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    Ok(())
}

/// Read a length-prefixed JSON message from the stream.
pub async fn read_message<T: DeserializeOwned, R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<T> {
    let frame = read_frame(reader).await?;
    let msg = serde_json::from_slice(&frame)?;
    Ok(msg)
}

/// Write a JSON message as a length-prefixed frame.
pub async fn write_message<T: Serialize, W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &T,
) -> Result<()> {
    let data = serde_json::to_vec(msg)?;
    write_frame(writer, &data).await
}
