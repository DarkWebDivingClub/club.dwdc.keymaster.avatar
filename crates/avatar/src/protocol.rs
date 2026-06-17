use serde::{Deserialize, Serialize};

/// Nostr event kind for Avatar/KM protocol traffic
pub const PROTOCOL_KIND: u16 = 27235;

/// Protocol request envelope
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
}

/// Protocol response envelope
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn ok() -> Self {
        Self {
            result: Some(serde_json::Value::String("ok".to_string())),
            error: None,
        }
    }

    pub fn result(value: serde_json::Value) -> Self {
        Self {
            result: Some(value),
            error: None,
        }
    }

    pub fn error(msg: &str) -> Self {
        Self {
            result: None,
            error: Some(msg.to_string()),
        }
    }
}
