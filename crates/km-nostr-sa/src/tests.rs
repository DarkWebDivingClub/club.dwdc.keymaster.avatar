use super::*;
use serde_json::json;

#[test]
fn hex_to_base64_converts_valid_hex() {
    // 32-byte key as hex (64 chars)
    let hex_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    let mut obj = json!({"public_key": hex_key});
    hex_to_base64_field(&mut obj, "public_key");

    let b64 = obj["public_key"].as_str().unwrap();
    // Verify round-trip: base64 → bytes → hex matches original
    let bytes = BASE64.decode(b64).unwrap();
    assert_eq!(hex::encode(&bytes), hex_key);
}

#[test]
fn base64_to_hex_converts_valid_base64() {
    let bytes = vec![0xdeu8, 0xad, 0xbe, 0xef];
    let b64 = BASE64.encode(&bytes);
    let mut obj = json!({"signature": b64});
    base64_to_hex_field(&mut obj, "signature");

    assert_eq!(obj["signature"].as_str().unwrap(), "deadbeef");
}

#[test]
fn hex_to_base64_skips_missing_field() {
    let mut obj = json!({"other": "value"});
    hex_to_base64_field(&mut obj, "public_key");
    // Should not crash, field should not exist
    assert!(obj.get("public_key").is_none());
}

#[test]
fn translate_sign_event_request() {
    let pk_hex = "ab".repeat(32);
    let hash_hex = "cd".repeat(32);
    let mut params = json!({
        "public_key": pk_hex,
        "event_hash": hash_hex
    });
    translate_request_params("sign_event", &mut params);

    // Both fields should be base64 now
    let pk_bytes = BASE64.decode(params["public_key"].as_str().unwrap()).unwrap();
    assert_eq!(pk_bytes.len(), 32);
    assert!(pk_bytes.iter().all(|&b| b == 0xab));

    let hash_bytes = BASE64.decode(params["event_hash"].as_str().unwrap()).unwrap();
    assert_eq!(hash_bytes.len(), 32);
    assert!(hash_bytes.iter().all(|&b| b == 0xcd));
}

#[test]
fn translate_encrypt_request() {
    let pk_hex = "aa".repeat(32);
    let peer_hex = "bb".repeat(32);
    let mut params = json!({
        "public_key": pk_hex,
        "peer_public_key": peer_hex,
        "plaintext": "hello"
    });
    translate_request_params("nip44_encrypt", &mut params);

    // Byte fields translated, plaintext unchanged
    let pk_bytes = BASE64.decode(params["public_key"].as_str().unwrap()).unwrap();
    assert_eq!(pk_bytes.len(), 32);
    assert_eq!(params["plaintext"].as_str().unwrap(), "hello");
}

#[test]
fn translate_get_public_keys_response() {
    let key1 = BASE64.encode(vec![0xaa; 32]);
    let key2 = BASE64.encode(vec![0xbb; 32]);
    let mut result = json!([
        {"public_key": key1},
        {"public_key": key2}
    ]);
    translate_response_result("get_public_keys", &mut result);

    let arr = result.as_array().unwrap();
    assert_eq!(arr[0]["public_key"].as_str().unwrap(), "aa".repeat(32));
    assert_eq!(arr[1]["public_key"].as_str().unwrap(), "bb".repeat(32));
}

#[test]
fn translate_sign_event_response() {
    let sig = BASE64.encode(vec![0xff; 64]);
    let mut result = json!({"signature": sig});
    translate_response_result("sign_event", &mut result);

    assert_eq!(result["signature"].as_str().unwrap(), "ff".repeat(64));
}

#[test]
fn translate_encrypt_response_unchanged() {
    let mut result = json!({"ciphertext": "some-base64-nip44-payload"});
    translate_response_result("nip44_encrypt", &mut result);
    // Ciphertext is a string, should not be translated
    assert_eq!(
        result["ciphertext"].as_str().unwrap(),
        "some-base64-nip44-payload"
    );
}

#[test]
fn translate_decrypt_response_unchanged() {
    let mut result = json!({"plaintext": "hello world"});
    translate_response_result("nip44_decrypt", &mut result);
    assert_eq!(result["plaintext"].as_str().unwrap(), "hello world");
}
