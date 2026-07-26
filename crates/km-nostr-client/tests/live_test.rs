//! Integration test against a live km-nostr-sa instance.
//!
//! Requires:
//! - km-nostr-sa running with an attached KeyMaster identity
//! - Socket at /run/user/$UID/keymaster-nostr-sa.sock
//!
//! Run with: cargo test --package km-nostr-client --test live_test

use km_nostr_client::KmNostrClient;

fn skip_if_no_socket() -> Option<KmNostrClient> {
    KmNostrClient::connect_default().ok()
}

#[test]
fn get_public_keys() {
    let client = match skip_if_no_socket() {
        Some(c) => c,
        None => {
            eprintln!("SKIPPED: km-nostr-sa socket not available");
            return;
        }
    };
    let keys = client.get_public_keys().unwrap();
    assert!(!keys.is_empty(), "expected at least one public key");
    for key in &keys {
        assert_ne!(key, &[0u8; 32], "public key should not be all zeros");
    }
    eprintln!("  got {} public keys", keys.len());
}

#[test]
fn mls_full_flow() {
    let client = match skip_if_no_socket() {
        Some(c) => c,
        None => {
            eprintln!("SKIPPED: km-nostr-sa socket not available");
            return;
        }
    };

    // 1. Get a Nostr pubkey
    let keys = client.get_public_keys().unwrap();
    assert!(!keys.is_empty());
    let nostr_pubkey = &keys[0];
    eprintln!("  nostr_pubkey: {}", hex::encode(nostr_pubkey));

    // 2. Get MLS pubkey
    let mls_pubkey = client.get_mls_pubkey(nostr_pubkey).unwrap();
    assert_ne!(mls_pubkey, [0u8; 32]);
    eprintln!("  mls_pubkey: {}", hex::encode(mls_pubkey));

    // 3. MLS sign
    let data = b"test data for signing";
    let sig = client.mls_sign(&mls_pubkey, data).unwrap();
    assert_ne!(sig, [0u8; 64]);
    eprintln!("  mls_sign: {} (64 bytes)", hex::encode(&sig[..8]));

    // 4. Sign account identity proof
    let proof_sig = client
        .sign_account_identity_proof(nostr_pubkey, &mls_pubkey, 1, 2)
        .unwrap();
    assert_ne!(proof_sig, [0u8; 64]);
    eprintln!(
        "  account_identity_proof: {} (64 bytes)",
        hex::encode(&proof_sig[..8])
    );

    // 5. HPKE pubkey at index 0
    let hpke_pub = client.mls_hpke_pubkey_at(&mls_pubkey, 0, 0).unwrap();
    assert_ne!(hpke_pub, [0u8; 32]);
    eprintln!("  hpke_pubkey[0]: {}", hex::encode(hpke_pub));

    // 6. HPKE DH — use X25519 basepoint as peer (DH with basepoint = own pubkey)
    let mut peer = [0u8; 32];
    peer[0] = 9; // X25519 basepoint
    let dh_result = client.mls_hpke_dh(&hpke_pub, &peer).unwrap();
    assert_ne!(dh_result, [0u8; 32]);
    // DH with basepoint should equal the public key
    assert_eq!(dh_result, hpke_pub, "DH(basepoint) should equal public key");
    eprintln!("  hpke_dh: {}", hex::encode(dh_result));

    // 7. HPKE decap (same operation, different wire name)
    let decap_result = client.mls_hpke_decap(&hpke_pub, &peer).unwrap();
    assert_eq!(decap_result, dh_result);
    eprintln!("  hpke_decap: matches dh");

    // 8. Next HPKE init key
    let (next_pub, next_idx) = client
        .mls_next_hpke_init_key(&mls_pubkey, Some(&hpke_pub))
        .unwrap();
    assert_ne!(next_pub, [0u8; 32]);
    assert_eq!(next_idx, 1, "next index after 0 should be 1");
    eprintln!("  next_hpke_init_key: index={}, {}", next_idx, hex::encode(next_pub));

    // 9. Next with None (should return index 0)
    let (first_pub, first_idx) = client.mls_next_hpke_init_key(&mls_pubkey, None).unwrap();
    assert_eq!(first_idx, 0);
    assert_eq!(first_pub, hpke_pub, "index 0 should match hpke_pubkey_at(0)");
    eprintln!("  next_hpke_init_key(None): index=0, matches");

    eprintln!("\n  ALL MLS TESTS PASSED");
}
