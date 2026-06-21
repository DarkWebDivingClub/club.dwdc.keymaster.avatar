// scd-shim: Thin Assuan-to-JSON-RPC translator for KeyMaster Avatar.
//
// Speaks the GnuPG Assuan protocol (stdin/stdout) and communicates with
// km-gpg-sa over a Unix socket (JSON-RPC 2.0). This replaces the direct
// avatar API connection that iz-scdaemon used.
//
// gpg-agent starts this binary as its scdaemon. The flow:
// 1. Connect to km-gpg-sa proxy socket (no avatar handshake needed)
// 2. Fetch identities via gpg.request_identities
// 3. Compute keygrips (matching libgcrypt's algorithm exactly)
// 4. Handle Assuan commands: SERIALNO, LEARN, READKEY, SETDATA, PKSIGN, etc.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Deserialize;
use sha1::{Sha1, Digest};
use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_SOCKET: &str = "/tmp/keymaster-avatar-gpg.sock";
const SERIAL: &str = "D2760001240103000000000000000100";

// ---- km-gpg-sa JSON-RPC client ----

#[derive(Debug, Deserialize)]
struct RawIdentity {
    key_type: String,
    public_key: String, // base64-encoded
    label: String,
}

/// Simple synchronous JSON-RPC client that connects to the km-gpg-sa proxy
/// socket. No avatar `connect` handshake — the proxy speaks raw JSON-RPC.
struct GpgSaClient {
    reader: io::BufReader<UnixStream>,
    writer: UnixStream,
    next_id: u64,
}

impl GpgSaClient {
    fn connect(socket_path: &std::path::Path) -> Result<Self, String> {
        let stream = UnixStream::connect(socket_path)
            .map_err(|e| format!("connect to {}: {}", socket_path.display(), e))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("set_read_timeout: {}", e))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| format!("set_write_timeout: {}", e))?;

        let writer = stream
            .try_clone()
            .map_err(|e| format!("clone stream: {}", e))?;
        let reader = io::BufReader::new(stream);

        Ok(GpgSaClient {
            reader,
            writer,
            next_id: 1,
        })
    }

    fn request(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.next_id,
        });
        self.next_id += 1;

        let mut data = serde_json::to_vec(&req).map_err(|e| format!("serialize: {}", e))?;
        data.push(b'\n');
        self.writer
            .write_all(&data)
            .map_err(|e| format!("write request: {}", e))?;
        self.writer
            .flush()
            .map_err(|e| format!("flush: {}", e))?;

        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .map_err(|e| format!("read response: {}", e))?;

        let resp: serde_json::Value = serde_json::from_str(line.trim_end())
            .map_err(|e| format!("parse response: {}", e))?;

        if let Some(err) = resp.get("error") {
            let message = err
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(format!("proxy error: {}", message));
        }

        Ok(resp
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    fn request_identities(&mut self) -> Result<Vec<RawIdentity>, String> {
        let payload = self.request("gpg.request_identities", serde_json::json!({}))?;
        let identities_val = payload
            .get("identities")
            .ok_or("missing 'identities' in response")?;
        serde_json::from_value(identities_val.clone())
            .map_err(|e| format!("parse identities: {}", e))
    }

    fn sign(&mut self, key_index: usize, public_key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let payload = self.request(
            "gpg.sign_request",
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
        BASE64
            .decode(sig_b64)
            .map_err(|e| format!("decode signature: {}", e))
    }
}

/// Find the km-gpg-sa proxy socket path.
/// Priority: KM_GPG_SA_SOCKET env → {GNUPGHOME}/km-gpg-sa.socket file → default.
fn find_socket_path() -> PathBuf {
    // 1. Explicit env var
    if let Ok(path) = std::env::var("KM_GPG_SA_SOCKET") {
        return PathBuf::from(path);
    }

    // 2. Read from GNUPGHOME/km-gpg-sa.socket file (written by km-gpg-sa)
    if let Ok(gnupg_home) = std::env::var("GNUPGHOME") {
        let socket_file = PathBuf::from(&gnupg_home).join("km-gpg-sa.socket");
        if let Ok(contents) = std::fs::read_to_string(&socket_file) {
            let path = contents.trim();
            if !path.is_empty() {
                return PathBuf::from(path);
            }
        }
    }

    // 3. Default
    PathBuf::from(DEFAULT_SOCKET)
}

// ---- Identity ----

struct Identity {
    public_key: Vec<u8>, // 32-byte Ed25519 public key
    index: usize,
    keygrip: String, // 40 uppercase hex chars (from GPG's libgcrypt)
    keyref: String,  // e.g. "OPENPGP.1"
}

/// Build the canonical S-expression for a full Ed25519 public key,
/// used in the READKEY response (Assuan protocol).
///   (10:public-key(3:ecc(5:curve7:Ed25519)(5:flags5:eddsa)(1:q33:\x40<pubkey>)))
fn public_key_sexp(public_key: &[u8]) -> Vec<u8> {
    let mut sexp = Vec::with_capacity(80);
    sexp.extend_from_slice(b"(10:public-key(3:ecc(5:curve7:Ed25519)(5:flags5:eddsa)(1:q33:");
    sexp.push(0x40);
    sexp.extend_from_slice(public_key);
    sexp.extend_from_slice(b")))");
    sexp
}

/// Compute keygrip from an Ed25519 public key, matching libgcrypt's
/// algorithm exactly.
///
/// libgcrypt computes ECC keygrips by SHA-1 hashing the curve parameters
/// (p, a, b, g, n) plus the public key point (q), each wrapped in
/// canonical S-expression notation:
///   `(1:p<len>:<bytes>)(1:a<len>:<bytes>)...(1:q<len>:<bytes>)`
///
/// For Ed25519, the parameters are hardcoded from libgcrypt's curve table:
///   p = 2^255 - 19
///   a = 1 (absolute value of -1)
///   b = |d| where d = -121665/121666
///   g = 0x04 || y || x (uncompressed SEC1 generator point)
///   n = group order
///   q = 0x40 || public_key (EdDSA native format)
fn compute_keygrip(public_key: &[u8]) -> String {
    // Ed25519 curve parameters (from libgcrypt ecc-curves.c).
    // Verified empirically against libgcrypt 1.10/1.12 gcry_pk_get_keygrip.
    //
    // p = 2^255 - 19
    let p: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED,
    ];
    // a = |−1| = 0x01 (absolute value; libgcrypt's _gcry_mpi_get_buffer
    // returns unsigned representation, so negative sign is dropped)
    let a: [u8; 1] = [0x01];
    // b = |d| where d = −121665/121666 mod p
    //   = 0x2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A
    let b: [u8; 32] = [
        0x2D, 0xFC, 0x93, 0x11, 0xD4, 0x90, 0x01, 0x8C,
        0x73, 0x38, 0xBF, 0x86, 0x88, 0x86, 0x17, 0x67,
        0xFF, 0x8F, 0xF5, 0xB2, 0xBE, 0xBE, 0x27, 0x54,
        0x8A, 0x14, 0xB2, 0x35, 0xEC, 0xA6, 0x87, 0x4A,
    ];
    // g = 0x04 || G.x || G.y (SEC1 uncompressed format, x first)
    //   G.x = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
    //   G.y = 0x6666666666666666666666666666666666666666666666666666666666666658
    let g: [u8; 65] = [
        0x04,
        0x21, 0x69, 0x36, 0xD3, 0xCD, 0x6E, 0x53, 0xFE,
        0xC0, 0xA4, 0xE2, 0x31, 0xFD, 0xD6, 0xDC, 0x5C,
        0x69, 0x2C, 0xC7, 0x60, 0x95, 0x25, 0xA7, 0xB2,
        0xC9, 0x56, 0x2D, 0x60, 0x8F, 0x25, 0xD5, 0x1A,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58,
    ];
    // n = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    let n: [u8; 32] = [
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6,
        0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED,
    ];

    // q = public_key (32 bytes, compact EdDSA form without the 0x40
    // prefix — libgcrypt's _gcry_ecc_eddsa_ensure_compact strips it)

    // Hash: (1:p<len>:<bytes>)(1:a<len>:<bytes>)...(1:q<len>:<bytes>)
    let mut hasher = Sha1::new();
    for (name, value) in [
        ("p", p.as_slice()),
        ("a", a.as_slice()),
        ("b", b.as_slice()),
        ("g", g.as_slice()),
        ("n", n.as_slice()),
        ("q", public_key),
    ] {
        let header = format!("(1:{}{}", name, value.len());
        hasher.update(header.as_bytes());
        hasher.update(b":");
        hasher.update(value);
        hasher.update(b")");
    }

    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{:02X}", b)).collect()
}

// ---- Hex utilities ----

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| format!("hex decode at {}: {}", i, e))?;
        out.push(byte);
    }
    Ok(out)
}

// ---- Assuan protocol output ----

fn send_ok(out: &mut impl Write, msg: &str) {
    if msg.is_empty() {
        let _ = out.write_all(b"OK\n");
    } else {
        let _ = write!(out, "OK {}\n", msg);
    }
    let _ = out.flush();
}

fn send_err(out: &mut impl Write, code: u32, msg: &str) {
    let _ = write!(out, "ERR {} {}\n", code, msg);
    let _ = out.flush();
}

fn send_status(out: &mut impl Write, keyword: &str, value: &str) {
    let _ = write!(out, "S {} {}\n", keyword, value);
}

/// Send binary data on D lines with percent-encoding (CR, LF, %).
fn send_data(out: &mut impl Write, data: &[u8]) {
    let _ = out.write_all(b"D ");
    for &byte in data {
        match byte {
            b'%' => { let _ = out.write_all(b"%25"); }
            b'\r' => { let _ = out.write_all(b"%0D"); }
            b'\n' => { let _ = out.write_all(b"%0A"); }
            _ => { let _ = out.write_all(&[byte]); }
        }
    }
    let _ = out.write_all(b"\n");
}

// ---- Scdaemon state ----

struct ScdState {
    identities: Vec<Identity>,
    stored_data: Vec<u8>,
    client: GpgSaClient,
}

// ---- Command parsing ----

fn parse_command(line: &str) -> (&str, &str) {
    match line.find(|c: char| c.is_whitespace()) {
        Some(i) => (&line[..i], line[i..].trim_start()),
        None => (line, ""),
    }
}

fn skip_options(line: &str) -> &str {
    let mut rest = line;
    loop {
        rest = rest.trim_start();
        if rest.starts_with("--") {
            match rest.find(|c: char| c.is_whitespace()) {
                Some(i) => rest = &rest[i..],
                None => return "",
            }
        } else {
            return rest;
        }
    }
}

// ---- Command handlers ----

fn handle_serialno(out: &mut impl Write, args: &str, log: &dyn Fn(&str)) {
    // Parse --demand=<serial> if present
    if let Some(demand_start) = args.find("--demand=") {
        let demand = &args[demand_start + 9..];
        // Extract hex serial from demand (stop at whitespace)
        let demand_serial: String = demand.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        // Compare: strip trailing zeros from both, since GnuPG may pad
        let our = SERIAL.trim_end_matches('0');
        let theirs = demand_serial.trim_end_matches('0');
        log(&format!("SERIALNO --demand: ours={}, theirs={}, match={}",
            SERIAL, demand_serial, our == theirs));
        if our == theirs {
            send_status(out, "SERIALNO", SERIAL);
            send_ok(out, "");
        } else {
            send_err(out, 67, "Card not present");
        }
        return;
    }
    send_status(out, "SERIALNO", SERIAL);
    send_ok(out, "");
}

fn handle_learn(out: &mut impl Write, state: &ScdState) {
    send_status(out, "SERIALNO", SERIAL);
    send_status(out, "APPTYPE", "OPENPGP");
    for id in &state.identities {
        send_status(out, "KEYPAIRINFO", &format!("{} {}", id.keygrip, id.keyref));
    }
    send_ok(out, "");
}

fn handle_readkey(out: &mut impl Write, state: &ScdState, args: &str) {
    let keyref = skip_options(args).trim();
    let identity = state
        .identities
        .iter()
        .find(|id| id.keyref == keyref || id.keygrip == keyref);

    match identity {
        Some(id) => {
            let sexp = public_key_sexp(&id.public_key);
            send_data(out, &sexp);
            send_ok(out, "");
        }
        None => {
            send_err(out, 69, "No such key");
        }
    }
}

fn handle_setdata(out: &mut impl Write, state: &mut ScdState, args: &str) {
    let hex_str: String = args.split_whitespace().collect();
    match hex_decode(&hex_str) {
        Ok(data) => {
            state.stored_data = data;
            send_ok(out, "");
        }
        Err(e) => {
            send_err(out, 62, &format!("Invalid hex data: {}", e));
        }
    }
}

/// Strip DigestInfo ASN.1 wrapper from PKCS#1-padded hash data.
/// GnuPG 2.2.x sends DigestInfo-wrapped hashes even for EdDSA keys.
/// Ed25519 signing needs the raw hash, not the DigestInfo wrapper.
fn strip_digest_info(data: &[u8]) -> &[u8] {
    // SHA-256 DigestInfo prefix (19 bytes):
    // 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
    const SHA256_PREFIX: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ];
    // SHA-512 DigestInfo prefix (19 bytes):
    // 30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40
    const SHA512_PREFIX: &[u8] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
    ];

    if data.len() == 51 && data.starts_with(SHA256_PREFIX) {
        &data[SHA256_PREFIX.len()..] // 32 bytes
    } else if data.len() == 83 && data.starts_with(SHA512_PREFIX) {
        &data[SHA512_PREFIX.len()..] // 64 bytes
    } else {
        data // already raw hash or unknown format
    }
}

fn handle_pksign(out: &mut impl Write, state: &mut ScdState, args: &str, log: &dyn Fn(&str)) {
    let keyid = skip_options(args).trim();

    let identity = state
        .identities
        .iter()
        .find(|id| id.keygrip == keyid || id.keyref == keyid)
        .or_else(|| state.identities.iter().find(|id| id.keyref == "OPENPGP.3"));

    let identity = match identity {
        Some(id) => id,
        None => {
            send_err(out, 69, "No matching key found");
            return;
        }
    };

    if state.stored_data.is_empty() {
        send_err(out, 76, "No data to sign (call SETDATA first)");
        return;
    }

    // Strip DigestInfo wrapper if present — GnuPG 2.2.x sends DigestInfo
    // even for EdDSA keys, but Ed25519 signing needs the raw hash.
    let sign_data = strip_digest_info(&state.stored_data);

    log(&format!(
        "PKSIGN: key={} (index={}), raw_data_len={}, sign_data_len={}",
        identity.keyref, identity.index, state.stored_data.len(), sign_data.len()
    ));

    match state.client.sign(identity.index, &identity.public_key, sign_data) {
        Ok(sig) => {
            if sig.len() != 64 {
                log(&format!("unexpected signature length: {}", sig.len()));
                send_err(out, 2, "Invalid signature length");
                return;
            }
            log(&format!("PKSIGN: got {}-byte signature", sig.len()));
            send_data(out, &sig);
            send_ok(out, "");
        }
        Err(e) => {
            log(&format!("PKSIGN sign failed: {}", e));
            send_err(out, 2, &format!("Sign error: {}", e));
        }
    }

    state.stored_data.clear();
}

fn handle_keyinfo(out: &mut impl Write, state: &ScdState) {
    for id in &state.identities {
        send_status(
            out,
            "KEYINFO",
            &format!("{} T {} {} - - - -", id.keygrip, SERIAL, id.keyref),
        );
    }
    send_ok(out, "");
}

fn handle_getattr(out: &mut impl Write, state: &ScdState, args: &str) {
    let attr = args.trim();
    match attr {
        "SERIALNO" => {
            send_status(out, "SERIALNO", SERIAL);
            send_ok(out, "");
        }
        "APPTYPE" => {
            send_status(out, "APPTYPE", "OPENPGP");
            send_ok(out, "");
        }
        "KEY-ATTR" => {
            for id in &state.identities {
                send_status(out, "KEY-ATTR", &format!("{} 22 1.3.101.112", id.keyref));
            }
            send_ok(out, "");
        }
        "$AUTHKEYID" => {
            if let Some(id) = state.identities.iter().find(|id| id.keyref == "OPENPGP.3") {
                send_status(out, "AUTHKEYID", &id.keyref);
            }
            send_ok(out, "");
        }
        "CHV-STATUS" => {
            send_status(out, "CHV-STATUS", "1 -1 -1 -1 3 3 3");
            send_ok(out, "");
        }
        "DISP-NAME" => {
            send_status(out, "DISP-NAME", "KeyMaster");
            send_ok(out, "");
        }
        _ => {
            send_ok(out, "");
        }
    }
}

fn handle_getinfo(out: &mut impl Write, args: &str) {
    let what = args.trim();
    match what {
        "socket_name" => {
            send_err(out, 69, "Not a socket-based daemon");
        }
        "version" => {
            send_data(out, b"0.1.0");
            send_ok(out, "");
        }
        "pid" => {
            let pid = std::process::id();
            let _ = write!(out, "D {}\n", pid);
            send_ok(out, "");
        }
        _ => {
            send_ok(out, "");
        }
    }
}

// ---- Main ----

fn main() {
    let log_path = std::env::var("GNUPGHOME")
        .map(|h| PathBuf::from(h).join("scd-shim.log"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/scd-shim.log"));

    let log = move |msg: &str| {
        eprintln!("scd-shim: {}", msg);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let _ = writeln!(f, "{}", msg);
        }
    };

    // Find km-gpg-sa proxy socket
    let socket_path = find_socket_path();
    log(&format!("starting, socket={}", socket_path.display()));

    // Connect to km-gpg-sa proxy
    let mut client = match GpgSaClient::connect(&socket_path) {
        Ok(c) => {
            log("connected to km-gpg-sa");
            c
        }
        Err(e) => {
            log(&format!("FATAL: connect failed: {}", e));
            let mut stdout = io::stdout().lock();
            let _ = write!(stdout, "ERR 2 Cannot connect to km-gpg-sa: {}\n", e);
            let _ = stdout.flush();
            std::process::exit(1);
        }
    };

    // Fetch identities (for public keys and sign operations)
    let raw_identities = match client.request_identities() {
        Ok(ids) => {
            log(&format!("got {} identities", ids.len()));
            ids
        }
        Err(e) => {
            log(&format!("FATAL: request_identities failed: {}", e));
            let mut stdout = io::stdout().lock();
            let _ = write!(stdout, "ERR 2 Cannot fetch identities: {}\n", e);
            let _ = stdout.flush();
            std::process::exit(1);
        }
    };

    // Decode public keys from identities
    let decoded_identities: Vec<(Vec<u8>, String, usize)> = raw_identities
        .into_iter()
        .enumerate()
        .filter_map(|(i, raw)| {
            if raw.key_type != "ed25519" {
                log(&format!("skipping unsupported key type: {}", raw.key_type));
                return None;
            }
            let pk = match BASE64.decode(&raw.public_key) {
                Ok(pk) if pk.len() == 32 => pk,
                Ok(pk) => {
                    log(&format!("unexpected public key length: {}", pk.len()));
                    return None;
                }
                Err(e) => {
                    log(&format!("decode public_key failed: {}", e));
                    return None;
                }
            };
            Some((pk, raw.label, i))
        })
        .collect();

    // Compute keygrips internally from public keys using SHA-1 of the
    // canonical S-expression. This matches libgcrypt's computation and
    // avoids running `gpg --list-keys` before the greeting (which would
    // deadlock: gpg-agent is waiting for our greeting, and `gpg` would
    // try to connect to the already-running gpg-agent).
    let keyrefs = ["OPENPGP.1", "OPENPGP.3"];
    let identities: Vec<Identity> = decoded_identities
        .into_iter()
        .enumerate()
        .map(|(i, (pk, label, index))| {
            let keygrip = compute_keygrip(&pk);
            let keyref = keyrefs.get(i).unwrap_or(&"OPENPGP.1").to_string();
            log(&format!(
                "identity {}: label={}, keyref={}, keygrip={}",
                i, label, keyref, keygrip
            ));
            Identity {
                public_key: pk,
                index,
                keygrip,
                keyref,
            }
        })
        .collect();

    let mut state = ScdState {
        identities,
        stored_data: Vec::new(),
        client,
    };

    // Assuan greeting — gpg-agent is waiting for this before it can
    // process any other requests (including LEARN).
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_all(b"OK scd-shim ready\n");
    let _ = stdout.flush();

    log("greeting sent, entering command loop");

    // Command loop
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                log(&format!("stdin read error: {}", e));
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        log(&format!("CMD: {}", trimmed));

        let (cmd, args) = parse_command(trimmed);

        match cmd.to_uppercase().as_str() {
            "SERIALNO" => handle_serialno(&mut stdout, args, &log),
            "LEARN" => handle_learn(&mut stdout, &state),
            "READKEY" => handle_readkey(&mut stdout, &state, args),
            "SETDATA" => handle_setdata(&mut stdout, &mut state, args),
            "PKSIGN" => handle_pksign(&mut stdout, &mut state, args, &log),
            "KEYINFO" => handle_keyinfo(&mut stdout, &state),
            "GETATTR" => handle_getattr(&mut stdout, &state, args),
            "GETINFO" => handle_getinfo(&mut stdout, args),
            "READCERT" => send_err(&mut stdout, 69, "Not supported"),
            "RESTART" => {
                state.stored_data.clear();
                send_ok(&mut stdout, "");
            }
            "RESET" => {
                state.stored_data.clear();
                send_ok(&mut stdout, "");
            }
            "BYE" => {
                send_ok(&mut stdout, "closing connection");
                log("BYE received, exiting");
                break;
            }
            "NOP" => send_ok(&mut stdout, ""),
            "OPTION" => send_ok(&mut stdout, ""),
            _ => {
                log(&format!("unknown command: {}", cmd));
                send_ok(&mut stdout, "");
            }
        }
    }
}
