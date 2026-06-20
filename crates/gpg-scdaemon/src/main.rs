// Custom GnuPG scdaemon for KeyMaster Avatar.
//
// Speaks the GnuPG Assuan protocol (stdin/stdout) and communicates with
// the avatar's local API over a Unix socket. This replaces gnupg-pkcs11-scd
// which does not support Ed25519/EdDSA keys.
//
// gpg-agent starts this binary as its scdaemon. The flow:
// 1. Connect to avatar local API, fetch identities + GPG public cert
// 2. Import cert into GPG synchronously (gpg --no-autostart --import)
// 3. Extract keygrips from GPG (matching libgcrypt's computation)
// 4. Handle Assuan commands: SERIALNO, LEARN, READKEY, SETDATA, PKSIGN, etc.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Deserialize;
use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const DEFAULT_SOCKET: &str = "/tmp/keymaster-avatar.sock";
const SERIAL: &str = "D2760001240103000000000000000100";

// ---- Local API client (adapted from pkcs11-gpg/local_client.rs) ----

#[derive(Debug, Deserialize)]
struct RawIdentity {
    key_type: String,
    public_key: String, // base64-encoded
    label: String,
}

struct LocalClient {
    reader: io::BufReader<UnixStream>,
    writer: UnixStream,
    next_id: u64,
}

impl LocalClient {
    fn connect(socket_path: &Path) -> Result<Self, String> {
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

        let mut client = LocalClient {
            reader,
            writer,
            next_id: 1,
        };

        // Send connect handshake (required by local API)
        client.send_connect()?;

        Ok(client)
    }

    fn send_connect(&mut self) -> Result<(), String> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "connect",
            "params": { "type": "gpg" },
            "id": self.next_id,
        });
        self.next_id += 1;

        let mut data = serde_json::to_vec(&req).map_err(|e| format!("serialize: {}", e))?;
        data.push(b'\n');
        self.writer
            .write_all(&data)
            .map_err(|e| format!("write connect: {}", e))?;
        self.writer
            .flush()
            .map_err(|e| format!("flush connect: {}", e))?;

        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .map_err(|e| format!("read connect response: {}", e))?;

        let resp: serde_json::Value = serde_json::from_str(line.trim_end())
            .map_err(|e| format!("parse connect response: {}", e))?;

        if resp.get("error").is_some() {
            return Err("connect handshake failed".into());
        }
        Ok(())
    }

    fn request(
        &mut self,
        operation: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": format!("gpg.{}", operation),
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
            return Err(format!("avatar error: {}", message));
        }

        Ok(resp
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    fn request_identities(&mut self) -> Result<Vec<RawIdentity>, String> {
        let payload = self.request("request_identities", serde_json::json!({}))?;
        let identities_val = payload
            .get("identities")
            .ok_or("missing 'identities' in response")?;
        serde_json::from_value(identities_val.clone())
            .map_err(|e| format!("parse identities: {}", e))
    }

    fn get_public_cert(&mut self) -> Result<String, String> {
        let payload = self.request("get_public_cert", serde_json::json!({}))?;
        payload
            .get("public_cert_armor")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "missing 'public_cert_armor' in response".into())
    }

    fn sign(&mut self, key_index: usize, public_key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
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
        BASE64
            .decode(sig_b64)
            .map_err(|e| format!("decode signature: {}", e))
    }
}

// ---- Identity ----

struct Identity {
    public_key: Vec<u8>, // 32-byte Ed25519 public key
    index: usize,
    keygrip: String, // 40 uppercase hex chars (from GPG's libgcrypt)
    keyref: String,  // e.g. "OPENPGP.1"
}

/// Build the canonical S-expression for a full Ed25519 public key.
///   (10:public-key(3:ecc(5:curve7:Ed25519)(5:flags5:eddsa)(1:q33:\x40<pubkey>)))
fn public_key_sexp(public_key: &[u8]) -> Vec<u8> {
    let mut sexp = Vec::with_capacity(80);
    sexp.extend_from_slice(b"(10:public-key(3:ecc(5:curve7:Ed25519)(5:flags5:eddsa)(1:q33:");
    sexp.push(0x40);
    sexp.extend_from_slice(public_key);
    sexp.extend_from_slice(b")))");
    sexp
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

// ---- Cert import and keygrip extraction ----

/// Extract keygrips from GPG's keyring using --with-keygrip.
/// Returns keygrips for all keys (primary + subkeys) in order.
fn extract_keygrips(homedir: &str, log: &dyn Fn(&str)) -> Vec<String> {
    let output = match Command::new("gpg")
        .args([
            "--homedir", homedir, "--no-autostart", "--batch",
            "--with-colons", "--with-keygrip", "--list-keys",
        ])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            log(&format!("gpg --list-keys failed: {}", e));
            return Vec::new();
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse grp records - order is: primary key, then subkeys
    // grp:::::::::KEYGRIP:
    let keygrips: Vec<String> = stdout
        .lines()
        .filter(|l| l.starts_with("grp:"))
        .filter_map(|l| l.split(':').nth(9).map(|s| s.to_string()))
        .filter(|s| s.len() == 40) // valid keygrips are 40 hex chars
        .collect();

    keygrips
}

/// Import the GPG public cert and extract keygrips from GPG.
///
/// If the cert is already imported (keygrips exist), skips the import.
/// This avoids a deadlock when gpg-agent restarts scdaemon: the restarted
/// scdaemon's `gpg --import` would connect back to the gpg-agent that is
/// waiting for scdaemon's greeting.
fn import_cert_and_get_keygrips(
    cert_armor: &str,
    log: &dyn Fn(&str),
) -> Result<Vec<String>, String> {
    let gnupghome = std::env::var("GNUPGHOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".gnupg")))
        .map_err(|_| "GNUPGHOME and HOME not set".to_string())?;

    let homedir = gnupghome.to_string_lossy().to_string();

    // Try to extract keygrips first — cert might already be imported
    // from a previous scdaemon instance. This avoids calling gpg --import
    // when gpg-agent is waiting for our greeting (which would deadlock).
    let existing = extract_keygrips(&homedir, log);
    if existing.len() >= 2 {
        log(&format!(
            "cert already imported, {} keygrips: {:?}",
            existing.len(),
            existing
        ));
        return Ok(existing);
    }

    // Write cert to file
    let cert_path = gnupghome.join("keymaster-public.asc");
    std::fs::write(&cert_path, cert_armor.as_bytes())
        .map_err(|e| format!("write cert: {}", e))?;
    log(&format!("cert written to {}", cert_path.display()));

    let cert = cert_path.to_string_lossy().to_string();

    // Import cert (synchronous, no gpg-agent needed for public key import)
    let import_output = Command::new("gpg")
        .args(["--homedir", &homedir, "--no-autostart", "--batch", "--import", &cert])
        .output()
        .map_err(|e| format!("run gpg --import: {}", e))?;
    log(&format!(
        "gpg --import: exit={}, stderr={}",
        import_output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&import_output.stderr).trim()
    ));

    // Set ownertrust to ultimate
    let fpr_output = Command::new("gpg")
        .args([
            "--homedir", &homedir, "--no-autostart", "--batch",
            "--with-colons", "--list-keys",
        ])
        .output()
        .map_err(|e| format!("run gpg --list-keys: {}", e))?;
    let fpr_stdout = String::from_utf8_lossy(&fpr_output.stdout);
    if let Some(fpr_line) = fpr_stdout.lines().find(|l| l.starts_with("fpr:")) {
        let fpr = fpr_line.split(':').nth(9).unwrap_or("");
        if !fpr.is_empty() {
            let trust_input = format!("{}:6:\n", fpr);
            let mut trust_proc = Command::new("gpg")
                .args([
                    "--homedir", &homedir, "--no-autostart", "--batch",
                    "--import-ownertrust",
                ])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|e| format!("run gpg --import-ownertrust: {}", e))?;
            if let Some(ref mut stdin) = trust_proc.stdin {
                let _ = stdin.write_all(trust_input.as_bytes());
            }
            let _ = trust_proc.wait();
            log(&format!("ownertrust set for {}", fpr));
        }
    }

    // Extract keygrips
    let keygrips = extract_keygrips(&homedir, log);
    log(&format!("extracted {} keygrips: {:?}", keygrips.len(), keygrips));

    if keygrips.len() < 2 {
        return Err(format!(
            "expected at least 2 keygrips, got {}",
            keygrips.len()
        ));
    }

    Ok(keygrips)
}

// ---- Scdaemon state ----

struct ScdState {
    identities: Vec<Identity>,
    stored_data: Vec<u8>,
    client: LocalClient,
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
        .map(|h| PathBuf::from(h).join("iz-scdaemon.log"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/iz-scdaemon.log"));

    let log = move |msg: &str| {
        eprintln!("iz-scdaemon: {}", msg);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let _ = writeln!(f, "{}", msg);
        }
    };

    let socket_path = std::env::var("IZ_PKCS11_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET));

    log(&format!("starting, socket={}", socket_path.display()));

    // Connect to avatar local API
    let mut client = match LocalClient::connect(&socket_path) {
        Ok(c) => {
            log("connected to avatar");
            c
        }
        Err(e) => {
            log(&format!("FATAL: connect failed: {}", e));
            let mut stdout = io::stdout().lock();
            let _ = write!(stdout, "ERR 2 Cannot connect to avatar: {}\n", e);
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

    // Fetch GPG public cert and import it synchronously.
    // This runs BEFORE the Assuan greeting; gpg --import --no-autostart only
    // touches the public keyring and does NOT need gpg-agent.
    let cert_armor = match client.get_public_cert() {
        Ok(c) => c,
        Err(e) => {
            log(&format!("FATAL: get_public_cert failed: {}", e));
            let mut stdout = io::stdout().lock();
            let _ = write!(stdout, "ERR 2 Cannot fetch cert: {}\n", e);
            let _ = stdout.flush();
            std::process::exit(1);
        }
    };

    let keygrips = match import_cert_and_get_keygrips(&cert_armor, &log) {
        Ok(grips) => grips,
        Err(e) => {
            log(&format!("FATAL: cert import/keygrip extraction failed: {}", e));
            let mut stdout = io::stdout().lock();
            let _ = write!(stdout, "ERR 2 Cert import failed: {}\n", e);
            let _ = stdout.flush();
            std::process::exit(1);
        }
    };

    // Map identities to keyrefs with keygrips from GPG:
    //   keygrips[0] = primary/cert key → identity 0 → OPENPGP.1
    //   keygrips[1] = signing subkey   → identity 1 → OPENPGP.3
    let keyrefs = ["OPENPGP.1", "OPENPGP.3"];
    let identities: Vec<Identity> = decoded_identities
        .into_iter()
        .enumerate()
        .filter_map(|(i, (pk, label, index))| {
            let keygrip = keygrips.get(i)?.clone();
            let keyref = keyrefs.get(i).unwrap_or(&"OPENPGP.1").to_string();
            log(&format!(
                "identity {}: label={}, keyref={}, keygrip={}",
                i, label, keyref, keygrip
            ));
            Some(Identity {
                public_key: pk,
                index,
                keygrip,
                keyref,
            })
        })
        .collect();

    let mut state = ScdState {
        identities,
        stored_data: Vec::new(),
        client,
    };

    // Assuan greeting
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_all(b"OK iz-scdaemon ready\n");
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
