// PKCS#11 function implementations for GPG signing via keymaster-avatar.
// Ed25519 only. Connects to avatar's local API socket using blocking I/O.

use crate::local_client::LocalClient;
use crate::pkcs11_types::*;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

// Ed25519 OID 1.3.101.112 as DER-encoded
const ED25519_EC_PARAMS: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

const DEFAULT_SOCKET: &str = "/tmp/keymaster-avatar.sock";

/// A single identity from the avatar, mapped to PKCS#11 objects.
struct Identity {
    /// Raw 32-byte Ed25519 public key
    public_key: Vec<u8>,
    /// DER-encoded self-signed X.509 certificate (needed by gnupg-pkcs11-scd)
    cert_der: Vec<u8>,
    /// Label from avatar (e.g. "alice / certification")
    label: String,
    /// Index in the identities list (for sign_request)
    index: usize,
}

struct SignOp {
    key_handle: CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
}

struct FindOp {
    handles: Vec<CK_OBJECT_HANDLE>,
    position: usize,
}

struct ModuleState {
    initialized: bool,
    socket_path: PathBuf,
    identities: Vec<Identity>,
    session_open: bool,
    session_handle: CK_SESSION_HANDLE,
    sign_op: Option<SignOp>,
    find_op: Option<FindOp>,
}

static STATE: Mutex<Option<ModuleState>> = Mutex::new(None);

// --- Handle type for object handle decoding ---

#[derive(Clone, Copy, PartialEq)]
enum HandleType {
    PrivateKey,
    PublicKey,
    Certificate,
}

fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut ModuleState) -> R,
{
    let mut guard = STATE.lock().unwrap();
    let state = guard.as_mut().unwrap();
    f(state)
}

fn is_initialized() -> bool {
    STATE
        .lock()
        .unwrap()
        .as_ref()
        .map_or(false, |s| s.initialized)
}

// Object handle layout:
//   handle = identity_index * 3 + 1  -> private key
//   handle = identity_index * 3 + 2  -> public key
//   handle = identity_index * 3 + 3  -> certificate

fn handle_to_identity_index(handle: CK_OBJECT_HANDLE) -> Option<(usize, HandleType)> {
    if handle == 0 {
        return None;
    }
    let h = (handle as usize) - 1;
    let index = h / 3;
    let kind = match h % 3 {
        0 => HandleType::PrivateKey,
        1 => HandleType::PublicKey,
        2 => HandleType::Certificate,
        _ => unreachable!(),
    };
    Some((index, kind))
}

// --- Self-signed X.509 certificate generation ---
// gnupg-pkcs11-scd discovers keys by enumerating X.509 certificate objects.
// We generate a minimal self-signed cert for each Ed25519 identity so that
// gnupg-pkcs11-scd can compute the key grip and report it to gpg-agent.

fn create_self_signed_cert(public_key: &[u8], label: &str) -> Vec<u8> {
    // DER encoding helpers
    fn der_len(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len < 256 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, len as u8]
        }
    }

    fn der_tag(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&der_len(contents.len()));
        out.extend_from_slice(contents);
        out
    }

    fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
        let mut contents = Vec::new();
        for p in parts {
            contents.extend_from_slice(p);
        }
        der_tag(0x30, &contents)
    }

    // Ed25519 OID: 1.3.101.112 → 06 03 2b 65 70
    let ed25519_oid: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
    let ed25519_algo = der_seq(&[ed25519_oid]);

    // CN OID: 2.5.4.3
    let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let cn_value = der_tag(0x0c, label.as_bytes()); // UTF8String
    let cn_attr = der_seq(&[cn_oid, &cn_value]);
    let cn_set = der_tag(0x31, &cn_attr); // SET
    let name = der_seq(&[&cn_set]);

    // Validity (1970-01-01 to 2049-12-31)
    let not_before = der_tag(0x17, b"700101000000Z"); // UTCTime
    let not_after = der_tag(0x17, b"491231235959Z");
    let validity = der_seq(&[&not_before, &not_after]);

    // SubjectPublicKeyInfo
    let pub_key_bits = der_tag(0x03, &{
        let mut bs = vec![0x00]; // 0 unused bits
        bs.extend_from_slice(public_key);
        bs
    });
    let spki = der_seq(&[&ed25519_algo, &pub_key_bits]);

    // Version v3
    let version = der_tag(0xa0, &der_tag(0x02, &[2])); // [0] EXPLICIT INTEGER 2
    // Serial number
    let serial = der_tag(0x02, &[1]);

    // TBSCertificate
    let tbs_cert = der_seq(&[
        &version,
        &serial,
        &ed25519_algo,
        &name,        // issuer
        &validity,
        &name,        // subject
        &spki,
    ]);

    // Dummy signature (64 zero bytes — gnupg-pkcs11-scd doesn't verify)
    let dummy_sig = der_tag(0x03, &{
        let mut bs = vec![0x00]; // 0 unused bits
        bs.extend_from_slice(&[0u8; 64]);
        bs
    });

    // Full Certificate
    der_seq(&[&tbs_cert, &ed25519_algo, &dummy_sig])
}

// --- PKCS#11 function implementations ---

pub unsafe extern "C" fn c_initialize(_init_args: CK_VOID_PTR) -> CK_RV {
    // Canary: touch a file immediately to prove we entered C_Initialize
    let _ = std::fs::File::create("/tmp/iz-pkcs11-alive");

    let mut guard = STATE.lock().unwrap();
    if guard.as_ref().map_or(false, |s| s.initialized) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    let socket_path = std::env::var("IZ_PKCS11_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET));

    // Write debug info to a file since stderr may not be captured
    let log_path = std::env::var("GNUPGHOME")
        .map(|h| PathBuf::from(h).join("iz-pkcs11.log"))
        .unwrap_or_else(|_| PathBuf::from("/tmp/iz-pkcs11.log"));

    let log = |msg: &str| {
        eprintln!("{}", msg);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true).append(true).open(&log_path) {
            let _ = writeln!(f, "{}", msg);
        }
    };

    log(&format!("C_Initialize: socket={}", socket_path.display()));

    // Connect to avatar local API and fetch identities
    let mut client = match LocalClient::connect(&socket_path) {
        Ok(c) => {
            log("C_Initialize: connected");
            c
        }
        Err(e) => {
            log(&format!("C_Initialize: connect failed: {}", e));
            return CKR_DEVICE_ERROR;
        }
    };

    let raw_identities = match client.request_identities() {
        Ok(ids) => {
            log(&format!("C_Initialize: got {} identities", ids.len()));
            ids
        }
        Err(e) => {
            log(&format!("C_Initialize: request_identities failed: {}", e));
            return CKR_DEVICE_ERROR;
        }
    };

    let identities: Vec<Identity> = raw_identities
        .into_iter()
        .enumerate()
        .filter_map(|(i, id)| {
            if id.key_type != "ed25519" {
                eprintln!(
                    "iz_pkcs11_gpg: skipping unsupported key type: {}",
                    id.key_type
                );
                return None;
            }
            let public_key = match BASE64.decode(&id.public_key) {
                Ok(pk) => pk,
                Err(e) => {
                    eprintln!("iz_pkcs11_gpg: decode public_key failed: {}", e);
                    return None;
                }
            };
            if public_key.len() != 32 {
                eprintln!(
                    "iz_pkcs11_gpg: unexpected public key length: {}",
                    public_key.len()
                );
                return None;
            }
            let cert_der = create_self_signed_cert(&public_key, &id.label);
            // Debug: write cert DER to file for diagnosis
            if let Ok(gnupghome) = std::env::var("GNUPGHOME") {
                let cert_path = PathBuf::from(&gnupghome)
                    .join(format!("debug-cert-{}.der", i));
                let _ = std::fs::write(&cert_path, &cert_der);
            }
            Some(Identity {
                public_key,
                cert_der,
                label: id.label,
                index: i,
            })
        })
        .collect();

    // Fetch GPG public cert and schedule deferred import
    import_gpg_cert(&mut client);

    eprintln!(
        "iz_pkcs11_gpg: initialized with {} identit{} from {}",
        identities.len(),
        if identities.len() == 1 { "y" } else { "ies" },
        socket_path.display()
    );

    *guard = Some(ModuleState {
        initialized: true,
        socket_path,
        identities,
        session_open: false,
        session_handle: CK_INVALID_HANDLE,
        sign_op: None,
        find_op: None,
    });

    CKR_OK
}

/// Fetch GPG public cert from keymaster, write it to GNUPGHOME, and schedule
/// a deferred `gpg --import` + ownertrust as a fire-and-forget subprocess.
///
/// We cannot call `gpg --import` synchronously inside C_Initialize because
/// GPG 2.x connects to gpg-agent, which is blocked waiting for scdaemon (us)
/// to finish — that would deadlock. Instead we spawn a detached shell process
/// that sleeps until the LEARN handshake completes, then imports.
fn import_gpg_cert(client: &mut LocalClient) {
    let cert_armor = match client.get_public_cert() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("iz_pkcs11_gpg: get_public_cert failed (non-fatal): {}", e);
            return;
        }
    };

    let gnupghome = match std::env::var("GNUPGHOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => match std::env::var("HOME") {
            Ok(home) => PathBuf::from(home).join(".gnupg"),
            Err(_) => {
                eprintln!("iz_pkcs11_gpg: GNUPGHOME and HOME not set, skipping cert import");
                return;
            }
        },
    };

    // Write cert to file
    let cert_path = gnupghome.join("keymaster-public.asc");
    if let Err(e) = std::fs::File::create(&cert_path)
        .and_then(|mut f| f.write_all(cert_armor.as_bytes()))
    {
        eprintln!("iz_pkcs11_gpg: write cert failed (non-fatal): {}", e);
        return;
    }

    eprintln!("iz_pkcs11_gpg: cert written to {}", cert_path.display());

    // Spawn a detached shell process to import after a delay.
    // The process survives parent (scdaemon) death via reparenting to init.
    // --no-autostart: don't start a new gpg-agent (one will be started by
    // the next gpg invocation that needs it).
    let homedir = gnupghome.to_string_lossy().to_string();
    let cert = cert_path.to_string_lossy().to_string();
    let script = format!(
        "sleep 3; \
         gpg --homedir '{homedir}' --no-autostart --batch --import '{cert}' 2>/dev/null; \
         FPR=$(gpg --homedir '{homedir}' --no-autostart --batch --with-colons --list-keys 2>/dev/null \
               | grep '^fpr' | head -1 | cut -d: -f10); \
         [ -n \"$FPR\" ] && echo \"$FPR:6:\" | \
             gpg --homedir '{homedir}' --no-autostart --batch --import-ownertrust 2>/dev/null; \
         exit 0",
    );

    match Command::new("sh")
        .arg("-c")
        .arg(&script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => eprintln!("iz_pkcs11_gpg: deferred cert import scheduled"),
        Err(e) => eprintln!("iz_pkcs11_gpg: failed to spawn import process (non-fatal): {}", e),
    }
}

pub unsafe extern "C" fn c_finalize(_reserved: CK_VOID_PTR) -> CK_RV {
    let mut guard = STATE.lock().unwrap();
    if guard.as_ref().map_or(true, |s| !s.initialized) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    *guard = None;
    CKR_OK
}

pub unsafe extern "C" fn c_get_info(info: *mut CK_INFO) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let out = &mut *info;
    out.cryptoki_version = CK_VERSION {
        major: 2,
        minor: 40,
    };
    out.manufacturer_id = pad_str("IZ RedToken");
    out.flags = 0;
    out.library_description = pad_str("IZ KeyMaster GPG PKCS#11");
    out.library_version = CK_VERSION {
        major: 0,
        minor: 1,
    };
    CKR_OK
}

pub unsafe extern "C" fn c_get_slot_list(
    _token_present: CK_BBOOL,
    slot_list: *mut CK_SLOT_ID,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if slot_list.is_null() {
        *count = 1;
        return CKR_OK;
    }
    if *count < 1 {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    *slot_list = 0; // slot ID 0
    *count = 1;
    CKR_OK
}

pub unsafe extern "C" fn c_get_slot_info(slot_id: CK_SLOT_ID, info: *mut CK_SLOT_INFO) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if slot_id != 0 {
        return CKR_SLOT_ID_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let out = &mut *info;
    out.slot_description = pad_str("IZ Avatar GPG");
    out.manufacturer_id = pad_str("IZ RedToken");
    out.flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
    out.hardware_version = CK_VERSION {
        major: 0,
        minor: 1,
    };
    out.firmware_version = CK_VERSION {
        major: 0,
        minor: 1,
    };
    CKR_OK
}

pub unsafe extern "C" fn c_get_token_info(
    slot_id: CK_SLOT_ID,
    info: *mut CK_TOKEN_INFO,
) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if slot_id != 0 {
        return CKR_SLOT_ID_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let out = &mut *info;
    out.label = pad_str("IZ KeyMaster GPG");
    out.manufacturer_id = pad_str("IZ RedToken");
    out.model = pad_str("Avatar");
    out.serial_number = pad_str("0000000000000001");
    out.flags = CKF_TOKEN_INITIALIZED;
    out.max_session_count = 1;
    out.session_count = 0;
    out.max_rw_session_count = 1;
    out.rw_session_count = 0;
    out.max_pin_len = 0;
    out.min_pin_len = 0;
    out.total_public_memory = CK_UNAVAILABLE_INFORMATION;
    out.free_public_memory = CK_UNAVAILABLE_INFORMATION;
    out.total_private_memory = CK_UNAVAILABLE_INFORMATION;
    out.free_private_memory = CK_UNAVAILABLE_INFORMATION;
    out.hardware_version = CK_VERSION {
        major: 0,
        minor: 1,
    };
    out.firmware_version = CK_VERSION {
        major: 0,
        minor: 1,
    };
    out.utc_time = pad_str("");
    CKR_OK
}

pub unsafe extern "C" fn c_get_mechanism_list(
    slot_id: CK_SLOT_ID,
    mechanism_list: CK_MECHANISM_TYPE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if slot_id != 0 {
        return CKR_SLOT_ID_INVALID;
    }
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if mechanism_list.is_null() {
        *count = 1;
        return CKR_OK;
    }
    if *count < 1 {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    *mechanism_list = CKM_EDDSA;
    *count = 1;
    CKR_OK
}

pub unsafe extern "C" fn c_get_mechanism_info(
    slot_id: CK_SLOT_ID,
    mechanism: CK_MECHANISM_TYPE,
    info: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if slot_id != 0 {
        return CKR_SLOT_ID_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let out = &mut *info;
    match mechanism {
        CKM_EDDSA => {
            out.min_key_size = 256;
            out.max_key_size = 256;
            out.flags = CKF_SIGN | CKF_VERIFY;
        }
        _ => return CKR_MECHANISM_INVALID,
    }
    CKR_OK
}

pub unsafe extern "C" fn c_open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    session: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if slot_id != 0 {
        return CKR_SLOT_ID_INVALID;
    }
    if session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if flags & CKF_SERIAL_SESSION == 0 {
        return CKR_GENERAL_ERROR;
    }
    with_state(|state| {
        state.session_open = true;
        state.session_handle = 1;
        *session = 1;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_close_session(session: CK_SESSION_HANDLE) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    with_state(|state| {
        if !state.session_open || session != state.session_handle {
            return CKR_SESSION_HANDLE_INVALID;
        }
        state.session_open = false;
        state.session_handle = CK_INVALID_HANDLE;
        state.sign_op = None;
        state.find_op = None;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if slot_id != 0 {
        return CKR_SLOT_ID_INVALID;
    }
    with_state(|state| {
        state.session_open = false;
        state.session_handle = CK_INVALID_HANDLE;
        state.sign_op = None;
        state.find_op = None;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_session_info(
    session: CK_SESSION_HANDLE,
    info: *mut CK_SESSION_INFO,
) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        if !state.session_open || session != state.session_handle {
            return CKR_SESSION_HANDLE_INVALID;
        }
        let out = &mut *info;
        out.slot_id = 0;
        out.state = CKS_RW_PUBLIC_SESSION;
        out.flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        out.device_error = 0;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_login(
    session: CK_SESSION_HANDLE,
    _user_type: CK_ULONG,
    _pin: CK_BYTE_PTR,
    _pin_len: CK_ULONG,
) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    with_state(|state| {
        if !state.session_open || session != state.session_handle {
            return CKR_SESSION_HANDLE_INVALID;
        }
        CKR_OK // no-op — no login required
    })
}

pub unsafe extern "C" fn c_logout(session: CK_SESSION_HANDLE) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    with_state(|state| {
        if !state.session_open || session != state.session_handle {
            return CKR_SESSION_HANDLE_INVALID;
        }
        CKR_OK // no-op
    })
}

pub unsafe extern "C" fn c_find_objects_init(
    session: CK_SESSION_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    with_state(|state| {
        if !state.session_open || session != state.session_handle {
            return CKR_SESSION_HANDLE_INVALID;
        }

        // Parse template to determine filter
        let mut want_class: Option<CK_OBJECT_CLASS> = None;

        if !template.is_null() {
            let attrs = std::slice::from_raw_parts(template, count as usize);
            for attr in attrs {
                if attr.attr_type == CKA_CLASS
                    && !attr.p_value.is_null()
                    && attr.value_len == std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG
                {
                    want_class = Some(*(attr.p_value as *const CK_OBJECT_CLASS));
                }
            }
        }

        // Build list of matching object handles
        let mut handles = Vec::new();
        for i in 0..state.identities.len() {
            let priv_handle = (i * 3 + 1) as CK_OBJECT_HANDLE;
            let pub_handle = (i * 3 + 2) as CK_OBJECT_HANDLE;
            let cert_handle = (i * 3 + 3) as CK_OBJECT_HANDLE;

            match want_class {
                Some(CKO_PRIVATE_KEY) => handles.push(priv_handle),
                Some(CKO_PUBLIC_KEY) => handles.push(pub_handle),
                Some(CKO_CERTIFICATE) => handles.push(cert_handle),
                None => {
                    handles.push(priv_handle);
                    handles.push(pub_handle);
                    handles.push(cert_handle);
                }
                Some(_) => {} // no match
            }
        }

        state.find_op = Some(FindOp {
            handles,
            position: 0,
        });
        CKR_OK
    })
}

pub unsafe extern "C" fn c_find_objects(
    session: CK_SESSION_HANDLE,
    objects: CK_OBJECT_HANDLE_PTR,
    max_count: CK_ULONG,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if objects.is_null() || count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        if !state.session_open || session != state.session_handle {
            return CKR_SESSION_HANDLE_INVALID;
        }
        let find = match state.find_op.as_mut() {
            Some(f) => f,
            None => return CKR_OPERATION_NOT_INITIALIZED,
        };

        let remaining = find.handles.len() - find.position;
        let to_return = remaining.min(max_count as usize);

        for i in 0..to_return {
            *objects.add(i) = find.handles[find.position + i];
        }
        find.position += to_return;
        *count = to_return as CK_ULONG;

        CKR_OK
    })
}

pub unsafe extern "C" fn c_find_objects_final(session: CK_SESSION_HANDLE) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    with_state(|state| {
        if !state.session_open || session != state.session_handle {
            return CKR_SESSION_HANDLE_INVALID;
        }
        state.find_op = None;
        CKR_OK
    })
}

pub unsafe extern "C" fn c_get_attribute_value(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if template.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    with_state(|state| {
        if !state.session_open || session != state.session_handle {
            return CKR_SESSION_HANDLE_INVALID;
        }

        let (idx, handle_type) = match handle_to_identity_index(object) {
            Some(v) => v,
            None => return CKR_OBJECT_HANDLE_INVALID,
        };
        if idx >= state.identities.len() {
            return CKR_OBJECT_HANDLE_INVALID;
        }
        let identity = &state.identities[idx];

        let attrs = std::slice::from_raw_parts_mut(template, count as usize);
        let mut rv = CKR_OK;

        for attr in attrs.iter_mut() {
            // Use a stack buffer for small values (CK_ULONG, CK_BBOOL)
            let mut tmp = [0u8; 8];
            let data: Option<&[u8]> = match (handle_type, attr.attr_type) {
                // --- Common attributes ---
                (_, CKA_TOKEN) => {
                    tmp[0] = CK_TRUE;
                    Some(&tmp[..1])
                }
                (_, CKA_ID) => {
                    tmp[0] = (idx + 1) as u8;
                    Some(&tmp[..1])
                }
                (_, CKA_LABEL) => Some(identity.label.as_bytes()),

                // --- CKA_CLASS ---
                (HandleType::PrivateKey, CKA_CLASS) => {
                    let size = std::mem::size_of::<CK_OBJECT_CLASS>();
                    tmp[..size].copy_from_slice(&CKO_PRIVATE_KEY.to_ne_bytes());
                    Some(&tmp[..size])
                }
                (HandleType::PublicKey, CKA_CLASS) => {
                    let size = std::mem::size_of::<CK_OBJECT_CLASS>();
                    tmp[..size].copy_from_slice(&CKO_PUBLIC_KEY.to_ne_bytes());
                    Some(&tmp[..size])
                }
                (HandleType::Certificate, CKA_CLASS) => {
                    let size = std::mem::size_of::<CK_OBJECT_CLASS>();
                    tmp[..size].copy_from_slice(&CKO_CERTIFICATE.to_ne_bytes());
                    Some(&tmp[..size])
                }

                // --- CKA_PRIVATE ---
                (HandleType::PrivateKey, CKA_PRIVATE) => {
                    tmp[0] = CK_TRUE;
                    Some(&tmp[..1])
                }
                (_, CKA_PRIVATE) => {
                    tmp[0] = CK_FALSE;
                    Some(&tmp[..1])
                }

                // --- Certificate attributes ---
                (HandleType::Certificate, CKA_CERTIFICATE_TYPE) => {
                    let size = std::mem::size_of::<CK_CERTIFICATE_TYPE>();
                    tmp[..size].copy_from_slice(&CKC_X_509.to_ne_bytes());
                    Some(&tmp[..size])
                }
                (HandleType::Certificate, CKA_VALUE) => {
                    Some(identity.cert_der.as_slice())
                }
                (HandleType::Certificate, CKA_SUBJECT) | (HandleType::Certificate, CKA_ISSUER) => {
                    // Return empty — gnupg-pkcs11-scd may not require these
                    Some(&[])
                }
                (HandleType::Certificate, CKA_SERIAL_NUMBER) => {
                    // DER INTEGER 1
                    Some(&[0x02, 0x01, 0x01])
                }

                // --- Key-specific attributes (Ed25519 only) ---
                (HandleType::PrivateKey | HandleType::PublicKey, CKA_KEY_TYPE) => {
                    let size = std::mem::size_of::<CK_KEY_TYPE>();
                    tmp[..size].copy_from_slice(&CKK_EC_EDWARDS.to_ne_bytes());
                    Some(&tmp[..size])
                }
                (HandleType::PrivateKey, CKA_SIGN) => {
                    tmp[0] = CK_TRUE;
                    Some(&tmp[..1])
                }
                (HandleType::PublicKey, CKA_VERIFY) => {
                    tmp[0] = CK_TRUE;
                    Some(&tmp[..1])
                }
                (HandleType::PrivateKey | HandleType::PublicKey, CKA_ALWAYS_AUTHENTICATE) => {
                    tmp[0] = CK_FALSE;
                    Some(&tmp[..1])
                }
                (HandleType::PrivateKey | HandleType::PublicKey, CKA_EC_PARAMS) => {
                    Some(ED25519_EC_PARAMS)
                }
                (HandleType::PrivateKey | HandleType::PublicKey, CKA_EC_POINT) => {
                    Some(identity.public_key.as_slice())
                }

                // --- Unknown attribute ---
                _ => {
                    attr.value_len = CK_UNAVAILABLE_INFORMATION;
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                    continue;
                }
            };

            if let Some(bytes) = data {
                let len = bytes.len() as CK_ULONG;
                if attr.p_value.is_null() {
                    attr.value_len = len;
                } else if attr.value_len < len {
                    attr.value_len = len;
                    rv = CKR_BUFFER_TOO_SMALL;
                } else {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        attr.p_value as *mut u8,
                        bytes.len(),
                    );
                    attr.value_len = len;
                }
            }
        }

        rv
    })
}

pub unsafe extern "C" fn c_sign_init(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    with_state(|state| {
        if !state.session_open || session != state.session_handle {
            return CKR_SESSION_HANDLE_INVALID;
        }

        let mech = &*mechanism;
        let mech_type = mech.mechanism;

        let (idx, handle_type) = match handle_to_identity_index(key) {
            Some(v) => v,
            None => return CKR_OBJECT_HANDLE_INVALID,
        };
        if idx >= state.identities.len() || handle_type != HandleType::PrivateKey {
            return CKR_OBJECT_HANDLE_INVALID;
        }

        // Only CKM_EDDSA supported
        if mech_type != CKM_EDDSA {
            return CKR_MECHANISM_INVALID;
        }

        state.sign_op = Some(SignOp {
            key_handle: key,
            mechanism: mech_type,
        });
        CKR_OK
    })
}

pub unsafe extern "C" fn c_sign(
    session: CK_SESSION_HANDLE,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    signature: CK_BYTE_PTR,
    signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if !is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if data.is_null() || signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Extract the public key and identity index under the lock, then drop before I/O
    let (public_key, identity_index, socket_path) = {
        let mut guard = STATE.lock().unwrap();
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };

        if !state.session_open || session != state.session_handle {
            return CKR_SESSION_HANDLE_INVALID;
        }

        let sign_op = match state.sign_op.as_ref() {
            Some(op) => op,
            None => return CKR_OPERATION_NOT_INITIALIZED,
        };

        let (idx, _) = match handle_to_identity_index(sign_op.key_handle) {
            Some(v) => v,
            None => return CKR_GENERAL_ERROR,
        };
        if idx >= state.identities.len() {
            return CKR_GENERAL_ERROR;
        }

        let pk = state.identities[idx].public_key.clone();
        let index = state.identities[idx].index;
        let path = state.socket_path.clone();

        // Consume the sign operation
        state.sign_op = None;

        (pk, index, path)
    };

    const ED25519_SIG_LEN: CK_ULONG = 64;

    // Size query
    if signature.is_null() {
        *signature_len = ED25519_SIG_LEN;
        return CKR_OK;
    }

    if *signature_len < ED25519_SIG_LEN {
        *signature_len = ED25519_SIG_LEN;
        return CKR_BUFFER_TOO_SMALL;
    }

    let data_slice = std::slice::from_raw_parts(data, data_len as usize);

    // Connect to avatar local API and sign (outside lock)
    let mut client = match LocalClient::connect(&socket_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("iz_pkcs11_gpg: sign connect failed: {}", e);
            return CKR_DEVICE_ERROR;
        }
    };

    let raw_sig = match client.sign(identity_index, &public_key, data_slice) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("iz_pkcs11_gpg: sign failed: {}", e);
            return CKR_DEVICE_ERROR;
        }
    };

    if raw_sig.len() != ED25519_SIG_LEN as usize {
        eprintln!(
            "iz_pkcs11_gpg: unexpected signature length: {} (expected {})",
            raw_sig.len(),
            ED25519_SIG_LEN
        );
        return CKR_DEVICE_ERROR;
    }

    std::ptr::copy_nonoverlapping(raw_sig.as_ptr(), signature, ED25519_SIG_LEN as usize);
    *signature_len = ED25519_SIG_LEN;

    CKR_OK
}

// --- Stub functions returning CKR_FUNCTION_NOT_SUPPORTED ---

macro_rules! stub {
    ($name:ident ( $($arg:ident : $ty:ty),* )) => {
        pub unsafe extern "C" fn $name($(_: $ty),*) -> CK_RV {
            CKR_FUNCTION_NOT_SUPPORTED
        }
    };
}

stub!(c_init_token(slot_id: CK_SLOT_ID, pin: CK_BYTE_PTR, pin_len: CK_ULONG, label: CK_BYTE_PTR));
stub!(c_init_pin(session: CK_SESSION_HANDLE, pin: CK_BYTE_PTR, pin_len: CK_ULONG));
stub!(c_set_pin(session: CK_SESSION_HANDLE, old: CK_BYTE_PTR, old_len: CK_ULONG, new: CK_BYTE_PTR, new_len: CK_ULONG));
stub!(c_get_operation_state(session: CK_SESSION_HANDLE, state: CK_BYTE_PTR, len: CK_ULONG_PTR));
stub!(c_set_operation_state(session: CK_SESSION_HANDLE, state: CK_BYTE_PTR, len: CK_ULONG, enc: CK_OBJECT_HANDLE, auth: CK_OBJECT_HANDLE));
stub!(c_create_object(session: CK_SESSION_HANDLE, templ: *mut CK_ATTRIBUTE, count: CK_ULONG, obj: CK_OBJECT_HANDLE_PTR));
stub!(c_copy_object(session: CK_SESSION_HANDLE, obj: CK_OBJECT_HANDLE, templ: *mut CK_ATTRIBUTE, count: CK_ULONG, new_obj: CK_OBJECT_HANDLE_PTR));
stub!(c_destroy_object(session: CK_SESSION_HANDLE, obj: CK_OBJECT_HANDLE));
stub!(c_get_object_size(session: CK_SESSION_HANDLE, obj: CK_OBJECT_HANDLE, size: CK_ULONG_PTR));
stub!(c_set_attribute_value(session: CK_SESSION_HANDLE, obj: CK_OBJECT_HANDLE, templ: *mut CK_ATTRIBUTE, count: CK_ULONG));
stub!(c_encrypt_init(session: CK_SESSION_HANDLE, mech: *mut CK_MECHANISM, key: CK_OBJECT_HANDLE));
stub!(c_encrypt(session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, dl: CK_ULONG, enc: CK_BYTE_PTR, el: CK_ULONG_PTR));
stub!(c_encrypt_update(session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, pl: CK_ULONG, enc: CK_BYTE_PTR, el: CK_ULONG_PTR));
stub!(c_encrypt_final(session: CK_SESSION_HANDLE, enc: CK_BYTE_PTR, el: CK_ULONG_PTR));
stub!(c_decrypt_init(session: CK_SESSION_HANDLE, mech: *mut CK_MECHANISM, key: CK_OBJECT_HANDLE));
stub!(c_decrypt(session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, dl: CK_ULONG, dec: CK_BYTE_PTR, decl: CK_ULONG_PTR));
stub!(c_decrypt_update(session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, pl: CK_ULONG, dec: CK_BYTE_PTR, decl: CK_ULONG_PTR));
stub!(c_decrypt_final(session: CK_SESSION_HANDLE, dec: CK_BYTE_PTR, decl: CK_ULONG_PTR));
stub!(c_digest_init(session: CK_SESSION_HANDLE, mech: *mut CK_MECHANISM));
stub!(c_digest(session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, dl: CK_ULONG, dig: CK_BYTE_PTR, digl: CK_ULONG_PTR));
stub!(c_digest_update(session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, dl: CK_ULONG));
stub!(c_digest_key(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE));
stub!(c_digest_final(session: CK_SESSION_HANDLE, dig: CK_BYTE_PTR, digl: CK_ULONG_PTR));
stub!(c_sign_update(session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, pl: CK_ULONG));
stub!(c_sign_final(session: CK_SESSION_HANDLE, sig: CK_BYTE_PTR, sl: CK_ULONG_PTR));
stub!(c_sign_recover_init(session: CK_SESSION_HANDLE, mech: *mut CK_MECHANISM, key: CK_OBJECT_HANDLE));
stub!(c_sign_recover(session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, dl: CK_ULONG, sig: CK_BYTE_PTR, sl: CK_ULONG_PTR));
stub!(c_verify_init(session: CK_SESSION_HANDLE, mech: *mut CK_MECHANISM, key: CK_OBJECT_HANDLE));
stub!(c_verify(session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, dl: CK_ULONG, sig: CK_BYTE_PTR, sl: CK_ULONG));
stub!(c_verify_update(session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, pl: CK_ULONG));
stub!(c_verify_final(session: CK_SESSION_HANDLE, sig: CK_BYTE_PTR, sl: CK_ULONG));
stub!(c_verify_recover_init(session: CK_SESSION_HANDLE, mech: *mut CK_MECHANISM, key: CK_OBJECT_HANDLE));
stub!(c_verify_recover(session: CK_SESSION_HANDLE, sig: CK_BYTE_PTR, sl: CK_ULONG, data: CK_BYTE_PTR, dl: CK_ULONG_PTR));
stub!(c_digest_encrypt_update(session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, pl: CK_ULONG, enc: CK_BYTE_PTR, el: CK_ULONG_PTR));
stub!(c_decrypt_digest_update(session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, pl: CK_ULONG, dec: CK_BYTE_PTR, dl: CK_ULONG_PTR));
stub!(c_sign_encrypt_update(session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, pl: CK_ULONG, enc: CK_BYTE_PTR, el: CK_ULONG_PTR));
stub!(c_decrypt_verify_update(session: CK_SESSION_HANDLE, part: CK_BYTE_PTR, pl: CK_ULONG, dec: CK_BYTE_PTR, dl: CK_ULONG_PTR));
stub!(c_generate_key(session: CK_SESSION_HANDLE, mech: *mut CK_MECHANISM, templ: *mut CK_ATTRIBUTE, count: CK_ULONG, key: CK_OBJECT_HANDLE_PTR));
stub!(c_generate_key_pair(session: CK_SESSION_HANDLE, mech: *mut CK_MECHANISM, pub_t: *mut CK_ATTRIBUTE, pub_c: CK_ULONG, priv_t: *mut CK_ATTRIBUTE, priv_c: CK_ULONG, pub_k: CK_OBJECT_HANDLE_PTR, priv_k: CK_OBJECT_HANDLE_PTR));
stub!(c_wrap_key(session: CK_SESSION_HANDLE, mech: *mut CK_MECHANISM, wrap: CK_OBJECT_HANDLE, key: CK_OBJECT_HANDLE, out: CK_BYTE_PTR, ol: CK_ULONG_PTR));
stub!(c_unwrap_key(session: CK_SESSION_HANDLE, mech: *mut CK_MECHANISM, unwrap: CK_OBJECT_HANDLE, data: CK_BYTE_PTR, dl: CK_ULONG, templ: *mut CK_ATTRIBUTE, count: CK_ULONG, key: CK_OBJECT_HANDLE_PTR));
stub!(c_derive_key(session: CK_SESSION_HANDLE, mech: *mut CK_MECHANISM, base: CK_OBJECT_HANDLE, templ: *mut CK_ATTRIBUTE, count: CK_ULONG, key: CK_OBJECT_HANDLE_PTR));
stub!(c_seed_random(session: CK_SESSION_HANDLE, seed: CK_BYTE_PTR, len: CK_ULONG));
stub!(c_generate_random(session: CK_SESSION_HANDLE, data: CK_BYTE_PTR, len: CK_ULONG));
stub!(c_get_function_status(session: CK_SESSION_HANDLE));
stub!(c_cancel_function(session: CK_SESSION_HANDLE));
stub!(c_wait_for_slot_event(flags: CK_FLAGS, slot: *mut CK_SLOT_ID, reserved: CK_VOID_PTR));
