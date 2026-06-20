// PKCS#11 type definitions (Cryptoki v2.40)
// No external dependencies — pure Rust type mappings.

pub type CK_ULONG = std::os::raw::c_ulong;
pub type CK_LONG = std::os::raw::c_long;
pub type CK_BYTE = u8;
pub type CK_BBOOL = CK_BYTE;
pub type CK_CHAR = CK_BYTE;
pub type CK_UTF8CHAR = CK_BYTE;
pub type CK_FLAGS = CK_ULONG;
pub type CK_RV = CK_ULONG;
pub type CK_SLOT_ID = CK_ULONG;
pub type CK_SESSION_HANDLE = CK_ULONG;
pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_OBJECT_CLASS = CK_ULONG;
pub type CK_KEY_TYPE = CK_ULONG;
pub type CK_MECHANISM_TYPE = CK_ULONG;
pub type CK_ATTRIBUTE_TYPE = CK_ULONG;
pub type CK_CERTIFICATE_TYPE = CK_ULONG;
pub type CK_VOID_PTR = *mut std::os::raw::c_void;
pub type CK_BYTE_PTR = *mut CK_BYTE;
pub type CK_ULONG_PTR = *mut CK_ULONG;
pub type CK_OBJECT_HANDLE_PTR = *mut CK_OBJECT_HANDLE;
pub type CK_MECHANISM_TYPE_PTR = *mut CK_MECHANISM_TYPE;
pub type CK_NOTIFY = Option<extern "C" fn(CK_SESSION_HANDLE, CK_ULONG, CK_VOID_PTR) -> CK_RV>;

pub const CK_TRUE: CK_BBOOL = 1;
pub const CK_FALSE: CK_BBOOL = 0;
pub const CK_INVALID_HANDLE: CK_ULONG = 0;
pub const CK_UNAVAILABLE_INFORMATION: CK_ULONG = CK_ULONG::MAX;

// Return values
pub const CKR_OK: CK_RV = 0x00000000;
pub const CKR_CANCEL: CK_RV = 0x00000001;
pub const CKR_ARGUMENTS_BAD: CK_RV = 0x00000007;
pub const CKR_ATTRIBUTE_TYPE_INVALID: CK_RV = 0x00000012;
pub const CKR_BUFFER_TOO_SMALL: CK_RV = 0x00000150;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x00000190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x00000191;
pub const CKR_DEVICE_ERROR: CK_RV = 0x00000030;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x00000054;
pub const CKR_GENERAL_ERROR: CK_RV = 0x00000005;
pub const CKR_MECHANISM_INVALID: CK_RV = 0x00000070;
pub const CKR_OBJECT_HANDLE_INVALID: CK_RV = 0x00000082;
pub const CKR_OPERATION_NOT_INITIALIZED: CK_RV = 0x00000091;
pub const CKR_SESSION_HANDLE_INVALID: CK_RV = 0x000000B3;
pub const CKR_SESSION_CLOSED: CK_RV = 0x000000B0;
pub const CKR_SLOT_ID_INVALID: CK_RV = 0x00000065;
pub const CKR_TOKEN_NOT_PRESENT: CK_RV = 0x000000E0;

// Object classes
pub const CKO_CERTIFICATE: CK_OBJECT_CLASS = 0x00000001;
pub const CKO_PUBLIC_KEY: CK_OBJECT_CLASS = 0x00000002;
pub const CKO_PRIVATE_KEY: CK_OBJECT_CLASS = 0x00000003;

// Certificate types
pub const CKC_X_509: CK_CERTIFICATE_TYPE = 0x00000000;

// Key types
pub const CKK_EC_EDWARDS: CK_KEY_TYPE = 0x00000040;

// Mechanism types
pub const CKM_EDDSA: CK_MECHANISM_TYPE = 0x00001057;

// Attribute types
pub const CKA_CLASS: CK_ATTRIBUTE_TYPE = 0x00000000;
pub const CKA_TOKEN: CK_ATTRIBUTE_TYPE = 0x00000001;
pub const CKA_PRIVATE: CK_ATTRIBUTE_TYPE = 0x00000002;
pub const CKA_LABEL: CK_ATTRIBUTE_TYPE = 0x00000003;
pub const CKA_VALUE: CK_ATTRIBUTE_TYPE = 0x00000011;
pub const CKA_CERTIFICATE_TYPE: CK_ATTRIBUTE_TYPE = 0x00000080;
pub const CKA_ISSUER: CK_ATTRIBUTE_TYPE = 0x00000081;
pub const CKA_SERIAL_NUMBER: CK_ATTRIBUTE_TYPE = 0x00000082;
pub const CKA_KEY_TYPE: CK_ATTRIBUTE_TYPE = 0x00000100;
pub const CKA_SUBJECT: CK_ATTRIBUTE_TYPE = 0x00000101;
pub const CKA_ID: CK_ATTRIBUTE_TYPE = 0x00000102;
pub const CKA_SIGN: CK_ATTRIBUTE_TYPE = 0x00000108;
pub const CKA_VERIFY: CK_ATTRIBUTE_TYPE = 0x0000010A;
pub const CKA_EC_PARAMS: CK_ATTRIBUTE_TYPE = 0x00000180;
pub const CKA_EC_POINT: CK_ATTRIBUTE_TYPE = 0x00000181;
pub const CKA_ALWAYS_AUTHENTICATE: CK_ATTRIBUTE_TYPE = 0x00000202;

// Flags
pub const CKF_SERIAL_SESSION: CK_FLAGS = 0x00000004;
pub const CKF_RW_SESSION: CK_FLAGS = 0x00000002;
pub const CKF_TOKEN_INITIALIZED: CK_FLAGS = 0x00000400;
pub const CKF_LOGIN_REQUIRED: CK_FLAGS = 0x00000004;
pub const CKF_SIGN: CK_FLAGS = 0x00000800;
pub const CKF_VERIFY: CK_FLAGS = 0x00002000;
pub const CKF_HW_SLOT: CK_FLAGS = 0x00000004;
pub const CKF_TOKEN_PRESENT: CK_FLAGS = 0x00000001;
pub const CKF_REMOVABLE_DEVICE: CK_FLAGS = 0x00000002;

// Session states
pub const CKS_RO_PUBLIC_SESSION: CK_ULONG = 0;
pub const CKS_RW_PUBLIC_SESSION: CK_ULONG = 2;

// User types
pub const CKU_USER: CK_ULONG = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_VERSION {
    pub major: CK_BYTE,
    pub minor: CK_BYTE,
}

#[repr(C)]
pub struct CK_INFO {
    pub cryptoki_version: CK_VERSION,
    pub manufacturer_id: [CK_UTF8CHAR; 32],
    pub flags: CK_FLAGS,
    pub library_description: [CK_UTF8CHAR; 32],
    pub library_version: CK_VERSION,
}

#[repr(C)]
pub struct CK_SLOT_INFO {
    pub slot_description: [CK_UTF8CHAR; 64],
    pub manufacturer_id: [CK_UTF8CHAR; 32],
    pub flags: CK_FLAGS,
    pub hardware_version: CK_VERSION,
    pub firmware_version: CK_VERSION,
}

#[repr(C)]
pub struct CK_TOKEN_INFO {
    pub label: [CK_UTF8CHAR; 32],
    pub manufacturer_id: [CK_UTF8CHAR; 32],
    pub model: [CK_UTF8CHAR; 16],
    pub serial_number: [CK_CHAR; 16],
    pub flags: CK_FLAGS,
    pub max_session_count: CK_ULONG,
    pub session_count: CK_ULONG,
    pub max_rw_session_count: CK_ULONG,
    pub rw_session_count: CK_ULONG,
    pub max_pin_len: CK_ULONG,
    pub min_pin_len: CK_ULONG,
    pub total_public_memory: CK_ULONG,
    pub free_public_memory: CK_ULONG,
    pub total_private_memory: CK_ULONG,
    pub free_private_memory: CK_ULONG,
    pub hardware_version: CK_VERSION,
    pub firmware_version: CK_VERSION,
    pub utc_time: [CK_CHAR; 16],
}

#[repr(C)]
pub struct CK_MECHANISM {
    pub mechanism: CK_MECHANISM_TYPE,
    pub p_parameter: CK_VOID_PTR,
    pub parameter_len: CK_ULONG,
}

#[repr(C)]
pub struct CK_MECHANISM_INFO {
    pub min_key_size: CK_ULONG,
    pub max_key_size: CK_ULONG,
    pub flags: CK_FLAGS,
}

#[repr(C)]
pub struct CK_ATTRIBUTE {
    pub attr_type: CK_ATTRIBUTE_TYPE,
    pub p_value: CK_VOID_PTR,
    pub value_len: CK_ULONG,
}

#[repr(C)]
pub struct CK_SESSION_INFO {
    pub slot_id: CK_SLOT_ID,
    pub state: CK_ULONG,
    pub flags: CK_FLAGS,
    pub device_error: CK_ULONG,
}

// Function pointer types for CK_FUNCTION_LIST
pub type CK_C_Initialize = Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>;
pub type CK_C_Finalize = Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>;
pub type CK_C_GetInfo = Option<unsafe extern "C" fn(*mut CK_INFO) -> CK_RV>;
pub type CK_C_GetSlotList =
    Option<unsafe extern "C" fn(CK_BBOOL, *mut CK_SLOT_ID, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_GetSlotInfo = Option<unsafe extern "C" fn(CK_SLOT_ID, *mut CK_SLOT_INFO) -> CK_RV>;
pub type CK_C_GetTokenInfo =
    Option<unsafe extern "C" fn(CK_SLOT_ID, *mut CK_TOKEN_INFO) -> CK_RV>;
pub type CK_C_GetMechanismList =
    Option<unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_GetMechanismInfo = Option<
    unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, *mut CK_MECHANISM_INFO) -> CK_RV,
>;
pub type CK_C_InitToken =
    Option<unsafe extern "C" fn(CK_SLOT_ID, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR) -> CK_RV>;
pub type CK_C_InitPIN =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_SetPIN = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
>;
pub type CK_C_OpenSession = Option<
    unsafe extern "C" fn(
        CK_SLOT_ID,
        CK_FLAGS,
        CK_VOID_PTR,
        CK_NOTIFY,
        *mut CK_SESSION_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_CloseSession = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_CloseAllSessions = Option<unsafe extern "C" fn(CK_SLOT_ID) -> CK_RV>;
pub type CK_C_GetSessionInfo =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_SESSION_INFO) -> CK_RV>;
pub type CK_C_GetOperationState =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_SetOperationState = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_Login =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_Logout = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_CreateObject = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_CopyObject = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DestroyObject =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_GetObjectSize =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_GetAttributeValue = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
    ) -> CK_RV,
>;
pub type CK_C_SetAttributeValue = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
    ) -> CK_RV,
>;
pub type CK_C_FindObjectsInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV>;
pub type CK_C_FindObjects = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE_PTR,
        CK_ULONG,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_FindObjectsFinal = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_EncryptInit = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV,
>;
pub type CK_C_Encrypt = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_EncryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_EncryptFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_DecryptInit = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV,
>;
pub type CK_C_Decrypt = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_DigestInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM) -> CK_RV>;
pub type CK_C_Digest = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DigestUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_DigestKey =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_DigestFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_SignInit = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV,
>;
pub type CK_C_Sign = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_SignUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_SignFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>;
pub type CK_C_SignRecoverInit = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV,
>;
pub type CK_C_SignRecover = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_VerifyInit = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV,
>;
pub type CK_C_Verify = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
>;
pub type CK_C_VerifyUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_VerifyFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_VerifyRecoverInit = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV,
>;
pub type CK_C_VerifyRecover = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DigestEncryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptDigestUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_SignEncryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DecryptVerifyUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_GenerateKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_MECHANISM,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_GenerateKeyPair = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_MECHANISM,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_WrapKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_MECHANISM,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
>;
pub type CK_C_UnwrapKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_MECHANISM,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_DeriveKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_MECHANISM,
        CK_OBJECT_HANDLE,
        *mut CK_ATTRIBUTE,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
>;
pub type CK_C_SeedRandom =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_GenerateRandom =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>;
pub type CK_C_GetFunctionStatus = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_CancelFunction = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_WaitForSlotEvent =
    Option<unsafe extern "C" fn(CK_FLAGS, *mut CK_SLOT_ID, CK_VOID_PTR) -> CK_RV>;

#[repr(C)]
pub struct CK_FUNCTION_LIST {
    pub version: CK_VERSION,
    pub c_initialize: CK_C_Initialize,
    pub c_finalize: CK_C_Finalize,
    pub c_get_info: CK_C_GetInfo,
    pub c_get_function_list:
        Option<unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV>,
    pub c_get_slot_list: CK_C_GetSlotList,
    pub c_get_slot_info: CK_C_GetSlotInfo,
    pub c_get_token_info: CK_C_GetTokenInfo,
    pub c_get_mechanism_list: CK_C_GetMechanismList,
    pub c_get_mechanism_info: CK_C_GetMechanismInfo,
    pub c_init_token: CK_C_InitToken,
    pub c_init_pin: CK_C_InitPIN,
    pub c_set_pin: CK_C_SetPIN,
    pub c_open_session: CK_C_OpenSession,
    pub c_close_session: CK_C_CloseSession,
    pub c_close_all_sessions: CK_C_CloseAllSessions,
    pub c_get_session_info: CK_C_GetSessionInfo,
    pub c_get_operation_state: CK_C_GetOperationState,
    pub c_set_operation_state: CK_C_SetOperationState,
    pub c_login: CK_C_Login,
    pub c_logout: CK_C_Logout,
    pub c_create_object: CK_C_CreateObject,
    pub c_copy_object: CK_C_CopyObject,
    pub c_destroy_object: CK_C_DestroyObject,
    pub c_get_object_size: CK_C_GetObjectSize,
    pub c_get_attribute_value: CK_C_GetAttributeValue,
    pub c_set_attribute_value: CK_C_SetAttributeValue,
    pub c_find_objects_init: CK_C_FindObjectsInit,
    pub c_find_objects: CK_C_FindObjects,
    pub c_find_objects_final: CK_C_FindObjectsFinal,
    pub c_encrypt_init: CK_C_EncryptInit,
    pub c_encrypt: CK_C_Encrypt,
    pub c_encrypt_update: CK_C_EncryptUpdate,
    pub c_encrypt_final: CK_C_EncryptFinal,
    pub c_decrypt_init: CK_C_DecryptInit,
    pub c_decrypt: CK_C_Decrypt,
    pub c_decrypt_update: CK_C_DecryptUpdate,
    pub c_decrypt_final: CK_C_DecryptFinal,
    pub c_digest_init: CK_C_DigestInit,
    pub c_digest: CK_C_Digest,
    pub c_digest_update: CK_C_DigestUpdate,
    pub c_digest_key: CK_C_DigestKey,
    pub c_digest_final: CK_C_DigestFinal,
    pub c_sign_init: CK_C_SignInit,
    pub c_sign: CK_C_Sign,
    pub c_sign_update: CK_C_SignUpdate,
    pub c_sign_final: CK_C_SignFinal,
    pub c_sign_recover_init: CK_C_SignRecoverInit,
    pub c_sign_recover: CK_C_SignRecover,
    pub c_verify_init: CK_C_VerifyInit,
    pub c_verify: CK_C_Verify,
    pub c_verify_update: CK_C_VerifyUpdate,
    pub c_verify_final: CK_C_VerifyFinal,
    pub c_verify_recover_init: CK_C_VerifyRecoverInit,
    pub c_verify_recover: CK_C_VerifyRecover,
    pub c_digest_encrypt_update: CK_C_DigestEncryptUpdate,
    pub c_decrypt_digest_update: CK_C_DecryptDigestUpdate,
    pub c_sign_encrypt_update: CK_C_SignEncryptUpdate,
    pub c_decrypt_verify_update: CK_C_DecryptVerifyUpdate,
    pub c_generate_key: CK_C_GenerateKey,
    pub c_generate_key_pair: CK_C_GenerateKeyPair,
    pub c_wrap_key: CK_C_WrapKey,
    pub c_unwrap_key: CK_C_UnwrapKey,
    pub c_derive_key: CK_C_DeriveKey,
    pub c_seed_random: CK_C_SeedRandom,
    pub c_generate_random: CK_C_GenerateRandom,
    pub c_get_function_status: CK_C_GetFunctionStatus,
    pub c_cancel_function: CK_C_CancelFunction,
    pub c_wait_for_slot_event: CK_C_WaitForSlotEvent,
}

// Safety: The function list is read-only after initialization and contains only function pointers.
unsafe impl Sync for CK_FUNCTION_LIST {}
unsafe impl Send for CK_FUNCTION_LIST {}

/// Pad/truncate a string into a fixed-size PKCS#11 field (space-padded, no null terminator).
pub fn pad_str<const N: usize>(s: &str) -> [CK_UTF8CHAR; N] {
    let mut buf = [b' '; N];
    let bytes = s.as_bytes();
    let len = bytes.len().min(N);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}
