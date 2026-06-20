#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code)]

mod local_client;
mod module;
mod pkcs11_types;

use pkcs11_types::*;

static mut FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 40 },
    c_initialize: Some(module::c_initialize),
    c_finalize: Some(module::c_finalize),
    c_get_info: Some(module::c_get_info),
    c_get_function_list: Some(c_get_function_list),
    c_get_slot_list: Some(module::c_get_slot_list),
    c_get_slot_info: Some(module::c_get_slot_info),
    c_get_token_info: Some(module::c_get_token_info),
    c_get_mechanism_list: Some(module::c_get_mechanism_list),
    c_get_mechanism_info: Some(module::c_get_mechanism_info),
    c_init_token: Some(module::c_init_token),
    c_init_pin: Some(module::c_init_pin),
    c_set_pin: Some(module::c_set_pin),
    c_open_session: Some(module::c_open_session),
    c_close_session: Some(module::c_close_session),
    c_close_all_sessions: Some(module::c_close_all_sessions),
    c_get_session_info: Some(module::c_get_session_info),
    c_get_operation_state: Some(module::c_get_operation_state),
    c_set_operation_state: Some(module::c_set_operation_state),
    c_login: Some(module::c_login),
    c_logout: Some(module::c_logout),
    c_create_object: Some(module::c_create_object),
    c_copy_object: Some(module::c_copy_object),
    c_destroy_object: Some(module::c_destroy_object),
    c_get_object_size: Some(module::c_get_object_size),
    c_get_attribute_value: Some(module::c_get_attribute_value),
    c_set_attribute_value: Some(module::c_set_attribute_value),
    c_find_objects_init: Some(module::c_find_objects_init),
    c_find_objects: Some(module::c_find_objects),
    c_find_objects_final: Some(module::c_find_objects_final),
    c_encrypt_init: Some(module::c_encrypt_init),
    c_encrypt: Some(module::c_encrypt),
    c_encrypt_update: Some(module::c_encrypt_update),
    c_encrypt_final: Some(module::c_encrypt_final),
    c_decrypt_init: Some(module::c_decrypt_init),
    c_decrypt: Some(module::c_decrypt),
    c_decrypt_update: Some(module::c_decrypt_update),
    c_decrypt_final: Some(module::c_decrypt_final),
    c_digest_init: Some(module::c_digest_init),
    c_digest: Some(module::c_digest),
    c_digest_update: Some(module::c_digest_update),
    c_digest_key: Some(module::c_digest_key),
    c_digest_final: Some(module::c_digest_final),
    c_sign_init: Some(module::c_sign_init),
    c_sign: Some(module::c_sign),
    c_sign_update: Some(module::c_sign_update),
    c_sign_final: Some(module::c_sign_final),
    c_sign_recover_init: Some(module::c_sign_recover_init),
    c_sign_recover: Some(module::c_sign_recover),
    c_verify_init: Some(module::c_verify_init),
    c_verify: Some(module::c_verify),
    c_verify_update: Some(module::c_verify_update),
    c_verify_final: Some(module::c_verify_final),
    c_verify_recover_init: Some(module::c_verify_recover_init),
    c_verify_recover: Some(module::c_verify_recover),
    c_digest_encrypt_update: Some(module::c_digest_encrypt_update),
    c_decrypt_digest_update: Some(module::c_decrypt_digest_update),
    c_sign_encrypt_update: Some(module::c_sign_encrypt_update),
    c_decrypt_verify_update: Some(module::c_decrypt_verify_update),
    c_generate_key: Some(module::c_generate_key),
    c_generate_key_pair: Some(module::c_generate_key_pair),
    c_wrap_key: Some(module::c_wrap_key),
    c_unwrap_key: Some(module::c_unwrap_key),
    c_derive_key: Some(module::c_derive_key),
    c_seed_random: Some(module::c_seed_random),
    c_generate_random: Some(module::c_generate_random),
    c_get_function_status: Some(module::c_get_function_status),
    c_cancel_function: Some(module::c_cancel_function),
    c_wait_for_slot_event: Some(module::c_wait_for_slot_event),
};

/// PKCS#11 entry point. Called by gnupg-pkcs11-scd to get the function list.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *pp_function_list = std::ptr::addr_of_mut!(FUNCTION_LIST);
    CKR_OK
}

// Also export the lowercase version some implementations look for.
#[no_mangle]
pub unsafe extern "C" fn c_get_function_list(
    pp_function_list: *mut *mut CK_FUNCTION_LIST,
) -> CK_RV {
    C_GetFunctionList(pp_function_list)
}
