use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use cryptoki_sys::{
    CK_ATTRIBUTE_PTR, CK_BBOOL, CK_BYTE_PTR, CK_FLAGS, CK_FUNCTION_LIST,
    CK_INFO, CK_MECHANISM_INFO_PTR, CK_MECHANISM_PTR, CK_MECHANISM_TYPE, CK_MECHANISM_TYPE_PTR,
    CK_NOTIFY, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR, CK_RV, CK_SESSION_HANDLE,
    CK_SESSION_HANDLE_PTR, CK_SLOT_ID, CK_SLOT_INFO_PTR, CK_TOKEN_INFO_PTR, CK_ULONG,
    CK_ULONG_PTR, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_VERSION, CK_VOID_PTR,
    CKO_PRIVATE_KEY, CKO_PUBLIC_KEY,
    CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
    CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR, CKR_KEY_HANDLE_INVALID, CKR_MECHANISM_INVALID, CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, CKR_SLOT_ID_INVALID,
    CKF_RNG, CKF_SIGN, CKF_TOKEN_INITIALIZED, CKF_TOKEN_PRESENT,
};

mod attributes;
mod device;
mod state;

use state::{ProviderState, SessionState, PRIVATE_KEY_HANDLE, PUBLIC_KEY_HANDLE, SLOT_ID};

pub const CKM_SLH_DSA_SHA2_VENDOR: CK_MECHANISM_TYPE = cryptoki_sys::CKM_VENDOR_DEFINED + 1;

const CK_UNAVAILABLE_INFORMATION: CK_ULONG = CK_ULONG::MAX;

static STATE: Mutex<Option<ProviderState>> = Mutex::new(None);

fn with_state<R>(f: impl FnOnce(&mut ProviderState) -> Result<R, CK_RV>) -> Result<R, CK_RV> {
    let mut guard = STATE.lock().unwrap();
    match guard.as_mut() {
        Some(state) => f(state),
        None => Err(CKR_CRYPTOKI_NOT_INITIALIZED),
    }
}

unsafe extern "C" fn c_initialize(_init_args: CK_VOID_PTR) -> CK_RV {
    let endpoint = match std::env::var("PQC_HSM_ENDPOINT") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("pkcs11-provider: PQC_HSM_ENDPOINT not set (e.g. tcp://127.0.0.1:7878)");
            return CKR_GENERAL_ERROR;
        }
    };

    let connection = match device::connect(&endpoint) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("pkcs11-provider: failed to connect to {endpoint}: {e}");
            return CKR_DEVICE_ERROR;
        }
    };

    let state = match ProviderState::new(connection) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("pkcs11-provider: device handshake failed: {e}");
            return CKR_DEVICE_ERROR;
        }
    };

    *STATE.lock().unwrap() = Some(state);
    CKR_OK
}

unsafe extern "C" fn c_finalize(_reserved: CK_VOID_PTR) -> CK_RV {
    *STATE.lock().unwrap() = None;
    CKR_OK
}

unsafe extern "C" fn c_get_info(info: *mut CK_INFO) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut out = CK_INFO {
        cryptokiVersion: CK_VERSION { major: 2, minor: 40 },
        manufacturerID: pad_utf8::<32>("PQC Dev HSM project"),
        flags: 0,
        libraryDescription: pad_utf8::<32>("PQC Dev HSM PKCS#11 provider"),
        libraryVersion: CK_VERSION { major: 0, minor: 1 },
    };
    unsafe { std::ptr::write(info, std::mem::take(&mut out)) };
    CKR_OK
}

unsafe extern "C" fn c_get_slot_list(
    _token_present: CK_BBOOL,
    slot_list: cryptoki_sys::CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        if slot_list.is_null() {
            *count = 1;
            return CKR_OK;
        }
        if *count < 1 {
            *count = 1;
            return CKR_BUFFER_TOO_SMALL;
        }
        *slot_list = SLOT_ID;
        *count = 1;
    }
    CKR_OK
}

unsafe extern "C" fn c_get_slot_info(slot_id: CK_SLOT_ID, info: CK_SLOT_INFO_PTR) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let out = cryptoki_sys::CK_SLOT_INFO {
        slotDescription: pad_utf8::<64>("PQC Dev HSM: dev-signer/nano-signer over token-core"),
        manufacturerID: pad_utf8::<32>("PQC Dev HSM project"),
        flags: CKF_TOKEN_PRESENT,
        hardwareVersion: CK_VERSION { major: 0, minor: 1 },
        firmwareVersion: CK_VERSION { major: 0, minor: 1 },
    };
    unsafe { std::ptr::write(info, out) };
    CKR_OK
}

unsafe extern "C" fn c_get_token_info(slot_id: CK_SLOT_ID, info: CK_TOKEN_INFO_PTR) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let result = with_state(|state| {
        
        let out = cryptoki_sys::CK_TOKEN_INFO {
            label: pad_utf8::<32>("pqc-dev-hsm"),
            manufacturerID: pad_utf8::<32>("PQC Dev HSM project"),
            model: pad_utf8::<16>(&format!("slh-dsa-{}", state.param_set_name)),
            serialNumber: pad_utf8::<16>("0"),
            flags: CKF_RNG | CKF_TOKEN_INITIALIZED,
            ulMaxSessionCount: cryptoki_sys::CK_EFFECTIVELY_INFINITE,
            ulSessionCount: state.sessions.len() as CK_ULONG,
            ulMaxRwSessionCount: cryptoki_sys::CK_EFFECTIVELY_INFINITE,
            ulRwSessionCount: state.sessions.len() as CK_ULONG,
            ulMaxPinLen: 0,
            ulMinPinLen: 0,
            ulTotalPublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulTotalPrivateMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePrivateMemory: CK_UNAVAILABLE_INFORMATION,
            hardwareVersion: CK_VERSION { major: 0, minor: 1 },
            firmwareVersion: CK_VERSION { major: 0, minor: 1 },
            utcTime: [b' '; 16],
        };
        Ok(out)
    });

    match result {
        Ok(out) => {
            unsafe { std::ptr::write(info, out) };
            CKR_OK
        }
        Err(rv) => rv,
    }
}

unsafe extern "C" fn c_get_mechanism_list(
    slot_id: CK_SLOT_ID,
    mechanism_list: CK_MECHANISM_TYPE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        if mechanism_list.is_null() {
            *count = 1;
            return CKR_OK;
        }
        if *count < 1 {
            *count = 1;
            return CKR_BUFFER_TOO_SMALL;
        }
        *mechanism_list = CKM_SLH_DSA_SHA2_VENDOR;
        *count = 1;
    }
    CKR_OK
}

unsafe extern "C" fn c_get_mechanism_info(
    slot_id: CK_SLOT_ID,
    mechanism_type: CK_MECHANISM_TYPE,
    info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if mechanism_type != CKM_SLH_DSA_SHA2_VENDOR {
        return CKR_MECHANISM_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let out = cryptoki_sys::CK_MECHANISM_INFO {
        ulMinKeySize: 0,
        ulMaxKeySize: 0,
        flags: CKF_SIGN,
    };
    unsafe { std::ptr::write(info, out) };
    CKR_OK
}

unsafe extern "C" fn c_open_session(
    slot_id: CK_SLOT_ID,
    _flags: CK_FLAGS,
    _application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let result = with_state(|state| {
        let handle = state.next_session_handle;
        state.next_session_handle += 1;
        state.sessions.insert(handle, SessionState::default());
        Ok(handle)
    });

    match result {
        Ok(handle) => {
            unsafe { *session = handle };
            CKR_OK
        }
        Err(rv) => rv,
    }
}

unsafe extern "C" fn c_close_session(session: CK_SESSION_HANDLE) -> CK_RV {
    let result = with_state(|state| {
        if state.sessions.remove(&session).is_some() {
            Ok(())
        } else {
            Err(CKR_SESSION_HANDLE_INVALID)
        }
    });
    result.err().unwrap_or(CKR_OK)
}


unsafe extern "C" fn c_login(
    session: CK_SESSION_HANDLE,
    _user_type: CK_USER_TYPE,
    _pin: CK_UTF8CHAR_PTR,
    _pin_len: CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        if state.sessions.contains_key(&session) {
            Ok(())
        } else {
            Err(CKR_SESSION_HANDLE_INVALID)
        }
    })
    .err()
    .unwrap_or(CKR_OK)
}

unsafe extern "C" fn c_logout(session: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        if state.sessions.contains_key(&session) {
            Ok(())
        } else {
            Err(CKR_SESSION_HANDLE_INVALID)
        }
    })
    .err()
    .unwrap_or(CKR_OK)
}

unsafe extern "C" fn c_find_objects_init(
    session: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    let filter_class = if template.is_null() || count == 0 {
        None
    } else {
        let attrs = unsafe { std::slice::from_raw_parts(template, count as usize) };
        attributes::find_class_filter(attrs)
    };

    with_state(|state| {
        let Some(session_state) = state.sessions.get_mut(&session) else {
            return Err(CKR_SESSION_HANDLE_INVALID);
        };
        let handles: VecDeque<CK_OBJECT_HANDLE> = match filter_class {
            Some(CKO_PRIVATE_KEY) => [PRIVATE_KEY_HANDLE].into(),
            Some(CKO_PUBLIC_KEY) => [PUBLIC_KEY_HANDLE].into(),
            
            Some(_) => [].into(),
            None => [PRIVATE_KEY_HANDLE, PUBLIC_KEY_HANDLE].into(),
        };
        session_state.pending_find = Some(handles);
        Ok(())
    })
    .err()
    .unwrap_or(CKR_OK)
}

unsafe extern "C" fn c_find_objects(
    session: CK_SESSION_HANDLE,
    object_handles: CK_OBJECT_HANDLE_PTR,
    max_count: CK_ULONG,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if object_handles.is_null() || count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let result = with_state(|state| {
        let Some(session_state) = state.sessions.get_mut(&session) else {
            return Err(CKR_SESSION_HANDLE_INVALID);
        };
        let Some(pending) = session_state.pending_find.as_mut() else {
            return Err(CKR_OPERATION_NOT_INITIALIZED);
        };
        let mut found = Vec::new();
        while found.len() < max_count as usize {
            match pending.pop_front() {
                Some(handle) => found.push(handle),
                None => break,
            }
        }
        Ok(found)
    });

    match result {
        Ok(found) => {
            unsafe {
                for (i, handle) in found.iter().enumerate() {
                    *object_handles.add(i) = *handle;
                }
                *count = found.len() as CK_ULONG;
            }
            CKR_OK
        }
        Err(rv) => rv,
    }
}

unsafe extern "C" fn c_find_objects_final(session: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        let Some(session_state) = state.sessions.get_mut(&session) else {
            return Err(CKR_SESSION_HANDLE_INVALID);
        };
        session_state.pending_find = None;
        Ok(())
    })
    .err()
    .unwrap_or(CKR_OK)
}

unsafe extern "C" fn c_get_attribute_value(
    _session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    if template.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if object != PRIVATE_KEY_HANDLE && object != PUBLIC_KEY_HANDLE {
        return CKR_KEY_HANDLE_INVALID;
    }

    let public_key = match with_state(|state| Ok(state.public_key.clone())) {
        Ok(pk) => pk,
        Err(rv) => return rv,
    };

    let attrs = unsafe { std::slice::from_raw_parts_mut(template, count as usize) };
    attributes::get_attribute_values(object, &public_key, attrs)
}

unsafe extern "C" fn c_sign_init(
    session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if unsafe { (*mechanism).mechanism } != CKM_SLH_DSA_SHA2_VENDOR {
        return CKR_MECHANISM_INVALID;
    }
    if key != PRIVATE_KEY_HANDLE {
        return CKR_KEY_HANDLE_INVALID;
    }

    with_state(|state| {
        let Some(session_state) = state.sessions.get_mut(&session) else {
            return Err(CKR_SESSION_HANDLE_INVALID);
        };
        session_state.sign_active = true;
        Ok(())
    })
    .err()
    .unwrap_or(CKR_OK)
}

unsafe extern "C" fn c_sign(
    session: CK_SESSION_HANDLE,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    signature: CK_BYTE_PTR,
    signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let expected_len = match with_state(|state| {
        let Some(session_state) = state.sessions.get(&session) else {
            return Err(CKR_SESSION_HANDLE_INVALID);
        };
        if !session_state.sign_active {
            return Err(CKR_OPERATION_NOT_INITIALIZED);
        }
        Ok(state.signature_len)
    }) {
        Ok(len) => len,
        Err(rv) => return rv,
    };

    
    if signature.is_null() {
        unsafe { *signature_len = expected_len as CK_ULONG };
        return CKR_OK;
    }

    let have = unsafe { *signature_len } as usize;
    if have < expected_len {
        unsafe { *signature_len = expected_len as CK_ULONG };
        return CKR_BUFFER_TOO_SMALL;
    }

    let message = if data_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len as usize) }
    };

    let result = with_state(|state| {
        let sig = state
            .device
            .sign(message)
            .map_err(|e| {
                eprintln!("pkcs11-provider: sign request failed: {e}");
                CKR_DEVICE_ERROR
            })?;
        if sig.len() != expected_len {
            eprintln!(
                "pkcs11-provider: device returned a {}-byte signature, expected {expected_len}",
                sig.len()
            );
            return Err(CKR_DEVICE_ERROR);
        }
        let session_state = state.sessions.get_mut(&session).expect("checked above");
        session_state.sign_active = false;
        Ok(sig)
    });

    match result {
        Ok(sig) => {
            unsafe {
                std::ptr::copy_nonoverlapping(sig.as_ptr(), signature, sig.len());
                *signature_len = sig.len() as CK_ULONG;
            }
            CKR_OK
        }
        Err(rv) => rv,
    }
}


#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(function_list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    unsafe { c_get_function_list(function_list) }
}

unsafe extern "C" fn c_get_function_list(function_list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    if function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    static LIST: OnceLock<CK_FUNCTION_LIST> = OnceLock::new();
    let list = LIST.get_or_init(build_function_list);
    unsafe { *function_list = list as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST };
    CKR_OK
}

fn build_function_list() -> CK_FUNCTION_LIST {
    unsafe extern "C" fn unsupported() -> CK_RV {
        CKR_FUNCTION_NOT_SUPPORTED
    }
    
    let _ = unsupported as unsafe extern "C" fn() -> CK_RV;

    CK_FUNCTION_LIST {
        version: CK_VERSION { major: 2, minor: 40 },
        C_Initialize: Some(c_initialize),
        C_Finalize: Some(c_finalize),
        C_GetInfo: Some(c_get_info),
        C_GetFunctionList: Some(c_get_function_list),
        C_GetSlotList: Some(c_get_slot_list),
        C_GetSlotInfo: Some(c_get_slot_info),
        C_GetTokenInfo: Some(c_get_token_info),
        C_GetMechanismList: Some(c_get_mechanism_list),
        C_GetMechanismInfo: Some(c_get_mechanism_info),
        C_InitToken: None,
        C_InitPIN: None,
        C_SetPIN: None,
        C_OpenSession: Some(c_open_session),
        C_CloseSession: Some(c_close_session),
        C_CloseAllSessions: None,
        C_GetSessionInfo: None,
        C_GetOperationState: None,
        C_SetOperationState: None,
        C_Login: Some(c_login),
        C_Logout: Some(c_logout),
        C_CreateObject: None,
        C_CopyObject: None,
        C_DestroyObject: None,
        C_GetObjectSize: None,
        C_GetAttributeValue: Some(c_get_attribute_value),
        C_SetAttributeValue: None,
        C_FindObjectsInit: Some(c_find_objects_init),
        C_FindObjects: Some(c_find_objects),
        C_FindObjectsFinal: Some(c_find_objects_final),
        C_EncryptInit: None,
        C_Encrypt: None,
        C_EncryptUpdate: None,
        C_EncryptFinal: None,
        C_DecryptInit: None,
        C_Decrypt: None,
        C_DecryptUpdate: None,
        C_DecryptFinal: None,
        C_DigestInit: None,
        C_Digest: None,
        C_DigestUpdate: None,
        C_DigestKey: None,
        C_DigestFinal: None,
        C_SignInit: Some(c_sign_init),
        C_Sign: Some(c_sign),
        C_SignUpdate: None,
        C_SignFinal: None,
        C_SignRecoverInit: None,
        C_SignRecover: None,
        C_VerifyInit: None,
        C_Verify: None,
        C_VerifyUpdate: None,
        C_VerifyFinal: None,
        C_VerifyRecoverInit: None,
        C_VerifyRecover: None,
        C_DigestEncryptUpdate: None,
        C_DecryptDigestUpdate: None,
        C_SignEncryptUpdate: None,
        C_DecryptVerifyUpdate: None,
        C_GenerateKey: None,
        C_GenerateKeyPair: None,
        C_WrapKey: None,
        C_UnwrapKey: None,
        C_DeriveKey: None,
        C_SeedRandom: None,
        C_GenerateRandom: None,
        C_GetFunctionStatus: None,
        C_CancelFunction: None,
        C_WaitForSlotEvent: None,
    }
}


fn pad_utf8<const N: usize>(s: &str) -> [cryptoki_sys::CK_UTF8CHAR; N] {
    let mut out = [b' '; N];
    let bytes = s.as_bytes();
    let n = bytes.len().min(N);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}
