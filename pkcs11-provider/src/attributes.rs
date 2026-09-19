
use cryptoki_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_RV, CKA_CLASS, CKA_ID,
    CKA_KEY_TYPE, CKA_LABEL, CKA_SIGN, CKA_TOKEN, CKA_VALUE, CKA_VERIFY, CKK_VENDOR_DEFINED,
    CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL, CKR_OK, CK_FALSE, CK_TRUE,
};

use crate::state::{PRIVATE_KEY_HANDLE, PUBLIC_KEY_HANDLE};
use crate::CK_UNAVAILABLE_INFORMATION;

const LABEL: &[u8] = b"pqc-dev-hsm-key";
const ID: &[u8] = &[1];

pub fn find_class_filter(attrs: &[CK_ATTRIBUTE]) -> Option<CK_OBJECT_CLASS> {
    for attr in attrs {
        if attr.type_ == CKA_CLASS
            && !attr.pValue.is_null()
            && attr.ulValueLen as usize == size_of::<CK_OBJECT_CLASS>()
        {
            return Some(unsafe { *(attr.pValue as *const CK_OBJECT_CLASS) });
        }
    }
    None
}


pub fn get_attribute_values(
    object: CK_OBJECT_HANDLE,
    public_key: &[u8],
    attrs: &mut [CK_ATTRIBUTE],
) -> CK_RV {
    let mut overall = CKR_OK;
    let mut note = |rv: CK_RV| {
        if overall == CKR_OK {
            overall = rv;
        }
    };

    for attr in attrs.iter_mut() {
        let class_bytes: [u8; size_of::<CK_OBJECT_CLASS>()];
        let key_type_bytes: [u8; size_of::<cryptoki_sys::CK_KEY_TYPE>()];
        let bool_bytes: [u8; size_of::<CK_BBOOL>()];

        let bytes: &[u8] = match attr.type_ {
            CKA_CLASS => {
                let class: CK_OBJECT_CLASS = if object == PRIVATE_KEY_HANDLE {
                    CKO_PRIVATE_KEY
                } else {
                    CKO_PUBLIC_KEY
                };
                class_bytes = class.to_ne_bytes();
                &class_bytes
            }
            CKA_KEY_TYPE => {
                key_type_bytes = CKK_VENDOR_DEFINED.to_ne_bytes();
                &key_type_bytes
            }
            CKA_TOKEN => {
                bool_bytes = [CK_TRUE];
                &bool_bytes
            }
            CKA_SIGN => {
                bool_bytes = [if object == PRIVATE_KEY_HANDLE { CK_TRUE } else { CK_FALSE }];
                &bool_bytes
            }
            CKA_VERIFY => {
                bool_bytes = [if object == PUBLIC_KEY_HANDLE { CK_TRUE } else { CK_FALSE }];
                &bool_bytes
            }
            CKA_LABEL => LABEL,
            CKA_ID => ID,
            CKA_VALUE if object == PUBLIC_KEY_HANDLE => public_key,
            CKA_VALUE => {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                note(CKR_ATTRIBUTE_SENSITIVE);
                continue;
            }
            _ => {
                attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                note(CKR_ATTRIBUTE_TYPE_INVALID);
                continue;
            }
        };

        if attr.pValue.is_null() {
            attr.ulValueLen = bytes.len() as cryptoki_sys::CK_ULONG;
        } else if (attr.ulValueLen as usize) < bytes.len() {
            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            note(CKR_BUFFER_TOO_SMALL);
        } else {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), attr.pValue as *mut u8, bytes.len());
            }
            attr.ulValueLen = bytes.len() as cryptoki_sys::CK_ULONG;
        }
    }

    overall
}
