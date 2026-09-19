
use std::collections::{HashMap, VecDeque};

use cryptoki_sys::{CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_SLOT_ID};

use crate::device::{Connection, DeviceConnection};

pub const SLOT_ID: CK_SLOT_ID = 0;

pub const PRIVATE_KEY_HANDLE: CK_OBJECT_HANDLE = 1;
pub const PUBLIC_KEY_HANDLE: CK_OBJECT_HANDLE = 2;

#[derive(Default)]
pub struct SessionState {
    pub sign_active: bool,
    pub pending_find: Option<VecDeque<CK_OBJECT_HANDLE>>,
}

pub struct ProviderState {
    pub device: DeviceConnection,
    pub param_set_name: String,
    pub public_key: Vec<u8>,
    pub signature_len: usize,
    pub sessions: HashMap<CK_SESSION_HANDLE, SessionState>,
    pub next_session_handle: CK_SESSION_HANDLE,
}

impl ProviderState {
    
    pub fn new(connection: Connection) -> Result<Self, String> {
        let mut device = DeviceConnection::new(connection);
        let param_set_name = device.get_info()?;
        let public_key = device.get_public_key(token_core::FIXED_OBJECT_HANDLE)?;
        let signature_len = signature_len_for(&param_set_name).ok_or_else(|| {
            format!("device reported unknown parameter set '{param_set_name}'")
        })?;

        Ok(Self {
            device,
            param_set_name,
            public_key,
            signature_len,
            sessions: HashMap::new(),
            next_session_handle: 1,
        })
    }
}


fn signature_len_for(param_set_name: &str) -> Option<usize> {
    Some(match param_set_name {
        "128s" => 7856,
        "128f" => 17088,
        "192s" => 16224,
        "192f" => 35664,
        "256s" => 29792,
        "256f" => 49856,
        _ => return None,
    })
}
