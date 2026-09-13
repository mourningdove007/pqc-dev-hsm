#![allow(missing_docs)]

use esp_hal::sha::{Sha, Sha256 as HwSha256, Sha512 as HwSha512, ShaDigest};

static HW_SHA: critical_section::Mutex<core::cell::RefCell<Option<Sha<'static>>>> =
    critical_section::Mutex::new(core::cell::RefCell::new(None));

pub fn init_hw_sha(sha: Sha<'static>) {
    critical_section::with(|cs| {
        *HW_SHA.borrow_ref_mut(cs) = Some(sha);
    });
}

fn with_hw_sha<R>(f: impl FnOnce(&mut Sha<'static>) -> R) -> R {
    critical_section::with(|cs| {
        let mut slot = HW_SHA.borrow_ref_mut(cs);
        let sha = slot.as_mut().expect(
            "slh_dsa_hw hw-sha: hardware SHA peripheral not initialized -- call \
             slh_dsa_hw::init_hw_sha() once at boot before signing or verifying",
        );
        f(sha)
    })
}


fn hw_update_all<A: esp_hal::sha::ShaAlgorithm>(
    hasher: &mut ShaDigest<'static, A, &mut Sha<'static>>,
    mut data: &[u8],
) {
    while !data.is_empty() {
        data = nb::block!(hasher.update(data)).unwrap();
    }
}


pub(crate) fn hw_hash256<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut out = [0u8; 32];
    with_hw_sha(|sha| {
        let mut hasher = ShaDigest::<HwSha256, _>::new(sha);
        for part in parts {
            hw_update_all(&mut hasher, part);
        }
        nb::block!(hasher.finish(&mut out)).unwrap();
    });
    out
}

pub(crate) fn hw_hash512<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 64] {
    let mut out = [0u8; 64];
    with_hw_sha(|sha| {
        let mut hasher = ShaDigest::<HwSha512, _>::new(sha);
        for part in parts {
            hw_update_all(&mut hasher, part);
        }
        nb::block!(hasher.finish(&mut out)).unwrap();
    });
    out
}


pub(crate) fn hw_hmac_sha256<'a>(key: &[u8], parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (i, &b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let mut inner_out = [0u8; 32];
    with_hw_sha(|sha| {
        let mut hasher = ShaDigest::<HwSha256, _>::new(sha);
        hw_update_all(&mut hasher, &ipad);
        for part in parts {
            hw_update_all(&mut hasher, part);
        }
        nb::block!(hasher.finish(&mut inner_out)).unwrap();
    });
    hw_hash256([opad.as_slice(), inner_out.as_slice()])
}

pub(crate) fn hw_hmac_sha512<'a>(key: &[u8], parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 64] {
    const BLOCK: usize = 128;
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (i, &b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let mut inner_out = [0u8; 64];
    with_hw_sha(|sha| {
        let mut hasher = ShaDigest::<HwSha512, _>::new(sha);
        hw_update_all(&mut hasher, &ipad);
        for part in parts {
            hw_update_all(&mut hasher, part);
        }
        nb::block!(hasher.finish(&mut inner_out)).unwrap();
    });
    hw_hash512([opad.as_slice(), inner_out.as_slice()])
}

#[derive(Clone, Debug)]
pub(crate) struct HwPrefix256 {
    block: [u8; 64],
}

impl HwPrefix256 {
    pub(crate) fn new(pk_seed: &[u8], zero_padding: &[u8]) -> Self {
        let mut block = [0u8; 64];
        let (seed_part, pad_part) = block.split_at_mut(pk_seed.len());
        seed_part.copy_from_slice(pk_seed);
        pad_part[..zero_padding.len()].copy_from_slice(zero_padding);
        Self { block }
    }

    pub(crate) fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
        let mut out = [0u8; 32];
        with_hw_sha(|sha| {
            let mut hasher = ShaDigest::<HwSha256, _>::new(sha);
            hw_update_all(&mut hasher, &self.block);
            for part in parts {
                hw_update_all(&mut hasher, part);
            }
            nb::block!(hasher.finish(&mut out)).unwrap();
        });
        out
    }
}


#[derive(Clone, Debug)]
pub(crate) struct HwPrefix512 {
    block: [u8; 128],
}

impl HwPrefix512 {
    pub(crate) fn new(pk_seed: &[u8], zero_padding: &[u8]) -> Self {
        let mut block = [0u8; 128];
        let (seed_part, pad_part) = block.split_at_mut(pk_seed.len());
        seed_part.copy_from_slice(pk_seed);
        pad_part[..zero_padding.len()].copy_from_slice(zero_padding);
        Self { block }
    }

    pub(crate) fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 64] {
        let mut out = [0u8; 64];
        with_hw_sha(|sha| {
            let mut hasher = ShaDigest::<HwSha512, _>::new(sha);
            hw_update_all(&mut hasher, &self.block);
            for part in parts {
                hw_update_all(&mut hasher, part);
            }
            nb::block!(hasher.finish(&mut out)).unwrap();
        });
        out
    }
}
