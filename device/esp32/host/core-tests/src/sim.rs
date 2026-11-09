//! Simulated hardware for host runs: a NOR flash (erase -> 0xFF, writes can only clear bits,
//! like the ESP32's SPI flash), a key-value store standing in for NVS, and an A/B slot pair for
//! OTA. Each exposes the C callback tables the core expects.

use crate::err::*;
use crate::ffi2::*;
use core::ffi::{c_char, c_void, CStr};
use std::collections::BTreeMap;

/// NOR flash region with sector erase.
pub struct NorFlash {
    pub data: Vec<u8>,
    pub sector: u32,
    /// Fail the next N writes after this many more successful writes (power-cut tests).
    pub fail_after_writes: Option<usize>,
    pub writes: usize,
}

impl NorFlash {
    pub fn new(size: u32, sector: u32) -> Box<Self> {
        Box::new(Self {
            data: vec![0xFF; size as usize],
            sector,
            fail_after_writes: None,
            writes: 0,
        })
    }

    /// The `im_storage_t` view (self must stay boxed and alive).
    pub fn storage(&mut self) -> im_storage_t {
        im_storage_t {
            read: Some(nor_read),
            write: Some(nor_write),
            erase: Some(nor_erase),
            ctx: (self as *mut Self).cast(),
            size: self.data.len() as u32,
            sector_size: self.sector,
        }
    }
}

unsafe extern "C" fn nor_read(ctx: *mut c_void, off: u32, buf: *mut u8, len: usize) -> i32 {
    let f = &*(ctx as *const NorFlash);
    let off = off as usize;
    if off.checked_add(len).is_none_or(|e| e > f.data.len()) {
        return IM_ERR_IO;
    }
    core::slice::from_raw_parts_mut(buf, len).copy_from_slice(&f.data[off..off + len]);
    IM_OK
}

unsafe extern "C" fn nor_write(ctx: *mut c_void, off: u32, data: *const u8, len: usize) -> i32 {
    let f = &mut *(ctx as *mut NorFlash);
    let off = off as usize;
    if off.checked_add(len).is_none_or(|e| e > f.data.len()) {
        return IM_ERR_IO;
    }
    if let Some(n) = f.fail_after_writes {
        if f.writes >= n {
            // torn write: only the first half lands
            let src = crate::crypto::cslice(data, len);
            for (i, b) in src.iter().take(len / 2).enumerate() {
                f.data[off + i] &= *b;
            }
            return IM_ERR_IO;
        }
    }
    f.writes += 1;
    let src = crate::crypto::cslice(data, len);
    for (i, b) in src.iter().enumerate() {
        f.data[off + i] &= *b; // NOR: bits can only go 1 -> 0
    }
    IM_OK
}

unsafe extern "C" fn nor_erase(ctx: *mut c_void, off: u32, len: usize) -> i32 {
    let f = &mut *(ctx as *mut NorFlash);
    let off = off as usize;
    if !off.is_multiple_of(f.sector as usize) || !len.is_multiple_of(f.sector as usize) || off + len > f.data.len() {
        return IM_ERR_ARG;
    }
    f.data[off..off + len].fill(0xFF);
    IM_OK
}

/// In-memory NVS replacement (persisted by the shim to a JSON file between "reboots").
#[derive(Default)]
pub struct Kv {
    pub map: BTreeMap<String, Vec<u8>>,
    pub fail_sets: bool,
}

impl Kv {
    pub fn ffi(&mut self) -> im_kv_t {
        im_kv_t {
            get: Some(kv_get),
            set: Some(kv_set),
            erase: Some(kv_erase),
            ctx: (self as *mut Self).cast(),
        }
    }
}

unsafe fn key(k: *const c_char) -> String {
    CStr::from_ptr(k).to_string_lossy().into_owned()
}

unsafe extern "C" fn kv_get(ctx: *mut c_void, k: *const c_char, buf: *mut u8, cap: usize, len: *mut usize) -> i32 {
    let kv = &*(ctx as *const Kv);
    match kv.map.get(&key(k)) {
        Some(v) if v.len() <= cap => {
            core::slice::from_raw_parts_mut(buf, v.len()).copy_from_slice(v);
            *len = v.len();
            IM_OK
        }
        Some(_) => IM_ERR_BUFFER,
        None => IM_ERR_NOT_FOUND,
    }
}

unsafe extern "C" fn kv_set(ctx: *mut c_void, k: *const c_char, d: *const u8, n: usize) -> i32 {
    let kv = &mut *(ctx as *mut Kv);
    if kv.fail_sets {
        return IM_ERR_STORAGE;
    }
    kv.map.insert(key(k), crate::crypto::cslice(d, n).to_vec());
    IM_OK
}

unsafe extern "C" fn kv_erase(ctx: *mut c_void, k: *const c_char) -> i32 {
    let kv = &mut *(ctx as *mut Kv);
    kv.map.remove(&key(k));
    IM_OK
}

/// One firmware slot of the simulated A/B pair.
#[derive(Clone, Debug, Default)]
pub struct Slot {
    pub name: String,
    pub image: Vec<u8>,
    pub version: String,
    pub version_code: u64,
    /// "valid", "pending_verify", "new", "invalid", "empty"
    pub state: String,
}

/// A/B slots with ESP-IDF-like semantics: set_boot marks the inactive slot pending; the next boot
/// runs it in `pending_verify`; mark_valid confirms; rollback (or a reboot while still pending)
/// reverts to the other slot.
#[derive(Debug)]
pub struct Slots {
    pub slots: [Slot; 2],
    pub active: usize,
    pub boot_next: Option<usize>,
    pub writing: Vec<u8>,
    pub writing_meta: Option<(String, u64)>,
}

impl Slots {
    pub fn new(image: Vec<u8>, version: &str, version_code: u64) -> Self {
        Self {
            slots: [
                Slot {
                    name: "ota_0".into(),
                    image,
                    version: version.into(),
                    version_code,
                    state: "valid".into(),
                },
                Slot {
                    name: "ota_1".into(),
                    state: "empty".into(),
                    ..Default::default()
                },
            ],
            active: 0,
            boot_next: None,
            writing: Vec::new(),
            writing_meta: None,
        }
    }

    pub fn inactive(&self) -> usize {
        1 - self.active
    }

    pub fn running(&self) -> &Slot {
        &self.slots[self.active]
    }

    /// Simulated reset: returns the boot reason (`IM_REBOOT_*`) the bootloader would report.
    pub fn reset(&mut self) -> i32 {
        if self.slots[self.active].state == "pending_verify" {
            // CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE: an unconfirmed image is reverted
            self.slots[self.active].state = "invalid".into();
            self.active = 1 - self.active;
            self.boot_next = None;
            return IM_REBOOT_ROLLBACK;
        }
        if let Some(n) = self.boot_next.take() {
            self.active = n;
            self.slots[n].state = "pending_verify".into();
            return IM_REBOOT_OTA_APPLY;
        }
        IM_REBOOT_REQUESTED
    }
}
