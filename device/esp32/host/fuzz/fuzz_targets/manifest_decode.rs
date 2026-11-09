//! Manifest map decoder, the COSE_Sign verify path with a trusted Ed25519 key, and the pure
//! acceptance rules on whatever decodes.
#![no_main]
use im_host::ffi::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    unsafe {
        let mut m = im_manifest_t::default();
        if im_manifest_decode(data.as_ptr(), data.len(), core::ptr::null(), &mut m) == 0 {
            assert!(m.min_version_code <= m.version_code);
            let _ = im_manifest_precheck(&m, 5, c"sensor-esp32".as_ptr());
            let _ = im_manifest_accept_patch(&m, 10, [0u8; 32].as_ptr(), [0u8; 32].as_ptr());
        }
        let key = [0x9fu8; 32];
        let keys = im_fw_keys_t {
            key: [key.as_ptr(), core::ptr::null(), core::ptr::null(), core::ptr::null()],
            len: [32, 0, 0, 0],
            n: 1,
        };
        let mut work = vec![0u8; data.len() + 64];
        let mut pq = false;
        let require_pq = data.first().is_some_and(|b| b & 1 == 1);
        let _ = im_manifest_verify(data.as_ptr(), data.len(), &keys, require_pq, core::ptr::null(), work.as_mut_ptr(), work.len(), &mut m, &mut pq);
    }
});
