//! COSE_Sign1 / COSE_Sign / COSE_Encrypt0 structural parsers (+ the Sign1 verification path).
#![no_main]
use im_host::ffi::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    unsafe {
        let mut s1: im_sign1_t = core::mem::zeroed();
        if im_cose_sign1_decode(data.as_ptr(), data.len(), core::ptr::null(), &mut s1) == 0 {
            assert!(s1.sig_len == 64 && s1.kid_len >= 1 && s1.kid_len <= 255);
            let mut work = vec![0u8; data.len() + 64];
            let mut k = im_pubkey_t::default();
            im_pubkey_ed25519(&mut k, [9u8; 32].as_ptr(), 32);
            let _ = im_cose_sign1_verify(&s1, &k, work.as_mut_ptr(), work.len());
        }
        let mut s: im_sign_t = core::mem::zeroed();
        if im_cose_sign_decode(data.as_ptr(), data.len(), core::ptr::null(), &mut s) == 0 {
            assert!(s.nsigs >= 1 && s.nsigs <= 2);
        }
        let mut e0: im_encrypt0_t = core::mem::zeroed();
        if im_cose_encrypt0_decode(data.as_ptr(), data.len(), core::ptr::null(), &mut e0) == 0 {
            assert!(e0.ct_len >= 16);
        }
    }
});
