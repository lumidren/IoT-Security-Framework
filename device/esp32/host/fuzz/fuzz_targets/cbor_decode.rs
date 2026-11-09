//! Strict CBOR validator + reader + canonical re-encoder: any accepted input must re-encode to
//! itself (canonical CBOR has exactly one encoding), and nothing may crash or read out of bounds.
#![no_main]
use im_host::ffi::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut top = im_cbor_val_t::default();
    let lim = im_cbor_limits_t { max_size: 65536, max_depth: 16 };
    if unsafe { im_cbor_decode(data.as_ptr(), data.len(), &lim, &mut top) } == 0 {
        let mut out = vec![0u8; data.len() + 16];
        let mut e = im_cbor_enc_t::new(&mut out);
        assert_eq!(unsafe { im_cbor_reencode(&top, &mut e) }, 0);
        assert_eq!(&out[..e.len], data, "canonical round trip");
    }
});
