//! DUT control-line JSON parser + accessors, base64 decoder, and the JSON writer on the parsed
//! strings (writer output must itself parse).
#![no_main]
use core::ffi::c_char;
use im_host::ffi2::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    unsafe {
        let mut toks = vec![im_json_tok_t::default(); 64];
        let mut j = im_json_t { js: core::ptr::null(), len: 0, tok: core::ptr::null_mut(), ntok: 0 };
        if im_json_parse(&mut j, data.as_ptr().cast(), data.len(), toks.as_mut_ptr(), toks.len()) != 0 {
            return;
        }
        assert!(j.ntok >= 1 && j.ntok <= 64);
        assert_eq!(toks[0].span as usize, j.ntok, "root spans every token");
        let mut buf = vec![0 as c_char; 4096];
        let mut out = vec![0 as c_char; 16384];
        let mut w: im_json_w_t = core::mem::zeroed();
        im_jw_init(&mut w, out.as_mut_ptr(), out.len());
        im_jw_arr(&mut w);
        for t in 0..j.ntok as i32 {
            let mut n = 0usize;
            let mut v = 0u64;
            let mut b = false;
            if im_json_str(&j, t, buf.as_mut_ptr(), buf.len(), &mut n) {
                im_jw_str(&mut w, buf.as_ptr(), n);
                let mut dec = vec![0u8; n];
                let mut m = 0usize;
                let _ = im_b64_decode(buf.as_ptr(), n, dec.as_mut_ptr(), dec.len(), &mut m);
            }
            let _ = im_json_u64(&j, t, &mut v);
            let _ = im_json_bool(&j, t, &mut b);
        }
        for key in [c"id", c"op", c"args", c"topic"] {
            let _ = im_json_get(&j, 0, key.as_ptr());
        }
        im_jw_arr_end(&mut w);
        let mut n = 0usize;
        if im_jw_finish(&mut w, &mut n) == 0 {
            let mut t2 = vec![im_json_tok_t::default(); 256];
            let mut j2 = im_json_t { js: core::ptr::null(), len: 0, tok: core::ptr::null_mut(), ntok: 0 };
            let r = im_json_parse(&mut j2, out.as_ptr(), n, t2.as_mut_ptr(), t2.len());
            assert_eq!(r, 0, "writer output is valid JSON");
        }
    }
});
