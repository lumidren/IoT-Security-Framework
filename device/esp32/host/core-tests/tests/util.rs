//! DUT JSON subset parser/serializer, base64, command idempotency cache and replay store.

use core::ffi::c_char;
use im_host::err::*;
use im_host::err_name;
use im_host::ffi::*;
use im_host::ffi2::*;
use std::ffi::CString;

struct J {
    _src: Vec<u8>,
    _toks: Vec<im_json_tok_t>,
    j: im_json_t,
}

fn parse_with(s: &str, max: usize) -> Result<J, &'static str> {
    let src = s.as_bytes().to_vec();
    let mut toks = vec![im_json_tok_t::default(); max];
    let mut j = im_json_t {
        js: std::ptr::null(),
        len: 0,
        tok: std::ptr::null_mut(),
        ntok: 0,
    };
    let r = unsafe { im_json_parse(&mut j, src.as_ptr().cast(), src.len(), toks.as_mut_ptr(), max) };
    if r != IM_OK {
        return Err(err_name(r));
    }
    Ok(J { _src: src, _toks: toks, j })
}

fn parse(s: &str) -> Result<J, &'static str> {
    parse_with(s, 64)
}

fn get(j: &J, obj: i32, k: &str) -> i32 {
    let k = std::ffi::CString::new(k).unwrap();
    unsafe { im_json_get(&j.j, obj, k.as_ptr()) }
}

fn str_of(j: &J, t: i32) -> Option<String> {
    let mut buf = [0 as c_char; 256];
    let mut n = 0usize;
    unsafe { im_json_str(&j.j, t, buf.as_mut_ptr(), buf.len(), &mut n) }
        .then(|| String::from_utf8(buf[..n].iter().map(|&c| c as u8).collect()).unwrap())
}

fn u64_of(j: &J, t: i32) -> Option<u64> {
    let mut v = 0u64;
    unsafe { im_json_u64(&j.j, t, &mut v) }.then_some(v)
}

#[test]
fn json_requests() {
    let j = parse(r#" {"id": 42, "op":"publish_raw", "args": {"topic":"im/v1/x","payload_b64":"aGk=","qos":1,"retain":false, "nested": {"a":[1,2,{"b":null}]}}} "#).unwrap();
    assert_eq!(u64_of(&j, get(&j, 0, "id")), Some(42));
    assert_eq!(str_of(&j, get(&j, 0, "op")).as_deref(), Some("publish_raw"));
    let args = get(&j, 0, "args");
    assert_eq!(str_of(&j, get(&j, args, "topic")).as_deref(), Some("im/v1/x"));
    let mut b = true;
    assert!(unsafe { im_json_bool(&j.j, get(&j, args, "retain"), &mut b) } && !b);
    assert_eq!(get(&j, args, "missing"), -1);
    assert_eq!(get(&j, 0, "nested"), -1, "lookup is not recursive");
    // u64 bounds
    let j = parse(r#"{"a":18446744073709551615,"b":18446744073709551616,"c":-1,"d":1.5,"e":1e3}"#).unwrap();
    assert_eq!(u64_of(&j, get(&j, 0, "a")), Some(u64::MAX));
    for k in ["b", "c", "d", "e"] {
        assert_eq!(u64_of(&j, get(&j, 0, k)), None, "{k}");
    }
    // escapes and unicode, including a surrogate pair
    let j = parse(r#"{"s":"a\"b\\c\/d\n\t\u00e9\u6c34\ud83d\ude00"}"#).unwrap();
    assert_eq!(str_of(&j, get(&j, 0, "s")).as_deref(), Some("a\"b\\c/d\n\t\u{e9}\u{6c34}\u{1f600}"));
    let j = parse(r#"{"s":"\u0000"}"#).unwrap();
    assert_eq!(str_of(&j, get(&j, 0, "s")), None, "NUL cannot be returned as a C string");
}

#[test]
fn json_rejections() {
    let bad = [
        "",
        "{",
        "}",
        "{\"a\":1,}",
        "[1,]",
        "{\"a\" 1}",
        "{a:1}",
        "01",
        "-",
        "1.",
        "1e",
        "+1",
        "{\"a\":01}",
        "\"\\x\"",
        "\"\\u12G4\"",
        "\"\\udc00\"",
        "\"\\ud800\"",
        "\"\\ud800\\u0041\"",
        "\"a\tb\"",
        "\"unterminated",
        "tru",
        "nulls",
        "{} {}",
        "[[[[[[[[[1]]]]]]]]]",
        "{\"a\":1}x",
    ];
    for b in bad {
        assert!(parse(b).is_err(), "should reject {b:?}");
    }
    // depth counts every value (like CBOR): 7 nested arrays + scalar = 8 is the limit
    assert!(parse("[[[[[[[1]]]]]]]").is_ok());
    assert!(parse("[[[[[[[[1]]]]]]]]").is_err());
    assert_eq!(parse_with("[1,2,3,4]", 4).err(), Some("JSON"), "token budget");
    // invalid UTF-8 in the line
    let src = [b'"', 0xC3, 0x28, b'"'];
    let mut toks = vec![im_json_tok_t::default(); 4];
    let mut j = im_json_t {
        js: std::ptr::null(),
        len: 0,
        tok: std::ptr::null_mut(),
        ntok: 0,
    };
    assert_eq!(
        err_name(unsafe { im_json_parse(&mut j, src.as_ptr().cast(), 4, toks.as_mut_ptr(), 4) }),
        "JSON"
    );
}

#[test]
fn json_writer_escapes_and_nests() {
    let mut buf = vec![0 as c_char; 256];
    let mut w: im_json_w_t = unsafe { core::mem::zeroed() };
    let mut n = 0usize;
    unsafe {
        im_jw_init(&mut w, buf.as_mut_ptr(), buf.len());
        im_jw_obj(&mut w);
        im_jw_key(&mut w, c"s".as_ptr());
        let s = "q\"\\\n\u{1}é";
        im_jw_str(&mut w, s.as_ptr().cast(), s.len());
        im_jw_key(&mut w, c"a".as_ptr());
        im_jw_arr(&mut w);
        im_jw_u64(&mut w, u64::MAX);
        im_jw_i64(&mut w, i64::MIN);
        im_jw_bool(&mut w, true);
        im_jw_null(&mut w);
        im_jw_hex(&mut w, [0xde, 0xad].as_ptr(), 2);
        im_jw_arr_end(&mut w);
        im_jw_obj_end(&mut w);
        assert_eq!(im_jw_finish(&mut w, &mut n), IM_OK);
    }
    let out: String = buf[..n].iter().map(|&c| c as u8 as char).collect::<String>();
    let out = String::from_utf8(out.chars().map(|c| c as u8).collect()).unwrap();
    assert_eq!(
        out,
        "{\"s\":\"q\\\"\\\\\\n\\u0001é\",\"a\":[18446744073709551615,-9223372036854775808,true,null,\"dead\"]}"
    );
    // round trip through the parser
    let j = parse(&out).unwrap();
    assert_eq!(str_of(&j, get(&j, 0, "s")).as_deref(), Some("q\"\\\n\u{1}é"));
    // overflow is reported, never truncated silently
    let mut small = vec![0 as c_char; 8];
    unsafe {
        im_jw_init(&mut w, small.as_mut_ptr(), small.len());
        im_jw_obj(&mut w);
        im_jw_key(&mut w, c"long_key".as_ptr());
        im_jw_u64(&mut w, 1);
        im_jw_obj_end(&mut w);
        assert_eq!(err_name(im_jw_finish(&mut w, &mut n)), "BUFFER");
    }
}

#[test]
fn base64_strict() {
    for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", &[0u8, 255, 128, 7][..]] {
        let mut enc = vec![0 as c_char; 64];
        let mut n = 0usize;
        assert_eq!(
            unsafe { im_b64_encode(data.as_ptr(), data.len(), enc.as_mut_ptr(), enc.len(), &mut n) },
            IM_OK
        );
        let mut dec = vec![0u8; 64];
        let mut m = 0usize;
        assert_eq!(
            unsafe { im_b64_decode(enc.as_ptr(), n, dec.as_mut_ptr(), dec.len(), &mut m) },
            IM_OK
        );
        assert_eq!(&dec[..m], data);
    }
    let mut out = [0u8; 16];
    let mut m = 0usize;
    for bad in ["Zm9", "Zm9v=", "Zg=a", "Zh==", "Zm=v", "Z===", "Zm9v\n", "Zm9!"] {
        assert_ne!(
            unsafe { im_b64_decode(bad.as_ptr().cast(), bad.len(), out.as_mut_ptr(), out.len(), &mut m) },
            IM_OK,
            "{bad}"
        );
    }
    assert_eq!(
        err_name(unsafe { im_b64_decode(c"Zm9vYmFy".as_ptr(), 8, out.as_mut_ptr(), 5, &mut m) }),
        "BUFFER"
    );
}

#[test]
fn command_idempotency_cache() {
    let mut c: im_cmd_cache_t = unsafe { core::mem::zeroed() };
    unsafe { im_cmd_cache_init(&mut c) };
    let key = "idem-1";
    let mut st = 0u8;
    let mut id = [0 as c_char; 37];
    assert_eq!(
        err_name(unsafe { im_cmd_cache_lookup(&mut c, key.as_ptr().cast(), key.len(), 1000, &mut st, id.as_mut_ptr()) }),
        "NOT_FOUND"
    );
    let cmd = c"123e4567-e89b-12d3-a456-426614174000";
    assert_eq!(
        unsafe { im_cmd_cache_store(&mut c, key.as_ptr().cast(), key.len(), cmd.as_ptr(), 2, 1100, 1000) },
        IM_OK
    );
    assert_eq!(
        unsafe { im_cmd_cache_lookup(&mut c, key.as_ptr().cast(), key.len(), 1050, &mut st, id.as_mut_ptr()) },
        IM_OK
    );
    assert_eq!(st, 2);
    // retained for IM_CMD_RETAIN_S (600 s) past expiry, then forgotten
    assert_eq!(
        unsafe { im_cmd_cache_lookup(&mut c, key.as_ptr().cast(), key.len(), 1700, &mut st, id.as_mut_ptr()) },
        IM_OK
    );
    assert_eq!(
        err_name(unsafe { im_cmd_cache_lookup(&mut c, key.as_ptr().cast(), key.len(), 1701, &mut st, id.as_mut_ptr()) }),
        "NOT_FOUND"
    );
    // LRU eviction when full keeps the most recently used keys
    for i in 0..20 {
        let k = format!("k{i}");
        unsafe { im_cmd_cache_store(&mut c, k.as_ptr().cast(), k.len(), cmd.as_ptr(), 0, 5000, 2000) };
    }
    let k = "k19";
    assert_eq!(
        unsafe { im_cmd_cache_lookup(&mut c, k.as_ptr().cast(), k.len(), 2000, &mut st, id.as_mut_ptr()) },
        IM_OK
    );
    let k = "k0";
    assert_ne!(
        unsafe { im_cmd_cache_lookup(&mut c, k.as_ptr().cast(), k.len(), 2000, &mut st, id.as_mut_ptr()) },
        IM_OK
    );
}

unsafe extern "C" fn persist_fail(_ctx: *mut core::ffi::c_void, _e: *const im_replay_entry_t) -> i32 {
    IM_ERR_STORAGE
}

#[test]
fn replay_store_fail_closed() {
    let mut s: Box<im_replay_mem_t> = Box::new(unsafe { core::mem::zeroed() });
    unsafe { im_replay_mem_init(&mut *s) };
    let mut st: im_replay_store_t = unsafe { core::mem::zeroed() };
    unsafe { im_replay_mem_store(&mut *s, &mut st) };
    let cb = st.check_and_record.unwrap();
    // 8 distinct senders fill the table; a 9th is refused rather than evicting a window
    for i in 0..8u8 {
        assert_eq!(unsafe { cb(st.ctx, [i + 1].as_ptr(), 1, 0, 5) }, IM_OK);
    }
    assert_eq!(err_name(unsafe { cb(st.ctx, [99u8].as_ptr(), 1, 0, 5) }), "FULL");
    assert_eq!(err_name(unsafe { cb(st.ctx, [1u8].as_ptr(), 1, 0, 5) }), "ENV_REPLAY");
    assert_eq!(
        unsafe { cb(st.ctx, [1u8].as_ptr(), 1, 1, 5) },
        IM_ERR_FULL,
        "direction is part of the key"
    );
    assert_eq!(unsafe { cb(st.ctx, [1u8].as_ptr(), 1, 0, 6) }, IM_OK);
    // a failing durability hook rejects the message and leaves the window unchanged
    s.persist = Some(persist_fail);
    assert_eq!(err_name(unsafe { cb(st.ctx, [1u8].as_ptr(), 1, 0, 7) }), "STORAGE");
    let mut last = 0u64;
    assert!(unsafe { im_replay_mem_last(&*s, [1u8].as_ptr(), 1, 0, &mut last) });
    assert_eq!(last, 6);
}

// ---- endpoint policy (T-29 EST pinning, T-60 artifact host allowlist) -------------------------

fn pins_select(bundle: &[[u8; 32]], factory: &[[u8; 32]], cap: usize) -> Result<Vec<[u8; 32]>, &'static str> {
    let b: Vec<u8> = bundle.iter().flatten().copied().collect();
    let f: Vec<u8> = factory.iter().flatten().copied().collect();
    let mut out = vec![0u8; cap.max(1) * IM_PIN_LEN];
    let mut n = 0usize;
    let r = unsafe {
        im_est_pins_select(
            if b.is_empty() { std::ptr::null() } else { b.as_ptr() },
            bundle.len(),
            if f.is_empty() { std::ptr::null() } else { f.as_ptr() },
            factory.len(),
            out.as_mut_ptr(),
            cap,
            &mut n,
        )
    };
    if r != IM_OK {
        return Err(err_name(r));
    }
    Ok(out[..n * IM_PIN_LEN].chunks(IM_PIN_LEN).map(|c| c.try_into().unwrap()).collect())
}

#[test]
fn est_pins_bundle_first_then_factory_never_none() {
    let (b1, b2, f1) = ([1u8; 32], [2u8; 32], [9u8; 32]);
    assert_eq!(pins_select(&[b1, b2], &[f1], 4).unwrap(), vec![b1, b2]);
    assert_eq!(pins_select(&[], &[f1], 4).unwrap(), vec![f1]);
    assert_eq!(pins_select(&[b1, b2], &[], 1).unwrap(), vec![b1], "truncated to cap");
    assert_eq!(pins_select(&[], &[], 4).unwrap_err(), "NOT_FOUND");
    assert_eq!(pins_select(&[b1], &[f1], 0).unwrap_err(), "ARG");
}

#[test]
fn pin_match_is_exact() {
    let pins: Vec<u8> = [[1u8; 32], [2u8; 32]].iter().flatten().copied().collect();
    assert!(unsafe { im_pin_match([2u8; 32].as_ptr(), pins.as_ptr(), 2) });
    let mut near = [2u8; 32];
    near[31] = 3;
    assert!(!unsafe { im_pin_match(near.as_ptr(), pins.as_ptr(), 2) });
    assert!(!unsafe { im_pin_match([2u8; 32].as_ptr(), pins.as_ptr(), 1) });
    assert!(!unsafe { im_pin_match([2u8; 32].as_ptr(), std::ptr::null(), 2) });
}

fn url_host(url: &str) -> Option<String> {
    let mut host: *const c_char = std::ptr::null();
    let mut n = 0usize;
    let r = unsafe { im_url_https_host(url.as_ptr().cast(), url.len(), &mut host, &mut n) };
    (r == IM_OK).then(|| String::from_utf8(unsafe { std::slice::from_raw_parts(host.cast::<u8>(), n) }.to_vec()).unwrap())
}

#[test]
fn https_url_host_parsing() {
    assert_eq!(url_host("https://ota.example/fw.bin").as_deref(), Some("ota.example"));
    assert_eq!(url_host("https://ota.example").as_deref(), Some("ota.example"));
    assert_eq!(url_host("https://ota.example:8443/a?b#c").as_deref(), Some("ota.example"));
    assert_eq!(url_host("https://ota.example?x").as_deref(), Some("ota.example"));
    assert_eq!(url_host("https://[2001:db8::1]:443/x").as_deref(), Some("2001:db8::1"));
    for bad in [
        "http://ota.example/x",
        "HTTPS://ota.example/x",
        "https://",
        "https:///x",
        "https://:443/x",
        "https://user@ota.example/x",
        "https://ota.example:/x",
        "https://ota.example:0/x",
        "https://ota.example:65536/x",
        "https://ota.example:123456/x",
        "https://ota.example:44a/x",
        "https://ota example/x",
        "https://ota.example\0.evil/x",
        "https://[]/x",
        "https://[::1/x",
        "https://[::1]x/x",
        "https://ota\\evil/x",
    ] {
        assert_eq!(url_host(bad), None, "{bad:?}");
    }
}

#[test]
fn host_allowlist_is_exact_and_case_insensitive() {
    let names = [CString::new("OTA.example").unwrap(), CString::new("").unwrap()];
    let list = [names[0].as_ptr(), names[1].as_ptr(), std::ptr::null()];
    let allowed = |h: &str| unsafe { im_host_allowed(h.as_ptr().cast(), h.len(), list.as_ptr(), list.len()) };
    assert!(allowed("ota.example"));
    assert!(allowed("Ota.Example"));
    assert!(!allowed("ota.example.evil"));
    assert!(!allowed("xota.example"));
    assert!(!allowed("ota.exampl"));
    assert!(!allowed(""), "an empty host never matches the empty entry");
    assert!(
        !unsafe { im_host_allowed("ota.example".as_ptr().cast(), 11, list.as_ptr(), 0) },
        "empty list allows nothing"
    );
}
