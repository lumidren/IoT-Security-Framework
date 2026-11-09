//! Shared helpers for the integration tests.
#![allow(dead_code)]

use im_host::ffi::*;
use serde_json::Value;
use std::path::PathBuf;

pub fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../common/vectors")
}

pub fn load(name: &str) -> Value {
    let p = vectors_dir().join(name);
    let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    serde_json::from_str(&s).expect("json")
}

pub fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}

pub fn s(v: &Value) -> &str {
    v.as_str().expect("string")
}

pub fn u(v: &Value) -> u64 {
    v.as_u64().expect("u64")
}

pub fn name(code: i32) -> &'static str {
    im_host::err_name(code)
}

/// Minimal canonical CBOR encoder for JSON values (an independent oracle for app maps).
pub fn cbor_json(v: &Value) -> Vec<u8> {
    fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
        let mt = major << 5;
        if arg < 24 {
            out.push(mt | arg as u8);
        } else if arg <= 0xff {
            out.push(mt | 24);
            out.push(arg as u8);
        } else if arg <= 0xffff {
            out.push(mt | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        } else if arg <= 0xffff_ffff {
            out.push(mt | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        } else {
            out.push(mt | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
    fn enc(out: &mut Vec<u8>, v: &Value) {
        match v {
            Value::Null => out.push(0xf6),
            Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
            Value::Number(n) => {
                if let Some(x) = n.as_u64() {
                    head(out, 0, x);
                } else if let Some(x) = n.as_i64() {
                    head(out, 1, (-1 - x) as u64);
                } else {
                    panic!("floats not needed in app maps here");
                }
            }
            Value::String(t) => {
                head(out, 3, t.len() as u64);
                out.extend_from_slice(t.as_bytes());
            }
            Value::Array(a) => {
                head(out, 4, a.len() as u64);
                for x in a {
                    enc(out, x);
                }
            }
            Value::Object(m) => {
                let mut entries: Vec<(Vec<u8>, Vec<u8>)> = m
                    .iter()
                    .map(|(k, x)| {
                        let mut kb = Vec::new();
                        enc(&mut kb, &Value::String(k.clone()));
                        let mut vb = Vec::new();
                        enc(&mut vb, x);
                        (kb, vb)
                    })
                    .collect();
                entries.sort();
                head(out, 5, entries.len() as u64);
                for (k, x) in entries {
                    out.extend(k);
                    out.extend(x);
                }
            }
        }
    }
    let mut out = Vec::new();
    enc(&mut out, v);
    out
}

/// Encoder over a Vec-backed buffer.
pub struct Enc {
    pub buf: Vec<u8>,
    pub e: im_cbor_enc_t,
}

impl Enc {
    pub fn new(cap: usize) -> Box<Self> {
        let mut b = Box::new(Self {
            buf: vec![0u8; cap],
            e: im_cbor_enc_t {
                buf: core::ptr::null_mut(),
                cap: 0,
                len: 0,
                err: 0,
            },
        });
        let p = b.buf.as_mut_ptr();
        unsafe { im_cbor_enc_init(&mut b.e, p, cap) };
        b
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.buf[..self.e.len].to_vec()
    }
}

pub fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).unwrap()
}
