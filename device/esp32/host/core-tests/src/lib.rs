//! Host build of the IronMesh ESP32 protocol core.
//!
//! * `build.rs` compiles `components/im_core/*.c` (MSVC `/W4 /WX /sdl`).
//! * [`crypto`] implements the `im_crypto.h` provider with RustCrypto (the ESP32 uses mbedTLS +
//!   libsodium, `components/im_platform_esp/im_crypto_mbedtls.c`).
//! * [`ffi`] declares the C API; this module adds small safe helpers used by the tests, the
//!   fuzz targets and the DUT shim: a software P-256 identity, an Ed25519 signer and a static key
//!   resolver.

pub mod crypto;
pub mod ffi;
pub mod ffi2;
pub mod mldsa;
pub mod sim;
pub mod testkit;

/// Error codes generated from `im_err.h` (`IM_OK`, `IM_ERR_*`, `ERR_NAMES`).
pub mod err {
    include!(concat!(env!("OUT_DIR"), "/err_codes.rs"));
}

use core::ffi::c_void;
use ffi::*;
use std::collections::HashMap;
use std::ffi::CString;

/// Stable name of a C error code (`"OK"`, `"CBOR_TRUNCATED"`, ...).
pub fn err_name(code: i32) -> &'static str {
    usize::try_from(code)
        .ok()
        .and_then(|i| err::ERR_NAMES.get(i))
        .copied()
        .unwrap_or("UNKNOWN")
}

/// Convert a C result into `Result<(), &'static str>`.
pub fn check(code: i32) -> Result<(), &'static str> {
    if code == err::IM_OK {
        Ok(())
    } else {
        Err(err_name(code))
    }
}

/// A software P-256 device identity implementing `im_identity_t` (the host stand-in for the
/// ATECC608 / encrypted-NVS key stores).
pub struct SoftIdentity {
    sk: p256::SecretKey,
    se_type: CString,
}

impl SoftIdentity {
    /// Identity from a 32-byte big-endian private scalar.
    pub fn from_scalar(scalar: &[u8]) -> Box<Self> {
        let sk = p256::SecretKey::from_slice(scalar).expect("valid P-256 scalar");
        Box::new(Self {
            sk,
            se_type: CString::new("software").unwrap(),
        })
    }

    /// Fresh random identity (a "new key generated in the secure element").
    pub fn random() -> Box<Self> {
        let sk = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        Box::new(Self {
            sk,
            se_type: CString::new("software").unwrap(),
        })
    }

    /// Uncompressed 65-byte public key.
    pub fn public_raw(&self) -> [u8; 65] {
        use p256::elliptic_curve::sec1::ToSec1Point;
        let pt = self.sk.public_key().to_sec1_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(pt.as_bytes());
        out
    }

    /// PKCS#8-free raw private scalar (tests and the shim's simulated secure storage only).
    pub fn scalar(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.sk.to_bytes());
        out
    }

    /// Borrow as the C identity vtable. `self` must stay pinned in its `Box` while used.
    pub fn ffi(&self) -> im_identity_t {
        im_identity_t {
            ctx: self as *const Self as *mut c_void,
            get_pubkey: Some(id_get_pubkey),
            sign_digest: Some(id_sign_digest),
            ecdh: Some(id_ecdh),
            se_type: self.se_type.as_ptr(),
        }
    }

    /// The P-256 secret key (used by the shim to build CSRs and TLS client auth).
    pub fn secret(&self) -> &p256::SecretKey {
        &self.sk
    }
}

unsafe extern "C" fn id_get_pubkey(ctx: *mut c_void, out: *mut u8) -> i32 {
    let s = &*(ctx as *const SoftIdentity);
    core::slice::from_raw_parts_mut(out, 65).copy_from_slice(&s.public_raw());
    err::IM_OK
}

unsafe extern "C" fn id_sign_digest(ctx: *mut c_void, digest: *const u8, sig: *mut u8) -> i32 {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let s = &*(ctx as *const SoftIdentity);
    let key = p256::ecdsa::SigningKey::from(&s.sk);
    let d = core::slice::from_raw_parts(digest, 32);
    let r: Result<p256::ecdsa::Signature, _> = key.sign_prehash(d);
    match r {
        Ok(sg) => {
            core::slice::from_raw_parts_mut(sig, 64).copy_from_slice(&sg.to_bytes());
            err::IM_OK
        }
        Err(_) => err::IM_ERR_CRYPTO,
    }
}

unsafe extern "C" fn id_ecdh(ctx: *mut c_void, peer: *const u8, shared: *mut u8) -> i32 {
    let s = &*(ctx as *const SoftIdentity);
    let Ok(pk) = p256::PublicKey::from_sec1_bytes(core::slice::from_raw_parts(peer, 65)) else {
        return err::IM_ERR_CRYPTO;
    };
    let ss = p256::ecdh::diffie_hellman(s.sk.to_nonzero_scalar(), pk.as_affine());
    core::slice::from_raw_parts_mut(shared, 32).copy_from_slice(ss.raw_secret_bytes());
    err::IM_OK
}

/// Ed25519 signer usable as an `im_signer_t` (tenant / firmware keys in tests).
pub struct EdSigner {
    pub key: ed25519_dalek::SigningKey,
}

impl EdSigner {
    pub fn from_seed(seed: &[u8]) -> Box<Self> {
        let mut s = [0u8; 32];
        s.copy_from_slice(seed);
        Box::new(Self {
            key: ed25519_dalek::SigningKey::from_bytes(&s),
        })
    }

    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn ffi(&self) -> im_signer_t {
        im_signer_t {
            alg: -8,
            sign: Some(ed_sign),
            ctx: self as *const Self as *mut c_void,
        }
    }
}

unsafe extern "C" fn ed_sign(ctx: *mut c_void, data: *const u8, len: usize, sig: *mut u8) -> i32 {
    use ed25519_dalek::Signer;
    let s = &*(ctx as *const EdSigner);
    let sg = s.key.sign(crypto::cslice(data, len));
    core::slice::from_raw_parts_mut(sig, 64).copy_from_slice(&sg.to_bytes());
    err::IM_OK
}

/// A kid -> public key map implementing `im_key_resolver_t`.
#[derive(Default)]
pub struct StaticResolver {
    keys: HashMap<(Vec<u8>, bool), im_pubkey_t>,
}

impl StaticResolver {
    pub fn add_p256(&mut self, kid: &[u8], raw: &[u8]) {
        let mut k = im_pubkey_t::default();
        assert_eq!(unsafe { im_pubkey_p256(&mut k, raw.as_ptr(), raw.len()) }, err::IM_OK);
        self.keys.insert((kid.to_vec(), false), k);
    }

    pub fn add_ed25519(&mut self, kid: &str, raw: &[u8]) {
        let mut k = im_pubkey_t::default();
        assert_eq!(unsafe { im_pubkey_ed25519(&mut k, raw.as_ptr(), raw.len()) }, err::IM_OK);
        self.keys.insert((kid.as_bytes().to_vec(), true), k);
    }

    /// The resolver vtable; `self` must outlive its use.
    pub fn ffi(&self) -> im_key_resolver_t {
        im_key_resolver_t {
            resolve: Some(resolve_cb),
            ctx: self as *const Self as *mut c_void,
        }
    }
}

unsafe extern "C" fn resolve_cb(ctx: *mut c_void, kid: *const u8, kid_len: usize, kid_text: bool, out: *mut im_pubkey_t) -> i32 {
    let s = &*(ctx as *const StaticResolver);
    match s.keys.get(&(crypto::cslice(kid, kid_len).to_vec(), kid_text)) {
        Some(k) => {
            *out = *k;
            err::IM_OK
        }
        None => err::IM_ERR_NOT_FOUND,
    }
}

/// Owned, 8-byte aligned storage for an opaque C context of `size` bytes.
pub struct Opaque {
    buf: Vec<u64>,
}

impl Opaque {
    pub fn new(size: usize) -> Self {
        Self {
            buf: vec![0u64; size.div_ceil(8)],
        }
    }

    pub fn ptr(&mut self) -> *mut c_void {
        self.buf.as_mut_ptr().cast()
    }
}
