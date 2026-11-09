//! The `im_crypto.h` provider for the host build, implemented with RustCrypto.
//!
//! This is the host counterpart of `components/im_platform_esp/im_crypto_mbedtls.c`: the C core
//! calls these `extern "C"` functions for every primitive. Return values follow `im_crypto.h`:
//! `IM_OK`, `IM_ERR_COSE_SIGNATURE` for a failed verification, `IM_ERR_CRYPTO` otherwise.
//!
//! # Safety
//! Every `extern "C"` function here is called by the C core with the pointer/length contract
//! documented in `im_crypto.h` (non-NULL buffers of the stated sizes, valid for the call). They
//! are not meant to be called from Rust; the per-function `# Safety` sections are therefore this
//! module-level contract (justified `missing_safety_doc` allowance below).
#![allow(clippy::missing_safety_doc)]

use crate::err::*;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce, Tag};
use core::slice;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Mirror of `im_sha256_ctx_t` (256 bytes, 8-byte aligned).
#[repr(C, align(8))]
pub struct ImSha256Ctx {
    pub opaque: [u8; 256],
}

const _: () = assert!(core::mem::size_of::<Sha256>() <= 256);
const _: () = assert!(core::mem::align_of::<Sha256>() <= 8);

/// Build a slice from a C pointer/length pair, tolerating `NULL` for empty inputs.
///
/// # Safety
/// `p` must be valid for `n` bytes when `n > 0`.
pub unsafe fn cslice<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 || p.is_null() {
        &[]
    } else {
        slice::from_raw_parts(p, n)
    }
}

/// # Safety
/// `p` must be valid for writes of `n` bytes when `n > 0`.
pub unsafe fn cslice_mut<'a>(p: *mut u8, n: usize) -> &'a mut [u8] {
    if n == 0 || p.is_null() {
        &mut []
    } else {
        slice::from_raw_parts_mut(p, n)
    }
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_sha256_init(ctx: *mut ImSha256Ctx) -> i32 {
    if ctx.is_null() {
        return IM_ERR_ARG;
    }
    core::ptr::write(ctx.cast::<Sha256>(), Sha256::new());
    IM_OK
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_sha256_update(ctx: *mut ImSha256Ctx, data: *const u8, len: usize) -> i32 {
    if ctx.is_null() || (data.is_null() && len != 0) {
        return IM_ERR_ARG;
    }
    (*ctx.cast::<Sha256>()).update(cslice(data, len));
    IM_OK
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_sha256_finish(ctx: *mut ImSha256Ctx, out: *mut u8) -> i32 {
    if ctx.is_null() || out.is_null() {
        return IM_ERR_ARG;
    }
    let h = core::ptr::read(ctx.cast::<Sha256>());
    let d = h.finalize();
    cslice_mut(out, 32).copy_from_slice(&d);
    (*ctx).opaque = [0u8; 256];
    IM_OK
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_sha256_free(ctx: *mut ImSha256Ctx) {
    if !ctx.is_null() {
        (*ctx).opaque = [0u8; 256];
    }
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_hkdf_extract(salt: *const u8, salt_len: usize, ikm: *const u8, ikm_len: usize, prk: *mut u8) -> i32 {
    if prk.is_null() {
        return IM_ERR_ARG;
    }
    let salt = cslice(salt, salt_len);
    let (out, _) = hkdf::Hkdf::<Sha256>::extract(Some(salt), cslice(ikm, ikm_len));
    cslice_mut(prk, 32).copy_from_slice(&out);
    IM_OK
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_hkdf_expand(prk: *const u8, info: *const u8, info_len: usize, okm: *mut u8, okm_len: usize) -> i32 {
    if prk.is_null() || (okm.is_null() && okm_len != 0) {
        return IM_ERR_ARG;
    }
    let Ok(h) = hkdf::Hkdf::<Sha256>::from_prk(cslice(prk, 32)) else {
        return IM_ERR_CRYPTO;
    };
    match h.expand(cslice(info, info_len), cslice_mut(okm, okm_len)) {
        Ok(()) => IM_OK,
        Err(_) => IM_ERR_CRYPTO,
    }
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_ecdsa_p256_verify(pubkey: *const u8, digest: *const u8, sig: *const u8) -> i32 {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    if pubkey.is_null() || digest.is_null() || sig.is_null() {
        return IM_ERR_ARG;
    }
    let Ok(vk) = VerifyingKey::from_sec1_bytes(cslice(pubkey, 65)) else {
        return IM_ERR_COSE_SIGNATURE;
    };
    let Ok(s) = Signature::from_slice(cslice(sig, 64)) else {
        return IM_ERR_COSE_SIGNATURE;
    };
    match vk.verify_prehash(cslice(digest, 32), &s) {
        Ok(()) => IM_OK,
        Err(_) => IM_ERR_COSE_SIGNATURE,
    }
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_ed25519_verify(pubkey: *const u8, msg: *const u8, len: usize, sig: *const u8) -> i32 {
    if pubkey.is_null() || sig.is_null() || (msg.is_null() && len != 0) {
        return IM_ERR_ARG;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(cslice(pubkey, 32));
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else {
        return IM_ERR_COSE_SIGNATURE;
    };
    let mut s = [0u8; 64];
    s.copy_from_slice(cslice(sig, 64));
    let sig = ed25519_dalek::Signature::from_bytes(&s);
    // verify_strict matches libsodium's crypto_sign_verify_detached (rejects small-order keys
    // and non-canonical encodings), which is what the ESP32 build uses.
    match vk.verify_strict(cslice(msg, len), &sig) {
        Ok(()) => IM_OK,
        Err(_) => IM_ERR_COSE_SIGNATURE,
    }
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_mldsa65_verify(
    pubkey: *const u8,
    pub_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    crate::mldsa::verify(cslice(pubkey, pub_len), cslice(msg, msg_len), cslice(sig, sig_len))
}

unsafe fn gcm(encrypt: bool, key: &[u8], iv: &[u8], aad: &[u8], buf: &mut [u8], tag: *mut u8) -> i32 {
    let mut ivb = [0u8; 12];
    ivb.copy_from_slice(iv);
    let nonce = &Nonce::from(ivb);
    match key.len() {
        16 => {
            let c = Aes128Gcm::new_from_slice(key).expect("16-byte key");
            if encrypt {
                match c.encrypt_in_place_detached(nonce, aad, buf) {
                    Ok(t) => {
                        cslice_mut(tag, 16).copy_from_slice(&t);
                        IM_OK
                    }
                    Err(_) => IM_ERR_CRYPTO,
                }
            } else {
                let mut tb = [0u8; 16];
                tb.copy_from_slice(cslice(tag, 16));
                let t = Tag::from(tb);
                match c.decrypt_in_place_detached(nonce, aad, buf, &t) {
                    Ok(()) => IM_OK,
                    Err(_) => IM_ERR_CRYPTO,
                }
            }
        }
        32 => {
            let c = Aes256Gcm::new_from_slice(key).expect("32-byte key");
            if encrypt {
                match c.encrypt_in_place_detached(nonce, aad, buf) {
                    Ok(t) => {
                        cslice_mut(tag, 16).copy_from_slice(&t);
                        IM_OK
                    }
                    Err(_) => IM_ERR_CRYPTO,
                }
            } else {
                let mut tb = [0u8; 16];
                tb.copy_from_slice(cslice(tag, 16));
                let t = Tag::from(tb);
                match c.decrypt_in_place_detached(nonce, aad, buf, &t) {
                    Ok(()) => IM_OK,
                    Err(_) => IM_ERR_CRYPTO,
                }
            }
        }
        _ => IM_ERR_ARG,
    }
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_aes_gcm_encrypt(
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    aad: *const u8,
    aad_len: usize,
    input: *const u8,
    len: usize,
    out: *mut u8,
    tag: *mut u8,
) -> i32 {
    if key.is_null() || iv.is_null() || tag.is_null() || (len != 0 && (input.is_null() || out.is_null())) {
        return IM_ERR_ARG;
    }
    let mut buf = cslice(input, len).to_vec();
    let r = gcm(true, cslice(key, key_len), cslice(iv, 12), cslice(aad, aad_len), &mut buf, tag);
    if r == IM_OK {
        cslice_mut(out, len).copy_from_slice(&buf);
    }
    r
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_aes_gcm_decrypt(
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    aad: *const u8,
    aad_len: usize,
    input: *const u8,
    len: usize,
    tag: *const u8,
    out: *mut u8,
) -> i32 {
    if key.is_null() || iv.is_null() || tag.is_null() || (len != 0 && (input.is_null() || out.is_null())) {
        return IM_ERR_ARG;
    }
    let mut buf = cslice(input, len).to_vec();
    let r = gcm(
        false,
        cslice(key, key_len),
        cslice(iv, 12),
        cslice(aad, aad_len),
        &mut buf,
        tag as *mut u8,
    );
    if r == IM_OK {
        cslice_mut(out, len).copy_from_slice(&buf);
    }
    r
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_p256_point_check(pubkey: *const u8) -> i32 {
    if pubkey.is_null() {
        return IM_ERR_ARG;
    }
    let raw = cslice(pubkey, 65);
    if raw[0] != 0x04 {
        return IM_ERR_CRYPTO;
    }
    match p256::PublicKey::from_sec1_bytes(raw) {
        Ok(_) => IM_OK,
        Err(_) => IM_ERR_CRYPTO,
    }
}

#[no_mangle]
pub unsafe extern "C" fn im_crypto_random(out: *mut u8, len: usize) -> i32 {
    if out.is_null() && len != 0 {
        return IM_ERR_ARG;
    }
    OsRng.fill_bytes(cslice_mut(out, len));
    IM_OK
}

#[no_mangle]
pub extern "C" fn im_crypto_mldsa65_available() -> i32 {
    1
}
