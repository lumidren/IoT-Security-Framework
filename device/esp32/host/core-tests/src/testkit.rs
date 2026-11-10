//! Test material builders shared by the integration tests, the DUT shim's simulated cloud and
//! the fuzz seed generator: signed manifests, tenant-signed downlink envelopes, IMDELTA1 patches.

use crate::err::*;
use crate::ffi::*;
use crate::EdSigner;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::ptr;

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// Description of a manifest to build.
pub struct ManifestSpec<'a> {
    pub product: &'a str,
    pub version: &'a str,
    pub version_code: u64,
    pub min_version_code: u64,
    pub image: &'a [u8],
    /// (base image hash, patch bytes) for delta manifests
    pub delta: Option<([u8; 32], &'a [u8])>,
}

/// Canonical manifest + COSE_Sign (Ed25519 only) built with the C encoders.
pub fn signed_manifest(spec: &ManifestSpec, signer: &EdSigner) -> Vec<u8> {
    let image_sha = sha256(spec.image);
    let kid_id = CString::new("fw-signing-test").unwrap();
    let (base, patch_sha, patch_len) = match spec.delta {
        Some((b, p)) => (b, sha256(p), p.len() as u64),
        None => ([0u8; 32], [0u8; 32], 0),
    };
    let m = im_manifest_t {
        product: spec.product.as_ptr().cast(),
        product_len: spec.product.len(),
        version: spec.version.as_ptr().cast(),
        version_len: spec.version.len(),
        version_code: spec.version_code,
        image_sha256: image_sha.as_ptr(),
        image_size: spec.image.len() as u64,
        created_at: 1_767_139_200,
        min_version_code: spec.min_version_code,
        has_delta: spec.delta.is_some(),
        delta_base_sha256: base.as_ptr(),
        delta_patch_sha256: patch_sha.as_ptr(),
        delta_patch_size: patch_len,
        signing_key_id: kid_id.as_ptr(),
        signing_key_id_len: 15,
    };
    let mut payload = vec![0u8; 512];
    let mut n = 0usize;
    assert_eq!(
        unsafe { im_manifest_encode(&m, payload.as_mut_ptr(), payload.len(), &mut n) },
        IM_OK
    );
    payload.truncate(n);
    let mut kid = [0u8; 8];
    let pk = signer.public();
    unsafe { im_cose_key_id(pk.as_ptr(), 32, kid.as_mut_ptr()) };
    let s = signer.ffi();
    let mut out = vec![0u8; 1024];
    let mut work = vec![0u8; 1024];
    let r = unsafe {
        im_cose_sign_encode_ed25519(
            &s,
            kid.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            work.as_mut_ptr(),
            work.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut n,
        )
    };
    assert_eq!(r, IM_OK);
    out.truncate(n);
    out
}

/// Tenant-signed downlink envelope (Ed25519, kid tenant-cmd-<tenant>) around a body produced by
/// `body` (writes into the C encoder).
pub fn tenant_envelope(
    signer: &EdSigner,
    tenant: &str,
    seq: u64,
    ts: u64,
    msg_type: u8,
    nonce: Option<&[u8; 16]>,
    body: impl FnOnce(*mut im_cbor_enc_t),
) -> Vec<u8> {
    let mut buf = vec![0u8; 8192];
    let mut e = im_cbor_enc_t {
        buf: ptr::null_mut(),
        cap: 0,
        len: 0,
        err: 0,
    };
    unsafe { im_cbor_enc_init(&mut e, buf.as_mut_ptr(), buf.len()) };
    let mut n = 0usize;
    unsafe { im_env_payload_begin(&mut e, seq, ts, msg_type, nonce.is_some()) };
    body(&mut e);
    let r = unsafe { im_env_payload_end(&mut e, nonce.map_or(ptr::null(), |x| x.as_ptr()), &mut n) };
    assert_eq!(r, IM_OK, "payload: {}", crate::err_name(r));
    buf.truncate(n);
    let kid = format!("tenant-cmd-{tenant}");
    let s = signer.ffi();
    let mut out = vec![0u8; 8192 + 256];
    let mut work = vec![0u8; 8192 + 256];
    let r = unsafe {
        im_cose_sign1_encode(
            &s,
            kid.as_ptr(),
            kid.len(),
            true,
            buf.as_ptr(),
            buf.len(),
            work.as_mut_ptr(),
            work.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut n,
        )
    };
    assert_eq!(r, IM_OK);
    out.truncate(n);
    out
}

/// IMDELTA1 reference encoder (DELTA_FORMAT.md §5).
pub fn make_delta(old: &[u8], new: &[u8]) -> Vec<u8> {
    const B: usize = 4096;
    let mut index = std::collections::HashMap::new();
    for i in 0..old.len() / B {
        index.entry(sha256(&old[i * B..(i + 1) * B])).or_insert(i);
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"IMDELTA1");
    out.extend_from_slice(&(B as u32).to_be_bytes());
    out.extend_from_slice(&(old.len() as u64).to_be_bytes());
    out.extend_from_slice(&sha256(old));
    out.extend_from_slice(&sha256(new));
    out.extend_from_slice(&(new.len() as u64).to_be_bytes());
    for chunk in new.chunks(B) {
        let hit = if chunk.len() == B {
            index.get(&sha256(chunk)).copied()
        } else {
            None
        };
        match hit {
            Some(i) if &old[i * B..(i + 1) * B] == chunk => {
                out.push(1);
                out.extend_from_slice(&(i as u32).to_be_bytes());
            }
            _ => {
                out.push(2);
                out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                out.extend_from_slice(chunk);
            }
        }
    }
    out.push(3);
    out
}

/// Encode a COSE_Sign1 trust bundle (contract §3 step 6) signed by the PKI bundle key.
pub fn bundle(signer: &EdSigner, tenant_pub: &[u8; 32], fw_keys: &[&[u8]], host: &str, port: u16, pins: &[[u8; 32]]) -> Vec<u8> {
    let mut buf = vec![0u8; 8192];
    let mut e = im_cbor_enc_t {
        buf: ptr::null_mut(),
        cap: 0,
        len: 0,
        err: 0,
    };
    unsafe {
        im_cbor_enc_init(&mut e, buf.as_mut_ptr(), buf.len());
        im_cbor_enc_map(&mut e, 5);
        im_cbor_enc_uint(&mut e, 1);
        im_cbor_enc_bstr(&mut e, tenant_pub.as_ptr(), 32);
        im_cbor_enc_uint(&mut e, 2);
        im_cbor_enc_array(&mut e, fw_keys.len() as u64);
        for k in fw_keys {
            im_cbor_enc_bstr(&mut e, k.as_ptr(), k.len());
        }
        im_cbor_enc_uint(&mut e, 3);
        im_cbor_enc_tstr(&mut e, host.as_ptr().cast(), host.len());
        im_cbor_enc_uint(&mut e, 4);
        im_cbor_enc_uint(&mut e, port as u64);
        im_cbor_enc_uint(&mut e, 5);
        im_cbor_enc_array(&mut e, pins.len() as u64);
        for p in pins {
            im_cbor_enc_bstr(&mut e, p.as_ptr(), 32);
        }
    }
    let mut n = 0;
    assert_eq!(unsafe { im_cbor_enc_finish(&e, &mut n) }, IM_OK);
    buf.truncate(n);
    let s = signer.ffi();
    let mut out = vec![0u8; 9000];
    let mut work = vec![0u8; 9000];
    let kid = b"pki-bundle";
    let r = unsafe {
        im_cose_sign1_encode(
            &s,
            kid.as_ptr(),
            kid.len(),
            false,
            buf.as_ptr(),
            buf.len(),
            work.as_mut_ptr(),
            work.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut n,
        )
    };
    assert_eq!(r, IM_OK);
    out.truncate(n);
    out
}

/// Sender side of the Config key wrap (WIRE_FORMAT.md §5) for tests and the simulated cloud:
/// HPKE base mode to the device's current certificate key, then AES-256-GCM, as COSE_Encrypt0.
pub fn wrap_config(device_pub: &[u8; 65], plaintext: &[u8]) -> Vec<u8> {
    use crate::crypto::{im_crypto_aes_gcm_encrypt, im_crypto_random};
    use hkdf::Hkdf;
    use p256::elliptic_curve::sec1::ToSec1Point;
    // ephemeral key and DH
    let sk_e = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
    let enc_pt = sk_e.public_key().to_sec1_point(false);
    let mut enc = [0u8; 65];
    enc.copy_from_slice(enc_pt.as_bytes());
    let pk_r = p256::PublicKey::from_sec1_bytes(device_pub).expect("device key");
    let dh = p256::ecdh::diffie_hellman(sk_e.to_nonzero_scalar(), pk_r.as_affine());
    // ExtractAndExpand with the KEM suite id
    let suite = b"KEM\x00\x10";
    let mut ikm = b"HPKE-v1".to_vec();
    ikm.extend_from_slice(suite);
    ikm.extend_from_slice(b"eae_prk");
    ikm.extend_from_slice(dh.raw_secret_bytes());
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&[]), &ikm);
    let mut info = 32u16.to_be_bytes().to_vec();
    info.extend_from_slice(b"HPKE-v1");
    info.extend_from_slice(suite);
    info.extend_from_slice(b"shared_secret");
    info.extend_from_slice(&enc);
    info.extend_from_slice(device_pub);
    let mut shared = [0u8; 32];
    Hkdf::<Sha256>::from_prk(&prk).unwrap().expand(&info, &mut shared).unwrap();
    // C key schedule + seal of the CEK
    let mut ctx = im_hpke_ctx_t::default();
    let hinfo = b"ironmesh-config-cek-v1";
    assert_eq!(
        unsafe { im_hpke_key_schedule(shared.as_ptr(), hinfo.as_ptr(), hinfo.len(), &mut ctx) },
        IM_OK
    );
    let mut cek = [0u8; 32];
    let mut iv = [0u8; 12];
    unsafe {
        im_crypto_random(cek.as_mut_ptr(), 32);
        im_crypto_random(iv.as_mut_ptr(), 12);
    }
    let aad = [
        0x83u8, 0x68, b'E', b'n', b'c', b'r', b'y', b'p', b't', b'0', 0x43, 0xa1, 0x01, 0x03, 0x40,
    ];
    let mut wrapped = [0u8; 48];
    assert_eq!(
        unsafe { im_hpke_seal(&mut ctx, aad.as_ptr(), aad.len(), cek.as_ptr(), 32, wrapped.as_mut_ptr()) },
        IM_OK
    );
    let mut ct = vec![0u8; plaintext.len() + 16];
    let (body, tag) = ct.split_at_mut(plaintext.len());
    assert_eq!(
        unsafe {
            im_crypto_aes_gcm_encrypt(
                cek.as_ptr(),
                32,
                iv.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                body.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        },
        IM_OK
    );
    let mut out = vec![0u8; ct.len() + 256];
    let mut n = 0usize;
    assert_eq!(
        unsafe {
            im_cose_encrypt0_encode(
                iv.as_ptr(),
                enc.as_ptr(),
                wrapped.as_ptr(),
                ct.as_ptr(),
                ct.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut n,
            )
        },
        IM_OK
    );
    out.truncate(n);
    out
}
