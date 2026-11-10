//! HPKE (RFC 9180) base mode, DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, and the
//! IronMesh Config unwrap (`WIRE_FORMAT.md` §5).
//!
//! The recipient's Diffie-Hellman operation is abstracted ([`EcdhRecipient`]) so the private key
//! can stay inside a secure element (TPM `ECDH_ZGen`, OP-TEE TA) or a software key store.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::cbor::DecodeLimits;
use super::cose::{self, ENCRYPT0_PROTECTED};
use super::error::{err, ErrorCode as C, WireError, WireResult};

const KEM_ID: u16 = 0x0010;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0001;
const N_SECRET: usize = 32;
const N_SK: usize = 32;
const N_K: usize = 16;
const N_N: usize = 12;
const N_H: usize = 32;
/// HPKE `info` for the Config CEK.
pub const CONFIG_HPKE_INFO: &[u8] = b"ironmesh-config-cek-v1";
const CEK_SIZE: usize = 32;

fn kem_suite() -> Vec<u8> {
    let mut s = b"KEM".to_vec();
    s.extend_from_slice(&KEM_ID.to_be_bytes());
    s
}

fn hpke_suite() -> Vec<u8> {
    let mut s = b"HPKE".to_vec();
    s.extend_from_slice(&KEM_ID.to_be_bytes());
    s.extend_from_slice(&KDF_ID.to_be_bytes());
    s.extend_from_slice(&AEAD_ID.to_be_bytes());
    s
}

fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    Zeroizing::new(prk.into())
}

fn expand(prk: &[u8], info: &[u8], length: usize) -> WireResult<Zeroizing<Vec<u8>>> {
    if length > 255 * N_H {
        return Err(err(C::HpkeDerive, "HKDF-Expand length too large"));
    }
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| err(C::HpkeDerive, "PRK too short"))?;
    let mut out = Zeroizing::new(vec![0u8; length]);
    hk.expand(info, &mut out).map_err(|_| err(C::HpkeDerive, "HKDF-Expand failed"))?;
    Ok(out)
}

fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8], suite: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut input = Zeroizing::new(b"HPKE-v1".to_vec());
    input.extend_from_slice(suite);
    input.extend_from_slice(label);
    input.extend_from_slice(ikm);
    extract(salt, &input)
}

fn labeled_expand(prk: &[u8], label: &[u8], info: &[u8], length: usize, suite: &[u8]) -> WireResult<Zeroizing<Vec<u8>>> {
    let mut li = (length as u16).to_be_bytes().to_vec();
    li.extend_from_slice(b"HPKE-v1");
    li.extend_from_slice(suite);
    li.extend_from_slice(label);
    li.extend_from_slice(info);
    expand(prk, &li, length)
}

/// `DeriveKeyPair` for P-256 (RFC 9180 §7.1.3).
///
/// # Errors
/// `HPKE_DERIVE` if no valid scalar is found in 256 attempts.
pub fn derive_key_pair(ikm: &[u8]) -> WireResult<p256::SecretKey> {
    let suite = kem_suite();
    let prk = labeled_extract(b"", b"dkp_prk", ikm, &suite);
    for counter in 0u8..=255 {
        let candidate = labeled_expand(&prk[..], b"candidate", &[counter], N_SK, &suite)?;
        if let Ok(sk) = p256::SecretKey::from_slice(&candidate) {
            return Ok(sk);
        }
    }
    Err(err(C::HpkeDerive, "DeriveKeyPair failed after 256 attempts"))
}

fn deserialize_public_key(data: &[u8]) -> WireResult<p256::PublicKey> {
    if data.len() != 65 || data.first() != Some(&0x04) {
        return Err(err(C::HpkeKey, "public key must be a 65-byte uncompressed P-256 point"));
    }
    p256::PublicKey::from_sec1_bytes(data).map_err(|_| err(C::HpkeKey, "public key is not on the P-256 curve"))
}

fn serialize_public_key(pk: &p256::PublicKey) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    pk.to_sec1_point(false).as_bytes().to_vec()
}

fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> WireResult<Zeroizing<Vec<u8>>> {
    let suite = kem_suite();
    let prk = labeled_extract(b"", b"eae_prk", dh, &suite);
    labeled_expand(&prk[..], b"shared_secret", kem_context, N_SECRET, &suite)
}

/// The recipient side of DHKEM: performs `DH(skR, pkE)` without exposing `skR`.
pub trait EcdhRecipient {
    /// The recipient public key (65-byte uncompressed point).
    fn public_key_sec1(&self) -> Vec<u8>;
    /// The x-coordinate of `skR * peer`.
    ///
    /// # Errors
    /// `HPKE_KEY` on failure.
    fn ecdh(&self, peer: &p256::PublicKey) -> WireResult<Zeroizing<[u8; 32]>>;
}

impl EcdhRecipient for p256::SecretKey {
    fn public_key_sec1(&self) -> Vec<u8> {
        serialize_public_key(&self.public_key())
    }

    fn ecdh(&self, peer: &p256::PublicKey) -> WireResult<Zeroizing<[u8; 32]>> {
        let shared = p256::ecdh::diffie_hellman(self.to_nonzero_scalar(), peer.as_affine());
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(shared.raw_secret_bytes());
        Ok(out)
    }
}

/// `Encap(pkR)` with an optional fixed ephemeral `ikm_e`: returns `(shared_secret, enc)`.
///
/// # Errors
/// `HPKE_KEY` / `HPKE_DERIVE`.
pub fn encap(pk_r: &p256::PublicKey, ikm_e: Option<&[u8]>) -> WireResult<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let sk_e = match ikm_e {
        Some(ikm) => derive_key_pair(ikm)?,
        None => <p256::SecretKey as p256::elliptic_curve::Generate>::generate(),
    };
    let dh = sk_e.ecdh(pk_r)?;
    let enc = serialize_public_key(&sk_e.public_key());
    let mut kem_context = enc.clone();
    kem_context.extend_from_slice(&serialize_public_key(pk_r));
    Ok((extract_and_expand(&dh[..], &kem_context)?, enc))
}

/// `Decap(enc, skR)`.
///
/// # Errors
/// `HPKE_KEY`.
pub fn decap(enc: &[u8], recipient: &dyn EcdhRecipient) -> WireResult<Zeroizing<Vec<u8>>> {
    let pk_e = deserialize_public_key(enc)?;
    let dh = recipient.ecdh(&pk_e)?;
    let mut kem_context = enc.to_vec();
    kem_context.extend_from_slice(&recipient.public_key_sec1());
    extract_and_expand(&dh[..], &kem_context)
}

/// An HPKE context.
pub struct Context {
    key: Zeroizing<Vec<u8>>,
    base_nonce: Vec<u8>,
    exporter_secret: Zeroizing<Vec<u8>>,
    seq: u128,
}

impl Context {
    fn nonce(&self) -> WireResult<[u8; N_N]> {
        if self.seq >= (1u128 << (8 * N_N)) {
            return Err(err(C::HpkeSeq, "message limit reached"));
        }
        let seq = self.seq.to_be_bytes();
        let mut n = [0u8; N_N];
        for (i, b) in n.iter_mut().enumerate() {
            *b = self.base_nonce[i] ^ seq[16 - N_N + i];
        }
        Ok(n)
    }

    /// Set the sequence number (test vectors).
    pub fn set_seq(&mut self, seq: u128) {
        self.seq = seq;
    }

    /// AEAD key (test vectors).
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Base nonce (test vectors).
    #[must_use]
    pub fn base_nonce(&self) -> &[u8] {
        &self.base_nonce
    }

    /// Exporter secret (test vectors).
    #[must_use]
    pub fn exporter_secret(&self) -> &[u8] {
        &self.exporter_secret
    }

    /// `Seal`.
    ///
    /// # Errors
    /// `HPKE_SEQ` / `HPKE_OPEN`.
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> WireResult<Vec<u8>> {
        let nonce = self.nonce()?;
        let cipher = Aes128Gcm::new_from_slice(&self.key).map_err(|_| err(C::HpkeKey, "bad AEAD key"))?;
        let ct = cipher.encrypt(&nonce.into(), Payload { msg: pt, aad }).map_err(|_| err(C::HpkeOpen, "AEAD seal failed"))?;
        self.seq += 1;
        Ok(ct)
    }

    /// `Open`.
    ///
    /// # Errors
    /// `HPKE_OPEN` on authentication failure.
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> WireResult<Zeroizing<Vec<u8>>> {
        let nonce = self.nonce()?;
        let cipher = Aes128Gcm::new_from_slice(&self.key).map_err(|_| err(C::HpkeKey, "bad AEAD key"))?;
        let pt = cipher.decrypt(&nonce.into(), Payload { msg: ct, aad }).map_err(|_| err(C::HpkeOpen, "AEAD authentication failed"))?;
        self.seq += 1;
        Ok(Zeroizing::new(pt))
    }

    /// `Export`.
    ///
    /// # Errors
    /// `HPKE_DERIVE` for an oversized length.
    pub fn export(&self, exporter_context: &[u8], length: usize) -> WireResult<Zeroizing<Vec<u8>>> {
        labeled_expand(&self.exporter_secret, b"sec", exporter_context, length, &hpke_suite())
    }
}

/// `KeySchedule` (base mode).
///
/// # Errors
/// Never in practice.
pub fn key_schedule(shared_secret: &[u8], info: &[u8]) -> WireResult<Context> {
    let suite = hpke_suite();
    let psk_id_hash = labeled_extract(b"", b"psk_id_hash", b"", &suite);
    let info_hash = labeled_extract(b"", b"info_hash", info, &suite);
    let mut ksc = vec![0u8];
    ksc.extend_from_slice(&psk_id_hash[..]);
    ksc.extend_from_slice(&info_hash[..]);
    let secret = labeled_extract(shared_secret, b"secret", b"", &suite);
    Ok(Context {
        key: labeled_expand(&secret[..], b"key", &ksc, N_K, &suite)?,
        base_nonce: labeled_expand(&secret[..], b"base_nonce", &ksc, N_N, &suite)?.to_vec(),
        exporter_secret: labeled_expand(&secret[..], b"exp", &ksc, N_H, &suite)?,
        seq: 0,
    })
}

/// Key-schedule context bytes (test vectors).
#[must_use]
pub fn key_schedule_context(info: &[u8]) -> Vec<u8> {
    let suite = hpke_suite();
    let mut ksc = vec![0u8];
    ksc.extend_from_slice(&labeled_extract(b"", b"psk_id_hash", b"", &suite)[..]);
    ksc.extend_from_slice(&labeled_extract(b"", b"info_hash", info, &suite)[..]);
    ksc
}

/// `secret` of the key schedule (test vectors).
#[must_use]
pub fn key_schedule_secret(shared_secret: &[u8]) -> Vec<u8> {
    labeled_extract(shared_secret, b"secret", b"", &hpke_suite()).to_vec()
}

/// `SetupBaseS`.
///
/// # Errors
/// See [`encap`].
pub fn setup_base_s(pk_r: &p256::PublicKey, info: &[u8], ikm_e: Option<&[u8]>) -> WireResult<(Vec<u8>, Context)> {
    let (ss, enc) = encap(pk_r, ikm_e)?;
    Ok((enc, key_schedule(&ss, info)?))
}

/// `SetupBaseR`.
///
/// # Errors
/// See [`decap`].
pub fn setup_base_r(enc: &[u8], recipient: &dyn EcdhRecipient, info: &[u8]) -> WireResult<Context> {
    key_schedule(&decap(enc, recipient)?, info)
}

/// Encrypt a signed Config envelope for one device (`wrap_config`).
///
/// # Errors
/// `HPKE_KEY` for bad inputs.
pub fn wrap_config(
    plaintext: &[u8],
    device_public_key: &p256::PublicKey,
    cek: Option<&[u8]>,
    iv: Option<&[u8]>,
    ikm_e: Option<&[u8]>,
) -> WireResult<Vec<u8>> {
    use rand::RngCore;
    let mut content_key = Zeroizing::new([0u8; CEK_SIZE]);
    match cek {
        Some(c) if c.len() == CEK_SIZE => content_key.copy_from_slice(c),
        Some(_) => return Err(err(C::HpkeKey, "CEK must be 32 bytes")),
        None => rand::rngs::OsRng.fill_bytes(&mut content_key[..]),
    }
    let mut nonce = [0u8; cose::A256GCM_IV_SIZE];
    match iv {
        Some(v) if v.len() == nonce.len() => nonce.copy_from_slice(v),
        Some(_) => return Err(err(C::HpkeKey, "IV must be 12 bytes")),
        None => rand::rngs::OsRng.fill_bytes(&mut nonce),
    }
    let enc_structure = cose::enc_structure0(&ENCRYPT0_PROTECTED)?;
    let (enc, mut ctx) = setup_base_s(device_public_key, CONFIG_HPKE_INFO, ikm_e)?;
    let wrapped = ctx.seal(&enc_structure, &content_key[..])?;
    let cipher = Aes256Gcm::new_from_slice(&content_key[..]).map_err(|_| err(C::HpkeKey, "bad CEK"))?;
    let ciphertext = cipher
        .encrypt(&nonce.into(), Payload { msg: plaintext, aad: &enc_structure })
        .map_err(|_| err(C::CoseDecrypt, "content encryption failed"))?;
    cose::encrypt0_encode(&nonce, &enc, &wrapped, &ciphertext)
}

/// Decrypt a Config COSE_Encrypt0 (`unwrap_config`); returns the inner signed envelope.
///
/// # Errors
/// `COSE_*` structure errors, `HPKE_KEY`, `HPKE_OPEN`, `COSE_DECRYPT`.
pub fn unwrap_config(data: &[u8], recipient: &dyn EcdhRecipient, limits: DecodeLimits) -> WireResult<Zeroizing<Vec<u8>>> {
    let message = cose::encrypt0_decode(data, limits)?;
    let enc_structure = message.enc_structure()?;
    let mut ctx = setup_base_r(&message.enc, recipient, CONFIG_HPKE_INFO)?;
    let cek = ctx.open(&enc_structure, &message.wrapped_key)?;
    if cek.len() != CEK_SIZE {
        return Err(err(C::HpkeOpen, "unwrapped CEK has wrong size"));
    }
    let cipher = Aes256Gcm::new_from_slice(&cek).map_err(|_| err(C::HpkeOpen, "bad CEK"))?;
    cipher
        .decrypt(&message.iv.into(), Payload { msg: &message.ciphertext, aad: &enc_structure })
        .map(Zeroizing::new)
        .map_err(|_| WireError::new(C::CoseDecrypt, "content authentication failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip() {
        let sk = p256::SecretKey::from_slice(&[3u8; 32]).unwrap();
        let wire = wrap_config(b"hello", &sk.public_key(), None, None, None).unwrap();
        let pt = unwrap_config(&wire, &sk, DecodeLimits::default()).unwrap();
        assert_eq!(&pt[..], b"hello");
        let other = p256::SecretKey::from_slice(&[4u8; 32]).unwrap();
        assert_eq!(unwrap_config(&wire, &other, DecodeLimits::default()).unwrap_err().code(), C::HpkeOpen);
        assert_eq!(wrap_config(b"x", &sk.public_key(), Some(&[0; 3]), None, None).unwrap_err().code(), C::HpkeKey);
        assert_eq!(wrap_config(b"x", &sk.public_key(), None, Some(&[0; 3]), None).unwrap_err().code(), C::HpkeKey);
        assert_eq!(decap(&[4u8; 65], &sk).unwrap_err().code(), C::HpkeKey);
        assert_eq!(decap(&[5u8; 65], &sk).unwrap_err().code(), C::HpkeKey);
        assert_eq!(expand(&[0; 32], b"", 255 * 32 + 1).unwrap_err().code(), C::HpkeDerive);
    }

    #[test]
    fn context_seq_limit() {
        let mut ctx = key_schedule(&[1u8; 32], b"").unwrap();
        ctx.set_seq(1u128 << 96);
        assert_eq!(ctx.seal(b"", b"").unwrap_err().code(), C::HpkeSeq);
        assert_eq!(ctx.key().len(), 16);
        assert_eq!(ctx.exporter_secret().len(), 32);
        assert_eq!(ctx.base_nonce().len(), 12);
    }
}
