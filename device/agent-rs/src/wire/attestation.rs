//! Attestation (`WIRE_FORMAT.md` §4): build the type-10 envelope for the EST
//! `X-IronMesh-Attestation` header, and verify it (server-side rules, used by tests and the
//! conformance harness doubles).

use sha2::{Digest, Sha256};

use super::cbor::DecodeLimits;
use super::cose::Kid;
use super::envelope::{self, Attestation, Body, DecodeOptions, InMemoryReplayStore, Message, SeType, Tpm2Evidence, Verified};
use super::error::{err, ErrorCode as C, WireResult};
use super::ids::Direction;
use super::keys::{CoseSigner, PublicKey};

/// `TPM_GENERATED_VALUE`.
pub const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
/// `TPM_ST_ATTEST_QUOTE`.
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
/// `TPM_ALG_SHA256`.
pub const TPM_ALG_SHA256: u16 = 0x000b;
/// PCRs covered by the quote.
pub const REQUIRED_PCRS: [u32; 4] = [0, 2, 4, 7];

/// Build the signed attestation envelope.
///
/// # Errors
/// Envelope validation or signer errors.
#[allow(clippy::too_many_arguments)]
pub fn build_attestation(
    signer: &dyn CoseSigner,
    kid: &Kid,
    seq: u64,
    ts: u64,
    nonce: &[u8; 32],
    csr_der: &[u8],
    fw_hash: &[u8; 32],
    fw_version: &str,
    se_type: SeType,
    evidence: Option<Tpm2Evidence>,
) -> WireResult<Vec<u8>> {
    let body = Attestation {
        nonce: *nonce,
        csr_hash: Sha256::digest(csr_der).into(),
        fw_hash: *fw_hash,
        fw_version: fw_version.to_owned(),
        se_type,
        evidence,
    };
    envelope::encode(&Message { seq, ts, body: Body::Attestation(body), nonce: None }, signer, kid)
}

/// Decoded quote `TPMS_ATTEST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmsAttest {
    /// `extraData` (qualifying data).
    pub extra_data: Vec<u8>,
    /// `(hash_alg, selected PCRs)` per bank.
    pub pcr_selections: Vec<(u16, Vec<u32>)>,
    /// PCR digest.
    pub pcr_digest: Vec<u8>,
    /// TPM clock.
    pub clock: u64,
}

struct Cursor<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> WireResult<&'a [u8]> {
        let s = self.d.get(self.p..self.p.saturating_add(n)).ok_or_else(|| err(C::AttEvidence, what))?;
        self.p += n;
        Ok(s)
    }
    fn u16(&mut self, what: &'static str) -> WireResult<u16> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self, what: &'static str) -> WireResult<u32> {
        let b = self.take(4, what)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn tpm2b(&mut self, what: &'static str) -> WireResult<&'a [u8]> {
        let n = self.u16(what)?;
        self.take(usize::from(n), what)
    }
}

/// Parse a quote `TPMS_ATTEST` (TPM 2.0 Part 2 §10.12).
///
/// # Errors
/// `ATT_EVIDENCE` on any structural problem.
pub fn parse_tpms_attest(data: &[u8]) -> WireResult<TpmsAttest> {
    let mut c = Cursor { d: data, p: 0 };
    if c.u32("TPMS_ATTEST too short")? != TPM_GENERATED_VALUE {
        return Err(err(C::AttEvidence, "TPMS_ATTEST magic is not TPM_GENERATED_VALUE"));
    }
    if c.u16("TPMS_ATTEST too short")? != TPM_ST_ATTEST_QUOTE {
        return Err(err(C::AttEvidence, "TPMS_ATTEST type is not TPM_ST_ATTEST_QUOTE"));
    }
    c.tpm2b("TPMS_ATTEST truncated in qualifiedSigner")?;
    let extra_data = c.tpm2b("TPMS_ATTEST truncated in extraData")?.to_vec();
    let clock_info = c.take(17, "TPMS_ATTEST truncated in clockInfo")?;
    let mut clock_bytes = [0u8; 8];
    clock_bytes.copy_from_slice(&clock_info[..8]);
    c.take(8, "TPMS_ATTEST truncated in firmwareVersion")?;
    let count = c.u32("TPMS_ATTEST truncated in pcrSelect")?;
    let mut pcr_selections = Vec::new();
    for _ in 0..count {
        let alg = c.u16("TPMS_ATTEST truncated in pcrSelect")?;
        let size = c.take(1, "TPMS_ATTEST truncated in pcrSelect")?[0];
        let bitmap = c.take(usize::from(size), "TPMS_ATTEST truncated in pcrSelect")?;
        let mut selected = Vec::new();
        for (byte_index, value) in bitmap.iter().enumerate() {
            for bit in 0..8u32 {
                if value & (1 << bit) != 0 {
                    selected.push(byte_index as u32 * 8 + bit);
                }
            }
        }
        pcr_selections.push((alg, selected));
    }
    let pcr_digest = c.tpm2b("TPMS_ATTEST truncated in pcrDigest")?.to_vec();
    if c.p != data.len() {
        return Err(err(C::AttEvidence, "trailing bytes after TPMS_ATTEST"));
    }
    Ok(TpmsAttest { extra_data, pcr_selections, pcr_digest, clock: u64::from_be_bytes(clock_bytes) })
}

/// Build a quote `TPMS_ATTEST` (used by tests and the TPM backend's self-check).
#[must_use]
pub fn encode_tpms_attest(extra_data: &[u8], pcrs: &[u32], pcr_digest: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
    out.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&(extra_data.len() as u16).to_be_bytes());
    out.extend_from_slice(extra_data);
    out.extend_from_slice(&[0u8; 17]);
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    out.push(3);
    let mut bitmap = [0u8; 3];
    for p in pcrs {
        if let Some(b) = bitmap.get_mut((*p / 8) as usize) {
            *b |= 1 << (p % 8);
        }
    }
    out.extend_from_slice(&bitmap);
    out.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
    out.extend_from_slice(pcr_digest);
    out
}

/// Inputs for [`verify_attestation`].
pub struct VerifyAttestation<'a> {
    /// TLS client certificate public key.
    pub identity_public_key: &'a PublicKey,
    /// Issued nonce.
    pub expected_nonce: &'a [u8],
    /// Submitted CSR.
    pub csr_der: &'a [u8],
    /// Now (unix s).
    pub now: u64,
    /// Expected kid (TLS cert serial).
    pub expected_kid: Option<&'a [u8]>,
    /// Allowed secure-element types (`None`: all).
    pub allowed_se_types: Option<&'a [SeType]>,
}

/// Verify an attestation envelope (server rules of `WIRE_FORMAT.md` §4).
///
/// # Errors
/// Envelope codes, `ATT_TYPE`, `ENV_KID`, `ATT_NONCE`, `ATT_CSR_HASH`, `ATT_SE_TYPE`, `ATT_EVIDENCE`.
pub fn verify_attestation(data: &[u8], v: &VerifyAttestation<'_>) -> WireResult<Verified> {
    let mut store = InMemoryReplayStore::new();
    let key = v.identity_public_key.clone();
    let opts =
        DecodeOptions { now: v.now, expected_direction: Some(Direction::Uplink), limits: DecodeLimits::default(), ..Default::default() };
    let verified = envelope::decode(data, &|_| Some(key.clone()), &mut store, &opts)?;
    let Body::Attestation(body) = &verified.message.body else {
        return Err(err(C::AttType, "expected an Attestation"));
    };
    if let Some(kid) = v.expected_kid {
        if verified.sender_kid != Kid::Bytes(kid.to_vec()) {
            return Err(err(C::EnvKid, "attestation kid does not match the TLS certificate"));
        }
    }
    if body.nonce[..] != *v.expected_nonce {
        return Err(err(C::AttNonce, "nonce does not match the issued nonce"));
    }
    if body.csr_hash != <[u8; 32]>::from(Sha256::digest(v.csr_der)) {
        return Err(err(C::AttCsrHash, "csr_hash does not bind the submitted CSR"));
    }
    if v.allowed_se_types.is_some_and(|allowed| !allowed.contains(&body.se_type)) {
        return Err(err(C::AttSeType, "se_type not allowed by policy"));
    }
    if let Some(evidence) = &body.evidence {
        let quote = parse_tpms_attest(&evidence.quote)?;
        if quote.extra_data != v.expected_nonce {
            return Err(err(C::AttEvidence, "quote qualifying data is not the nonce"));
        }
        let mut want = REQUIRED_PCRS.to_vec();
        want.sort_unstable();
        let ok = quote.pcr_selections.iter().any(|(alg, pcrs)| {
            let mut p = pcrs.clone();
            p.sort_unstable();
            p.dedup();
            *alg == TPM_ALG_SHA256 && p == want
        });
        if !ok {
            return Err(err(C::AttEvidence, "quote must cover exactly PCRs 0,2,4,7 (SHA-256)"));
        }
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_evidence_flow() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[8u8; 32]).unwrap();
        let pk = PublicKey::P256(*sk.verifying_key());
        let kid = Kid::Bytes(vec![1, 2]);
        let nonce = [7u8; 32];
        let quote = encode_tpms_attest(&nonce, &REQUIRED_PCRS, &[1; 32]);
        let parsed = parse_tpms_attest(&quote).unwrap();
        assert_eq!(parsed.extra_data, nonce);
        assert_eq!(parsed.pcr_digest, vec![1; 32]);
        assert_eq!(parsed.clock, 0);
        let ev = Tpm2Evidence { quote, signature: vec![1], ak_cert_der: vec![1] };
        let wire = build_attestation(&sk, &kid, 1, 100, &nonce, b"csr", &[0; 32], "1.0.0", SeType::Tpm2, Some(ev)).unwrap();
        let v = VerifyAttestation {
            identity_public_key: &pk,
            expected_nonce: &nonce,
            csr_der: b"csr",
            now: 100,
            expected_kid: Some(&[1, 2]),
            allowed_se_types: Some(&[SeType::Tpm2]),
        };
        verify_attestation(&wire, &v).unwrap();
        let bad_kid = VerifyAttestation { expected_kid: Some(&[9]), ..v };
        assert_eq!(verify_attestation(&wire, &bad_kid).unwrap_err().code(), C::EnvKid);
        let bad_quote = encode_tpms_attest(&nonce, &[0, 2, 4], &[1; 32]);
        let ev = Tpm2Evidence { quote: bad_quote, signature: vec![1], ak_cert_der: vec![1] };
        let wire = build_attestation(&sk, &kid, 1, 100, &nonce, b"csr", &[0; 32], "1.0.0", SeType::Tpm2, Some(ev)).unwrap();
        let v = VerifyAttestation {
            identity_public_key: &pk,
            expected_nonce: &nonce,
            csr_der: b"csr",
            now: 100,
            expected_kid: None,
            allowed_se_types: None,
        };
        assert_eq!(verify_attestation(&wire, &v).unwrap_err().code(), C::AttEvidence);
        let other_nonce = encode_tpms_attest(&[1; 32], &REQUIRED_PCRS, &[1; 32]);
        let ev = Tpm2Evidence { quote: other_nonce, signature: vec![1], ak_cert_der: vec![1] };
        let wire = build_attestation(&sk, &kid, 1, 100, &nonce, b"csr", &[0; 32], "1.0.0", SeType::Tpm2, Some(ev)).unwrap();
        assert_eq!(verify_attestation(&wire, &v).unwrap_err().code(), C::AttEvidence);
    }

    #[test]
    fn tpms_parse_errors() {
        let good = encode_tpms_attest(&[1; 32], &REQUIRED_PCRS, &[1; 32]);
        for n in [0, 3, 5, 7, 40, 70, good.len() - 1] {
            assert_eq!(parse_tpms_attest(&good[..n]).unwrap_err().code(), C::AttEvidence, "{n}");
        }
        let mut bad = good.clone();
        bad[0] = 0;
        assert_eq!(parse_tpms_attest(&bad).unwrap_err().code(), C::AttEvidence);
        let mut bad = good.clone();
        bad[5] = 0;
        assert_eq!(parse_tpms_attest(&bad).unwrap_err().code(), C::AttEvidence);
        let mut bad = good;
        bad.push(0);
        assert_eq!(parse_tpms_attest(&bad).unwrap_err().code(), C::AttEvidence);
    }

    #[test]
    fn telemetry_is_not_attestation() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[8u8; 32]).unwrap();
        let pk = PublicKey::P256(*sk.verifying_key());
        let msg = Message {
            seq: 1,
            ts: 5,
            body: Body::Telemetry(envelope::Telemetry { fw_version: "1.0.0".into(), ..Default::default() }),
            nonce: None,
        };
        let wire = envelope::encode(&msg, &sk, &Kid::Bytes(vec![1])).unwrap();
        let v = VerifyAttestation {
            identity_public_key: &pk,
            expected_nonce: &[0; 32],
            csr_der: b"",
            now: 5,
            expected_kid: None,
            allowed_se_types: None,
        };
        assert_eq!(verify_attestation(&wire, &v).unwrap_err().code(), C::AttType);
    }
}
