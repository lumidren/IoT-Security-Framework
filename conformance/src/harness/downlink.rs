//! Tenant-signed downlink messages (WIRE_FORMAT §3) and the encrypted Config wrapper (§5), plus
//! verification of the uplink messages the broker captured (the harness never trusts a DUT event
//! alone when the bytes on the wire can be checked).

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use ironmesh_agent::wire::cbor::{DecodeLimits, Value};
use ironmesh_agent::wire::cose::Kid;
use ironmesh_agent::wire::envelope::{
    self, Body, Command, Config, DecodeOptions, InMemoryReplayStore, Message, OtaNotify, ShadowState, Verified,
};
use ironmesh_agent::wire::hpke;
use ironmesh_agent::wire::ids::{self, Direction};
use ironmesh_agent::wire::keys::PublicKey;

use crate::util;

/// Signs downlinks as `tenant-cmd-<tenant>` and keeps one sequence per downlink type (§3.6 step
/// 11: registry types 4, 5, 9 and OTA type 7 are separate replay streams).
pub struct TenantSigner {
    /// Tenant id.
    pub tenant_id: String,
    key: SigningKey,
    seq: Mutex<HashMap<u8, u64>>,
}

/// A built downlink: wire bytes plus the message (for later ack checks).
#[derive(Debug, Clone)]
pub struct Downlink {
    /// COSE_Sign1 bytes.
    pub wire: Vec<u8>,
    /// The message.
    pub message: Message,
}

impl TenantSigner {
    /// New signer.
    #[must_use]
    pub fn new(tenant_id: &str, key: SigningKey) -> Self {
        Self { tenant_id: tenant_id.to_owned(), key, seq: Mutex::new(HashMap::new()) }
    }

    /// Tenant public key.
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Next sequence number of a downlink type (starts at 1000).
    pub fn next_seq(&self, message_type: u8) -> u64 {
        let mut s = self.seq.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let v = s.entry(message_type).or_insert(999);
        *v += 1;
        *v
    }

    /// Sign `body` with an explicit seq/ts (and optionally another key: forgeries).
    ///
    /// # Errors
    /// Body validation failures.
    pub fn sign_with(&self, key: &SigningKey, seq: u64, ts: u64, body: Body, nonce: Option<[u8; 16]>) -> Result<Downlink> {
        let kid = Kid::Text(ids::tenant_kid(&self.tenant_id)?);
        let message = Message { seq, ts, body, nonce };
        let wire = envelope::encode(&message, key, &kid).map_err(|e| anyhow!("encode downlink: {e}"))?;
        Ok(Downlink { wire, message })
    }

    /// Sign with the tenant key, the next seq of the type and `ts = now`.
    ///
    /// # Errors
    /// Body validation failures.
    pub fn sign(&self, body: Body, nonce: Option<[u8; 16]>) -> Result<Downlink> {
        let seq = self.next_seq(body.message_type());
        self.sign_with(&self.key, seq, util::now_unix(), body, nonce)
    }

    /// The tenant key (for explicit-seq signing).
    #[must_use]
    pub fn key(&self) -> &SigningKey {
        &self.key
    }
}

/// A Command body.
#[must_use]
pub fn command_body(name: &str, idempotency_key: &str, ttl_s: u64) -> Body {
    Body::Command(Command {
        cmd_id: util::uuid4(),
        name: name.to_owned(),
        args: Vec::new(),
        idempotency_key: idempotency_key.to_owned(),
        expires_at: util::now_unix() + ttl_s,
    })
}

/// A random command nonce.
#[must_use]
pub fn nonce16() -> [u8; 16] {
    let mut n = [0u8; 16];
    n.copy_from_slice(&util::random_bytes(16));
    n
}

/// An OtaNotify body.
#[must_use]
pub fn ota_notify_body(campaign_id: &str, manifest: Vec<u8>, url: &str, delta_from: Option<[u8; 32]>) -> Body {
    Body::OtaNotify(OtaNotify { campaign_id: campaign_id.to_owned(), manifest, url: url.to_owned(), delta_from })
}

/// A Config body.
#[must_use]
pub fn config_body(version: u64, settings: Vec<(String, Value)>) -> Body {
    Body::Config(Config { version, settings })
}

/// A ShadowDesired body.
#[must_use]
pub fn shadow_body(version: u64, state: Vec<(String, Value)>) -> Body {
    Body::ShadowDesired(ShadowState { state, version })
}

/// HPKE-wrap a signed Config envelope to a device certificate key (65-byte SEC1 point).
///
/// # Errors
/// Invalid key.
pub fn wrap_config(signed_config: &[u8], device_public_sec1: &[u8]) -> Result<Vec<u8>> {
    let pk = p256::PublicKey::from_sec1_bytes(device_public_sec1).context("device public key")?;
    hpke::wrap_config(signed_config, &pk, None, None, None).map_err(|e| anyhow!("wrap_config: {e}"))
}

/// Verify an uplink envelope captured on the broker with the device certificate key and decode
/// it (no replay store: the caller checks ordering itself).
///
/// # Errors
/// The wire error of the first failing check.
pub fn verify_uplink(wire: &[u8], device_public_sec1: &[u8], now: u64) -> Result<Verified> {
    let key = PublicKey::p256_from_sec1(device_public_sec1).map_err(|e| anyhow!("{e}"))?;
    let mut store = InMemoryReplayStore::new();
    let opts = DecodeOptions { now, expected_direction: Some(Direction::Uplink), limits: DecodeLimits::default(), ..Default::default() };
    envelope::decode(wire, &|_| Some(key.clone()), &mut store, &opts).map_err(|e| anyhow!("{}: {}", e.code().as_str(), e.detail()))
}

/// Kid (hex) of a COSE_Sign1 without verifying it.
#[must_use]
pub fn kid_hex(wire: &[u8]) -> Option<String> {
    ironmesh_agent::wire::cose::sign1_decode(wire, DecodeLimits::default()).ok().map(|s| match s.kid {
        Kid::Bytes(b) => hex::encode(b),
        Kid::Text(t) => t,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_vector_is_reproduced_with_the_vector_tenant_key() {
        // Deterministic Ed25519: the harness signer must produce the published bytes.
        let root = util::repo_root();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("device/common/vectors/envelope_command_ack.json")).unwrap()).unwrap();
        let keys = super::super::keys::HarnessKeys::load(&root);
        let tenant = v["tenant_id"].as_str().unwrap();
        let s = TenantSigner::new(tenant, keys.tenant.clone());
        let c = &v["command"];
        let body = &c["body"];
        let args: Vec<(String, Value)> = body["args"]
            .as_object()
            .map(|o| {
                o.iter()
                    .map(|(k, v)| {
                        let val = match v {
                            serde_json::Value::Number(n) => Value::int(n.as_i64().unwrap()),
                            serde_json::Value::String(s) => Value::text(s.clone()),
                            serde_json::Value::Bool(b) => Value::Bool(*b),
                            _ => Value::Null,
                        };
                        (k.clone(), val)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let b = Body::Command(Command {
            cmd_id: body["cmd_id"].as_str().unwrap().into(),
            name: body["name"].as_str().unwrap().into(),
            args,
            idempotency_key: body["idempotency_key"].as_str().unwrap().into(),
            expires_at: body["expires_at"].as_u64().unwrap(),
        });
        let nonce: [u8; 16] = hex::decode(c["nonce_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
        let d = s.sign_with(s.key(), c["seq"].as_u64().unwrap(), c["ts"].as_u64().unwrap(), b, Some(nonce)).unwrap();
        let payload = envelope::encode_payload(&d.message).unwrap();
        assert_eq!(hex::encode(payload), c["payload_hex"].as_str().unwrap(), "payload");
        assert_eq!(hex::encode(&d.wire), c["wire_hex"].as_str().unwrap(), "wire");
    }

    #[test]
    fn per_type_sequences() {
        let s = TenantSigner::new("7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11", SigningKey::from_bytes(&[1; 32]));
        assert_eq!(s.next_seq(5), 1000);
        assert_eq!(s.next_seq(5), 1001);
        assert_eq!(s.next_seq(7), 1000);
    }

    #[test]
    fn config_wrap_roundtrip() {
        let sk = <p256::SecretKey as p256::elliptic_curve::Generate>::generate();
        let pk = sk.public_key();
        use p256::elliptic_curve::sec1::ToSec1Point;
        let sec1 = pk.to_sec1_point(false);
        let s = TenantSigner::new("7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11", SigningKey::from_bytes(&[2; 32]));
        let inner = s.sign(config_body(3, vec![("log_level".into(), Value::text("info"))]), None).unwrap();
        let wrapped = wrap_config(&inner.wire, sec1.as_bytes()).unwrap();
        assert_eq!(wrapped[0], 0xd0, "COSE_Encrypt0 tag 16");
        assert!(!wrapped.windows(9).any(|w| w == b"log_level"), "ciphertext only");
        let pt = hpke::unwrap_config(&wrapped, &sk, DecodeLimits::default()).unwrap();
        assert_eq!(&pt[..], &inner.wire[..]);
    }
}
