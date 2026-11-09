//! `X-IronMesh-Bundle` (contract §3 step 6): a COSE_Sign1 (EdDSA, kid `pki-bundle`) over the
//! canonical CBOR map `{1: tenant_cmd_pubkey, 2: fw_signing_pubkeys, 3: broker_host,
//! 4: broker_port, 5: ca_pins}`, verified with the PKI bundle public key baked in at the factory.

use crate::wire::cbor::{self, DecodeLimits, Value};
use crate::wire::cose::{self, Kid};
use crate::wire::envelope::Fields;
use crate::wire::error::{ErrorCode, WireError};
use crate::wire::keys::{CoseSigner, PublicKey, ML_DSA_65_PUBLIC_KEY_SIZE};

/// kid used by the PKI for bundles.
pub const BUNDLE_KID: &[u8] = b"pki-bundle";
const MAX_LIST: usize = 16;

/// Bundle verification error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    /// COSE / CBOR failure (signature, structure).
    #[error("bundle: {0}")]
    Wire(WireError),
    /// Semantic problem in the payload.
    #[error("bundle payload: {0}")]
    Field(&'static str),
}

/// The verified trust bundle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustBundle {
    /// Tenant command key (Ed25519), absent if the tenant has none yet.
    pub tenant_cmd_pubkey: Option<[u8; 32]>,
    /// Trusted firmware signing keys (32-byte Ed25519 / 1952-byte ML-DSA-65).
    pub fw_signing_pubkeys: Vec<Vec<u8>>,
    /// Broker host.
    pub broker_host: String,
    /// Broker port.
    pub broker_port: u16,
    /// SHA-256 SPKI pins of the Services CA (and root).
    pub ca_pins: Vec<[u8; 32]>,
}

impl TrustBundle {
    fn to_value(&self) -> Value {
        cbor::int_map(vec![
            (1, Value::bytes(self.tenant_cmd_pubkey.map(|k| k.to_vec()).unwrap_or_default())),
            (2, Value::Array(self.fw_signing_pubkeys.iter().map(|k| Value::bytes(k.clone())).collect())),
            (3, Value::text(self.broker_host.clone())),
            (4, Value::int(self.broker_port)),
            (5, Value::Array(self.ca_pins.iter().map(|p| Value::bytes(p.to_vec())).collect())),
        ])
    }
}

fn bstr_list(v: Option<&Value>) -> Result<Vec<Vec<u8>>, BundleError> {
    match v {
        Some(Value::Array(items)) if items.len() <= MAX_LIST => {
            items.iter().map(|i| i.as_bytes().map(<[u8]>::to_vec).ok_or(BundleError::Field("list items must be bstr"))).collect()
        }
        _ => Err(BundleError::Field("expected an array of at most 16 bstr")),
    }
}

/// Verify the bundle signature with the factory bundle key and decode the payload.
///
/// # Errors
/// [`BundleError`] on any failure (fail closed).
pub fn verify_bundle(raw: &[u8], bundle_key: &[u8; 32]) -> Result<TrustBundle, BundleError> {
    let msg = cose::sign1_decode(raw, DecodeLimits::default()).map_err(BundleError::Wire)?;
    let key = PublicKey::ed25519_from_raw(bundle_key).map_err(BundleError::Wire)?;
    cose::sign1_verify(&msg, &key).map_err(BundleError::Wire)?;
    decode_payload(&msg.payload)
}

/// Decode and validate a bundle payload (after its signature was verified).
///
/// # Errors
/// [`BundleError`].
pub fn decode_payload(payload: &[u8]) -> Result<TrustBundle, BundleError> {
    let m = cbor::decode_map(payload, DecodeLimits::default()).map_err(BundleError::Wire)?;
    let f = Fields::new(&m, ErrorCode::EnvField);
    f.expect_keys(&[1, 2, 3, 4, 5], &[], "bundle keys").map_err(|_| BundleError::Field("bundle must have exactly keys 1..5"))?;
    let tenant = f.bstr(1, None, "tenant_cmd_pubkey").map_err(|_| BundleError::Field("tenant_cmd_pubkey must be a bstr"))?;
    let tenant_cmd_pubkey = match tenant.len() {
        0 => None,
        32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&tenant);
            PublicKey::ed25519_from_raw(&k).map_err(|_| BundleError::Field("tenant_cmd_pubkey is not a valid Ed25519 key"))?;
            Some(k)
        }
        _ => return Err(BundleError::Field("tenant_cmd_pubkey must be 32 bytes")),
    };
    let fw_signing_pubkeys = bstr_list(f.get(2))?;
    if fw_signing_pubkeys.iter().any(|k| k.len() != 32 && k.len() != ML_DSA_65_PUBLIC_KEY_SIZE) {
        return Err(BundleError::Field("fw_signing_pubkeys must be Ed25519 or ML-DSA-65 keys"));
    }
    let broker_host = f.tstr(3, 1, 253, "broker_host").map_err(|_| BundleError::Field("broker_host must be 1..253 chars"))?;
    let broker_port = f.uint_max(4, 65535, "broker_port").map_err(|_| BundleError::Field("broker_port must be 1..65535"))?;
    if broker_port == 0 {
        return Err(BundleError::Field("broker_port must be 1..65535"));
    }
    let ca_pins = bstr_list(f.get(5))?
        .into_iter()
        .map(|p| <[u8; 32]>::try_from(p.as_slice()).map_err(|_| BundleError::Field("ca_pins must be 32-byte digests")))
        .collect::<Result<Vec<_>, _>>()?;
    if ca_pins.is_empty() {
        return Err(BundleError::Field("ca_pins must not be empty"));
    }
    Ok(TrustBundle { tenant_cmd_pubkey, fw_signing_pubkeys, broker_host, broker_port: broker_port as u16, ca_pins })
}

/// Sign a bundle (PKI side; used by test servers and tooling).
///
/// # Errors
/// Encoding errors.
pub fn sign_bundle(bundle: &TrustBundle, key: &ed25519_dalek::SigningKey) -> Result<Vec<u8>, WireError> {
    let payload = cbor::encode(&bundle.to_value())?;
    let _: &dyn CoseSigner = key;
    cose::sign1_encode(&payload, key, &Kid::Bytes(BUNDLE_KID.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TrustBundle {
        TrustBundle {
            tenant_cmd_pubkey: Some(ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes()),
            fw_signing_pubkeys: vec![ed25519_dalek::SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes().to_vec()],
            broker_host: "localhost".into(),
            broker_port: 8883,
            ca_pins: vec![[7; 32]],
        }
    }

    #[test]
    fn sign_and_verify() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let pk = key.verifying_key().to_bytes();
        let raw = sign_bundle(&sample(), &key).unwrap();
        assert_eq!(verify_bundle(&raw, &pk).unwrap(), sample());
        let other = ed25519_dalek::SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes();
        assert!(matches!(verify_bundle(&raw, &other), Err(BundleError::Wire(_))));
        let mut empty_tenant = sample();
        empty_tenant.tenant_cmd_pubkey = None;
        assert_eq!(verify_bundle(&sign_bundle(&empty_tenant, &key).unwrap(), &pk).unwrap().tenant_cmd_pubkey, None);
        let mut b = sample();
        b.ca_pins.clear();
        assert!(verify_bundle(&sign_bundle(&b, &key).unwrap(), &pk).is_err());
        let mut b = sample();
        b.broker_port = 0;
        assert!(verify_bundle(&sign_bundle(&b, &key).unwrap(), &pk).is_err());
        let mut b = sample();
        b.fw_signing_pubkeys.push(vec![1; 5]);
        assert!(verify_bundle(&sign_bundle(&b, &key).unwrap(), &pk).is_err());
        let mut b = sample();
        b.broker_host = String::new();
        assert!(verify_bundle(&sign_bundle(&b, &key).unwrap(), &pk).is_err());
        let payload = cbor::encode(&cbor::int_map(vec![(1, Value::bytes(vec![1; 3]))])).unwrap();
        let raw = cose::sign1_encode(&payload, &key, &Kid::Bytes(BUNDLE_KID.to_vec())).unwrap();
        assert!(verify_bundle(&raw, &pk).is_err());
        let mut v = sample().to_value();
        if let Value::Map(m) = &mut v {
            m[0].1 = Value::bytes(vec![1; 31]);
        }
        let raw = cose::sign1_encode(&cbor::encode(&v).unwrap(), &key, &Kid::Bytes(BUNDLE_KID.to_vec())).unwrap();
        assert!(verify_bundle(&raw, &pk).is_err());
        assert!(verify_bundle(b"\x00", &pk).is_err());
    }
}
