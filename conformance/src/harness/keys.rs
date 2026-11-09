//! Signing keys of the hermetic cloud. The tenant command key and the firmware signing keys are
//! the public **test vector** keys of `libs/python/ironmesh-wire/tests/keys/` (so every artifact
//! the suite produces can be re-checked with the reference implementation); if the repository
//! files are not available, fresh random keys are generated instead.

use std::path::Path;

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use ed25519_dalek::SigningKey;

/// The keys of the hermetic cloud.
pub struct HarnessKeys {
    /// Tenant command key (signs every downlink; its public key is `tenant_cmd_pubkey`).
    pub tenant: SigningKey,
    /// Firmware signing key (its public key is in `fw_signing_pubkeys`).
    pub firmware: SigningKey,
    /// A firmware key no device trusts (C-OTA-3).
    pub untrusted_firmware: SigningKey,
    /// A non-tenant Ed25519 key used to forge downlinks (C-RPL-3).
    pub attacker: SigningKey,
    /// Where the keys came from.
    pub source: String,
}

/// Parse an Ed25519 PKCS#8 v1 PEM (RFC 8410) into a signing key.
///
/// # Errors
/// Not an Ed25519 PKCS#8 key.
pub fn ed25519_from_pkcs8_pem(pem: &str) -> Result<SigningKey> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64)?;
    // SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING seed } }
    const PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    if der.len() != 48 || der[..16] != PREFIX {
        bail!("not an Ed25519 PKCS#8 v1 private key");
    }
    let seed: [u8; 32] = der[16..].try_into().map_err(|_| anyhow!("seed"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn random_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

impl HarnessKeys {
    /// Load the vector keys from `<repo>/libs/python/ironmesh-wire/tests/keys`, or generate keys.
    #[must_use]
    pub fn load(repo_root: &Path) -> Self {
        let dir = repo_root.join("libs").join("python").join("ironmesh-wire").join("tests").join("keys");
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).ok().and_then(|p| ed25519_from_pkcs8_pem(&p).ok());
        match (read("tenant_ed25519.pem"), read("fw_ed25519.pem"), read("fw_ed25519_untrusted.pem")) {
            (Some(tenant), Some(firmware), Some(untrusted_firmware)) => Self {
                tenant,
                firmware,
                untrusted_firmware,
                attacker: random_key(),
                source: format!("test-vector keys from {}", dir.display()),
            },
            _ => Self {
                tenant: random_key(),
                firmware: random_key(),
                untrusted_firmware: random_key(),
                attacker: random_key(),
                source: "generated (vector keys not found)".into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_keys_match_the_published_raw_keys() {
        let root = crate::util::repo_root();
        let k = HarnessKeys::load(&root);
        assert!(k.source.starts_with("test-vector"), "{}", k.source);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("device/common/vectors/envelope_command_ack.json")).unwrap()).unwrap();
        assert_eq!(hex::encode(k.tenant.verifying_key().to_bytes()), v["tenant_key"]["public_raw_hex"].as_str().unwrap());
        let m: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("device/common/vectors/manifest_signed.json")).unwrap()).unwrap();
        assert_eq!(hex::encode(k.firmware.verifying_key().to_bytes()), m["ed25519_key"]["public_raw_hex"].as_str().unwrap());
        assert_eq!(hex::encode(k.untrusted_firmware.verifying_key().to_bytes()), m["untrusted_ed25519_public_raw_hex"].as_str().unwrap());
        assert!(ed25519_from_pkcs8_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----").is_err());
    }
}
