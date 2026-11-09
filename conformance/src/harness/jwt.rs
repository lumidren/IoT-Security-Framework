//! ES256 service JWTs the way the IronMesh services mint them for each other (contract §7, the
//! registry's `REGISTRY_SERVICE_JWT_PRIVATE_KEY_FILE`): `iss` / `sub` = the calling service, `aud` =
//! the receiver, `iat`, `exp` (60 s lifetime, the receivers cap `exp - iat` at 300 s) and a random
//! `jti`. The policy and PKI services accept every `jti` **once** (`POLICY_JWT_SINGLE_USE`,
//! `PKI_MGMT_JWT_SINGLE_USE`, both on by default), so a token is minted per request and never
//! cached.

use anyhow::{anyhow, Result};
use base64::Engine;
use p256::ecdsa::SigningKey;
use serde_json::{json, Map, Value};

/// Lifetime of a minted token (s); the receivers' bound is 300 s.
pub const LIFETIME_S: u64 = 60;

/// A service identity that mints single-use ES256 JWTs.
pub struct ServiceJwt {
    key: SigningKey,
    /// `iss` claim.
    pub issuer: String,
    /// `sub` claim (the service name the receivers authorize, `svc-` prefix optional).
    pub subject: String,
}

impl std::fmt::Debug for ServiceJwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceJwt").field("issuer", &self.issuer).field("subject", &self.subject).finish_non_exhaustive()
    }
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

impl ServiceJwt {
    /// A fresh P-256 key for `iss` / `sub`.
    #[must_use]
    pub fn random(issuer: &str, subject: &str) -> Self {
        Self { key: SigningKey::random(&mut rand::rngs::OsRng), issuer: issuer.to_owned(), subject: subject.to_owned() }
    }

    /// Load a PKCS#8 (`PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`) P-256 key.
    ///
    /// # Errors
    /// Unreadable file or not a P-256 key.
    pub fn from_pem_file(path: &std::path::Path, issuer: &str, subject: &str) -> Result<Self> {
        use p256::pkcs8::DecodePrivateKey;
        let text = std::fs::read_to_string(path).map_err(|e| anyhow!("read {}: {e}", path.display()))?;
        let key = SigningKey::from_pkcs8_pem(&text)
            .or_else(|_| p256::SecretKey::from_sec1_pem(&text).map(SigningKey::from))
            .map_err(|e| anyhow!("{}: not a P-256 private key: {e}", path.display()))?;
        Ok(Self { key, issuer: issuer.to_owned(), subject: subject.to_owned() })
    }

    /// The verification key as a PEM `PUBLIC KEY` block (`POLICY_JWT_PUBLIC_KEY_PEM`,
    /// `PKI_MGMT_JWT_PUBLIC_KEY_FILE`).
    ///
    /// # Errors
    /// Encoding failure.
    pub fn public_pem(&self) -> Result<String> {
        use p256::pkcs8::EncodePublicKey;
        self.key.verifying_key().to_public_key_pem(p256::pkcs8::LineEnding::LF).map_err(|e| anyhow!("{e}"))
    }

    /// A new token for `aud` with a fresh `jti` (plus `extra` claims such as `role`).
    ///
    /// # Errors
    /// Signing failure.
    pub fn mint(&self, aud: &str, extra: &[(&str, Value)]) -> Result<String> {
        use p256::ecdsa::signature::Signer;
        let now = crate::util::now_unix();
        let mut claims = Map::new();
        claims.insert("iss".into(), json!(self.issuer));
        claims.insert("sub".into(), json!(self.subject));
        claims.insert("aud".into(), json!(aud));
        claims.insert("iat".into(), json!(now));
        claims.insert("exp".into(), json!(now + LIFETIME_S));
        claims.insert("jti".into(), json!(crate::util::uuid4()));
        for (k, v) in extra {
            claims.insert((*k).to_owned(), v.clone());
        }
        let header = b64(json!({"alg": "ES256", "typ": "JWT"}).to_string().as_bytes());
        let body = b64(Value::Object(claims).to_string().as_bytes());
        let input = format!("{header}.{body}");
        let sig: p256::ecdsa::Signature = self.key.try_sign(input.as_bytes()).map_err(|e| anyhow!("{e}"))?;
        Ok(format!("{input}.{}", b64(&sig.to_bytes())))
    }
}

/// The claims of a compact JWT (no verification; tests and evidence).
///
/// # Errors
/// Malformed token.
pub fn claims(token: &str) -> Result<Value> {
    let part = token.split('.').nth(1).ok_or_else(|| anyhow!("not a compact JWT"))?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part).map_err(|e| anyhow!("{e}"))?;
    Ok(serde_json::from_slice(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_token_is_fresh_short_lived_and_verifies() {
        use p256::ecdsa::signature::Verifier;
        let j = ServiceJwt::random("registry", "registry");
        let a = j.mint("pki", &[]).unwrap();
        let b = j.mint("pki", &[("role", json!("viewer"))]).unwrap();
        let (ca, cb) = (claims(&a).unwrap(), claims(&b).unwrap());
        assert_ne!(ca["jti"], cb["jti"], "jti must be unique per request");
        for c in [&ca, &cb] {
            let (iat, exp) = (c["iat"].as_u64().unwrap(), c["exp"].as_u64().unwrap());
            assert!(exp > iat && exp - iat <= 300, "lifetime must be positive and at most 300 s");
            assert_eq!(c["aud"], "pki");
            assert_eq!((c["iss"].as_str(), c["sub"].as_str()), (Some("registry"), Some("registry")));
        }
        assert_eq!(cb["role"], "viewer");
        let (input, sig) = a.rsplit_once('.').unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig).unwrap()).unwrap();
        j.key.verifying_key().verify(input.as_bytes(), &sig).unwrap();
        assert!(j.public_pem().unwrap().starts_with("-----BEGIN PUBLIC KEY-----"));
    }
}
