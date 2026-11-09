//! OTA artifacts (contract §6, WIRE_FORMAT §6, DELTA_FORMAT): manifests built and signed with the
//! same canonical rules as the wire library, and the fault variants the C-OTA cases serve.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use ed25519_dalek::SigningKey;
use ironmesh_agent::wire::delta;
use ironmesh_agent::wire::manifest::{self, DeltaInfo, Manifest};
use sha2::{Digest, Sha256};

use super::net::{self, ClientAuth, Versions};
use super::pki::TestPki;
use crate::util;

/// SHA-256.
#[must_use]
pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// A deterministic pseudo-random firmware image.
#[must_use]
pub fn firmware_image(seed: u32, size: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9) | 1;
    (0..size)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

/// Derive a new image from `base` by changing a few 4 KiB blocks (so a delta is small) and
/// appending `grow` bytes.
#[must_use]
pub fn mutate_image(base: &[u8], salt: u8, grow: usize) -> Vec<u8> {
    let mut v = base.to_vec();
    for (i, off) in [100usize, 9_000, 30_000].iter().enumerate() {
        if *off < v.len() {
            v[*off] ^= salt.wrapping_add(i as u8) | 1;
        }
    }
    v.extend((0..grow).map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt)));
    v
}

/// The fault variants of the C-OTA cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// Correctly signed full image.
    Valid,
    /// OtaNotify carries the bare manifest CBOR, no COSE_Sign (C-OTA-1).
    Unsigned,
    /// Valid manifest, one byte of the served image flipped (C-OTA-2).
    Tampered,
    /// Manifest signed by a key not in `fw_signing_pubkeys` (C-OTA-3).
    UntrustedKey,
    /// `version_code` equal to the running one (C-OTA-4).
    Downgrade,
    /// Delta patch from the running image (C-OTA-7).
    Delta,
}

/// A built artifact.
#[derive(Debug, Clone)]
pub struct Artifact {
    /// The manifest as signed (or not).
    pub manifest: Manifest,
    /// Bytes for `OtaNotify.manifest`.
    pub notify_manifest: Vec<u8>,
    /// Bytes the artifact server serves (image or patch).
    pub served: Vec<u8>,
    /// The full target image.
    pub image: Vec<u8>,
    /// `OtaNotify.delta_from`.
    pub delta_from: Option<[u8; 32]>,
}

/// Inputs to [`build`].
pub struct BuildSpec<'a> {
    /// Product of the DUT.
    pub product: &'a str,
    /// Version string of the new image.
    pub version: &'a str,
    /// Version code of the new image.
    pub version_code: u64,
    /// The new image.
    pub image: Vec<u8>,
    /// Base image for deltas.
    pub base: Option<&'a [u8]>,
    /// Trusted firmware key.
    pub key: &'a SigningKey,
    /// Untrusted firmware key.
    pub untrusted: &'a SigningKey,
}

/// Build the artifact of a variant.
///
/// # Errors
/// Manifest validation (e.g. a delta variant without a base).
pub fn build(variant: Variant, spec: &BuildSpec<'_>) -> Result<Artifact> {
    let image = spec.image.clone();
    let mut m = Manifest {
        product: spec.product.to_owned(),
        version: spec.version.to_owned(),
        version_code: spec.version_code,
        image_sha256: sha256(&image),
        image_size: image.len() as u64,
        created_at: util::now_unix(),
        min_version_code: 0,
        delta: None,
        signing_key_id: "conformance-fw".into(),
    };
    let mut served = image.clone();
    let mut delta_from = None;
    if variant == Variant::Delta {
        let base = spec.base.ok_or_else(|| anyhow!("delta artifact without a base image"))?;
        let patch = delta::make_delta(base, &image);
        let roundtrip = delta::apply_delta(base, &patch, 1 << 30).map_err(|e| anyhow!("delta self-check: {e}"))?;
        if roundtrip != image {
            return Err(anyhow!("delta self-check: applied patch differs from the target image"));
        }
        m.delta = Some(DeltaInfo { base_sha256: sha256(base), patch_sha256: sha256(&patch), patch_size: patch.len() as u64 });
        delta_from = Some(sha256(base));
        served = patch;
    }
    let payload = manifest::encode_manifest(&m).map_err(|e| anyhow!("manifest: {e}"))?;
    let notify_manifest = match variant {
        Variant::Unsigned => payload,
        Variant::UntrustedKey => manifest::sign_manifest(&payload, spec.untrusted, None).map_err(|e| anyhow!("{e}"))?,
        _ => manifest::sign_manifest(&payload, spec.key, None).map_err(|e| anyhow!("{e}"))?,
    };
    if variant == Variant::Tampered {
        let i = served.len() / 2;
        served[i] ^= 0x01;
    }
    Ok(Artifact { manifest: m, notify_manifest, served, image, delta_from })
}

#[derive(Clone, Default)]
struct Store {
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    downloads: Arc<Mutex<HashMap<String, usize>>>,
}

/// HTTPS artifact server (Services CA certificate, `Range: bytes=N-` resume support).
pub struct ArtifactServer {
    /// Listen address.
    pub addr: SocketAddr,
    /// Host put into URLs.
    pub url_host: String,
    store: Store,
}

async fn serve_file(State(store): State<Store>, Path(name): Path<String>, h: HeaderMap) -> Response {
    let Some(data) = store.files.lock().ok().and_then(|f| f.get(&name).cloned()) else { return StatusCode::NOT_FOUND.into_response() };
    if let Ok(mut d) = store.downloads.lock() {
        *d.entry(name.clone()).or_default() += 1;
    }
    if let Some(start) = h
        .get("range")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("bytes="))
        .and_then(|v| v.strip_suffix('-'))
        .and_then(|v| v.parse::<usize>().ok())
    {
        let start = start.min(data.len());
        let range = format!("bytes {start}-{}/{}", data.len().saturating_sub(1), data.len());
        return (
            StatusCode::PARTIAL_CONTENT,
            [("content-range", range), ("content-type", "application/octet-stream".into())],
            data[start..].to_vec(),
        )
            .into_response();
    }
    (StatusCode::OK, [("content-type", "application/octet-stream")], data).into_response()
}

impl ArtifactServer {
    /// Start on `host:0`.
    ///
    /// # Errors
    /// Bind / TLS failures.
    pub async fn start(host: &str, url_host: &str, pki: &TestPki) -> Result<Self> {
        let store = Store::default();
        let router = Router::new().route("/fw/{name}", get(serve_file)).with_state(store.clone());
        let cfg = net::server_config(pki.artifacts.chain(&pki.services), pki.artifacts.key(), ClientAuth::None, Versions::Both, &[])?;
        let listener = net::bind(host, 0).await?;
        let addr = listener.local_addr()?;
        net::serve_https(listener, cfg, router);
        Ok(Self { addr, url_host: url_host.to_owned(), store })
    }

    /// Publish bytes; returns the HTTPS URL.
    pub fn put(&self, bytes: Vec<u8>) -> String {
        let name = format!("{}.bin", hex::encode(util::random_bytes(8)));
        if let Ok(mut f) = self.store.files.lock() {
            f.insert(name.clone(), bytes);
        }
        format!("https://{}:{}/fw/{name}", self.url_host, self.addr.port())
    }

    /// How many times the file behind `url` was fetched.
    #[must_use]
    pub fn downloads(&self, url: &str) -> usize {
        let name = url.rsplit('/').next().unwrap_or_default();
        self.store.downloads.lock().ok().and_then(|d| d.get(name).copied()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironmesh_agent::wire::cbor::DecodeLimits;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    #[test]
    fn manifest_vector_is_reproduced() {
        // The builder's encoder/signature path must match the published deterministic vector.
        let root = util::repo_root();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("device/common/vectors/manifest_signed.json")).unwrap()).unwrap();
        let mv = &v["manifest"];
        let m = Manifest {
            product: mv["product"].as_str().unwrap().into(),
            version: mv["version"].as_str().unwrap().into(),
            version_code: mv["version_code"].as_u64().unwrap(),
            image_sha256: hex::decode(mv["image_sha256_hex"].as_str().unwrap()).unwrap().try_into().unwrap(),
            image_size: mv["image_size"].as_u64().unwrap(),
            created_at: mv["created_at"].as_u64().unwrap(),
            min_version_code: mv["min_version_code"].as_u64().unwrap(),
            delta: None,
            signing_key_id: mv["signing_key_id"].as_str().unwrap().into(),
        };
        let payload = manifest::encode_manifest(&m).unwrap();
        assert_eq!(hex::encode(&payload), v["manifest_hex"].as_str().unwrap());
        let keys = super::super::keys::HarnessKeys::load(&root);
        let signed = manifest::sign_manifest(&payload, &keys.firmware, None).unwrap();
        assert_eq!(hex::encode(signed), v["signed_ed25519_only_hex"].as_str().unwrap());
    }

    #[test]
    fn variants() {
        let (k, u) = (key(1), key(2));
        let trusted = vec![k.verifying_key().to_bytes().to_vec()];
        let base = firmware_image(7, 200_000);
        let img = mutate_image(&base, 3, 1000);
        let spec = |image: Vec<u8>, vc: u64| BuildSpec {
            product: "p",
            version: "1.1.0",
            version_code: vc,
            image,
            base: Some(&base),
            key: &k,
            untrusted: &u,
        };
        let valid = build(Variant::Valid, &spec(img.clone(), 11)).unwrap();
        let vm = manifest::verify_manifest(&valid.notify_manifest, &trusted, false, DecodeLimits::default()).unwrap();
        assert_eq!(vm.manifest.image_sha256, sha256(&img));
        assert_eq!(valid.served, img);

        let unsigned = build(Variant::Unsigned, &spec(img.clone(), 11)).unwrap();
        assert!(manifest::verify_manifest(&unsigned.notify_manifest, &trusted, false, DecodeLimits::default()).is_err());
        assert_eq!(unsigned.notify_manifest[0] & 0xe0, 0xa0, "bare CBOR map");

        let tampered = build(Variant::Tampered, &spec(img.clone(), 11)).unwrap();
        assert_ne!(sha256(&tampered.served), tampered.manifest.image_sha256);
        assert_eq!(tampered.served.len(), img.len());
        assert_eq!(tampered.served.iter().zip(&img).filter(|(a, b)| a != b).count(), 1, "exactly one byte flipped");

        let untrusted = build(Variant::UntrustedKey, &spec(img.clone(), 11)).unwrap();
        let e = manifest::verify_manifest(&untrusted.notify_manifest, &trusted, false, DecodeLimits::default()).unwrap_err();
        assert_eq!(e.code().as_str(), "COSE_UNKNOWN_KEY");

        let d = build(Variant::Delta, &spec(img.clone(), 12)).unwrap();
        assert!(d.served.len() < img.len() / 4, "patch is small");
        assert_eq!(d.delta_from, Some(sha256(&base)));
        assert_eq!(delta::apply_delta(&base, &d.served, 1 << 30).unwrap(), img);
        let dm = manifest::verify_manifest(&d.notify_manifest, &trusted, false, DecodeLimits::default()).unwrap().manifest;
        assert_eq!(dm.delta.unwrap().patch_sha256, sha256(&d.served));
        assert!(build(Variant::Delta, &BuildSpec { base: None, ..spec(img, 13) }).is_err());
    }
}
