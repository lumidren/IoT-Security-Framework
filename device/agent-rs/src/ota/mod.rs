//! Signed A/B firmware updates (contract §6): manifest verification (Ed25519 always, ML-DSA-65
//! when required), resumable download, anti-rollback, IMDELTA1 delta apply, slot switch and the
//! post-boot health gate.

pub mod boot;
pub mod download;
pub mod slots;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use self::boot::{BootControl, Slot};
use self::slots::{PendingUpdate, SlotMeta, SlotStore};
use crate::settings::OtaSettings;
use crate::wire::cbor::DecodeLimits;
use crate::wire::delta::{self, DeltaApplier};
use crate::wire::envelope::{OtaNotify, OtaState};
use crate::wire::error::ErrorCode;
use crate::wire::manifest::{self, Manifest};

/// One OtaStatus to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtaReport {
    /// Campaign.
    pub campaign_id: String,
    /// State.
    pub state: OtaState,
    /// 0..100.
    pub progress_pct: u8,
    /// Error code (wire code or local reason).
    pub error: Option<String>,
    /// Image hash after apply.
    pub fw_hash: Option<[u8; 32]>,
}

/// Why an update was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtaFailure {
    /// Stable code (`WIRE_FORMAT.md` §8 code, or `DOWNLOAD` / `IO` / `URL_NOT_ALLOWED`).
    pub code: String,
    /// Detail.
    pub detail: String,
}

impl OtaFailure {
    fn wire(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self { code: code.as_str().into(), detail: detail.into() }
    }

    fn local(code: &str, detail: impl Into<String>) -> Self {
        Self { code: code.into(), detail: detail.into() }
    }

    /// DUT `ota_state.error` short reason (`conformance/DUT_PROTOCOL.md` C-OTA-*).
    #[must_use]
    pub fn dut_reason(&self) -> &'static str {
        dut_reason(&self.code)
    }
}

/// Map a rejection code to the DUT `ota_state.error` vocabulary (`conformance/DUT_PROTOCOL.md`:
/// `unsigned`, `signature`, `untrusted_key`, `image_hash`, `downgrade`, `product`, `image_size`,
/// `delta`, `health_check`, `download`, or empty).
#[must_use]
pub fn dut_reason(code: &str) -> &'static str {
    match code {
        "MF_HASH_MISMATCH" => "image_hash",
        "MF_SIZE_MISMATCH" => "image_size",
        "MF_ROLLBACK" | "MF_MIN_VERSION" => "downgrade",
        "MF_PRODUCT" => "product",
        "COSE_UNKNOWN_KEY" => "untrusted_key",
        // Not a COSE_Sign at all: the manifest is unsigned.
        "COSE_TAG" | "COSE_STRUCTURE" => "unsigned",
        c if c.starts_with("CBOR_") => "unsigned",
        c if c.starts_with("COSE_") || c == "MLDSA_NOT_AVAILABLE" => "signature",
        c if c.starts_with("DELTA_") || c == "MF_NO_DELTA" => "delta",
        "HEALTH_CHECK" => "health_check",
        "DOWNLOAD" | "URL_NOT_ALLOWED" => "download",
        _ => "",
    }
}

/// The firmware the device is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningFirmware {
    /// Running slot.
    pub slot: Slot,
    /// Version.
    pub version: String,
    /// Version code (max of slot metadata and the anti-rollback floor).
    pub version_code: u64,
    /// SHA-256 of the running image.
    pub fw_hash: [u8; 32],
    /// Base image used for deltas (`None` if the running image is not available as a file).
    pub image_path: Option<PathBuf>,
}

/// Everything an update needs.
pub struct OtaContext {
    /// Settings.
    pub settings: OtaSettings,
    /// Slots.
    pub slots: SlotStore,
    /// Boot control.
    pub boot: Arc<dyn BootControl>,
    /// Bundle `fw_signing_pubkeys`.
    pub trusted_keys: Vec<Vec<u8>>,
    /// Hosts artifacts may be downloaded from ([`crate::settings::Settings::download_allowlist`]);
    /// empty means no host is allowed.
    pub allowed_hosts: Vec<String>,
    /// Running firmware.
    pub running: RunningFirmware,
    /// TLS for artifact downloads.
    pub download_tls: Arc<rustls::ClientConfig>,
    /// Network timeout.
    pub timeout: Duration,
}

/// Successful staging: the slot to boot next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    /// Slot marked pending.
    pub slot: Slot,
    /// Manifest.
    pub manifest: Manifest,
}

fn io_fail(e: impl std::fmt::Display) -> OtaFailure {
    OtaFailure::local("IO", e.to_string())
}

fn hex32(h: &[u8; 32]) -> String {
    hex::encode(h)
}

/// Verify, download, check and stage an update announced by `notify`.
///
/// `report` is called for every state transition (received, downloading, verifying, applying,
/// rebooting); the caller publishes OtaStatus and triggers the reboot after `Ok`.
///
/// # Errors
/// [`OtaFailure`] with the rejecting code; the active slot is never touched.
pub async fn stage_update(ctx: &OtaContext, notify: &OtaNotify, report: &(dyn Fn(OtaReport) + Send + Sync)) -> Result<Staged, OtaFailure> {
    let r = |state: OtaState, progress_pct: u8| {
        report(OtaReport { campaign_id: notify.campaign_id.clone(), state, progress_pct, error: None, fw_hash: None });
    };
    r(OtaState::Received, 0);
    let vm = manifest::verify_manifest(&notify.manifest, &ctx.trusted_keys, ctx.settings.pq_required, DecodeLimits::default())
        .map_err(|e| OtaFailure::wire(e.code(), e.detail()))?;
    let m = vm.manifest;
    let current = ctx.running.version_code;
    if m.product != ctx.settings.product {
        return Err(OtaFailure::wire(ErrorCode::MfProduct, "product mismatch"));
    }
    if m.version_code <= current {
        return Err(OtaFailure::wire(ErrorCode::MfRollback, format!("version_code {} <= current {current}", m.version_code)));
    }
    if current < m.min_version_code {
        return Err(OtaFailure::wire(ErrorCode::MfMinVersion, "current version below min_version_code"));
    }
    let url = download::parse_https_url(&notify.url).map_err(|e| OtaFailure::local("URL_NOT_ALLOWED", e.to_string()))?;
    check_download_host(&ctx.allowed_hosts, &url.host)?;
    let use_delta = match (&m.delta, notify.delta_from) {
        (Some(_), Some(from)) => {
            if from != ctx.running.fw_hash {
                return Err(OtaFailure::wire(ErrorCode::DeltaBaseHash, "delta_from is not the running image"));
            }
            true
        }
        (None, Some(_)) => return Err(OtaFailure::wire(ErrorCode::MfNoDelta, "OtaNotify announces a delta but the manifest has none")),
        _ => false,
    };
    let max_len = if use_delta { m.delta.as_ref().map_or(0, |d| d.patch_size) } else { m.image_size };
    if max_len > ctx.settings.max_image_size || m.image_size > ctx.settings.max_image_size {
        return Err(OtaFailure::wire(ErrorCode::MfSizeMismatch, "artifact larger than the configured slot size"));
    }
    let target = ctx.running.slot.other();
    crate::persist::ensure_private_dir(&ctx.slots.download_dir()).map_err(io_fail)?;
    let part = ctx.slots.download_dir().join(format!("{}.part", notify.campaign_id));
    r(OtaState::Downloading, 0);
    let (len, sha) = download::download(ctx.download_tls.clone(), &url, &part, max_len, ctx.timeout)
        .await
        .map_err(|e| OtaFailure::local("DOWNLOAD", e.to_string()))?;
    r(OtaState::Downloading, 100);
    r(OtaState::Verifying, 0);
    let staging = ctx.slots.staging_path(target);
    let image_sha: [u8; 32] = if use_delta {
        if let Err(code) = manifest::accept_patch_digest(&m, len, &sha, &ctx.running.fw_hash) {
            let _ = std::fs::remove_file(&part);
            return Err(OtaFailure::wire(code, "patch rejected"));
        }
        r(OtaState::Applying, 0);
        let base_path = ctx
            .running
            .image_path
            .clone()
            .ok_or_else(|| OtaFailure::wire(ErrorCode::DeltaBaseHash, "running image not available for delta"))?;
        apply_delta_file(&base_path, &part, &staging, m.image_size, &m)?
    } else {
        if let Err(code) = manifest::accept_image_digest(&m, len, &sha, current, &ctx.settings.product) {
            let _ = std::fs::remove_file(&part);
            return Err(OtaFailure::wire(code, "image rejected"));
        }
        r(OtaState::Applying, 0);
        std::fs::rename(&part, &staging).map_err(io_fail)?;
        sha
    };
    // Final acceptance on exactly the bytes that will boot.
    let produced_len = std::fs::metadata(&staging).map_err(io_fail)?.len();
    if let Err(code) = manifest::accept_image_digest(&m, produced_len, &image_sha, current, &ctx.settings.product) {
        let _ = std::fs::remove_file(&staging);
        return Err(OtaFailure::wire(code, "produced image rejected"));
    }
    // Fail closed (T-57): the anti-rollback floor must be durably at least the running version
    // before anything is applied; a floor store that cannot be written stops the update here.
    if let Err(e) = ctx.slots.raise_anti_rollback(current) {
        let _ = std::fs::remove_file(&staging);
        return Err(OtaFailure::local("IO", format!("anti-rollback floor could not be persisted: {e}")));
    }
    let image = ctx.slots.image_path(target);
    std::fs::rename(&staging, &image).map_err(io_fail)?;
    let _ = std::fs::remove_file(&part);
    ctx.slots
        .set_meta(
            target,
            &SlotMeta {
                product: m.product.clone(),
                version: m.version.clone(),
                version_code: m.version_code,
                sha256_hex: hex32(&image_sha),
                state: "pending".into(),
            },
        )
        .map_err(io_fail)?;
    ctx.slots
        .set_pending_update(Some(&PendingUpdate {
            campaign_id: notify.campaign_id.clone(),
            slot: target,
            previous: ctx.running.slot,
            version_code: m.version_code,
            sha256_hex: hex32(&image_sha),
        }))
        .map_err(io_fail)?;
    ctx.boot.set_pending(target).map_err(io_fail)?;
    r(OtaState::Rebooting, 100);
    Ok(Staged { slot: target, manifest: m })
}

/// T-60: the artifact host must be on the allowlist; an empty allowlist allows nothing.
///
/// # Errors
/// `URL_NOT_ALLOWED` (DUT `ota_state.error` = `download`).
pub fn check_download_host(allowed: &[String], host: &str) -> Result<(), OtaFailure> {
    if allowed.iter().any(|h| h.eq_ignore_ascii_case(host)) {
        Ok(())
    } else {
        Err(OtaFailure::local("URL_NOT_ALLOWED", format!("host {host} not allowlisted")))
    }
}

fn apply_delta_file(
    base: &std::path::Path,
    patch: &std::path::Path,
    out: &std::path::Path,
    max: u64,
    m: &Manifest,
) -> Result<[u8; 32], OtaFailure> {
    use std::io::{Read, Write};
    let base_file = std::fs::File::open(base).map_err(io_fail)?;
    let base_len = base_file.metadata().map_err(io_fail)?.len();
    let mut out_file = std::fs::File::create(out).map_err(io_fail)?;
    let mut hasher = Sha256::new();
    let result = {
        let mut applier = DeltaApplier::new(
            base_file,
            base_len,
            |d: &[u8]| {
                hasher.update(d);
                out_file.write_all(d)
            },
            max,
        );
        let mut patch_file = std::fs::File::open(patch).map_err(io_fail)?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut res = Ok(());
        loop {
            match patch_file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = applier.feed(&buf[..n]) {
                        res = Err(e);
                        break;
                    }
                }
                Err(e) => {
                    res = Err(delta::ApplyError::Sink(e));
                    break;
                }
            }
        }
        res.and_then(|()| applier.finish())
    };
    let header = match result {
        Ok(h) => h,
        Err(e) => {
            drop(out_file);
            let _ = std::fs::remove_file(out);
            return Err(match e.code() {
                Some(c) => OtaFailure::wire(c, e.to_string()),
                None => io_fail(e),
            });
        }
    };
    out_file.sync_all().map_err(io_fail)?;
    let delta_info = m.delta.as_ref().ok_or_else(|| OtaFailure::wire(ErrorCode::MfNoDelta, "no delta"))?;
    if header.base_sha256 != delta_info.base_sha256 {
        let _ = std::fs::remove_file(out);
        return Err(OtaFailure::wire(ErrorCode::DeltaBaseHash, "patch header base differs from manifest"));
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dut_reasons() {
        assert_eq!(dut_reason("MF_HASH_MISMATCH"), "image_hash");
        assert_eq!(dut_reason("COSE_SIGNATURE"), "signature");
        assert_eq!(dut_reason("COSE_PQ_REQUIRED"), "signature");
        assert_eq!(dut_reason("CBOR_TRUNCATED"), "unsigned");
        assert_eq!(dut_reason("COSE_TAG"), "unsigned");
        assert_eq!(dut_reason("MF_FIELD"), "");
        assert_eq!(dut_reason("DELTA_OP"), "delta");
        assert_eq!(dut_reason("MF_NO_DELTA"), "delta");
        assert_eq!(dut_reason("MF_ROLLBACK"), "downgrade");
        assert_eq!(dut_reason("MF_MIN_VERSION"), "downgrade");
        assert_eq!(dut_reason("MF_SIZE_MISMATCH"), "image_size");
        assert_eq!(dut_reason("MF_PRODUCT"), "product");
        assert_eq!(dut_reason("COSE_UNKNOWN_KEY"), "untrusted_key");
        assert_eq!(dut_reason("HEALTH_CHECK"), "health_check");
        assert_eq!(dut_reason("IO"), "");
        assert_eq!(OtaFailure::local("URL_NOT_ALLOWED", "x").dut_reason(), "download");
        assert_eq!(OtaFailure::local("DOWNLOAD", "x").dut_reason(), "download");
    }

    #[test]
    fn download_host_allowlist() {
        let allowed = vec!["pki.example".to_string(), "OTA.example".to_string()];
        assert!(check_download_host(&allowed, "pki.example").is_ok());
        assert!(check_download_host(&allowed, "ota.EXAMPLE").is_ok());
        let e = check_download_host(&allowed, "evil.example").unwrap_err();
        assert_eq!(e.code, "URL_NOT_ALLOWED");
        assert_eq!(e.dut_reason(), "download");
        // Empty no longer means "any host".
        assert_eq!(check_download_host(&[], "pki.example").unwrap_err().dut_reason(), "download");
        assert!(check_download_host(&allowed, "pki.example.evil").is_err());
    }

    #[test]
    fn delta_file_apply() {
        let dir = tempfile::tempdir().unwrap();
        let old: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
        let mut new = old.clone();
        new[5000] ^= 1;
        let patch = delta::make_delta(&old, &new);
        let base = dir.path().join("base");
        let pp = dir.path().join("patch");
        let out = dir.path().join("out");
        std::fs::write(&base, &old).unwrap();
        std::fs::write(&pp, &patch).unwrap();
        let m = Manifest {
            product: "p".into(),
            version: "1.0.0".into(),
            version_code: 2,
            image_sha256: Sha256::digest(&new).into(),
            image_size: new.len() as u64,
            created_at: 0,
            min_version_code: 0,
            delta: Some(manifest::DeltaInfo {
                base_sha256: Sha256::digest(&old).into(),
                patch_sha256: Sha256::digest(&patch).into(),
                patch_size: patch.len() as u64,
            }),
            signing_key_id: "k".into(),
        };
        let h = apply_delta_file(&base, &pp, &out, new.len() as u64, &m).unwrap();
        assert_eq!(h, <[u8; 32]>::from(Sha256::digest(&new)));
        assert_eq!(std::fs::read(&out).unwrap(), new);
        std::fs::write(&pp, &patch[..patch.len() - 1]).unwrap();
        let e = apply_delta_file(&base, &pp, &out, new.len() as u64, &m).unwrap_err();
        assert_eq!(e.code, "DELTA_MISSING_END");
        assert!(!out.exists());
    }
}
