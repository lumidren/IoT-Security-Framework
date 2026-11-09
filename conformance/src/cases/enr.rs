//! C-ENR-1/2: zero-touch enrollment with attestation; refusal for a quarantined device.

use std::time::Duration;

use anyhow::Result;
use serde_json::json;

use super::{brief, ensure, fail, Ctx, Outcome};
use crate::harness::pki;

/// C-ENR-1.
pub async fn enr_1(ctx: &Ctx) -> Result<Outcome> {
    let dut = ctx.launch().await?;
    let st = dut.status().await?;
    if st["state"] != "unprovisioned" {
        ctx.warn(format!(
            "a fresh, never-enrolled device reports status.state={} (DUT_PROTOCOL: unprovisioned = no usable certificate)",
            st["state"]
        ));
    }
    let e = dut.enroll().await?;
    ctx.evidence(format!("enrolled {}", brief(&e.data)));
    let recs = match ctx.cloud.enrollments(dut.id()) {
        Ok(r) => r,
        Err(err) if err.downcast_ref::<crate::harness::Unsupported>().is_some() => return enr_1_real_pki(ctx, &dut, &e).await,
        Err(err) => return Err(err),
    };
    let ok: Vec<_> = recs.iter().filter(|r| r.status == 200).collect();
    ensure(ok.len() == 1, format!("expected exactly one successful EST enrollment, saw {}", ok.len()))?;
    let r = ok[0];
    ctx.evidence(format!(
        "EST: op={}, client cert serial {} (bootstrap {}), CSR CN={:?} OU={:?}, fresh key={}",
        if r.reenroll { "simplereenroll" } else { "simpleenroll" },
        r.client_serial_hex,
        dut.bootstrap_serial_hex,
        r.csr_cn,
        r.csr_ous,
        r.csr_key_fresh
    ));
    ensure(!r.reenroll, "first enrollment used simplereenroll")?;
    ensure(r.client_serial_hex == dut.bootstrap_serial_hex, "the TLS client certificate was not the bootstrap certificate")?;
    let att = r.attestation.clone().ok_or_else(|| fail("no attestation recorded"))?;
    ctx.evidence(format!(
        "attestation: kid {}, seq {}, ts {}, se_type {}, fw_version {}, fw_hash {}, signature by the TLS client key verified={}",
        att.kid_hex, att.seq, att.ts, att.se_type, att.fw_version, att.fw_hash_hex, att.signature_ok
    ));
    ensure(att.signature_ok, "attestation signature did not verify with the bootstrap key")?;
    ensure(att.kid_hex == dut.bootstrap_serial_hex, "attestation kid is not the bootstrap certificate serial")?;
    ensure(r.csr_cn.as_deref() == Some(dut.id()), format!("CSR CN {:?} != device id", r.csr_cn))?;
    ensure(r.csr_ous == vec![ctx.cloud.tenant_id.clone()], format!("CSR OU {:?} != tenant id", r.csr_ous))?;
    ensure(r.csr_key_fresh && r.csr_spki_sha256 != Some(r.client_spki_sha256), "the CSR reused the identity key")?;
    ensure(att.se_type == dut.info.se_type, format!("attested se_type {} != hello se_type {}", att.se_type, dut.info.se_type))?;
    ensure(e.data["se_type"] == att.se_type.as_str(), "enrolled.se_type differs from the attestation")?;
    let issued = r.issued_serial_hex.clone().unwrap_or_default();
    ensure(
        e.data["cert_serial_hex"] == issued.as_str(),
        format!("enrolled.cert_serial_hex {} != issued {issued}", e.data["cert_serial_hex"]),
    )?;
    let cert = ctx.cloud.certificate(&issued).await?;
    let f = pki::cert_facts(&cert)?;
    ensure(
        e.data["not_after"].as_u64() == Some(f.not_after),
        format!("enrolled.not_after {} != certificate notAfter {}", e.data["not_after"], f.not_after),
    )?;
    if att.fw_version != dut.info.fw_version {
        ctx.warn(format!("attested fw_version {} differs from hello fw_version {}", att.fw_version, dut.info.fw_version));
    }
    let st = dut.status().await?;
    ensure(st["cert_serial_hex"] == issued.as_str(), "status.cert_serial_hex is not the new certificate")?;
    ctx.measure("issued_serial", &issued);
    ctx.measure("assurance_ou", f.ous.join(","));
    Ok(Outcome::Pass)
}

/// C-ENR-1 against the real PKI: the PKI's EST handler verified the attestation (enrollment would
/// fail otherwise); the harness checks the issued certificate and the PKI's own records.
async fn enr_1_real_pki(ctx: &Ctx, dut: &crate::dut::Dut, e: &crate::dut::Event) -> Result<Outcome> {
    let serial = e.data["cert_serial_hex"].as_str().unwrap_or_default().to_owned();
    let cert = ctx.cloud.certificate(&serial).await?;
    let f = pki::cert_facts(&cert)?;
    ctx.evidence(format!("issued by the real PKI: subject {}, issuer {}, SAN {:?}", f.subject, f.issuer, f.san_uris));
    ensure(f.cn.as_deref() == Some(dut.id()), "certificate CN is not the device id")?;
    ensure(f.ous.contains(&ctx.cloud.tenant_id), "certificate OU does not carry the tenant")?;
    ensure(f.san_uris == vec![ironmesh_agent::x509::device_urn(&ctx.cloud.tenant_id, dut.id())], "SAN URI mismatch")?;
    ensure(e.data["not_after"].as_u64() == Some(f.not_after), "enrolled.not_after does not match the certificate")?;
    let boot = ctx.cloud.bootstrap_cert(dut.id()).ok_or_else(|| fail("bootstrap certificate unknown"))?;
    ensure(pki::cert_facts(&boot)?.spki_sha256 != f.spki_sha256, "the operational certificate certifies the bootstrap key")?;
    let recs = ctx.cloud.pki_device_certificates(dut.id()).await?;
    let list = recs
        .as_array()
        .cloned()
        .or_else(|| recs["items"].as_array().cloned())
        .or_else(|| recs["certificates"].as_array().cloned())
        .unwrap_or_default();
    let rec = list.iter().find(|r| r["serial"].as_str().is_some_and(|s| s.eq_ignore_ascii_case(&serial)));
    ctx.evidence(format!("PKI record: {}", rec.map(brief).unwrap_or_else(|| brief(&recs))));
    let rec = rec.ok_or_else(|| fail("the PKI has no record of the issued certificate"))?;
    ensure(rec["kind"] == "operational", format!("PKI record kind {}", rec["kind"]))?;
    ensure(
        rec["assurance_level"] == dut.info.se_type.as_str() || rec["assurance_level"] == "software",
        format!("PKI assurance {}", rec["assurance_level"]),
    )?;
    ctx.measure("issued_serial", &serial);
    ctx.measure("attestation_verified_by", "services/pki EST handler (real PKI)");
    Ok(Outcome::Pass)
}

/// C-ENR-2.
pub async fn enr_2(ctx: &Ctx) -> Result<Outcome> {
    let dut = ctx.launch().await?;
    ctx.cloud.quarantine(dut.id()).await?;
    let m = dut.mark();
    dut.ok("enroll", json!({})).await?;
    let e = dut.expect_any(m, &["enroll_failed", "enrolled"], Duration::from_secs(30)).await?;
    ctx.evidence(format!("{} {}", e.name, brief(&e.data)));
    ensure(e.name == "enroll_failed", "a quarantined device was enrolled")?;
    ctx.measure("http_status", e.data["http_status"].clone());
    if let Ok(recs) = ctx.cloud.enrollments(dut.id()) {
        for r in &recs {
            ctx.evidence(format!("EST answered {}: {}", r.status, r.error.clone().unwrap_or_default()));
        }
        ensure(recs.iter().all(|r| r.issued_der.is_none()), "a certificate was issued")?;
    }
    ensure(e.data["http_status"] == 403, format!("enroll_failed.http_status = {} (expected 403)", e.data["http_status"]))?;
    let st = dut.status().await?;
    ensure(st["cert_serial_hex"].is_null() || st["state"] == "unprovisioned", format!("status after the refusal: {}", brief(&st)))?;
    Ok(Outcome::Pass)
}
