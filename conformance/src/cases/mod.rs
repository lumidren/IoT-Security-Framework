//! The conformance cases of `conformance/DUT_PROTOCOL.md`, one module per family. Every case
//! starts its own freshly provisioned device (fresh device id, so state in the real policy
//! service - notably its persistent revocation deny list - never leaks between cases), drives it
//! only through the DUT protocol, and cross-checks DUT events against what the cloud observed on
//! the wire (broker packets, EST requests, signatures verified by the harness).

pub mod acl;
pub mod cfg;
pub mod enr;
pub mod hook;
pub mod off;
pub mod ota;
pub mod rev;
pub mod rot;
pub mod rpl;
pub mod tls;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use ironmesh_agent::wire::envelope::Verified;

use crate::dut::{Dut, LaunchOptions, Launcher, TargetProfile};
use crate::harness::{downlink, pki, Cloud, Unsupported};

/// Case verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Criterion met.
    Passed,
    /// Criterion not met (DUT behaviour).
    Failed,
    /// Not applicable to this target / mode, with a written reason.
    NotApplicable,
    /// The harness could not run the case.
    Error,
}

impl Verdict {
    /// Report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Verdict::Passed => "pass",
            Verdict::Failed => "FAIL",
            Verdict::NotApplicable => "n/a",
            Verdict::Error => "ERROR",
        }
    }
}

/// The result of one case.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CaseResult {
    /// Case id (`C-TLS-1`).
    pub id: String,
    /// Title.
    pub title: String,
    /// Pass criterion of the table.
    pub criterion: String,
    /// Verdict.
    pub verdict: Verdict,
    /// Failure / n/a reason.
    pub reason: String,
    /// Measured values `(name, value)`.
    pub measurements: Vec<(String, String)>,
    /// Evidence lines.
    pub evidence: Vec<String>,
    /// Warnings (contract deviations outside the pass criterion).
    pub warnings: Vec<String>,
    /// Duration (s).
    pub seconds: f64,
    /// Raw numeric series for the summary (e.g. revocation latencies).
    pub series: Vec<(String, Vec<f64>)>,
}

/// What a case function returns on success.
pub enum Outcome {
    /// Passed.
    Pass,
    /// Not applicable with a reason.
    NotApplicable(String),
}

/// A case failure carrying the reason (anything else that bubbles up is also a failure).
#[derive(Debug)]
pub struct Fail(pub String);

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Fail {}

/// Fail the case unless `cond`.
///
/// # Errors
/// `cond` is false.
pub fn ensure(cond: bool, msg: impl Into<String>) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(anyhow::Error::new(Fail(msg.into())))
    }
}

/// A failure.
#[must_use]
pub fn fail(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Fail(msg.into()))
}

#[derive(Default)]
struct Recorder {
    measurements: Vec<(String, String)>,
    evidence: Vec<String>,
    warnings: Vec<String>,
    series: Vec<(String, Vec<f64>)>,
}

/// Everything a case gets.
pub struct Ctx {
    /// The cloud.
    pub cloud: Arc<Cloud>,
    /// The target launcher.
    pub launcher: Arc<Launcher>,
    /// Target profile.
    pub profile: TargetProfile,
    /// Case id.
    pub case_id: String,
    /// Options.
    pub options: RunOptions,
    rec: Mutex<Recorder>,
    duts: Mutex<Vec<Arc<Dut>>>,
}

/// Run-wide options.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// C-REV-1 iterations.
    pub rev_iterations: usize,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self { rev_iterations: 20 }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Ctx {
    /// Record a measurement.
    pub fn measure(&self, name: &str, value: impl std::fmt::Display) {
        lock(&self.rec).measurements.push((name.to_owned(), value.to_string()));
    }

    /// Record an evidence line.
    pub fn evidence(&self, line: impl Into<String>) {
        lock(&self.rec).evidence.push(line.into());
    }

    /// Record a warning.
    pub fn warn(&self, line: impl Into<String>) {
        lock(&self.rec).warnings.push(line.into());
    }

    /// Record a numeric series.
    pub fn series(&self, name: &str, values: Vec<f64>) {
        lock(&self.rec).series.push((name.to_owned(), values));
    }

    /// Provision and start a fresh device.
    ///
    /// # Errors
    /// Launch failures.
    pub async fn launch(&self) -> Result<Arc<Dut>> {
        self.launch_with(LaunchOptions { label: self.case_id.clone(), backoff_scale: None }).await
    }

    /// Provision and start with options.
    ///
    /// # Errors
    /// Launch failures.
    pub async fn launch_with(&self, opts: LaunchOptions) -> Result<Arc<Dut>> {
        let d = Arc::new(self.launcher.launch(&self.cloud, &opts).await.map_err(|e| anyhow!("launch DUT: {e:#}"))?);
        self.evidence(format!(
            "DUT {} ({} fw {} code {}, se_type {}), bootstrap serial {}",
            d.id(),
            d.info.target,
            d.info.fw_version,
            d.info.fw_version_code,
            d.info.se_type,
            d.bootstrap_serial_hex
        ));
        lock(&self.duts).push(d.clone());
        Ok(d)
    }

    /// Stop one DUT now (others are stopped when the case ends).
    pub async fn stop(&self, dut: &Arc<Dut>) {
        dut.shutdown().await;
        lock(&self.duts).retain(|d| !Arc::ptr_eq(d, dut));
    }

    /// The device's certificate public keys by serial (from EST issuance records).
    ///
    /// # Errors
    /// [`Unsupported`] in stack mode.
    pub fn device_keys(&self, device_id: &str) -> Result<Vec<(String, Vec<u8>)>> {
        // Certificates the device presented to the broker, plus what the in-process EST issued.
        let mut ders = self.cloud.broker("broker-side capture of client certificates")?.client_certs(device_id);
        if let Ok(recs) = self.cloud.enrollments(device_id) {
            ders.extend(recs.into_iter().filter_map(|r| r.issued_der));
        }
        let mut out: Vec<(String, Vec<u8>)> = Vec::new();
        for f in ders.iter().filter_map(|d| pki::cert_facts(d).ok()) {
            if !out.iter().any(|(s, _)| *s == f.serial_hex) {
                out.push((f.serial_hex, f.public_key_raw));
            }
        }
        Ok(out)
    }

    /// Uplinks the broker accepted from `device_id` on `suffix`, verified with the certificate key
    /// named by each message's kid. Unverifiable messages are returned as errors.
    ///
    /// # Errors
    /// [`Unsupported`] in stack mode.
    pub fn verified_uplinks(&self, device_id: &str, suffix: &str) -> Result<Vec<Result<Verified, String>>> {
        let keys = self.device_keys(device_id)?;
        let broker = self.cloud.broker("broker-side capture of uplinks")?;
        let now = crate::util::now_unix();
        Ok(broker
            .accepted_publishes(device_id, suffix)
            .into_iter()
            .map(|(_, wire)| {
                let kid = downlink::kid_hex(&wire).ok_or_else(|| "not a COSE_Sign1".to_string())?;
                let (_, key) =
                    keys.iter().find(|(s, _)| *s == kid).ok_or_else(|| format!("kid {kid} is not a certificate issued to this device"))?;
                downlink::verify_uplink(&wire, key, now).map_err(|e| e.to_string())
            })
            .collect())
    }
}

/// A case function.
pub type CaseFn = for<'a> fn(&'a Ctx) -> Pin<Box<dyn Future<Output = Result<Outcome>> + Send + 'a>>;

/// A case definition.
pub struct CaseDef {
    /// Id.
    pub id: &'static str,
    /// Title (from the case table).
    pub title: &'static str,
    /// Pass criterion (from the case table).
    pub criterion: &'static str,
    /// Implementation.
    pub run: CaseFn,
    /// Overall time limit.
    pub limit: Duration,
}

/// Box an async case function.
#[macro_export]
macro_rules! case_fn {
    ($f:path) => {{
        fn wrapper<'a>(
            ctx: &'a $crate::cases::Ctx,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<$crate::cases::Outcome>> + Send + 'a>> {
            Box::pin($f(ctx))
        }
        wrapper as $crate::cases::CaseFn
    }};
}

/// Every case, in table order.
#[must_use]
pub fn all() -> Vec<CaseDef> {
    let m = |id, title, criterion, run, mins: u64| CaseDef { id, title, criterion, run, limit: Duration::from_secs(mins * 60) };
    vec![
        m(
            "C-TLS-1",
            "mTLS handshake with valid operational cert",
            "`connected` with `tls_version=TLSv1.3`, `alpn=mqtt`",
            case_fn!(tls::tls_1),
            3,
        ),
        m(
            "C-TLS-2",
            "Broker presents cert from an unpinned CA (rogue broker)",
            "`connect_failed{reason=tls_pin_mismatch}`; no CONNECT packet observed",
            case_fn!(tls::tls_2),
            3,
        ),
        m("C-TLS-3", "Broker offers TLS 1.2 only", "`connect_failed{reason=tls_handshake}`", case_fn!(tls::tls_3), 3),
        m(
            "C-TLS-4",
            "Session resumption on reconnect",
            "second `connected.resumed=true` (where the target supports tickets)",
            case_fn!(tls::tls_4),
            3,
        ),
        m(
            "C-TLS-5",
            "Bounded reconnect backoff",
            "reconnect attempts follow base 1 s, factor 2, cap 300 s, full jitter (verified on attempt timestamps with clock scaling)",
            case_fn!(tls::tls_5),
            8,
        ),
        m(
            "C-ENR-1",
            "Zero-touch enrollment with attestation",
            "`enrolled`; harness verifies attestation, CSR CN, fresh key",
            case_fn!(enr::enr_1),
            3,
        ),
        m("C-ENR-2", "Enrollment refused for quarantined device", "`enroll_failed{http_status=403}`", case_fn!(enr::enr_2), 3),
        m(
            "C-ROT-1",
            "Certificate rotation (`renew`) keeps identity, changes key and serial",
            "`cert_renewed`, new serial, new SPKI, reconnect succeeds",
            case_fn!(rot::rot_1),
            3,
        ),
        m(
            "C-ROT-2",
            "Automatic rotation at 50 % lifetime (short-lived test certs)",
            "`cert_renewed` without an explicit `renew`",
            case_fn!(rot::rot_2),
            4,
        ),
        m(
            "C-REV-1",
            "Revocation reaction time",
            "revoke -> broker disconnect -> DUT cannot reconnect with the revoked cert, measured < 10 s",
            case_fn!(rev::rev_1),
            15,
        ),
        m(
            "C-REV-2",
            "Single-certificate revocation refuses the serial, renewed certificate admitted",
            "after a single-certificate revocation (`device_deny=false`) the revoked serial is refused at CONNECT (policy reason `revoked_serial`) while the renewed certificate is admitted and its session is not kicked; the device id is never deny-listed",
            case_fn!(rev::rev_2),
            4,
        ),
        m(
            "C-ACL-1",
            "Publish to another device's topic",
            "`publish_result.ok=false` (or disconnect) and harness subscriber receives nothing",
            case_fn!(acl::acl_1),
            3,
        ),
        m(
            "C-ACL-2",
            "Subscribe to another device's command topic or wildcard",
            "`subscribe_result.granted=false`",
            case_fn!(acl::acl_2),
            3,
        ),
        m("C-ACL-3", "Retained publish on telemetry", "rejected", case_fn!(acl::acl_3), 3),
        m("C-OTA-1", "Unsigned image", "`ota_state{state=rejected}`; active slot unchanged", case_fn!(ota::ota_1), 3),
        m(
            "C-OTA-2",
            "Tampered image (1 byte flipped, valid manifest)",
            "`ota_state{state=rejected, error=image_hash}`",
            case_fn!(ota::ota_2),
            3,
        ),
        m("C-OTA-3", "Manifest signed by an untrusted key", "rejected", case_fn!(ota::ota_3), 3),
        m("C-OTA-4", "Downgrade (`version_code` not greater)", "rejected", case_fn!(ota::ota_4), 3),
        m(
            "C-OTA-5",
            "Valid update applies and is marked healthy",
            "`rebooted{reason=ota_apply}`, new `version_code`, `ota_state=success`",
            case_fn!(ota::ota_5),
            5,
        ),
        m(
            "C-OTA-6",
            "Update that fails its health check rolls back",
            "`rebooted{reason=rollback}`, previous slot active, `ota_state=rolled_back`",
            case_fn!(ota::ota_6),
            8,
        ),
        m("C-OTA-7", "Delta update", "applied image hash equals full image hash", case_fn!(ota::ota_7), 6),
        m(
            "C-RPL-1",
            "Replayed command (same `seq`)",
            "`message_rejected{code=ENV_REPLAY}`; command not executed twice",
            case_fn!(rpl::rpl_1),
            3,
        ),
        m("C-RPL-2", "Command with stale timestamp", "`message_rejected{code=ENV_TS_SKEW}`", case_fn!(rpl::rpl_2), 3),
        m("C-RPL-3", "Command signed by a non-tenant key", "`message_rejected{code=COSE_SIGNATURE}`", case_fn!(rpl::rpl_3), 3),
        m("C-RPL-4", "Device `seq` strictly increases across reboot", "`status.seq_out` after reboot > before", case_fn!(rpl::rpl_4), 3),
        m(
            "C-OFF-1",
            "Offline buffering and resync",
            "telemetry sent while `net_down` is delivered after `net_up`, in order, no gaps, `buffer_flushed`",
            case_fn!(off::off_1),
            4,
        ),
        m("C-CFG-1", "Encrypted config delivery", "DUT applies config; retained broker copy is ciphertext only", case_fn!(cfg::cfg_1), 3),
        m("C-HOOK-1", "Release build has no control channel", "release `agent-rs` exits non-zero on `--dut`", case_fn!(hook::hook_1), 2),
    ]
}

/// Run one case.
pub async fn run_case(def: &CaseDef, cloud: Arc<Cloud>, launcher: Arc<Launcher>, options: RunOptions) -> CaseResult {
    let started = Instant::now();
    let ctx = Arc::new(Ctx {
        profile: launcher.profile(),
        cloud: cloud.clone(),
        launcher,
        case_id: def.id.to_owned(),
        options,
        rec: Mutex::new(Recorder::default()),
        duts: Mutex::new(Vec::new()),
    });
    let run = def.run;
    let c2 = ctx.clone();
    let limit = def.limit;
    let handle = tokio::spawn(async move { tokio::time::timeout(limit, run(&c2)).await });
    let joined = handle.await;
    let (verdict, reason) = match joined {
        Ok(Ok(Ok(Outcome::Pass))) => (Verdict::Passed, String::new()),
        Ok(Ok(Ok(Outcome::NotApplicable(r)))) => (Verdict::NotApplicable, r),
        Ok(Ok(Err(e))) => {
            if let Some(u) = e.downcast_ref::<Unsupported>() {
                (Verdict::NotApplicable, u.0.clone())
            } else {
                (Verdict::Failed, format!("{e:#}"))
            }
        }
        Ok(Err(_)) => (Verdict::Failed, format!("case did not finish within {limit:?}")),
        Err(e) => (Verdict::Error, format!("harness panic: {e}")),
    };
    let duts: Vec<Arc<Dut>> = lock(&ctx.duts).drain(..).collect();
    let mut warnings = Vec::new();
    for d in &duts {
        for v in d.link.violations() {
            warnings.push(format!("DUT protocol violation: {}", v.what));
        }
        for (op, t) in d.link.slow_responses() {
            warnings.push(format!("`{op}` answered after {:.1} s (protocol: within 5 s)", t.as_secs_f64()));
        }
        d.shutdown().await;
    }
    if let Ok(b) = cloud.broker("") {
        b.set_mode(crate::harness::broker::BrokerMode::Normal);
    }
    let rec = std::mem::take(&mut *lock(&ctx.rec));
    let mut all_warnings = rec.warnings;
    all_warnings.extend(warnings);
    CaseResult {
        id: def.id.into(),
        title: def.title.into(),
        criterion: def.criterion.into(),
        verdict,
        reason,
        measurements: rec.measurements,
        evidence: rec.evidence,
        warnings: all_warnings,
        seconds: started.elapsed().as_secs_f64(),
        series: rec.series,
    }
}

/// Short JSON rendering for evidence.
#[must_use]
pub fn brief(v: &serde_json::Value) -> String {
    let s = v.to_string();
    if s.len() > 300 {
        format!("{}...", &s[..300])
    } else {
        s
    }
}

/// Common: a DUT online with a verified broker session and its four downlink subscriptions
/// (shadow/desired, cmd/req, ota/notify, config) granted by the policy service.
///
/// # Errors
/// Any step failing.
pub async fn online(ctx: &Ctx, dut: &Dut) -> Result<()> {
    let since = Instant::now();
    let (e, c) = dut.online().await?;
    ctx.evidence(format!("enrolled {}; connected {}", brief(&e.data), brief(&c.data)));
    if let Ok(b) = ctx.cloud.broker("") {
        crate::util::wait_for(Duration::from_secs(5), || b.is_connected(dut.id()).then_some(()))
            .await
            .ok_or_else(|| fail("DUT reported `connected` but the broker has no session for it"))?;
        wait_subscriptions(ctx, dut, since).await;
    }
    Ok(())
}

/// Wait (up to 5 s) until the broker granted the device's downlink subscriptions since `since`.
pub async fn wait_subscriptions(ctx: &Ctx, dut: &Dut, since: Instant) {
    use ironmesh_agent::wire::ids::TopicClass;
    let Ok(b) = ctx.cloud.broker("") else { return };
    let want: Vec<String> = [TopicClass::ShadowDesired, TopicClass::CmdReq, TopicClass::OtaNotify, TopicClass::Config]
        .into_iter()
        .filter_map(|c| ctx.cloud.topic(dut.id(), c).ok())
        .collect();
    let granted = |b: &crate::harness::broker::Broker| -> Vec<String> {
        b.observations_since(since)
            .into_iter()
            .filter_map(|o| match o.kind {
                crate::harness::broker::ObsKind::Subscribe { client_id, filter, granted: true } if client_id == dut.id() => Some(filter),
                _ => None,
            })
            .collect()
    };
    let ok = crate::util::wait_for(Duration::from_secs(5), || {
        let g = granted(b);
        want.iter().all(|w| g.contains(w)).then_some(())
    })
    .await;
    if ok.is_none() {
        let g = granted(b);
        let missing: Vec<&String> = want.iter().filter(|w| !g.contains(w)).collect();
        ctx.warn(format!("downlink subscriptions not granted within 5 s of connecting: {missing:?}"));
    }
}

/// Wait until the DUT is back online after a disconnect that happened after event position
/// `mark` / instant `since`: a new `connected` event, a broker session and its subscriptions.
///
/// # Errors
/// Timeout.
pub async fn wait_reconnected(ctx: &Ctx, dut: &Dut, mark: usize, since: Instant, timeout: Duration) -> Result<()> {
    let b = ctx.cloud.broker("reconnect detection")?;
    let mut ev = dut.link.wait_event(mark, "connected", timeout, |_| true).await;
    if ev.is_none() {
        // ESP32: an explicit connect resets a long backoff.
        let m = dut.mark();
        let _ = dut.call("connect", serde_json::json!({})).await;
        ev = dut.link.wait_event(m, "connected", Duration::from_secs(15), |_| true).await;
    }
    ev.ok_or_else(|| fail("the DUT did not reconnect"))?;
    crate::util::wait_for(Duration::from_secs(5), || b.is_connected(dut.id()).then_some(()))
        .await
        .ok_or_else(|| fail("the DUT reported `connected` but the broker has no session"))?;
    wait_subscriptions(ctx, dut, since).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(())
}
