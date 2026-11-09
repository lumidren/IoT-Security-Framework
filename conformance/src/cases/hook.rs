//! C-HOOK-1: the release build has no control channel.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{ensure, fail, Ctx, Outcome};
use crate::dut::Target;

/// C-HOOK-1.
pub async fn hook_1(ctx: &Ctx) -> Result<Outcome> {
    if ctx.profile.target != Target::AgentRs {
        return Ok(Outcome::NotApplicable(
            "C-HOOK-1 is defined for the agent-rs release binary. On ESP32 the channel is excluded at build time: the prod profile forces \
             CONFIG_IRONMESH_DUT_CONTROL=n (checked by device/esp32/tools/check_prod_config.py in CI); the esp32-host shim and the hil \
             profile are test builds by definition"
                .into(),
        ));
    }
    let bin = ctx.profile.release_binary.clone().ok_or_else(|| fail("no release agent-rs binary configured (--agent-release-bin)"))?;
    ensure(bin.is_file(), format!("release binary {} not found", bin.display()))?;
    let dir = ctx.cloud.run_dir.join("devices").join("C-HOOK-1");
    std::fs::create_dir_all(&dir)?;
    let mut c = tokio::process::Command::new(&bin);
    crate::dut::scrub_env(&mut c);
    let mut child = c
        .arg("--dut")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("spawn release ironmesh-agent --dut")?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"{\"id\":1,\"op\":\"hello\",\"args\":{}}\n").await;
    }
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .map_err(|_| fail("the release binary kept running with --dut"))??;
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out).await;
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err).await;
    }
    ctx.evidence(format!("{} --dut -> exit {:?}; stderr: {}", bin.display(), status.code(), err.trim()));
    ctx.measure("exit_code", status.code().map_or_else(|| "signal".into(), |c| c.to_string()));
    ensure(!status.success(), "the release binary exited 0 on --dut")?;
    ensure(!out.contains("\"ok\""), format!("the release binary answered on the control channel: {}", out.trim()))?;
    // Positive control: the conformance build of the same agent does answer `hello` (every other
    // case relies on it), so the absence above is the build gate, not a broken binary.
    Ok(Outcome::Pass)
}
