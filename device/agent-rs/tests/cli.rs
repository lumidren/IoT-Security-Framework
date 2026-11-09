//! Command-line behaviour of the `ironmesh-agent` binary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ironmesh-agent"))
}

fn config(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("agent.toml");
    let root = dir.display().to_string().replace('\\', "/");
    std::fs::write(
        &p,
        format!(
            "[identity]\ndir = \"{root}/identity\"\nmachine_secret = \"{root}/identity/machine-secret\"\n[ota]\nslots_dir = \"{root}/slots\"\n[agent]\nstate_dir = \"{root}/state\"\n"
        ),
    )
    .unwrap();
    p
}

/// C-HOOK-1: a build without `dut-control` refuses `--dut` with a non-zero status.
#[cfg(not(feature = "dut-control"))]
#[test]
fn release_build_rejects_dut() {
    let out = bin().arg("--dut").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("dut-control"));
}

#[test]
fn factory_mode_prints_a_csr_and_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let run = || {
        bin()
            .args(["--config"])
            .arg(&cfg)
            .args(["--factory", "--device-id", "dev-0123456789abcdef", "--tenant-id", "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11", "--software"])
            .output()
            .unwrap()
    };
    let out = run();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let pem = String::from_utf8(out.stdout).unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
    let der = ironmesh_agent::x509::pem_or_der_first(pem.replace("CERTIFICATE REQUEST", "CERTIFICATE").as_bytes()).unwrap();
    let (cn, ou, _) = ironmesh_agent::x509::inspect_csr(&der).unwrap();
    assert_eq!(cn.as_deref(), Some("dev-0123456789abcdef"));
    assert_eq!(ou, vec!["7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11".to_string()]);
    assert!(!run().status.success(), "second factory run must not overwrite the key");
    let bad = bin().args(["--config"]).arg(&cfg).args(["--factory", "--device-id", "nope", "--tenant-id", "x"]).output().unwrap();
    assert!(!bad.status.success());
    // Installing a certificate that does not match the key fails.
    std::fs::write(dir.path().join("junk.crt"), b"junk").unwrap();
    let out = bin().args(["--config"]).arg(&cfg).arg("--install-bootstrap").arg(dir.path().join("junk.crt")).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn boot_status_and_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let out = bin().args(["--config"]).arg(&cfg).arg("--boot-status").output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["active"], "a");
    assert!(v["pending"].is_null());
    // Not provisioned: no at-rest key, so the floor is reported as unavailable (never as 0).
    assert!(v["anti_rollback_version_code"].is_null());
    assert!(v["anti_rollback_status"].as_str().unwrap().starts_with("invalid: unavailable"));
    assert!(bin().args(["--config"]).arg(&cfg).arg("--rollback").status().unwrap().success());
    let out = bin().args(["--config"]).arg(dir.path().join("missing.toml")).arg("--boot-status").output().unwrap();
    assert!(!out.status.success());
    // The service refuses to start without an identity.
    let out = bin().args(["--config"]).arg(&cfg).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("identity"));
}
