//! Fleet simulator against the in-process backend doubles: provisioning, staggered enrollment,
//! telemetry from every device, an anomalous device, and the per-device memory footprint.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use ironmesh_agent::fleet::{self, Anomaly, Stats};
use ironmesh_agent::identity::software::{SecretSource, SoftwareIdentity};
use ironmesh_agent::identity::{IdentityProvider, KeySlot};
use support::*;

fn rss() -> u64 {
    let mut sys = sysinfo::System::new();
    let pid = sysinfo::get_current_pid().unwrap();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    sys.process(pid).map_or(0, sysinfo::Process::memory)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fleet_devices_enroll_and_publish() {
    let env = Env::new(3600).await;
    let fleet_dir = env.dir.path().join("fleet");
    let n: u64 = 60;
    let index = fleet::provision(&fleet_dir, n, TENANT, 0x00c0_ffee).unwrap();
    for id in &index.devices {
        let dir = fleet_dir.join(id);
        let ident = SoftwareIdentity::open(&dir, &SecretSource::File(dir.join("machine-secret"))).unwrap();
        let pk = ident.public_key(KeySlot::Bootstrap).unwrap();
        std::fs::write(dir.join("bootstrap.crt"), ironmesh_agent::x509::to_pem("CERTIFICATE", &env.pki.bootstrap_cert_for(id, &pk)))
            .unwrap();
    }
    let mut settings = env.settings.clone();
    settings.telemetry.interval_s = 1;
    let settings = Arc::new(settings);
    let stats = Arc::new(Stats::default());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let before = rss();
    let mut tasks = Vec::new();
    for (i, id) in index.devices.iter().enumerate() {
        let anomaly = (i == 0).then_some(Anomaly::TopicViolation);
        tasks.push(tokio::spawn(fleet::run_device(
            settings.clone(),
            fleet_dir.join(id),
            i as u64,
            anomaly,
            stats.clone(),
            stop_rx.clone(),
        )));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    wait_until(Duration::from_secs(90), || stats.connected.load(Ordering::Relaxed) == n).await;
    let after = rss();
    wait_until(Duration::from_secs(30), || {
        let p = env.broker.state.lock().unwrap();
        index.devices.iter().all(|d| p.publishes.iter().any(|m| m.topic.contains(d.as_str())))
    })
    .await;
    assert_eq!(stats.enrolled.load(Ordering::Relaxed), n);
    wait_until(Duration::from_secs(10), || !env.broker.state.lock().unwrap().denied.is_empty()).await;
    let per_device = after.saturating_sub(before) / n;
    println!("fleet: {n} connected devices, ~{} KiB RSS per device (debug build, includes EST/TLS/broker-side state)", per_device / 1024);
    let _ = stop_tx.send(true);
    for t in tasks {
        tokio::time::timeout(Duration::from_secs(10), t).await.unwrap().unwrap();
    }
    assert_eq!(stats.connected.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn offline_bench_footprint() {
    let r = fleet::bench(2000, 2).await;
    assert_eq!(r.messages, 4000);
    println!("bench: {} devices, {} bytes/device", r.devices, r.bytes_per_device);
}
