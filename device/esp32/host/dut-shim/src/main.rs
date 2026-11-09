//! `im-dut-shim`: DUT control protocol (conformance/DUT_PROTOCOL.md) over stdin/stdout for the
//! target `esp32-host`. One JSON request per line in, one response per line out, asynchronous
//! events interleaved as their own lines. All protocol logic runs in the ESP32 C core.
//!
//! Usage:
//!   im-dut-shim                      simulated cloud (in-process broker / EST / artifacts)
//!   im-dut-shim --est HOST:PORT --ca ca.pem --bootstrap-cert boot.pem --bootstrap-key key.hex
//!               [--device-id dev-..] [--tenant-id uuid] [--bundle-pubkey hex32]
//!               [--est-pin hex32]... [--ota-host HOST]
//!                                    real IronMesh stack (TLS 1.3 + EST); not run in this repo's
//!                                    host CI, see README

use im_shim::{net::RealConfig, Device, DeviceConfig};
use std::io::{BufRead, Write};
use std::sync::mpsc;
use std::time::Duration;

fn pem_blocks(text: &str) -> Vec<Vec<u8>> {
    use base64::Engine;
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.starts_with("-----BEGIN") {
            inside = true;
            cur.clear();
        } else if line.starts_with("-----END") {
            inside = false;
            if let Ok(d) = base64::engine::general_purpose::STANDARD.decode(cur.trim()) {
                out.push(d);
            }
        } else if inside {
            cur.push_str(line.trim());
        }
    }
    out
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    if s.len() != 64 {
        return Err("expected 64 hex chars".into());
    }
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn config(args: &[String]) -> Result<DeviceConfig, String> {
    let mut cfg = DeviceConfig::sim();
    if let Some(v) = arg(args, "--device-id") {
        cfg.device_id = v;
    }
    if let Some(v) = arg(args, "--tenant-id") {
        cfg.tenant_id = v;
    }
    if let Some(v) = arg(args, "--telemetry-interval") {
        cfg.telemetry_interval_s = v.parse().map_err(|e| format!("--telemetry-interval: {e}"))?;
    }
    if let Some(est) = arg(args, "--est") {
        let (host, port) = est.rsplit_once(':').ok_or("--est HOST:PORT")?;
        let ca = std::fs::read_to_string(arg(args, "--ca").ok_or("--ca required")?).map_err(|e| e.to_string())?;
        let boot = std::fs::read_to_string(arg(args, "--bootstrap-cert").ok_or("--bootstrap-cert required")?).map_err(|e| e.to_string())?;
        let key = std::fs::read_to_string(arg(args, "--bootstrap-key").ok_or("--bootstrap-key required")?).map_err(|e| e.to_string())?;
        let bootstrap_cert = pem_blocks(&boot).into_iter().next().ok_or("bootstrap cert PEM")?;
        let serial = im_shim::der::parse_cert(&bootstrap_cert).ok_or("bootstrap cert DER")?.serial;
        let mut kid = serial.as_slice();
        while kid.len() > 1 && kid[0] == 0 {
            kid = &kid[1..];
        }
        cfg.bootstrap_serial = kid.to_vec();
        cfg.bundle_pubkey = hex32(&arg(args, "--bundle-pubkey").ok_or("--bundle-pubkey required")?)?;
        let ca_roots = pem_blocks(&ca);
        // T-29: factory EST pins (repeatable --est-pin); default: the non-self-issued CA(s) in --ca.
        let explicit: Vec<[u8; 32]> = args
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--est-pin")
            .map(|(i, _)| args.get(i + 1).ok_or("--est-pin needs a value".to_string()).and_then(|v| hex32(v)))
            .collect::<Result<_, _>>()?;
        let est_pins = if explicit.is_empty() {
            im_shim::net::default_est_pins(&ca_roots)
        } else {
            explicit
        };
        // T-60: artifacts only from the bundle's broker host or this host (default: the EST host).
        cfg.ota_host = arg(args, "--ota-host").unwrap_or_else(|| host.to_string());
        cfg.real = Some(RealConfig {
            est_host: host.into(),
            est_port: port.parse().map_err(|e| format!("--est port: {e}"))?,
            ca_roots,
            bootstrap_cert,
            bootstrap_key: hex32(key.trim())?,
            est_pins,
        });
    }
    Ok(cfg)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cfg = match config(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("im-dut-shim: {e}");
            std::process::exit(2);
        }
    };
    let mut dev = match Device::new(cfg) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("im-dut-shim: device init failed: {e}");
            std::process::exit(1);
        }
    };
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let stdout = std::io::stdout();
    let mut eof = false;
    loop {
        let mut out = stdout.lock();
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(line) => {
                let line = line.trim_end_matches('\r');
                if !line.trim().is_empty() {
                    let resp = dev.handle_line(line);
                    let _ = writeln!(out, "{resp}");
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => dev.poll(),
            Err(mpsc::RecvTimeoutError::Disconnected) => eof = true,
        }
        for ev in dev.take_events() {
            let _ = writeln!(out, "{ev}");
        }
        let _ = out.flush();
        if eof {
            break;
        }
    }
}
