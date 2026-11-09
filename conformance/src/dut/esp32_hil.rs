//! `esp32-hil` launcher: a real ESP32 board built with the `hil` profile
//! (`CONFIG_IRONMESH_DUT_CONTROL=y`), driven over USB-Serial/JTAG. Protocol lines carry the
//! `@@IM ` prefix; everything else on the port is device log output (kept in the transcript).
//!
//! The board is provisioned at the HIL station (bootstrap key in the ATECC608B, bootstrap
//! certificate from the HIL Factory CA, PKI bundle key and EST host in Kconfig). The HIL job
//! therefore starts the hermetic cloud with that Factory CA, bundle key and fixed ports
//! (`--hil-config`, see `README.md`). Only the transport and framing are exercised on the
//! development host, with a fake serial pair; the board itself runs in the HIL CI job.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

use super::{device_dir, Dut, DutLink, LaunchOptions, Resumption, Target, TargetProfile};
use crate::harness::Cloud;

/// `--hil-config` (TOML).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HilConfig {
    /// Serial port (`COM7`, `/dev/ttyACM0`).
    pub port: String,
    /// Baud rate (USB-Serial/JTAG ignores it).
    #[serde(default = "default_baud")]
    pub baud: u32,
    /// The board's bootstrap certificate (PEM), registered as the manufacture record.
    pub bootstrap_cert: PathBuf,
    /// Secure element type of the board.
    #[serde(default = "default_se")]
    pub se_type: String,
    /// Harness PKI written by `ironmesh-conformance export-pki` that the board was provisioned
    /// from (anchors, EST pin and bundle key in Kconfig, bootstrap certificate from its Factory CA).
    pub pki_dir: PathBuf,
    /// Host the board reaches the harness on (Wi-Fi LAN address).
    pub advertise_host: String,
    /// Fixed EST port (Kconfig `IRONMESH_EST_PORT`).
    pub est_port: u16,
}

fn default_baud() -> u32 {
    115_200
}

fn default_se() -> String {
    "atecc608".into()
}

/// Launcher.
pub struct Esp32HilLauncher {
    /// Configuration.
    pub config: HilConfig,
}

/// Bridge a blocking `Read`/`Write` pair (a serial port) to an async duplex stream. Two threads
/// pump bytes; they exit when either side closes.
pub fn bridge_blocking<R, W>(mut reader: R, mut writer: W) -> tokio::io::DuplexStream
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let (ours, theirs) = tokio::io::duplex(1 << 18);
    let (mut from_dev_tx, mut to_dev_rx) = {
        let (r, w) = tokio::io::split(theirs);
        (w, r)
    };
    let rt = tokio::runtime::Handle::current();
    let rt2 = rt.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    use tokio::io::AsyncWriteExt;
                    if rt.block_on(from_dev_tx.write_all(&buf[..n])).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
    });
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            use tokio::io::AsyncReadExt;
            match rt2.block_on(to_dev_rx.read(&mut buf)) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if writer.write_all(&buf[..n]).and_then(|()| writer.flush()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    ours
}

impl Esp32HilLauncher {
    /// Load the configuration.
    ///
    /// # Errors
    /// Unreadable / invalid file.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Ok(Self { config: toml::from_str(&text)? })
    }

    /// Profile.
    #[must_use]
    pub fn profile(&self) -> TargetProfile {
        TargetProfile {
            target: Target::Esp32Hil,
            product: super::esp32_host::PRODUCT.into(),
            set_clock: false,
            resumption: Resumption::TicketOffered,
            backoff_scale: 1.0,
            health_timeout_s: 120,
            benign_command: "noop".into(),
            factory_image: None,
            release_binary: None,
        }
    }

    /// Open the port and attach. The board keeps its identity across cases (one physical device),
    /// so its manufacture record is (re-)registered every time.
    ///
    /// # Errors
    /// Port or protocol failures.
    pub async fn launch(&self, cloud: &Cloud, opts: &LaunchOptions) -> Result<Dut> {
        let port = serialport::new(&self.config.port, self.config.baud)
            .timeout(Duration::from_millis(200))
            .open()
            .with_context(|| format!("open serial port {}", self.config.port))?;
        let writer = port.try_clone().context("clone serial port")?;
        let stream = bridge_blocking(port, writer);
        let (r, w) = tokio::io::split(stream);
        let link = DutLink::spawn(r, w, Some(super::link::SERIAL_PREFIX));
        let boot = ironmesh_agent::x509::pem_or_der_first(&std::fs::read(&self.config.bootstrap_cert)?).map_err(|e| anyhow!("{e}"))?;
        let facts = crate::harness::pki::cert_facts(&boot)?;
        let device_id = facts.cn.clone().ok_or_else(|| anyhow!("bootstrap certificate has no CN"))?;
        cloud.register_device(&device_id, &self.config.se_type, &facts.serial_hex, super::esp32_host::PRODUCT).await?;
        let dir = device_dir(cloud, &opts.label, &device_id);
        std::fs::create_dir_all(&dir)?;
        Dut::attach(link, self.profile(), dir, facts.serial_hex, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::mpsc;

    /// One end of an in-memory "serial pair": blocking reads with a timeout, like a tty.
    struct FakeSerial {
        rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::Sender<Vec<u8>>,
        pending: Vec<u8>,
    }

    fn pair() -> (FakeSerial, FakeSerial) {
        let (a_tx, b_rx) = mpsc::channel();
        let (b_tx, a_rx) = mpsc::channel();
        (FakeSerial { rx: a_rx, tx: a_tx, pending: Vec::new() }, FakeSerial { rx: b_rx, tx: b_tx, pending: Vec::new() })
    }

    impl Read for FakeSerial {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pending.is_empty() {
                match self.rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(d) => self.pending = d,
                    Err(mpsc::RecvTimeoutError::Timeout) => return Err(std::io::ErrorKind::TimedOut.into()),
                    Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
                }
            }
            let n = buf.len().min(self.pending.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            Ok(n)
        }
    }

    impl Write for FakeSerial {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.tx.send(buf.to_vec()).map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl FakeSerial {
        fn split(self) -> (Self, Self) {
            // Read half keeps rx, write half keeps tx (a cloned port in serialport terms).
            let (dummy_tx, dummy_rx) = mpsc::channel();
            drop(dummy_tx);
            let r = FakeSerial { rx: self.rx, tx: mpsc::channel().0, pending: Vec::new() };
            let w = FakeSerial { rx: dummy_rx, tx: self.tx, pending: Vec::new() };
            (r, w)
        }
    }

    /// The board side: emits boot log noise, answers `@@IM ` requests, interleaves log lines,
    /// splits one protocol line across two writes (as UART FIFOs do).
    fn fake_board(mut port: FakeSerial) {
        std::thread::spawn(move || {
            port.write_all(b"ets Jun  8 2016 00:22:57\r\nrst:0x1 (POWERON_RESET)\r\nI (312) ironmesh: boot\r\n").unwrap();
            let mut acc = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = match port.read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => continue,
                };
                acc.extend_from_slice(&buf[..n]);
                while let Some(i) = acc.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = acc.drain(..=i).collect();
                    let text = String::from_utf8_lossy(&line).trim().to_string();
                    let body = text.strip_prefix("@@IM ").expect("host frames requests");
                    let v: Value = serde_json::from_str(body).unwrap();
                    let id = v["id"].as_u64().unwrap();
                    let resp = match v["op"].as_str().unwrap() {
                        "hello" => {
                            json!({"id": id, "ok": true, "result": {"target": "esp32-hil", "fw_version": "1.0.0", "fw_version_code": 10000,
                            "se_type": "atecc608", "device_id": "dev-00000000000000aa", "tenant_id": "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11", "protocol_version": 1}})
                        }
                        "connect" => {
                            let ev = json!({"event": "connect_failed", "at_ms": 1234, "data": {"reason": "tls_pin_mismatch"}});
                            port.write_all(format!("W (5000) mqtt: handshake failed\r\n@@IM {ev}\r\n").as_bytes()).unwrap();
                            json!({"id": id, "ok": true, "result": {}})
                        }
                        _ => json!({"id": id, "ok": false, "error": {"code": "unsupported", "message": "?"}}),
                    };
                    let s = format!("@@IM {resp}\r\n");
                    let (a, b) = s.as_bytes().split_at(s.len() / 2);
                    port.write_all(a).unwrap();
                    std::thread::sleep(Duration::from_millis(5));
                    port.write_all(b).unwrap();
                }
            }
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hil_framing_over_a_fake_serial_pair() {
        let (host, board) = pair();
        fake_board(board);
        let (r, w) = host.split();
        let stream = bridge_blocking(r, w);
        let (rd, wr) = tokio::io::split(stream);
        let link = DutLink::spawn(rd, wr, Some(super::super::link::SERIAL_PREFIX));
        let h = link.call("hello", json!({}), Duration::from_secs(5)).await.unwrap();
        assert_eq!(h["target"], "esp32-hil");
        assert_eq!(h["protocol_version"], 1);
        let m = link.mark();
        link.call("connect", json!({}), Duration::from_secs(5)).await.unwrap();
        let e = link.wait_event(m, "connect_failed", Duration::from_secs(5), |_| true).await.unwrap();
        assert_eq!(e.data["reason"], "tls_pin_mismatch");
        assert_eq!(e.at_ms, 1234);
        assert_eq!(link.call("format", json!({}), Duration::from_secs(5)).await.unwrap_err().code(), Some("unsupported"));
        assert!(link.violations().is_empty(), "{:?}", link.violations());
    }

    #[test]
    fn config_parsing() {
        let c: HilConfig = toml::from_str(
            "port = \"COM7\"\nbootstrap_cert = \"b.pem\"\npki_dir = \"hil-pki\"\nadvertise_host = \"192.168.1.10\"\nest_port = 8443\n",
        )
        .unwrap();
        assert_eq!(c.baud, 115_200);
        assert_eq!(c.se_type, "atecc608");
        assert!(toml::from_str::<HilConfig>("port = \"x\"\nbogus = 1\n").is_err());
    }
}
