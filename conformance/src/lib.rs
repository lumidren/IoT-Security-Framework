//! IronMesh device conformance suite.
//!
//! One suite, run unchanged against every firmware target through the DUT control protocol
//! (`conformance/DUT_PROTOCOL.md`). The crate has four layers:
//!
//! * [`harness`]: the hermetic cloud (test PKI, EST server, MQTT 5 broker double that delegates
//!   every authn/authz decision to the **real** policy service, OTA artifact server, fault
//!   injection) and the `--stack` adapter for a real deployment.
//! * [`dut`]: the [`dut::Dut`] handle and one launcher per target (`agent-rs`, `esp32-host`,
//!   `esp32-hil`).
//! * [`cases`]: one module per case family of the DUT_PROTOCOL case table.
//! * [`report`]: JUnit XML, the per-target Markdown report and the cross-target summary.
//! * [`load`]: the 10 000-device load test on the same hermetic cloud (`ironmesh-conformance load`).
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod cases;
pub mod dut;
pub mod harness;
pub mod load;
pub mod report;
pub mod util;

/// Install the process-wide rustls crypto provider (ring). Idempotent.
pub fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
