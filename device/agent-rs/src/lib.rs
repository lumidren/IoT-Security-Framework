//! IronMesh Linux device agent.
//!
//! See `README.md` for the architecture; the binding specifications are
//! `docs/DESIGN_CONTRACT.md`, `device/common/WIRE_FORMAT.md` and `device/common/DELTA_FORMAT.md`.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![warn(missing_docs)]

pub mod agent;
pub mod app;
pub mod buffer;
pub mod commands;
pub mod config;
#[cfg(feature = "dut-control")]
pub mod dut;
pub mod enroll;
pub mod est;
pub mod fleet;
pub mod identity;
pub mod logging;
pub mod mqtt;
pub mod ota;
pub mod persist;
pub mod seq;
pub mod settings;
pub mod shadow;
pub mod telemetry;
pub mod tls;
pub mod wire;
pub mod x509;
