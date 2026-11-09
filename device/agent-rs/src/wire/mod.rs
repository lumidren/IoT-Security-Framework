//! IronMesh wire format v1 (`device/common/WIRE_FORMAT.md`, `DELTA_FORMAT.md`).
//!
//! Everything in this module parses untrusted bytes: it never panics on any input (fuzzed, see
//! `fuzz/`), bounds every allocation by the input size and the decoder limits, and reports the
//! stable error codes of the specification.

pub mod attestation;
pub mod cbor;
pub mod cose;
pub mod delta;
pub mod envelope;
pub mod error;
pub mod hpke;
pub mod ids;
pub mod keys;
pub mod manifest;

pub use error::{ErrorCode, WireError, WireResult};
