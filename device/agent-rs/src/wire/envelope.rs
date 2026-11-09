//! Message envelope (`WIRE_FORMAT.md` §3): typed bodies, signing and the verification algorithm
//! of §3.6 with exactly the check order of `ironmesh_wire/envelope.py`.

use super::cbor::{self, DecodeLimits, Value};
use super::cose::{self, Kid};
use super::error::{err, ErrorCode as C, WireError, WireResult};
use super::ids::{self, Direction};
use super::keys::{CoseSigner, PublicKey, ALG_EDDSA, ALG_ES256};

/// Default timestamp window.
pub const MAX_SKEW_DEFAULT: u64 = 300;
/// Nonce size on Command/CommandAck.
pub const NONCE_SIZE: usize = 16;
const MAX_NAME_LEN: usize = 64;
const MAX_URL_LEN: usize = 2048;
const MAX_ERROR_LEN: usize = 1024;
const MAX_TOP_PROCS: usize = 10;

/// An application map (`AppMap = { * tstr => any }`), in canonical order once decoded.
pub type AppMap = Vec<(String, Value)>;

fn field(detail: &'static str) -> WireError {
    err(C::EnvField, detail)
}

// ---------------------------------------------------------------------------------------------
// Field accessors (fields.py)
// ---------------------------------------------------------------------------------------------

/// Typed accessors over an integer-keyed map with a configurable error code.
pub(crate) struct Fields<'a> {
    pub(crate) m: &'a [(Value, Value)],
    pub(crate) code: C,
}

impl<'a> Fields<'a> {
    pub(crate) fn new(m: &'a [(Value, Value)], code: C) -> Self {
        Self { m, code }
    }

    fn e(&self, detail: &'static str) -> WireError {
        err(self.code, detail)
    }

    pub(crate) fn get(&self, key: i128) -> Option<&'a Value> {
        self.m.iter().find_map(|(k, v)| (*k == Value::Int(key)).then_some(v))
    }

    pub(crate) fn expect_keys(&self, required: &[i128], optional: &[i128], detail: &'static str) -> WireResult<()> {
        if required.iter().any(|k| self.get(*k).is_none()) {
            return Err(self.e(detail));
        }
        let known = |k: &Value| matches!(k, Value::Int(i) if required.contains(i) || optional.contains(i));
        if self.m.iter().any(|(k, _)| !known(k)) {
            return Err(self.e(detail));
        }
        Ok(())
    }

    pub(crate) fn uint_max(&self, key: i128, max: u64, detail: &'static str) -> WireResult<u64> {
        match self.get(key) {
            Some(Value::Int(i)) if *i >= 0 && *i <= i128::from(max) => Ok(*i as u64),
            _ => Err(self.e(detail)),
        }
    }

    pub(crate) fn uint(&self, key: i128, detail: &'static str) -> WireResult<u64> {
        self.uint_max(key, u64::MAX, detail)
    }

    pub(crate) fn uint_opt(&self, key: i128, detail: &'static str) -> WireResult<Option<u64>> {
        self.get(key).map(|_| self.uint(key, detail)).transpose()
    }

    pub(crate) fn int_opt(&self, key: i128, detail: &'static str) -> WireResult<Option<i64>> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Int(i)) => i64::try_from(*i).map(Some).map_err(|_| self.e(detail)),
            Some(_) => Err(self.e(detail)),
        }
    }

    pub(crate) fn float(&self, key: i128, detail: &'static str) -> WireResult<f64> {
        match self.get(key) {
            Some(Value::Float(f)) => Ok(*f),
            _ => Err(self.e(detail)),
        }
    }

    pub(crate) fn float_opt(&self, key: i128, detail: &'static str) -> WireResult<Option<f64>> {
        self.get(key).map(|_| self.float(key, detail)).transpose()
    }

    /// Text with a length bound counted in Unicode scalar values (as the reference does).
    pub(crate) fn tstr(&self, key: i128, min: usize, max: usize, detail: &'static str) -> WireResult<String> {
        match self.get(key) {
            Some(Value::Text(t)) if (min..=max).contains(&t.chars().count()) => Ok(t.clone()),
            _ => Err(self.e(detail)),
        }
    }

    pub(crate) fn tstr_opt(&self, key: i128, min: usize, max: usize, detail: &'static str) -> WireResult<Option<String>> {
        self.get(key).map(|_| self.tstr(key, min, max, detail)).transpose()
    }

    pub(crate) fn bstr(&self, key: i128, len: Option<usize>, detail: &'static str) -> WireResult<Vec<u8>> {
        match self.get(key) {
            Some(Value::Bytes(b)) if len.is_none_or(|l| b.len() == l) => Ok(b.clone()),
            _ => Err(self.e(detail)),
        }
    }

    pub(crate) fn bstr32(&self, key: i128, detail: &'static str) -> WireResult<[u8; 32]> {
        let b = self.bstr(key, Some(32), detail)?;
        b.try_into().map_err(|_| self.e(detail))
    }

    pub(crate) fn bstr32_opt(&self, key: i128, detail: &'static str) -> WireResult<Option<[u8; 32]>> {
        self.get(key).map(|_| self.bstr32(key, detail)).transpose()
    }

    pub(crate) fn bstr32_or_null(&self, key: i128, detail: &'static str) -> WireResult<Option<[u8; 32]>> {
        match self.get(key) {
            None => Err(self.e(detail)),
            Some(Value::Null) => Ok(None),
            Some(_) => self.bstr32(key, detail).map(Some),
        }
    }

    pub(crate) fn app_map(&self, key: i128, detail: &'static str) -> WireResult<AppMap> {
        match self.get(key) {
            Some(Value::Map(entries)) => entries
                .iter()
                .map(|(k, v)| match k {
                    Value::Text(t) => Ok((t.clone(), v.clone())),
                    _ => Err(self.e(detail)),
                })
                .collect(),
            _ => Err(self.e(detail)),
        }
    }

    pub(crate) fn app_map_opt(&self, key: i128, detail: &'static str) -> WireResult<Option<AppMap>> {
        self.get(key).map(|_| self.app_map(key, detail)).transpose()
    }

    fn tstr_list_opt(&self, key: i128, max_items: usize, detail: &'static str) -> WireResult<Option<Vec<String>>> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Array(items)) if items.len() <= max_items => {
                items.iter().map(|v| v.as_text().map(str::to_owned).ok_or_else(|| self.e(detail))).collect::<WireResult<Vec<_>>>().map(Some)
            }
            Some(_) => Err(self.e(detail)),
        }
    }
}

fn app_map_value(m: &AppMap) -> Value {
    Value::Map(m.iter().map(|(k, v)| (Value::Text(k.clone()), v.clone())).collect())
}

fn uuid_field(v: String, detail: &'static str) -> WireResult<String> {
    if ids::is_uuid(&v) {
        Ok(v)
    } else {
        Err(field(detail))
    }
}

fn uuid4_field(v: String, detail: &'static str) -> WireResult<String> {
    if ids::is_uuid4(&v) {
        Ok(v)
    } else {
        Err(field(detail))
    }
}

fn semver_field(v: String) -> WireResult<String> {
    if ids::is_semver(&v) {
        Ok(v)
    } else {
        Err(field("fw_version: not a semantic version"))
    }
}

// ---------------------------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------------------------

/// Telemetry body (type 1).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Telemetry {
    /// 1
    pub cpu_pct: f64,
    /// 2
    pub mem_pct: f64,
    /// 3
    pub net_rx_bytes: u64,
    /// 4
    pub net_tx_bytes: u64,
    /// 5
    pub temp_c: f64,
    /// 6
    pub uptime_s: u64,
    /// 7
    pub auth_failures: u64,
    /// 8
    pub fw_hash: [u8; 32],
    /// 9
    pub fw_version: String,
    /// 10
    pub proc_count: Option<u64>,
    /// 11
    pub top_procs: Option<Vec<String>>,
    /// 12
    pub rssi: Option<i64>,
    /// 13
    pub free_heap: Option<u64>,
    /// 14
    pub lat: Option<f64>,
    /// 15
    pub lon: Option<f64>,
}

/// Event body (type 2).
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// 1
    pub name: String,
    /// 2 (0..4)
    pub severity: u8,
    /// 3
    pub data: AppMap,
}

/// Shadow state body (types 3 and 4).
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowState {
    /// 1
    pub state: AppMap,
    /// 2
    pub version: u64,
}

/// Command body (type 5).
#[derive(Debug, Clone, PartialEq)]
pub struct Command {
    /// 1
    pub cmd_id: String,
    /// 2
    pub name: String,
    /// 3
    pub args: AppMap,
    /// 4
    pub idempotency_key: String,
    /// 5
    pub expires_at: u64,
}

/// CommandAck status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AckStatus {
    /// 0
    Ok = 0,
    /// 1
    Rejected = 1,
    /// 2
    Failed = 2,
    /// 3
    Expired = 3,
}

/// CommandAck body (type 6).
#[derive(Debug, Clone, PartialEq)]
pub struct CommandAck {
    /// 1
    pub cmd_id: String,
    /// 2 (0..3)
    pub status: u8,
    /// 3
    pub result: Option<AppMap>,
    /// 4
    pub error: Option<String>,
}

/// OtaNotify body (type 7).
#[derive(Debug, Clone, PartialEq)]
pub struct OtaNotify {
    /// 1
    pub campaign_id: String,
    /// 2
    pub manifest: Vec<u8>,
    /// 3
    pub url: String,
    /// 4
    pub delta_from: Option<[u8; 32]>,
}

/// OtaStatus states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum OtaState {
    /// 0
    Received = 0,
    /// 1
    Downloading = 1,
    /// 2
    Verifying = 2,
    /// 3
    Applying = 3,
    /// 4
    Rebooting = 4,
    /// 5
    Success = 5,
    /// 6
    RolledBack = 6,
    /// 7
    Rejected = 7,
}

impl OtaState {
    /// Name used in DUT events.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            OtaState::Received => "received",
            OtaState::Downloading => "downloading",
            OtaState::Verifying => "verifying",
            OtaState::Applying => "applying",
            OtaState::Rebooting => "rebooting",
            OtaState::Success => "success",
            OtaState::RolledBack => "rolled_back",
            OtaState::Rejected => "rejected",
        }
    }
}

/// OtaStatus body (type 8).
#[derive(Debug, Clone, PartialEq)]
pub struct OtaStatus {
    /// 1
    pub campaign_id: String,
    /// 2 (0..7)
    pub state: u8,
    /// 3 (0..100)
    pub progress_pct: u8,
    /// 4
    pub error: Option<String>,
    /// 5
    pub fw_hash: Option<[u8; 32]>,
}

/// Config body (type 9).
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// 1
    pub version: u64,
    /// 2
    pub settings: AppMap,
}

/// TPM 2.0 evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpm2Evidence {
    /// TPMS_ATTEST bytes.
    pub quote: Vec<u8>,
    /// Quote signature (TPMT_SIGNATURE bytes).
    pub signature: Vec<u8>,
    /// AK certificate DER.
    pub ak_cert_der: Vec<u8>,
}

/// Secure-element type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeType {
    /// ATECC608
    Atecc608,
    /// TPM 2.0
    Tpm2,
    /// OP-TEE
    Optee,
    /// Software key
    Software,
}

impl SeType {
    /// Wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SeType::Atecc608 => "atecc608",
            SeType::Tpm2 => "tpm2",
            SeType::Optee => "optee",
            SeType::Software => "software",
        }
    }

    /// Parse the wire string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "atecc608" => Some(SeType::Atecc608),
            "tpm2" => Some(SeType::Tpm2),
            "optee" => Some(SeType::Optee),
            "software" => Some(SeType::Software),
            _ => None,
        }
    }

    /// Assurance level (`software` / `hardware`).
    #[must_use]
    pub const fn assurance(self) -> &'static str {
        match self {
            SeType::Software => "software",
            _ => "hardware",
        }
    }
}

/// Attestation body (type 10).
#[derive(Debug, Clone, PartialEq)]
pub struct Attestation {
    /// 1
    pub nonce: [u8; 32],
    /// 2
    pub csr_hash: [u8; 32],
    /// 3
    pub fw_hash: [u8; 32],
    /// 4
    pub fw_version: String,
    /// 5
    pub se_type: SeType,
    /// 6
    pub evidence: Option<Tpm2Evidence>,
}

/// A typed message body.
#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    /// 1
    Telemetry(Telemetry),
    /// 2
    Event(Event),
    /// 3
    ShadowReported(ShadowState),
    /// 4
    ShadowDesired(ShadowState),
    /// 5
    Command(Command),
    /// 6
    CommandAck(CommandAck),
    /// 7
    OtaNotify(OtaNotify),
    /// 8
    OtaStatus(OtaStatus),
    /// 9
    Config(Config),
    /// 10
    Attestation(Attestation),
}

/// Direction of a message type (`None` for unknown types).
#[must_use]
pub fn direction_of(message_type: u8) -> Option<Direction> {
    match message_type {
        1 | 2 | 3 | 6 | 8 | 10 => Some(Direction::Uplink),
        4 | 5 | 7 | 9 => Some(Direction::Downlink),
        _ => None,
    }
}

fn opt_push(m: &mut Vec<(Value, Value)>, k: i128, v: Option<Value>) {
    if let Some(v) = v {
        m.push((Value::Int(k), v));
    }
}

impl Body {
    /// Envelope type number.
    #[must_use]
    pub const fn message_type(&self) -> u8 {
        match self {
            Body::Telemetry(_) => 1,
            Body::Event(_) => 2,
            Body::ShadowReported(_) => 3,
            Body::ShadowDesired(_) => 4,
            Body::Command(_) => 5,
            Body::CommandAck(_) => 6,
            Body::OtaNotify(_) => 7,
            Body::OtaStatus(_) => 8,
            Body::Config(_) => 9,
            Body::Attestation(_) => 10,
        }
    }

    /// Direction of this body's type.
    #[must_use]
    pub fn direction(&self) -> Direction {
        direction_of(self.message_type()).unwrap_or(Direction::Uplink)
    }

    /// Serialize to the integer-keyed body map.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let i = |k: i128, v: Value| (Value::Int(k), v);
        let mut m: Vec<(Value, Value)> = Vec::new();
        match self {
            Body::Telemetry(t) => {
                m.extend([
                    i(1, Value::Float(t.cpu_pct)),
                    i(2, Value::Float(t.mem_pct)),
                    i(3, Value::int(t.net_rx_bytes)),
                    i(4, Value::int(t.net_tx_bytes)),
                    i(5, Value::Float(t.temp_c)),
                    i(6, Value::int(t.uptime_s)),
                    i(7, Value::int(t.auth_failures)),
                    i(8, Value::bytes(t.fw_hash.to_vec())),
                    i(9, Value::text(t.fw_version.clone())),
                ]);
                opt_push(&mut m, 10, t.proc_count.map(Value::int));
                opt_push(&mut m, 11, t.top_procs.as_ref().map(|p| Value::Array(p.iter().map(|s| Value::text(s.clone())).collect())));
                opt_push(&mut m, 12, t.rssi.map(Value::int));
                opt_push(&mut m, 13, t.free_heap.map(Value::int));
                opt_push(&mut m, 14, t.lat.map(Value::Float));
                opt_push(&mut m, 15, t.lon.map(Value::Float));
            }
            Body::Event(e) => {
                m.extend([i(1, Value::text(e.name.clone())), i(2, Value::int(e.severity)), i(3, app_map_value(&e.data))]);
            }
            Body::ShadowReported(s) | Body::ShadowDesired(s) => {
                m.extend([i(1, app_map_value(&s.state)), i(2, Value::int(s.version))]);
            }
            Body::Command(c) => m.extend([
                i(1, Value::text(c.cmd_id.clone())),
                i(2, Value::text(c.name.clone())),
                i(3, app_map_value(&c.args)),
                i(4, Value::text(c.idempotency_key.clone())),
                i(5, Value::int(c.expires_at)),
            ]),
            Body::CommandAck(a) => {
                m.extend([i(1, Value::text(a.cmd_id.clone())), i(2, Value::int(a.status))]);
                opt_push(&mut m, 3, a.result.as_ref().map(app_map_value));
                opt_push(&mut m, 4, a.error.clone().map(Value::Text));
            }
            Body::OtaNotify(o) => m.extend([
                i(1, Value::text(o.campaign_id.clone())),
                i(2, Value::bytes(o.manifest.clone())),
                i(3, Value::text(o.url.clone())),
                i(4, o.delta_from.map_or(Value::Null, |d| Value::bytes(d.to_vec()))),
            ]),
            Body::OtaStatus(o) => {
                m.extend([i(1, Value::text(o.campaign_id.clone())), i(2, Value::int(o.state)), i(3, Value::int(o.progress_pct))]);
                opt_push(&mut m, 4, o.error.clone().map(Value::Text));
                opt_push(&mut m, 5, o.fw_hash.map(|h| Value::bytes(h.to_vec())));
            }
            Body::Config(c) => m.extend([i(1, Value::int(c.version)), i(2, app_map_value(&c.settings))]),
            Body::Attestation(a) => m.extend([
                i(1, Value::bytes(a.nonce.to_vec())),
                i(2, Value::bytes(a.csr_hash.to_vec())),
                i(3, Value::bytes(a.fw_hash.to_vec())),
                i(4, Value::text(a.fw_version.clone())),
                i(5, Value::text(a.se_type.as_str())),
                i(
                    6,
                    a.evidence.as_ref().map_or(Value::Null, |e| {
                        cbor::int_map(vec![
                            (1, Value::bytes(e.quote.clone())),
                            (2, Value::bytes(e.signature.clone())),
                            (3, Value::bytes(e.ak_cert_der.clone())),
                        ])
                    }),
                ),
            ]),
        }
        Value::Map(m)
    }

    /// Parse and validate a decoded body map for `message_type`.
    ///
    /// # Errors
    /// `ENV_FIELD` on any body violation; `ENV_TYPE` for an unknown type.
    pub fn from_map(message_type: u8, m: &[(Value, Value)]) -> WireResult<Body> {
        let f = Fields::new(m, C::EnvField);
        Ok(match message_type {
            1 => {
                f.expect_keys(&[1, 2, 3, 4, 5, 6, 7, 8, 9], &[10, 11, 12, 13, 14, 15], "Telemetry: key set")?;
                Body::Telemetry(Telemetry {
                    cpu_pct: f.float(1, "cpu_pct")?,
                    mem_pct: f.float(2, "mem_pct")?,
                    net_rx_bytes: f.uint(3, "net_rx_bytes")?,
                    net_tx_bytes: f.uint(4, "net_tx_bytes")?,
                    temp_c: f.float(5, "temp_c")?,
                    uptime_s: f.uint(6, "uptime_s")?,
                    auth_failures: f.uint(7, "auth_failures")?,
                    fw_hash: f.bstr32(8, "fw_hash")?,
                    fw_version: semver_field(f.tstr(9, 1, MAX_NAME_LEN, "fw_version")?)?,
                    proc_count: f.uint_opt(10, "proc_count")?,
                    top_procs: f.tstr_list_opt(11, MAX_TOP_PROCS, "top_procs")?,
                    rssi: f.int_opt(12, "rssi")?,
                    free_heap: f.uint_opt(13, "free_heap")?,
                    lat: f.float_opt(14, "lat")?,
                    lon: f.float_opt(15, "lon")?,
                })
            }
            2 => {
                f.expect_keys(&[1, 2, 3], &[], "Event: key set")?;
                Body::Event(Event {
                    name: f.tstr(1, 1, MAX_NAME_LEN, "name")?,
                    severity: f.uint_max(2, 4, "severity")? as u8,
                    data: f.app_map(3, "data")?,
                })
            }
            3 | 4 => {
                f.expect_keys(&[1, 2], &[], "Shadow: key set")?;
                let s = ShadowState { state: f.app_map(1, "state")?, version: f.uint(2, "version")? };
                if message_type == 3 {
                    Body::ShadowReported(s)
                } else {
                    Body::ShadowDesired(s)
                }
            }
            5 => {
                f.expect_keys(&[1, 2, 3, 4, 5], &[], "Command: key set")?;
                Body::Command(Command {
                    cmd_id: uuid_field(f.tstr(1, 36, 36, "cmd_id")?, "cmd_id: not a UUID")?,
                    name: f.tstr(2, 1, MAX_NAME_LEN, "name")?,
                    args: f.app_map(3, "args")?,
                    idempotency_key: f.tstr(4, 1, 128, "idempotency_key")?,
                    expires_at: f.uint(5, "expires_at")?,
                })
            }
            6 => {
                f.expect_keys(&[1, 2], &[3, 4], "CommandAck: key set")?;
                Body::CommandAck(CommandAck {
                    cmd_id: uuid_field(f.tstr(1, 36, 36, "cmd_id")?, "cmd_id: not a UUID")?,
                    status: f.uint_max(2, 3, "status")? as u8,
                    result: f.app_map_opt(3, "result")?,
                    error: f.tstr_opt(4, 1, MAX_ERROR_LEN, "error")?,
                })
            }
            7 => {
                f.expect_keys(&[1, 2, 3, 4], &[], "OtaNotify: key set")?;
                let manifest = f.bstr(2, None, "manifest")?;
                if manifest.is_empty() {
                    return Err(field("manifest: must not be empty"));
                }
                Body::OtaNotify(OtaNotify {
                    campaign_id: uuid4_field(f.tstr(1, 36, 36, "campaign_id")?, "campaign_id: not a UUIDv4")?,
                    manifest,
                    url: f.tstr(3, 1, MAX_URL_LEN, "url")?,
                    delta_from: f.bstr32_or_null(4, "delta_from")?,
                })
            }
            8 => {
                f.expect_keys(&[1, 2, 3], &[4, 5], "OtaStatus: key set")?;
                Body::OtaStatus(OtaStatus {
                    campaign_id: uuid4_field(f.tstr(1, 36, 36, "campaign_id")?, "campaign_id: not a UUIDv4")?,
                    state: f.uint_max(2, 7, "state")? as u8,
                    progress_pct: f.uint_max(3, 100, "progress_pct")? as u8,
                    error: f.tstr_opt(4, 1, MAX_ERROR_LEN, "error")?,
                    fw_hash: f.bstr32_opt(5, "fw_hash")?,
                })
            }
            9 => {
                f.expect_keys(&[1, 2], &[], "Config: key set")?;
                Body::Config(Config { version: f.uint(1, "version")?, settings: f.app_map(2, "settings")? })
            }
            10 => {
                f.expect_keys(&[1, 2, 3, 4, 5, 6], &[], "Attestation: key set")?;
                let se_text = f.tstr(5, 1, 16, "se_type")?;
                let se_type = SeType::parse(&se_text).ok_or_else(|| field("se_type: unknown value"))?;
                let evidence = match f.get(6) {
                    Some(Value::Null) | None => None,
                    Some(Value::Map(em)) => {
                        let ef = Fields::new(em, C::EnvField);
                        ef.expect_keys(&[1, 2, 3], &[], "Tpm2Evidence: key set")?;
                        let quote = ef.bstr(1, None, "quote")?;
                        let signature = ef.bstr(2, None, "signature")?;
                        let ak_cert_der = ef.bstr(3, None, "ak_cert_der")?;
                        if quote.is_empty() || signature.is_empty() || ak_cert_der.is_empty() {
                            return Err(field("Tpm2Evidence: fields must not be empty"));
                        }
                        Some(Tpm2Evidence { quote, signature, ak_cert_der })
                    }
                    Some(_) => return Err(field("evidence: expected null or map")),
                };
                if (se_type == SeType::Tpm2) != evidence.is_some() {
                    return Err(field("evidence: required iff se_type is tpm2"));
                }
                Body::Attestation(Attestation {
                    nonce: f.bstr32(1, "nonce")?,
                    csr_hash: f.bstr32(2, "csr_hash")?,
                    fw_hash: f.bstr32(3, "fw_hash")?,
                    fw_version: semver_field(f.tstr(4, 1, MAX_NAME_LEN, "fw_version")?)?,
                    se_type,
                    evidence,
                })
            }
            _ => return Err(err(C::EnvType, "unknown message type")),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------------------------

/// The envelope `{1: seq, 2: ts, 3: type, 4: body, ?5: nonce}`.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    /// Sequence number.
    pub seq: u64,
    /// Unix seconds.
    pub ts: u64,
    /// Body.
    pub body: Body,
    /// Nonce (Command/CommandAck only).
    pub nonce: Option<[u8; NONCE_SIZE]>,
}

impl Message {
    /// Message type.
    #[must_use]
    pub const fn message_type(&self) -> u8 {
        self.body.message_type()
    }

    /// Direction.
    #[must_use]
    pub fn direction(&self) -> Direction {
        self.body.direction()
    }
}

fn needs_nonce(message_type: u8) -> bool {
    matches!(message_type, 5 | 6)
}

fn check_nonce(message_type: u8, nonce: Option<&[u8]>) -> WireResult<()> {
    if needs_nonce(message_type) {
        if nonce.is_none_or(|n| n.len() != NONCE_SIZE) {
            return Err(err(C::EnvNonce, "nonce must be bstr(16)"));
        }
    } else if nonce.is_some() {
        return Err(err(C::EnvNonce, "nonce must be absent"));
    }
    Ok(())
}

/// Canonical CBOR of the envelope payload (validated, unsigned).
///
/// # Errors
/// `ENV_FIELD` / `ENV_NONCE` / `CBOR_*` if the message is invalid.
pub fn encode_payload(message: &Message) -> WireResult<Vec<u8>> {
    let body = message.body.to_value();
    // Validate exactly like a receiver would.
    Body::from_map(message.message_type(), body.as_map().unwrap_or(&[]))?;
    check_nonce(message.message_type(), message.nonce.as_ref().map(|n| &n[..]))?;
    let mut entries = vec![
        (Value::Int(1), Value::int(message.seq)),
        (Value::Int(2), Value::int(message.ts)),
        (Value::Int(3), Value::int(message.message_type())),
        (Value::Int(4), body),
    ];
    if let Some(n) = message.nonce {
        entries.push((Value::Int(5), Value::bytes(n.to_vec())));
    }
    cbor::encode(&Value::Map(entries))
}

/// Parse and validate an envelope payload (no cryptography, no replay checks).
///
/// # Errors
/// `CBOR_*`, `ENV_STRUCTURE`, `ENV_FIELD`, `ENV_TYPE`, `ENV_NONCE`.
pub fn decode_payload(data: &[u8], limits: DecodeLimits) -> WireResult<Message> {
    let m = cbor::decode_map(data, limits)?;
    let f = Fields::new(&m, C::EnvStructure);
    f.expect_keys(&[1, 2, 3, 4], &[5], "envelope: key set")?;
    let fe = Fields::new(&m, C::EnvField);
    let seq = fe.uint(1, "seq: expected uint64")?;
    let ts = fe.uint(2, "ts: expected uint64")?;
    let message_type = match f.get(3) {
        Some(Value::Int(t)) if (1..=10).contains(t) => *t as u8,
        _ => return Err(err(C::EnvType, "unknown message type")),
    };
    let Some(Value::Map(body_map)) = f.get(4) else {
        return Err(err(C::EnvStructure, "body must be a map"));
    };
    if body_map.iter().any(|(k, _)| !matches!(k, Value::Int(_))) {
        return Err(field("body keys must be integers"));
    }
    let body = Body::from_map(message_type, body_map)?;
    // Spec §3.5: the nonce MUST be absent on non-command types; a present `null` counts as present.
    let nonce = match f.get(5) {
        None => None,
        Some(Value::Bytes(b)) => Some(b.as_slice()),
        Some(_) => return Err(err(C::EnvNonce, "nonce must be a bstr")),
    };
    check_nonce(message_type, nonce)?;
    let nonce = nonce.map(|n| n.try_into().unwrap_or([0u8; NONCE_SIZE]));
    Ok(Message { seq, ts, body, nonce })
}

// ---------------------------------------------------------------------------------------------
// Replay store, key resolution, header profile
// ---------------------------------------------------------------------------------------------

/// Persists the last accepted `seq` per replay stream (see [`replay_stream`]) and direction.
pub trait ReplayStore {
    /// Atomically accept `seq` iff strictly greater than the last accepted value (or none) and
    /// record it. Returns `false` (store unchanged) otherwise. Implementations that cannot persist
    /// the new value MUST return `false` (fail closed).
    fn check_and_record(&mut self, kid: &Kid, direction: Direction, seq: u64) -> bool;

    /// Last accepted sequence number.
    fn last_seq(&self, kid: &Kid, direction: Direction) -> Option<u64>;
}

/// In-memory replay store.
#[derive(Debug, Default, Clone)]
pub struct InMemoryReplayStore {
    last: std::collections::BTreeMap<(Kid, Direction), u64>,
}

impl InMemoryReplayStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Last accepted value for a direction, any kid (used by the vector test).
    #[must_use]
    pub fn last_for_direction(&self, direction: Direction) -> Option<u64> {
        self.last.iter().filter(|((_, d), _)| *d == direction).map(|(_, v)| *v).max()
    }

    /// Snapshot of all entries.
    #[must_use]
    pub fn entries(&self) -> Vec<(Kid, Direction, u64)> {
        self.last.iter().map(|((k, d), v)| (k.clone(), *d, *v)).collect()
    }

    /// Restore an entry.
    pub fn insert(&mut self, kid: Kid, direction: Direction, seq: u64) {
        self.last.insert((kid, direction), seq);
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn check_and_record(&mut self, kid: &Kid, direction: Direction, seq: u64) -> bool {
        let key = (kid.clone(), direction);
        match self.last.get(&key) {
            Some(last) if seq <= *last => false,
            _ => {
                self.last.insert(key, seq);
                true
            }
        }
    }

    fn last_seq(&self, kid: &Kid, direction: Direction) -> Option<u64> {
        self.last.get(&(kid.clone(), direction)).copied()
    }
}

/// Downlink types that may arrive as retained MQTT messages (`WIRE_FORMAT.md` §3.6 step 9):
/// ShadowDesired (4), OtaNotify (7), Config (9). Only the future bound of the timestamp window
/// applies to them; `seq` ordering still blocks replays.
pub const RETAINABLE_TYPES: [u8; 3] = [4, 7, 9];

/// Replay-stream identifier (`WIRE_FORMAT.md` §3.6 step 11): the device kid for uplink and the
/// text `"<tenant kid>/<type>"` for downlink (one sequence per downlink type, because different
/// cloud services sign different types with the same tenant key).
#[must_use]
pub fn replay_stream(kid: &Kid, direction: Direction, message_type: u8) -> Kid {
    match (direction, kid) {
        (Direction::Downlink, Kid::Text(t)) => Kid::Text(format!("{t}/{message_type}")),
        (Direction::Downlink, Kid::Bytes(b)) => Kid::Text(format!("{}/{message_type}", hex::encode(b))),
        (Direction::Uplink, k) => k.clone(),
    }
}

/// A bstr kid means a device sender (uplink); a tstr kid means the cloud (downlink).
#[must_use]
pub fn header_direction(kid: &Kid) -> Direction {
    match kid {
        Kid::Bytes(_) => Direction::Uplink,
        Kid::Text(_) => Direction::Downlink,
    }
}

/// Enforce the header profile for a direction (`WIRE_FORMAT.md` §3.2/§3.3).
///
/// # Errors
/// `ENV_KID` or `ENV_DIRECTION`.
pub fn check_header_profile(alg: i64, kid: &Kid, direction: Direction) -> WireResult<()> {
    match direction {
        Direction::Uplink => {
            if !matches!(kid, Kid::Bytes(b) if ids::is_device_kid(b)) {
                return Err(err(C::EnvKid, "uplink kid must be the certificate serial (bstr 1..20)"));
            }
            if alg != ALG_ES256 {
                return Err(err(C::EnvDirection, "uplink messages must be signed with ES256"));
            }
        }
        Direction::Downlink => {
            if !matches!(kid, Kid::Text(t) if ids::is_tenant_kid(t)) {
                return Err(err(C::EnvKid, "downlink kid must be tenant-cmd-<tenant uuid>"));
            }
            if alg != ALG_EDDSA {
                return Err(err(C::EnvDirection, "downlink messages must be signed with EdDSA"));
            }
        }
    }
    Ok(())
}

/// Sign `message` as a COSE_Sign1 envelope.
///
/// # Errors
/// Validation errors of [`encode_payload`], `ENV_KID`/`ENV_DIRECTION`, signer failures.
pub fn encode(message: &Message, signer: &dyn CoseSigner, kid: &Kid) -> WireResult<Vec<u8>> {
    let payload = encode_payload(message)?;
    check_header_profile(signer.alg(), kid, message.direction())?;
    cose::sign1_encode(&payload, signer, kid)
}

/// Options for [`decode`].
#[derive(Debug, Clone, Default)]
pub struct DecodeOptions<'a> {
    /// Unix seconds "now".
    pub now: u64,
    /// Allowed skew (default 300 s when `None`).
    pub max_skew: Option<u64>,
    /// Required header direction.
    pub expected_direction: Option<Direction>,
    /// Required CommandAck nonce.
    pub expected_nonce: Option<[u8; NONCE_SIZE]>,
    /// Required tenant for downlink messages.
    pub expected_tenant: Option<&'a str>,
    /// Decoder limits.
    pub limits: DecodeLimits,
}

/// A verified message plus the sender kid.
#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    /// The message.
    pub message: Message,
    /// The verified sender's kid.
    pub sender_kid: Kid,
}

/// Verify and decode an envelope (`WIRE_FORMAT.md` §3.6).
///
/// # Errors
/// The code of the first failing step.
pub fn decode(
    data: &[u8],
    resolver: &dyn Fn(&Kid) -> Option<PublicKey>,
    store: &mut dyn ReplayStore,
    opts: &DecodeOptions<'_>,
) -> WireResult<Verified> {
    let signed = cose::sign1_decode(data, opts.limits)?;
    let direction = header_direction(&signed.kid);
    check_header_profile(signed.alg, &signed.kid, direction)?;
    if opts.expected_direction.is_some_and(|d| d != direction) {
        return Err(err(C::EnvDirection, "unexpected message direction"));
    }
    if let (Some(expected), Kid::Text(kid)) = (opts.expected_tenant, &signed.kid) {
        if ids::tenant_from_kid(kid) != Some(expected) {
            return Err(err(C::EnvTenant, "message signed by another tenant's key"));
        }
    }
    let key = resolver(&signed.kid).ok_or_else(|| err(C::EnvUnknownKey, "unknown sender kid"))?;
    cose::sign1_verify(&signed, &key)?;
    let message = decode_payload(&signed.payload, opts.limits)?;
    if message.direction() != direction {
        return Err(err(C::EnvDirection, "message type cannot be sent in this direction"));
    }
    let skew = opts.max_skew.unwrap_or(MAX_SKEW_DEFAULT);
    let retained = direction == Direction::Downlink && RETAINABLE_TYPES.contains(&message.message_type());
    let too_new = message.ts > opts.now && message.ts - opts.now > skew;
    let too_old = opts.now > message.ts && opts.now - message.ts > skew;
    if too_new || (!retained && too_old) {
        return Err(WireError::with(C::EnvTsSkew, format!("timestamp {} outside now +/- {skew}", message.ts)));
    }
    if let Some(expected) = opts.expected_nonce {
        if message.message_type() != 6 || message.nonce != Some(expected) {
            return Err(err(C::EnvNonce, "CommandAck nonce does not echo the command nonce"));
        }
    }
    let stream = replay_stream(&signed.kid, direction, message.message_type());
    if !store.check_and_record(&stream, direction, message.seq) {
        return Err(WireError::with(C::EnvReplay, format!("seq {} not greater than last accepted", message.seq)));
    }
    Ok(Verified { message, sender_kid: signed.kid })
}

/// Verify that `ack` answers `command`: same `cmd_id` and echoed nonce.
///
/// # Errors
/// `ENV_TYPE`, `ENV_NONCE`, `ENV_FIELD`.
pub fn check_ack(command: &Message, ack: &Message) -> WireResult<()> {
    let (Body::Command(c), Body::CommandAck(a)) = (&command.body, &ack.body) else {
        return Err(err(C::EnvType, "check_ack expects a Command and a CommandAck"));
    };
    if ack.nonce != command.nonce {
        return Err(err(C::EnvNonce, "CommandAck nonce does not echo the command nonce"));
    }
    if a.cmd_id != c.cmd_id {
        return Err(err(C::EnvField, "CommandAck cmd_id does not match the command"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11";

    fn tenant_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[5u8; 32])
    }

    fn device_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[6u8; 32]).unwrap()
    }

    fn telemetry() -> Telemetry {
        Telemetry { fw_version: "1.0.0".into(), top_procs: Some(vec!["a".into()]), lat: Some(1.5), ..Default::default() }
    }

    fn cmd() -> Command {
        Command {
            cmd_id: "123e4567-e89b-12d3-a456-426614174000".into(),
            name: "reboot".into(),
            args: vec![],
            idempotency_key: "k".into(),
            expires_at: 10,
        }
    }

    fn all_bodies() -> Vec<(Body, Option<[u8; 16]>)> {
        let n = Some([1u8; 16]);
        vec![
            (Body::Telemetry(telemetry()), None),
            (Body::Event(Event { name: "e".into(), severity: 4, data: vec![("k".into(), Value::Null)] }), None),
            (Body::ShadowReported(ShadowState { state: vec![], version: 1 }), None),
            (Body::ShadowDesired(ShadowState { state: vec![], version: 1 }), None),
            (Body::Command(cmd()), n),
            (Body::CommandAck(CommandAck { cmd_id: cmd().cmd_id, status: 2, result: Some(vec![]), error: Some("x".into()) }), n),
            (
                Body::OtaNotify(OtaNotify {
                    campaign_id: TENANT.into(),
                    manifest: vec![1],
                    url: "https://a".into(),
                    delta_from: Some([0; 32]),
                }),
                None,
            ),
            (
                Body::OtaStatus(OtaStatus {
                    campaign_id: TENANT.into(),
                    state: 7,
                    progress_pct: 100,
                    error: Some("e".into()),
                    fw_hash: Some([1; 32]),
                }),
                None,
            ),
            (Body::Config(Config { version: 1, settings: vec![("a".into(), Value::int(1))] }), None),
            (
                Body::Attestation(Attestation {
                    nonce: [0; 32],
                    csr_hash: [0; 32],
                    fw_hash: [0; 32],
                    fw_version: "1.0.0".into(),
                    se_type: SeType::Tpm2,
                    evidence: Some(Tpm2Evidence { quote: vec![1], signature: vec![1], ak_cert_der: vec![1] }),
                }),
                None,
            ),
        ]
    }

    #[test]
    fn every_body_round_trips() {
        let tkid = Kid::Text(ids::tenant_kid(TENANT).unwrap());
        let dkid = Kid::Bytes(vec![0x3f, 0xa1]);
        let tk = tenant_key();
        let dk = device_key();
        let tpub = PublicKey::Ed25519(tk.verifying_key());
        let dpub = PublicKey::P256(*dk.verifying_key());
        let mut store = InMemoryReplayStore::new();
        for (seq, (body, nonce)) in all_bodies().into_iter().enumerate() {
            let msg = Message { seq: seq as u64 + 1, ts: 1000, body, nonce };
            let (signer, kid): (&dyn CoseSigner, &Kid) = if msg.direction() == Direction::Uplink { (&dk, &dkid) } else { (&tk, &tkid) };
            let wire = encode(&msg, signer, kid).unwrap();
            let resolver = |k: &Kid| Some(if matches!(k, Kid::Bytes(_)) { dpub.clone() } else { tpub.clone() });
            let opts = DecodeOptions { now: 1000, expected_tenant: Some(TENANT), ..Default::default() };
            let v = decode(&wire, &resolver, &mut store, &opts).unwrap();
            assert_eq!(v.message, msg);
            assert_eq!(&v.sender_kid, kid);
        }
        assert_eq!(store.last_for_direction(Direction::Uplink), Some(10));
        // One uplink stream (device kid) plus one stream per downlink type (4, 5, 7, 9).
        assert_eq!(store.entries().len(), 5);
        assert_eq!(store.last_seq(&replay_stream(&tkid, Direction::Downlink, 5), Direction::Downlink), Some(5));
        assert_eq!(replay_stream(&Kid::Bytes(vec![1]), Direction::Downlink, 7), Kid::Text("01/7".into()));
    }

    #[test]
    fn encode_rejects_invalid() {
        let dk = device_key();
        let dkid = Kid::Bytes(vec![1]);
        let bad = Message { seq: 1, ts: 1, body: Body::Telemetry(Telemetry { fw_version: "x".into(), ..Default::default() }), nonce: None };
        assert_eq!(encode(&bad, &dk, &dkid).unwrap_err().code(), C::EnvField);
        let nonce_on_tel = Message { seq: 1, ts: 1, body: Body::Telemetry(telemetry()), nonce: Some([0; 16]) };
        assert_eq!(encode(&nonce_on_tel, &dk, &dkid).unwrap_err().code(), C::EnvNonce);
        let cmd_no_nonce = Message { seq: 1, ts: 1, body: Body::Command(cmd()), nonce: None };
        assert_eq!(encode(&cmd_no_nonce, &tenant_key(), &Kid::Text("x".into())).unwrap_err().code(), C::EnvNonce);
        let tel = Message { seq: 1, ts: 1, body: Body::Telemetry(telemetry()), nonce: None };
        assert_eq!(encode(&tel, &tenant_key(), &dkid).unwrap_err().code(), C::EnvDirection);
        assert_eq!(encode(&tel, &dk, &Kid::Bytes(vec![0, 1])).unwrap_err().code(), C::EnvKid);
        let cmdm = Message { seq: 1, ts: 1, body: Body::Command(cmd()), nonce: Some([0; 16]) };
        assert_eq!(encode(&cmdm, &tenant_key(), &Kid::Text("tenant-cmd-x".into())).unwrap_err().code(), C::EnvKid);
        assert_eq!(encode(&cmdm, &dk, &Kid::Text(ids::tenant_kid(TENANT).unwrap())).unwrap_err().code(), C::EnvDirection);
    }

    #[test]
    fn payload_errors() {
        let enc = |v: Value| cbor::encode(&v).unwrap();
        let lim = DecodeLimits::default();
        let tel = Body::Telemetry(telemetry()).to_value();
        let base = |extra: Vec<(i128, Value)>| {
            let mut e = vec![(1, Value::int(1)), (2, Value::int(2)), (3, Value::int(1)), (4, tel.clone())];
            e.extend(extra);
            cbor::int_map(e)
        };
        assert!(decode_payload(&enc(base(vec![])), lim).is_ok());
        assert_eq!(decode_payload(&enc(Value::Int(1)), lim).unwrap_err().code(), C::CborType);
        assert_eq!(decode_payload(&enc(cbor::int_map(vec![(1, Value::int(1))])), lim).unwrap_err().code(), C::EnvStructure);
        assert_eq!(decode_payload(&enc(base(vec![(6, Value::Null)])), lim).unwrap_err().code(), C::EnvStructure);
        // Key 5 present with any non-bstr value (including CBOR null) is ENV_NONCE.
        for bad in [Value::Null, Value::int(1), Value::text("n"), Value::Bool(false), Value::Array(vec![])] {
            assert_eq!(decode_payload(&enc(base(vec![(5, bad)])), lim).unwrap_err().code(), C::EnvNonce);
        }
        let cmd_null_nonce = cbor::int_map(vec![
            (1, Value::int(1)),
            (2, Value::int(2)),
            (3, Value::int(5)),
            (4, Body::Command(cmd()).to_value()),
            (5, Value::Null),
        ]);
        assert_eq!(decode_payload(&enc(cmd_null_nonce), lim).unwrap_err().code(), C::EnvNonce);
        // Non-ASCII digits are not semver digits.
        let mut t = telemetry();
        t.fw_version = "\u{0661}.0.0".into();
        let m = Message { seq: 1, ts: 1, body: Body::Telemetry(t), nonce: None };
        assert_eq!(encode_payload(&m).unwrap_err().code(), C::EnvField);
        assert_eq!(decode_payload(&enc(base(vec![(5, Value::bytes(vec![0; 16]))])), lim).unwrap_err().code(), C::EnvNonce);
        let mut bad_type = vec![(1, Value::int(1)), (2, Value::int(2)), (3, Value::int(11)), (4, tel.clone())];
        assert_eq!(decode_payload(&enc(cbor::int_map(bad_type.clone())), lim).unwrap_err().code(), C::EnvType);
        bad_type[2] = (3, Value::text("1"));
        assert_eq!(decode_payload(&enc(cbor::int_map(bad_type)), lim).unwrap_err().code(), C::EnvType);
        let bad_seq = cbor::int_map(vec![(1, Value::int(-1)), (2, Value::int(2)), (3, Value::int(1)), (4, tel.clone())]);
        assert_eq!(decode_payload(&enc(bad_seq), lim).unwrap_err().code(), C::EnvField);
        let bad_body = cbor::int_map(vec![(1, Value::int(1)), (2, Value::int(2)), (3, Value::int(1)), (4, Value::Null)]);
        assert_eq!(decode_payload(&enc(bad_body), lim).unwrap_err().code(), C::EnvStructure);
        let str_key = Value::Map(vec![(Value::text("a"), Value::Null)]);
        let bad_keys = cbor::int_map(vec![(1, Value::int(1)), (2, Value::int(2)), (3, Value::int(1)), (4, str_key)]);
        assert_eq!(decode_payload(&enc(bad_keys), lim).unwrap_err().code(), C::EnvField);
    }

    #[test]
    fn body_field_errors() {
        let f = |t: u8, v: Value| Body::from_map(t, v.as_map().unwrap()).unwrap_err().code();
        let mut tel = Body::Telemetry(telemetry()).to_value();
        if let Value::Map(m) = &mut tel {
            m[0].1 = Value::int(1);
        }
        assert_eq!(f(1, tel), C::EnvField);
        let ev = cbor::int_map(vec![(1, Value::text("e")), (2, Value::int(5)), (3, Value::Map(vec![]))]);
        assert_eq!(f(2, ev), C::EnvField);
        let ev = cbor::int_map(vec![(1, Value::text("e")), (2, Value::int(1)), (3, Value::Map(vec![(Value::int(1), Value::Null)]))]);
        assert_eq!(f(2, ev), C::EnvField);
        let mut c = Body::Command(cmd()).to_value();
        if let Value::Map(m) = &mut c {
            m[0].1 = Value::text("123E4567-E89B-12D3-A456-426614174000");
        }
        assert_eq!(f(5, c), C::EnvField);
        let on = cbor::int_map(vec![(1, Value::text(TENANT)), (2, Value::bytes(vec![])), (3, Value::text("u")), (4, Value::Null)]);
        assert_eq!(f(7, on), C::EnvField);
        let on = cbor::int_map(vec![(1, Value::text(TENANT)), (2, Value::bytes(vec![1])), (3, Value::text("u"))]);
        assert_eq!(f(7, on), C::EnvField);
        let os = cbor::int_map(vec![(1, Value::text(TENANT)), (2, Value::int(1)), (3, Value::int(101))]);
        assert_eq!(f(8, os), C::EnvField);
        let mut att = Body::Attestation(Attestation {
            nonce: [0; 32],
            csr_hash: [0; 32],
            fw_hash: [0; 32],
            fw_version: "1.0.0".into(),
            se_type: SeType::Software,
            evidence: None,
        })
        .to_value();
        assert!(Body::from_map(10, att.as_map().unwrap()).is_ok());
        if let Value::Map(m) = &mut att {
            m[4].1 = Value::text("tpm2");
        }
        assert_eq!(f(10, att.clone()), C::EnvField);
        if let Value::Map(m) = &mut att {
            m[4].1 = Value::text("bogus");
        }
        assert_eq!(f(10, att.clone()), C::EnvField);
        if let Value::Map(m) = &mut att {
            m[4].1 = Value::text("software");
            m[5].1 = Value::int(1);
        }
        assert_eq!(f(10, att.clone()), C::EnvField);
        if let Value::Map(m) = &mut att {
            m[5].1 = cbor::int_map(vec![(1, Value::bytes(vec![])), (2, Value::bytes(vec![1])), (3, Value::bytes(vec![1]))]);
        }
        assert_eq!(f(10, att), C::EnvField);
        assert_eq!(Body::from_map(11, &[]).unwrap_err().code(), C::EnvType);
        let tel = cbor::int_map(vec![]);
        let fields = Fields::new(tel.as_map().unwrap(), C::EnvField);
        assert!(fields.int_opt(12, "x").unwrap().is_none());
    }

    #[test]
    fn check_ack_rules() {
        let c = Message { seq: 1, ts: 1, body: Body::Command(cmd()), nonce: Some([1; 16]) };
        let a = Message {
            seq: 1,
            ts: 1,
            body: Body::CommandAck(CommandAck { cmd_id: cmd().cmd_id, status: 0, result: None, error: None }),
            nonce: Some([1; 16]),
        };
        check_ack(&c, &a).unwrap();
        let mut bad = a.clone();
        bad.nonce = Some([2; 16]);
        assert_eq!(check_ack(&c, &bad).unwrap_err().code(), C::EnvNonce);
        let mut bad = a.clone();
        if let Body::CommandAck(b) = &mut bad.body {
            b.cmd_id = "00000000-0000-0000-0000-000000000000".into();
        }
        assert_eq!(check_ack(&c, &bad).unwrap_err().code(), C::EnvField);
        assert_eq!(check_ack(&a, &c).unwrap_err().code(), C::EnvType);
        assert_eq!(OtaState::RolledBack.name(), "rolled_back");
        assert_eq!(SeType::Optee.assurance(), "hardware");
        assert_eq!(SeType::Software.assurance(), "software");
        assert_eq!(direction_of(0), None);
    }
}
