//! Structured JSON logs (contract §9: fields `ts, level, service, trace_id, span_id, tenant_id,
//! device_id, msg`) with a runtime-reloadable level, and W3C `traceparent` generation for MQTT 5
//! user properties.

use std::fmt::Write as _;
use std::sync::OnceLock;

use rand::RngCore;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

static IDS: OnceLock<(String, String)> = OnceLock::new();
static SERVICE: OnceLock<String> = OnceLock::new();
static RELOAD: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

/// A W3C trace context for one outbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    /// 32 hex chars.
    pub trace_id: String,
    /// 16 hex chars.
    pub span_id: String,
}

impl TraceContext {
    /// Fresh random context (sampled).
    #[must_use]
    pub fn new() -> Self {
        let mut t = [0u8; 16];
        let mut s = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut t);
        rand::thread_rng().fill_bytes(&mut s);
        if t == [0u8; 16] {
            t[15] = 1;
        }
        if s == [0u8; 8] {
            s[7] = 1;
        }
        Self { trace_id: hex::encode(t), span_id: hex::encode(s) }
    }

    /// `traceparent` header value (`00-<trace>-<span>-01`).
    #[must_use]
    pub fn traceparent(&self) -> String {
        format!("00-{}-{}-01", self.trace_id, self.span_id)
    }

    /// Parse a `traceparent` value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split('-').collect();
        let ok_hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        if parts.len() != 4 || parts[0] != "00" || !ok_hex(parts[1], 32) || !ok_hex(parts[2], 16) || !ok_hex(parts[3], 2) {
            return None;
        }
        if parts[1].bytes().all(|b| b == b'0') || parts[2].bytes().all(|b| b == b'0') {
            return None;
        }
        Some(Self { trace_id: parts[1].into(), span_id: parts[2].into() })
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Record the device identity for every log line.
pub fn set_identity(tenant_id: &str, device_id: &str) {
    let _ = IDS.set((tenant_id.to_owned(), device_id.to_owned()));
}

#[derive(Default)]
struct Fields(serde_json::Map<String, serde_json::Value>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), serde_json::Value::String(format!("{value:?}")));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), serde_json::Value::String(value.to_owned()));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.into());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_owned(), value.into());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_owned(), value.into());
    }
}

/// Formats each event as one JSON object with the contract field names.
#[derive(Debug, Default)]
pub struct ContractJson;

/// Render one log line (also used by tests).
#[must_use]
pub fn render(level: &str, target: &str, mut fields: serde_json::Map<String, serde_json::Value>, ts_ms: u128) -> String {
    let msg = fields.remove("message").unwrap_or_else(|| serde_json::Value::String(String::new()));
    let (tenant, device) = IDS.get().cloned().unwrap_or_default();
    let mut obj = serde_json::Map::new();
    obj.insert("ts".into(), format_rfc3339_ms(ts_ms).into());
    obj.insert("level".into(), level.to_ascii_lowercase().into());
    obj.insert("service".into(), SERVICE.get().cloned().unwrap_or_else(|| "ironmesh-agent".into()).into());
    obj.insert("trace_id".into(), fields.remove("trace_id").unwrap_or_else(|| "".into()));
    obj.insert("span_id".into(), fields.remove("span_id").unwrap_or_else(|| "".into()));
    obj.insert("tenant_id".into(), fields.remove("tenant_id").unwrap_or_else(|| tenant.into()));
    obj.insert("device_id".into(), fields.remove("device_id").unwrap_or_else(|| device.into()));
    obj.insert("msg".into(), msg);
    obj.insert("target".into(), target.into());
    for (k, v) in fields {
        obj.entry(k).or_insert(v);
    }
    serde_json::Value::Object(obj).to_string()
}

/// RFC 3339 UTC timestamp with milliseconds.
#[must_use]
pub fn format_rfc3339_ms(ms: u128) -> String {
    let secs = (ms / 1000) as i64;
    let millis = (ms % 1000) as u32;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // civil from days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let mut s = String::new();
    let _ = write!(s, "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", tod / 3600, (tod % 3600) / 60, tod % 60);
    s
}

impl<S, N> FormatEvent<S, N> for ContractJson
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(&self, _ctx: &FmtContext<'_, S, N>, mut writer: Writer<'_>, event: &Event<'_>) -> std::fmt::Result {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let meta = event.metadata();
        writeln!(writer, "{}", render(meta.level().as_str(), meta.target(), fields.0, ts))
    }
}

/// Install the global JSON subscriber (stderr). Idempotent.
pub fn init(level: &str, service: &str) {
    let _ = SERVICE.set(service.to_owned());
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    let (layer, handle) = reload::Layer::new(filter);
    let fmt = tracing_subscriber::fmt::layer().with_writer(std::io::stderr).event_format(ContractJson);
    if tracing_subscriber::registry().with(layer).with(fmt).try_init().is_ok() {
        let _ = RELOAD.set(handle);
    }
}

/// Change the level at runtime (`set_log_level` command / config).
pub fn set_level(level: &str) -> bool {
    match (RELOAD.get(), EnvFilter::try_new(level)) {
        (Some(h), Ok(f)) => h.reload(f).is_ok(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceparent_round_trip() {
        let t = TraceContext::new();
        let tp = t.traceparent();
        assert_eq!(tp.len(), 55);
        assert_eq!(TraceContext::parse(&tp), Some(t));
        assert!(TraceContext::parse("00-00000000000000000000000000000000-0000000000000001-01").is_none());
        assert!(TraceContext::parse("01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01").is_none());
        assert!(TraceContext::parse("garbage").is_none());
        assert!(TraceContext::default().trace_id.len() == 32);
    }

    #[test]
    fn json_line_has_contract_fields() {
        set_identity("7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11", "dev-0000000000000001");
        let mut f = serde_json::Map::new();
        f.insert("message".into(), "hello".into());
        f.insert("trace_id".into(), "abc".into());
        f.insert("extra".into(), 5.into());
        let line = render("INFO", "x", f, 1_767_225_600_123);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        for k in ["ts", "level", "service", "trace_id", "span_id", "tenant_id", "device_id", "msg"] {
            assert!(v.get(k).is_some(), "{k}");
        }
        assert_eq!(v["ts"], "2026-01-01T00:00:00.123Z");
        assert_eq!(v["msg"], "hello");
        assert_eq!(v["extra"], 5);
        assert_eq!(format_rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_rfc3339_ms(951_782_400_000), "2000-02-29T00:00:00.000Z");
        init("info", "test");
        tracing::info!(trace_id = "t", "init works");
        let _ = set_level("debug");
        assert!(!set_level("[[["));
    }
}
