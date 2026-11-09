//! Identifier validators, key identifiers and the MQTT topic scheme (`WIRE_FORMAT.md` §3.3, §7).

use super::error::{err, ErrorCode as C, WireResult};

/// Prefix of the tenant command key id.
pub const TENANT_KID_PREFIX: &str = "tenant-cmd-";
/// Maximum certificate serial length (RFC 5280).
pub const MAX_SERIAL_BYTES: usize = 20;
/// Topic prefix.
pub const TOPIC_PREFIX: &str = "im/v1";
/// Shared subscription reserved for the bridge.
pub const BRIDGE_SHARED_SUBSCRIPTION: &str = "$share/bridge/im/v1/#";

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn hex_run(s: &[u8], len: usize) -> bool {
    s.len() == len && s.iter().copied().all(is_lower_hex)
}

/// Any lower-case hyphenated UUID (`cmd_id`).
#[must_use]
pub fn is_uuid(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => is_lower_hex(*c),
        })
}

/// Lower-case hyphenated UUIDv4 (tenant id, campaign id).
#[must_use]
pub fn is_uuid4(value: &str) -> bool {
    let b = value.as_bytes();
    is_uuid(value) && b[14] == b'4' && matches!(b[19], b'8' | b'9' | b'a' | b'b')
}

/// Tenant id.
#[must_use]
pub fn is_tenant_id(value: &str) -> bool {
    is_uuid4(value)
}

/// Device id `^dev-[0-9a-f]{16}$`.
#[must_use]
pub fn is_device_id(value: &str) -> bool {
    value.strip_prefix("dev-").is_some_and(|rest| hex_run(rest.as_bytes(), 16))
}

/// Group slug `^[a-z0-9-]{1,48}$`.
#[must_use]
pub fn is_group_slug(value: &str) -> bool {
    (1..=48).contains(&value.len()) && value.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// Product `^[a-z0-9][a-z0-9-]{0,63}$`.
#[must_use]
pub fn is_product(value: &str) -> bool {
    let b = value.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn is_numeric_identifier(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
}

fn is_alnum_hyphen(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

/// Semantic Versioning 2.0.0.
#[must_use]
pub fn is_semver(value: &str) -> bool {
    let (rest, build) = match value.split_once('+') {
        Some((r, b)) => (r, Some(b)),
        None => (value, None),
    };
    if let Some(build) = build {
        if !build.split('.').all(is_alnum_hyphen) {
            return false;
        }
    }
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    if let Some(pre) = pre {
        let ok = pre.split('.').all(|id| is_alnum_hyphen(id) && (!id.bytes().all(|c| c.is_ascii_digit()) || is_numeric_identifier(id)));
        if !ok {
            return false;
        }
    }
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| is_numeric_identifier(p))
}

/// Validate a tenant id (`ID_FORMAT`).
///
/// # Errors
/// `ID_FORMAT`.
pub fn validate_tenant_id(value: &str) -> WireResult<&str> {
    if is_tenant_id(value) {
        Ok(value)
    } else {
        Err(err(C::IdFormat, "tenant id must be a lower-case hyphenated UUIDv4"))
    }
}

/// Validate a device id (`ID_FORMAT`).
///
/// # Errors
/// `ID_FORMAT`.
pub fn validate_device_id(value: &str) -> WireResult<&str> {
    if is_device_id(value) {
        Ok(value)
    } else {
        Err(err(C::IdFormat, "device id must match ^dev-[0-9a-f]{16}$"))
    }
}

/// Parse `<product>/<semver>`.
///
/// # Errors
/// `ID_FORMAT`.
pub fn parse_firmware_id(value: &str) -> WireResult<(&str, &str)> {
    let (product, version) = value.split_once('/').ok_or_else(|| err(C::IdFormat, "firmware id must be <product>/<semver>"))?;
    if !is_product(product) || !is_semver(version) {
        return Err(err(C::IdFormat, "firmware id must be <product>/<semver>"));
    }
    Ok((product, version))
}

/// Device kid from a DER serial content (big-endian, possibly with a leading `00`).
///
/// # Errors
/// `ID_FORMAT` if the minimal serial is longer than 20 bytes.
pub fn kid_from_serial(serial_be: &[u8]) -> WireResult<Vec<u8>> {
    let start = serial_be.iter().position(|b| *b != 0).unwrap_or(serial_be.len().saturating_sub(1));
    let minimal = serial_be.get(start..).unwrap_or(&[]).to_vec();
    let minimal = if minimal.is_empty() { vec![0] } else { minimal };
    if minimal.len() > MAX_SERIAL_BYTES {
        return Err(err(C::IdFormat, "certificate serial longer than 20 bytes"));
    }
    Ok(minimal)
}

/// A valid device kid: 1..20 bytes, minimal (no leading zero unless it is the only byte).
#[must_use]
pub fn is_device_kid(kid: &[u8]) -> bool {
    (1..=MAX_SERIAL_BYTES).contains(&kid.len()) && (kid.len() == 1 || kid[0] != 0)
}

/// `tenant-cmd-<tenant>`.
///
/// # Errors
/// `ID_FORMAT` for an invalid tenant id.
pub fn tenant_kid(tenant_id: &str) -> WireResult<String> {
    Ok(format!("{TENANT_KID_PREFIX}{}", validate_tenant_id(tenant_id)?))
}

/// Tenant id carried by a tenant kid, if the kid is well-formed.
#[must_use]
pub fn tenant_from_kid(kid: &str) -> Option<&str> {
    kid.strip_prefix(TENANT_KID_PREFIX).filter(|t| is_uuid4(t))
}

/// A valid tenant kid.
#[must_use]
pub fn is_tenant_kid(kid: &str) -> bool {
    tenant_from_kid(kid).is_some()
}

/// Message direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Device -> cloud.
    Uplink,
    /// Cloud -> device.
    Downlink,
}

impl Direction {
    /// `"uplink"` / `"downlink"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Direction::Uplink => "uplink",
            Direction::Downlink => "downlink",
        }
    }
}

/// The nine device topics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TopicClass {
    /// `telemetry`
    Telemetry,
    /// `events`
    Events,
    /// `shadow/reported`
    ShadowReported,
    /// `cmd/ack`
    CmdAck,
    /// `ota/status`
    OtaStatus,
    /// `shadow/desired`
    ShadowDesired,
    /// `cmd/req`
    CmdReq,
    /// `ota/notify`
    OtaNotify,
    /// `config`
    Config,
}

impl TopicClass {
    /// All classes in table order.
    pub const ALL: [TopicClass; 9] = [
        TopicClass::Telemetry,
        TopicClass::Events,
        TopicClass::ShadowReported,
        TopicClass::CmdAck,
        TopicClass::OtaStatus,
        TopicClass::ShadowDesired,
        TopicClass::CmdReq,
        TopicClass::OtaNotify,
        TopicClass::Config,
    ];

    /// Topic suffix.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            TopicClass::Telemetry => "telemetry",
            TopicClass::Events => "events",
            TopicClass::ShadowReported => "shadow/reported",
            TopicClass::CmdAck => "cmd/ack",
            TopicClass::OtaStatus => "ota/status",
            TopicClass::ShadowDesired => "shadow/desired",
            TopicClass::CmdReq => "cmd/req",
            TopicClass::OtaNotify => "ota/notify",
            TopicClass::Config => "config",
        }
    }

    /// Envelope message type carried on the topic.
    #[must_use]
    pub const fn message_type(self) -> u8 {
        match self {
            TopicClass::Telemetry => 1,
            TopicClass::Events => 2,
            TopicClass::ShadowReported => 3,
            TopicClass::ShadowDesired => 4,
            TopicClass::CmdReq => 5,
            TopicClass::CmdAck => 6,
            TopicClass::OtaNotify => 7,
            TopicClass::OtaStatus => 8,
            TopicClass::Config => 9,
        }
    }

    /// Direction of the topic.
    #[must_use]
    pub const fn direction(self) -> Direction {
        match self {
            TopicClass::Telemetry | TopicClass::Events | TopicClass::ShadowReported | TopicClass::CmdAck | TopicClass::OtaStatus => {
                Direction::Uplink
            }
            _ => Direction::Downlink,
        }
    }

    /// Retained messages allowed.
    #[must_use]
    pub const fn retained_allowed(self) -> bool {
        matches!(self, TopicClass::ShadowDesired | TopicClass::OtaNotify | TopicClass::Config)
    }

    /// Topic for a message type.
    #[must_use]
    pub fn for_message_type(t: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.message_type() == t)
    }
}

/// `im/v1/<tenant>/<device>/<suffix>`.
///
/// # Errors
/// `ID_FORMAT` for invalid ids.
pub fn build_topic(tenant_id: &str, device_id: &str, class: TopicClass) -> WireResult<String> {
    validate_tenant_id(tenant_id)?;
    validate_device_id(device_id)?;
    Ok(format!("{TOPIC_PREFIX}/{tenant_id}/{device_id}/{}", class.suffix()))
}

/// A parsed device topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topic {
    /// Tenant id.
    pub tenant_id: String,
    /// Device id.
    pub device_id: String,
    /// Topic class.
    pub class: TopicClass,
}

/// Parse and validate a device topic; wildcards and unknown suffixes are rejected.
///
/// # Errors
/// `TOPIC_FORMAT`.
pub fn parse_topic(topic: &str) -> WireResult<Topic> {
    let parts: Vec<&str> = topic.split('/').collect();
    if parts.len() < 5 || parts[0] != "im" || parts[1] != "v1" {
        return Err(err(C::TopicFormat, "topic must start with im/v1/<tenant>/<device>/"));
    }
    let (tenant, device) = (parts[2], parts[3]);
    let suffix = parts[4..].join("/");
    if !is_tenant_id(tenant) {
        return Err(err(C::TopicFormat, "invalid tenant id in topic"));
    }
    if !is_device_id(device) {
        return Err(err(C::TopicFormat, "invalid device id in topic"));
    }
    let class = TopicClass::ALL.into_iter().find(|c| c.suffix() == suffix).ok_or_else(|| err(C::TopicFormat, "unknown topic suffix"))?;
    Ok(Topic { tenant_id: tenant.to_owned(), device_id: device.to_owned(), class })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_cases() {
        for ok in ["0.0.0", "1.2.3", "1.0.0-rc.1+build.5", "1.0.0-alpha-1", "1.0.0+001", "1.0.0-0a"] {
            assert!(is_semver(ok), "{ok}");
        }
        for bad in [
            "\u{0661}.\u{0662}.\u{0663}",
            "1.2.\u{0663}",
            "1.0.0-\u{0661}",
            "1.0.0+\u{0661}",
            "\u{FF11}.0.0",
            "1.2",
            "01.2.3",
            "1.2.3-",
            "1.2.3-01",
            "1.2.3+",
            "1.2.3+a..b",
            "a.b.c",
            "1.2.3.4",
            "",
        ] {
            assert!(!is_semver(bad), "{bad}");
        }
    }

    #[test]
    fn kids() {
        assert_eq!(kid_from_serial(&[0x00, 0xff]).unwrap(), vec![0xff]);
        assert_eq!(kid_from_serial(&[0x00]).unwrap(), vec![0x00]);
        assert_eq!(kid_from_serial(&[]).unwrap(), vec![0x00]);
        assert_eq!(kid_from_serial(&[1; 21]).unwrap_err().code(), C::IdFormat);
        assert!(is_device_kid(&[0]));
        assert!(!is_device_kid(&[0, 1]));
        assert!(!is_device_kid(&[]));
        assert!(!is_device_kid(&[1; 21]));
        let t = tenant_kid("7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11").unwrap();
        assert!(is_tenant_kid(&t));
        assert!(tenant_kid("nope").is_err());
        assert!(!is_tenant_kid("tenant-cmd-nope"));
    }

    #[test]
    fn topics() {
        let t = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11";
        let d = "dev-8f3a1c2b9d4e5f60";
        for c in TopicClass::ALL {
            let topic = build_topic(t, d, c).unwrap();
            let parsed = parse_topic(&topic).unwrap();
            assert_eq!(parsed.class, c);
            assert_eq!(TopicClass::for_message_type(c.message_type()), Some(c));
        }
        assert!(build_topic("x", d, TopicClass::Config).is_err());
        assert!(build_topic(t, "x", TopicClass::Config).is_err());
        assert!(TopicClass::for_message_type(10).is_none());
        assert_eq!(Direction::Uplink.as_str(), "uplink");
        assert_eq!(Direction::Downlink.as_str(), "downlink");
        assert!(parse_firmware_id("gateway-rpi/2.4.1").is_ok());
        assert!(parse_firmware_id("gateway-rpi").is_err());
        assert!(is_group_slug("eu-west"));
        assert!(!is_group_slug(""));
    }
}
