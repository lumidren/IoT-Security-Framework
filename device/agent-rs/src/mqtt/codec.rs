//! MQTT 5.0 packet codec (OASIS MQTT v5.0): CONNECT, CONNACK, PUBLISH, PUBACK, SUBSCRIBE,
//! SUBACK, PINGREQ, PINGRESP and DISCONNECT with properties (including user properties for the
//! W3C `traceparent`).
//!
//! The decoder is strict and bounded: the remaining length is limited by the caller's maximum
//! packet size *before* any payload is buffered, every length is checked against the input, UTF-8
//! strings are validated (no U+0000), reserved flag bits must be zero and variable-byte integers
//! must use the minimal encoding. It never panics (fuzz target `mqtt_decode`).

/// Codec error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// Malformed packet (MQTT reason code 0x81).
    #[error("malformed MQTT packet: {0}")]
    Malformed(&'static str),
    /// Packet exceeds the maximum packet size (reason code 0x95).
    #[error("MQTT packet of {0} bytes exceeds the maximum packet size")]
    TooLarge(usize),
    /// Packet type not supported by this client (reason code 0x82).
    #[error("unsupported MQTT packet type {0}")]
    Unsupported(u8),
}

type R<T> = Result<T, CodecError>;

/// Property value types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropValue {
    /// Byte.
    Byte(u8),
    /// Two byte integer.
    U16(u16),
    /// Four byte integer.
    U32(u32),
    /// Variable byte integer.
    VarInt(u32),
    /// UTF-8 string.
    Str(String),
    /// Binary data.
    Bin(Vec<u8>),
    /// UTF-8 string pair.
    Pair(String, String),
}

/// Property identifiers used by IronMesh.
pub mod prop {
    /// Payload Format Indicator
    pub const PAYLOAD_FORMAT: u8 = 0x01;
    /// Message Expiry Interval
    pub const MESSAGE_EXPIRY: u8 = 0x02;
    /// Content Type
    pub const CONTENT_TYPE: u8 = 0x03;
    /// Response Topic
    pub const RESPONSE_TOPIC: u8 = 0x08;
    /// Correlation Data
    pub const CORRELATION_DATA: u8 = 0x09;
    /// Subscription Identifier
    pub const SUBSCRIPTION_ID: u8 = 0x0B;
    /// Session Expiry Interval
    pub const SESSION_EXPIRY: u8 = 0x11;
    /// Assigned Client Identifier
    pub const ASSIGNED_CLIENT_ID: u8 = 0x12;
    /// Server Keep Alive
    pub const SERVER_KEEP_ALIVE: u8 = 0x13;
    /// Authentication Method
    pub const AUTH_METHOD: u8 = 0x15;
    /// Authentication Data
    pub const AUTH_DATA: u8 = 0x16;
    /// Request Problem Information
    pub const REQUEST_PROBLEM_INFO: u8 = 0x17;
    /// Will Delay Interval
    pub const WILL_DELAY: u8 = 0x18;
    /// Request Response Information
    pub const REQUEST_RESPONSE_INFO: u8 = 0x19;
    /// Response Information
    pub const RESPONSE_INFO: u8 = 0x1A;
    /// Server Reference
    pub const SERVER_REFERENCE: u8 = 0x1C;
    /// Reason String
    pub const REASON_STRING: u8 = 0x1F;
    /// Receive Maximum
    pub const RECEIVE_MAXIMUM: u8 = 0x21;
    /// Topic Alias Maximum
    pub const TOPIC_ALIAS_MAXIMUM: u8 = 0x22;
    /// Topic Alias
    pub const TOPIC_ALIAS: u8 = 0x23;
    /// Maximum QoS
    pub const MAXIMUM_QOS: u8 = 0x24;
    /// Retain Available
    pub const RETAIN_AVAILABLE: u8 = 0x25;
    /// User Property
    pub const USER_PROPERTY: u8 = 0x26;
    /// Maximum Packet Size
    pub const MAXIMUM_PACKET_SIZE: u8 = 0x27;
    /// Wildcard Subscription Available
    pub const WILDCARD_AVAILABLE: u8 = 0x28;
    /// Subscription Identifier Available
    pub const SUBSCRIPTION_ID_AVAILABLE: u8 = 0x29;
    /// Shared Subscription Available
    pub const SHARED_AVAILABLE: u8 = 0x2A;
}

#[derive(Clone, Copy)]
enum PropKind {
    Byte,
    U16,
    U32,
    VarInt,
    Str,
    Bin,
    Pair,
}

fn prop_kind(id: u8) -> Option<PropKind> {
    use prop::*;
    Some(match id {
        PAYLOAD_FORMAT
        | REQUEST_PROBLEM_INFO
        | REQUEST_RESPONSE_INFO
        | MAXIMUM_QOS
        | RETAIN_AVAILABLE
        | WILDCARD_AVAILABLE
        | SUBSCRIPTION_ID_AVAILABLE
        | SHARED_AVAILABLE => PropKind::Byte,
        SERVER_KEEP_ALIVE | RECEIVE_MAXIMUM | TOPIC_ALIAS_MAXIMUM | TOPIC_ALIAS => PropKind::U16,
        MESSAGE_EXPIRY | SESSION_EXPIRY | WILL_DELAY | MAXIMUM_PACKET_SIZE => PropKind::U32,
        SUBSCRIPTION_ID => PropKind::VarInt,
        CONTENT_TYPE | RESPONSE_TOPIC | ASSIGNED_CLIENT_ID | AUTH_METHOD | RESPONSE_INFO | SERVER_REFERENCE | REASON_STRING => {
            PropKind::Str
        }
        CORRELATION_DATA | AUTH_DATA => PropKind::Bin,
        USER_PROPERTY => PropKind::Pair,
        _ => return None,
    })
}

/// An ordered property list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Properties(pub Vec<(u8, PropValue)>);

impl Properties {
    /// Empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a property.
    #[must_use]
    pub fn with(mut self, id: u8, value: PropValue) -> Self {
        self.0.push((id, value));
        self
    }

    /// Append a user property.
    #[must_use]
    pub fn with_user(self, k: &str, v: &str) -> Self {
        self.with(prop::USER_PROPERTY, PropValue::Pair(k.into(), v.into()))
    }

    /// First value of a property.
    #[must_use]
    pub fn get(&self, id: u8) -> Option<&PropValue> {
        self.0.iter().find_map(|(i, v)| (*i == id).then_some(v))
    }

    /// Numeric value of a property (byte / u16 / u32 / varint).
    #[must_use]
    pub fn get_u32(&self, id: u8) -> Option<u32> {
        match self.get(id)? {
            PropValue::Byte(b) => Some(u32::from(*b)),
            PropValue::U16(v) => Some(u32::from(*v)),
            PropValue::U32(v) | PropValue::VarInt(v) => Some(*v),
            _ => None,
        }
    }

    /// First user property with key `k`.
    #[must_use]
    pub fn user(&self, k: &str) -> Option<&str> {
        self.0.iter().find_map(|(i, v)| match (i, v) {
            (&prop::USER_PROPERTY, PropValue::Pair(key, val)) if key == k => Some(val.as_str()),
            _ => None,
        })
    }

    /// Reason string, if any.
    #[must_use]
    pub fn reason_string(&self) -> Option<&str> {
        match self.get(prop::REASON_STRING)? {
            PropValue::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// CONNECT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    /// Clean start flag.
    pub clean_start: bool,
    /// Keep alive (s).
    pub keep_alive: u16,
    /// Properties.
    pub properties: Properties,
    /// Client identifier.
    pub client_id: String,
    /// Will (topic, payload, qos, retain, properties).
    pub will: Option<Will>,
    /// User name.
    pub username: Option<String>,
    /// Password.
    pub password: Option<Vec<u8>>,
}

/// Will message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will {
    /// Topic.
    pub topic: String,
    /// Payload.
    pub payload: Vec<u8>,
    /// QoS.
    pub qos: u8,
    /// Retain.
    pub retain: bool,
    /// Will properties.
    pub properties: Properties,
}

/// CONNACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnAck {
    /// Session present.
    pub session_present: bool,
    /// Reason code.
    pub reason_code: u8,
    /// Properties.
    pub properties: Properties,
}

/// PUBLISH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    /// DUP.
    pub dup: bool,
    /// QoS (0..2).
    pub qos: u8,
    /// RETAIN.
    pub retain: bool,
    /// Topic name.
    pub topic: String,
    /// Packet identifier (QoS > 0).
    pub packet_id: Option<u16>,
    /// Properties.
    pub properties: Properties,
    /// Payload.
    pub payload: Vec<u8>,
}

/// PUBACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubAck {
    /// Packet identifier.
    pub packet_id: u16,
    /// Reason code.
    pub reason_code: u8,
    /// Properties.
    pub properties: Properties,
}

/// SUBSCRIBE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe {
    /// Packet identifier.
    pub packet_id: u16,
    /// Properties.
    pub properties: Properties,
    /// `(filter, options)`; options bits 0-1 = QoS.
    pub filters: Vec<(String, u8)>,
}

/// SUBACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubAck {
    /// Packet identifier.
    pub packet_id: u16,
    /// Properties.
    pub properties: Properties,
    /// One reason code per filter.
    pub reason_codes: Vec<u8>,
}

/// DISCONNECT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disconnect {
    /// Reason code.
    pub reason_code: u8,
    /// Properties.
    pub properties: Properties,
}

/// A control packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// 1
    Connect(Connect),
    /// 2
    ConnAck(ConnAck),
    /// 3
    Publish(Publish),
    /// 4
    PubAck(PubAck),
    /// 8
    Subscribe(Subscribe),
    /// 9
    SubAck(SubAck),
    /// 12
    PingReq,
    /// 13
    PingResp,
    /// 14
    Disconnect(Disconnect),
}

/// Reason codes used by IronMesh.
pub mod reason {
    /// Success / granted QoS 0.
    pub const SUCCESS: u8 = 0x00;
    /// Granted QoS 1.
    pub const GRANTED_QOS1: u8 = 0x01;
    /// No matching subscribers (PUBACK).
    pub const NO_MATCHING_SUBSCRIBERS: u8 = 0x10;
    /// Unspecified error.
    pub const UNSPECIFIED: u8 = 0x80;
    /// Malformed packet.
    pub const MALFORMED: u8 = 0x81;
    /// Protocol error.
    pub const PROTOCOL_ERROR: u8 = 0x82;
    /// Implementation specific error.
    pub const IMPLEMENTATION_SPECIFIC: u8 = 0x83;
    /// Client identifier not valid.
    pub const CLIENT_ID_INVALID: u8 = 0x85;
    /// Bad user name or password.
    pub const BAD_CREDENTIALS: u8 = 0x86;
    /// Not authorized.
    pub const NOT_AUTHORIZED: u8 = 0x87;
    /// Server unavailable.
    pub const SERVER_UNAVAILABLE: u8 = 0x88;
    /// Banned.
    pub const BANNED: u8 = 0x8A;
    /// Keep alive timeout.
    pub const KEEP_ALIVE_TIMEOUT: u8 = 0x8D;
    /// Session taken over.
    pub const SESSION_TAKEN_OVER: u8 = 0x8E;
    /// Topic filter invalid.
    pub const TOPIC_FILTER_INVALID: u8 = 0x8F;
    /// Topic name invalid.
    pub const TOPIC_NAME_INVALID: u8 = 0x90;
    /// Receive maximum exceeded.
    pub const RECEIVE_MAXIMUM_EXCEEDED: u8 = 0x93;
    /// Packet too large.
    pub const PACKET_TOO_LARGE: u8 = 0x95;
    /// Quota exceeded.
    pub const QUOTA_EXCEEDED: u8 = 0x97;
    /// Retain not supported.
    pub const RETAIN_NOT_SUPPORTED: u8 = 0x9A;
}

// ---------------------------------------------------------------------------------------------
// Primitive encoding
// ---------------------------------------------------------------------------------------------

/// Maximum value of a variable byte integer.
pub const VARINT_MAX: u32 = 268_435_455;

fn put_varint(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let mut byte = (v % 128) as u8;
        v /= 128;
        if v > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len().min(65535) as u16).to_be_bytes());
    out.extend_from_slice(&b[..b.len().min(65535)]);
}

fn put_bin(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len().min(65535) as u16).to_be_bytes());
    out.extend_from_slice(&b[..b.len().min(65535)]);
}

fn put_props(out: &mut Vec<u8>, props: &Properties) {
    let mut body = Vec::new();
    for (id, value) in &props.0 {
        body.push(*id);
        match value {
            PropValue::Byte(b) => body.push(*b),
            PropValue::U16(v) => body.extend_from_slice(&v.to_be_bytes()),
            PropValue::U32(v) => body.extend_from_slice(&v.to_be_bytes()),
            PropValue::VarInt(v) => put_varint(&mut body, (*v).min(VARINT_MAX)),
            PropValue::Str(s) => put_str(&mut body, s),
            PropValue::Bin(b) => put_bin(&mut body, b),
            PropValue::Pair(k, v) => {
                put_str(&mut body, k);
                put_str(&mut body, v);
            }
        }
    }
    put_varint(out, body.len() as u32);
    out.extend_from_slice(&body);
}

fn frame(first: u8, body: Vec<u8>) -> R<Vec<u8>> {
    if body.len() > VARINT_MAX as usize {
        return Err(CodecError::TooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(body.len() + 5);
    out.push(first);
    put_varint(&mut out, body.len() as u32);
    out.extend_from_slice(&body);
    Ok(out)
}

impl Packet {
    /// Serialize.
    ///
    /// # Errors
    /// [`CodecError::TooLarge`] if the packet cannot be framed, `Malformed` for invalid fields.
    pub fn encode(&self) -> R<Vec<u8>> {
        let mut b = Vec::new();
        match self {
            Packet::Connect(c) => {
                put_str(&mut b, "MQTT");
                b.push(5);
                let mut flags = 0u8;
                if c.username.is_some() {
                    flags |= 0x80;
                }
                if c.password.is_some() {
                    flags |= 0x40;
                }
                if let Some(w) = &c.will {
                    flags |= 0x04 | ((w.qos & 3) << 3);
                    if w.retain {
                        flags |= 0x20;
                    }
                }
                if c.clean_start {
                    flags |= 0x02;
                }
                b.push(flags);
                b.extend_from_slice(&c.keep_alive.to_be_bytes());
                put_props(&mut b, &c.properties);
                put_str(&mut b, &c.client_id);
                if let Some(w) = &c.will {
                    put_props(&mut b, &w.properties);
                    put_str(&mut b, &w.topic);
                    put_bin(&mut b, &w.payload);
                }
                if let Some(u) = &c.username {
                    put_str(&mut b, u);
                }
                if let Some(p) = &c.password {
                    put_bin(&mut b, p);
                }
                frame(0x10, b)
            }
            Packet::ConnAck(c) => {
                b.push(u8::from(c.session_present));
                b.push(c.reason_code);
                put_props(&mut b, &c.properties);
                frame(0x20, b)
            }
            Packet::Publish(p) => {
                if p.qos > 2 || (p.qos > 0) != p.packet_id.is_some() || p.packet_id == Some(0) {
                    return Err(CodecError::Malformed("PUBLISH QoS / packet id mismatch"));
                }
                let first = 0x30 | (u8::from(p.dup) << 3) | (p.qos << 1) | u8::from(p.retain);
                put_str(&mut b, &p.topic);
                if let Some(id) = p.packet_id {
                    b.extend_from_slice(&id.to_be_bytes());
                }
                put_props(&mut b, &p.properties);
                b.extend_from_slice(&p.payload);
                frame(first, b)
            }
            Packet::PubAck(a) => {
                b.extend_from_slice(&a.packet_id.to_be_bytes());
                if a.reason_code != 0 || !a.properties.0.is_empty() {
                    b.push(a.reason_code);
                    if !a.properties.0.is_empty() {
                        put_props(&mut b, &a.properties);
                    }
                }
                frame(0x40, b)
            }
            Packet::Subscribe(s) => {
                b.extend_from_slice(&s.packet_id.to_be_bytes());
                put_props(&mut b, &s.properties);
                for (f, o) in &s.filters {
                    put_str(&mut b, f);
                    b.push(*o);
                }
                frame(0x82, b)
            }
            Packet::SubAck(s) => {
                b.extend_from_slice(&s.packet_id.to_be_bytes());
                put_props(&mut b, &s.properties);
                b.extend_from_slice(&s.reason_codes);
                frame(0x90, b)
            }
            Packet::PingReq => frame(0xC0, b),
            Packet::PingResp => frame(0xD0, b),
            Packet::Disconnect(d) => {
                if d.reason_code != 0 || !d.properties.0.is_empty() {
                    b.push(d.reason_code);
                    put_props(&mut b, &d.properties);
                }
                frame(0xE0, b)
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------------------------

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn left(&self) -> usize {
        self.b.len() - self.p
    }

    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        let s = self.b.get(self.p..self.p.saturating_add(n)).ok_or(CodecError::Malformed("truncated"))?;
        self.p += n;
        Ok(s)
    }

    fn u8(&mut self) -> R<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> R<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> R<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn varint(&mut self) -> R<u32> {
        match read_varint(&self.b[self.p..])? {
            Some((v, n)) => {
                self.p += n;
                Ok(v)
            }
            None => Err(CodecError::Malformed("truncated variable byte integer")),
        }
    }

    fn string(&mut self) -> R<String> {
        let n = usize::from(self.u16()?);
        let raw = self.take(n)?;
        let s = std::str::from_utf8(raw).map_err(|_| CodecError::Malformed("invalid UTF-8 string"))?;
        if s.contains('\0') {
            return Err(CodecError::Malformed("UTF-8 string contains U+0000"));
        }
        Ok(s.to_owned())
    }

    fn binary(&mut self) -> R<Vec<u8>> {
        let n = usize::from(self.u16()?);
        Ok(self.take(n)?.to_vec())
    }

    fn props(&mut self) -> R<Properties> {
        let len = self.varint()? as usize;
        if len > self.left() {
            return Err(CodecError::Malformed("property length exceeds packet"));
        }
        let end = self.p + len;
        let mut out = Vec::new();
        while self.p < end {
            let id = self.u8()?;
            let kind = prop_kind(id).ok_or(CodecError::Malformed("unknown property identifier"))?;
            let value = match kind {
                PropKind::Byte => PropValue::Byte(self.u8()?),
                PropKind::U16 => PropValue::U16(self.u16()?),
                PropKind::U32 => PropValue::U32(self.u32()?),
                PropKind::VarInt => PropValue::VarInt(self.varint()?),
                PropKind::Str => PropValue::Str(self.string()?),
                PropKind::Bin => PropValue::Bin(self.binary()?),
                PropKind::Pair => PropValue::Pair(self.string()?, self.string()?),
            };
            if self.p > end {
                return Err(CodecError::Malformed("property overruns property length"));
            }
            out.push((id, value));
        }
        Ok(Properties(out))
    }

    fn done(&self) -> R<()> {
        if self.p == self.b.len() {
            Ok(())
        } else {
            Err(CodecError::Malformed("trailing bytes in packet"))
        }
    }
}

/// Decode a variable byte integer: `Ok(None)` if more bytes are needed.
///
/// # Errors
/// Overlong or non-minimal encodings.
pub fn read_varint(b: &[u8]) -> R<Option<(u32, usize)>> {
    let mut value: u32 = 0;
    for i in 0..4 {
        let Some(&byte) = b.get(i) else {
            return Ok(None);
        };
        value |= u32::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            if i > 0 && byte == 0 {
                return Err(CodecError::Malformed("non-minimal variable byte integer"));
            }
            return Ok(Some((value, i + 1)));
        }
    }
    Err(CodecError::Malformed("variable byte integer longer than 4 bytes"))
}

/// Valid topic name (no wildcards, non-empty).
#[must_use]
pub fn valid_topic_name(t: &str) -> bool {
    !t.is_empty() && !t.contains(['+', '#', '\0'])
}

/// Valid topic filter (wildcards only at legal positions).
#[must_use]
pub fn valid_topic_filter(f: &str) -> bool {
    if f.is_empty() || f.contains('\0') {
        return false;
    }
    let levels: Vec<&str> = f.split('/').collect();
    levels.iter().enumerate().all(|(i, l)| {
        if l.contains('#') {
            *l == "#" && i == levels.len() - 1
        } else if l.contains('+') {
            *l == "+"
        } else {
            true
        }
    })
}

/// Try to decode one packet from the front of `buf`.
///
/// Returns `Ok(None)` when more bytes are needed and `Ok(Some((packet, consumed)))` otherwise.
///
/// # Errors
/// [`CodecError`] for malformed, oversized or unsupported packets.
pub fn decode(buf: &[u8], max_packet_size: usize) -> R<Option<(Packet, usize)>> {
    let Some(&first) = buf.first() else {
        return Ok(None);
    };
    let Some((remaining, len_bytes)) = read_varint(&buf[1..])? else {
        return Ok(None);
    };
    let total = 1 + len_bytes + remaining as usize;
    if total > max_packet_size {
        return Err(CodecError::TooLarge(total));
    }
    if buf.len() < total {
        return Ok(None);
    }
    let body = &buf[1 + len_bytes..total];
    let packet = decode_body(first, body)?;
    Ok(Some((packet, total)))
}

fn decode_body(first: u8, body: &[u8]) -> R<Packet> {
    let kind = first >> 4;
    let flags = first & 0x0f;
    let mut r = Rd { b: body, p: 0 };
    let expect_flags = |want: u8| if flags == want { Ok(()) } else { Err(CodecError::Malformed("invalid fixed header flags")) };
    let packet = match kind {
        1 => {
            expect_flags(0)?;
            if r.string()? != "MQTT" {
                return Err(CodecError::Malformed("protocol name must be MQTT"));
            }
            if r.u8()? != 5 {
                return Err(CodecError::Unsupported(1));
            }
            let cf = r.u8()?;
            if cf & 0x01 != 0 {
                return Err(CodecError::Malformed("CONNECT reserved flag set"));
            }
            let will_flag = cf & 0x04 != 0;
            let will_qos = (cf >> 3) & 3;
            let will_retain = cf & 0x20 != 0;
            if !will_flag && (will_qos != 0 || will_retain) {
                return Err(CodecError::Malformed("will QoS/retain without will flag"));
            }
            if will_qos > 2 {
                return Err(CodecError::Malformed("will QoS 3"));
            }
            let keep_alive = r.u16()?;
            let properties = r.props()?;
            let client_id = r.string()?;
            let will = if will_flag {
                let properties = r.props()?;
                let topic = r.string()?;
                if !valid_topic_name(&topic) {
                    return Err(CodecError::Malformed("invalid will topic"));
                }
                Some(Will { topic, payload: r.binary()?, qos: will_qos, retain: will_retain, properties })
            } else {
                None
            };
            let username = if cf & 0x80 != 0 { Some(r.string()?) } else { None };
            let password = if cf & 0x40 != 0 { Some(r.binary()?) } else { None };
            r.done()?;
            Packet::Connect(Connect { clean_start: cf & 0x02 != 0, keep_alive, properties, client_id, will, username, password })
        }
        2 => {
            expect_flags(0)?;
            let ack_flags = r.u8()?;
            if ack_flags & 0xfe != 0 {
                return Err(CodecError::Malformed("CONNACK reserved flags set"));
            }
            let reason_code = r.u8()?;
            let properties = if r.left() > 0 { r.props()? } else { Properties::new() };
            r.done()?;
            Packet::ConnAck(ConnAck { session_present: ack_flags & 1 != 0, reason_code, properties })
        }
        3 => {
            let qos = (flags >> 1) & 3;
            if qos == 3 {
                return Err(CodecError::Malformed("PUBLISH QoS 3"));
            }
            let dup = flags & 0x08 != 0;
            if qos == 0 && dup {
                return Err(CodecError::Malformed("DUP set on QoS 0"));
            }
            let topic = r.string()?;
            let packet_id = if qos > 0 {
                let id = r.u16()?;
                if id == 0 {
                    return Err(CodecError::Malformed("packet identifier 0"));
                }
                Some(id)
            } else {
                None
            };
            let properties = r.props()?;
            if topic.is_empty() && properties.get(prop::TOPIC_ALIAS).is_none() {
                return Err(CodecError::Malformed("empty topic without alias"));
            }
            if topic.contains(['+', '#']) {
                return Err(CodecError::Malformed("wildcard in topic name"));
            }
            let payload = body[r.p..].to_vec();
            Packet::Publish(Publish { dup, qos, retain: flags & 1 != 0, topic, packet_id, properties, payload })
        }
        4 => {
            expect_flags(0)?;
            let packet_id = r.u16()?;
            let reason_code = if r.left() > 0 { r.u8()? } else { 0 };
            let properties = if r.left() > 0 { r.props()? } else { Properties::new() };
            r.done()?;
            Packet::PubAck(PubAck { packet_id, reason_code, properties })
        }
        8 => {
            expect_flags(2)?;
            let packet_id = r.u16()?;
            if packet_id == 0 {
                return Err(CodecError::Malformed("packet identifier 0"));
            }
            let properties = r.props()?;
            let mut filters = Vec::new();
            while r.left() > 0 {
                let f = r.string()?;
                let o = r.u8()?;
                if o & 0xC0 != 0 || o & 3 == 3 || (o >> 4) & 3 == 3 {
                    return Err(CodecError::Malformed("invalid subscription options"));
                }
                filters.push((f, o));
            }
            if filters.is_empty() {
                return Err(CodecError::Malformed("SUBSCRIBE without filters"));
            }
            Packet::Subscribe(Subscribe { packet_id, properties, filters })
        }
        9 => {
            expect_flags(0)?;
            let packet_id = r.u16()?;
            let properties = r.props()?;
            let reason_codes = body[r.p..].to_vec();
            if reason_codes.is_empty() {
                return Err(CodecError::Malformed("SUBACK without reason codes"));
            }
            Packet::SubAck(SubAck { packet_id, properties, reason_codes })
        }
        12 | 13 => {
            expect_flags(0)?;
            r.done()?;
            if kind == 12 {
                Packet::PingReq
            } else {
                Packet::PingResp
            }
        }
        14 => {
            expect_flags(0)?;
            let reason_code = if r.left() > 0 { r.u8()? } else { 0 };
            let properties = if r.left() > 0 { r.props()? } else { Properties::new() };
            r.done()?;
            Packet::Disconnect(Disconnect { reason_code, properties })
        }
        0 => return Err(CodecError::Malformed("reserved packet type 0")),
        other => return Err(CodecError::Unsupported(other)),
    };
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(p: Packet) {
        let enc = p.encode().unwrap();
        let (dec, n) = decode(&enc, 1 << 20).unwrap().unwrap();
        assert_eq!(n, enc.len());
        assert_eq!(dec, p);
        // Every strict prefix is "need more" (never an error, never a panic).
        for i in 0..enc.len() {
            if let Ok(Some(_)) = decode(&enc[..i], 1 << 20) {
                panic!("prefix {i} decoded");
            }
        }
    }

    #[test]
    fn round_trips() {
        let props = Properties::new()
            .with(prop::SESSION_EXPIRY, PropValue::U32(604_800))
            .with(prop::RECEIVE_MAXIMUM, PropValue::U16(32))
            .with(prop::PAYLOAD_FORMAT, PropValue::Byte(0))
            .with(prop::SUBSCRIPTION_ID, PropValue::VarInt(300))
            .with(prop::CORRELATION_DATA, PropValue::Bin(vec![1, 2]))
            .with(prop::CONTENT_TYPE, PropValue::Str("application/cose".into()))
            .with_user("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01");
        assert_eq!(props.user("traceparent").map(str::len), Some(55));
        assert_eq!(props.get_u32(prop::RECEIVE_MAXIMUM), Some(32));
        assert_eq!(props.get_u32(prop::SESSION_EXPIRY), Some(604_800));
        assert_eq!(props.get_u32(prop::PAYLOAD_FORMAT), Some(0));
        assert_eq!(props.get_u32(prop::SUBSCRIPTION_ID), Some(300));
        assert_eq!(props.get_u32(prop::CONTENT_TYPE), None);
        rt(Packet::Connect(Connect {
            clean_start: false,
            keep_alive: 60,
            properties: props.clone(),
            client_id: "dev-0123456789abcdef".into(),
            will: Some(Will { topic: "a/b".into(), payload: vec![1], qos: 1, retain: true, properties: Properties::new() }),
            username: Some("u".into()),
            password: Some(vec![9]),
        }));
        rt(Packet::Connect(Connect {
            clean_start: true,
            keep_alive: 0,
            properties: Properties::new(),
            client_id: String::new(),
            will: None,
            username: None,
            password: None,
        }));
        rt(Packet::ConnAck(ConnAck {
            session_present: true,
            reason_code: 0,
            properties: Properties::new().with(prop::REASON_STRING, PropValue::Str("ok".into())),
        }));
        rt(Packet::Publish(Publish {
            dup: true,
            qos: 1,
            retain: true,
            topic: "t".into(),
            packet_id: Some(7),
            properties: props.clone(),
            payload: vec![0; 300],
        }));
        rt(Packet::Publish(Publish {
            dup: false,
            qos: 0,
            retain: false,
            topic: "t".into(),
            packet_id: None,
            properties: Properties::new(),
            payload: vec![],
        }));
        rt(Packet::PubAck(PubAck { packet_id: 7, reason_code: 0, properties: Properties::new() }));
        rt(Packet::PubAck(PubAck { packet_id: 7, reason_code: 0x87, properties: Properties::new() }));
        rt(Packet::PubAck(PubAck {
            packet_id: 7,
            reason_code: 0x87,
            properties: Properties::new().with(prop::REASON_STRING, PropValue::Str("no".into())),
        }));
        rt(Packet::Subscribe(Subscribe {
            packet_id: 1,
            properties: Properties::new(),
            filters: vec![("a/+".into(), 1), ("b/#".into(), 0x21)],
        }));
        rt(Packet::SubAck(SubAck { packet_id: 1, properties: Properties::new(), reason_codes: vec![1, 0x87] }));
        rt(Packet::PingReq);
        rt(Packet::PingResp);
        rt(Packet::Disconnect(Disconnect { reason_code: 0, properties: Properties::new() }));
        rt(Packet::Disconnect(Disconnect { reason_code: 0x8e, properties: Properties::new() }));
    }

    #[test]
    fn rejects_malformed() {
        let bad = |b: &[u8]| decode(b, 1 << 20).unwrap_err();
        assert!(matches!(bad(&[0x00, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0xF0, 0x00]), CodecError::Unsupported(15)));
        assert!(matches!(bad(&[0xC1, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0xC0, 0x80, 0x80, 0x80, 0x80]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0xC0, 0x80, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x36, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x38, 0x03, 0x00, 0x01, b't']), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x32, 0x06, 0x00, 0x01, b't', 0x00, 0x00, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x30, 0x04, 0x00, 0x01, b'#', 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x30, 0x03, 0x00, 0x00, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x30, 0x05, 0x00, 0x01, b't', 0x02, 0x7f]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x30, 0x05, 0x00, 0x01, 0xff, 0x00, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x30, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x80, 0x03, 0x00, 0x01, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x82, 0x03, 0x00, 0x01, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x82, 0x03, 0x00, 0x00, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, b'a', 0xC0]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x90, 0x03, 0x00, 0x01, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x20, 0x02, 0x02, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0x40, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00]), CodecError::Malformed(_)));
        assert!(matches!(bad(&[0xE0, 0x03, 0x00, 0x00, 0x00]), CodecError::Malformed(_)));
        // CONNECT variants
        let mut c = Packet::Connect(Connect {
            clean_start: true,
            keep_alive: 1,
            properties: Properties::new(),
            client_id: "c".into(),
            will: None,
            username: None,
            password: None,
        })
        .encode()
        .unwrap();
        c[9] |= 0x01;
        assert!(matches!(bad(&c), CodecError::Malformed(_)));
        let mut c2 = Packet::Connect(Connect {
            clean_start: true,
            keep_alive: 1,
            properties: Properties::new(),
            client_id: "c".into(),
            will: None,
            username: None,
            password: None,
        })
        .encode()
        .unwrap();
        c2[8] = 4;
        assert!(matches!(bad(&c2), CodecError::Unsupported(1)));
        let mut c3 = Packet::Connect(Connect {
            clean_start: true,
            keep_alive: 1,
            properties: Properties::new(),
            client_id: "c".into(),
            will: None,
            username: None,
            password: None,
        })
        .encode()
        .unwrap();
        c3[9] |= 0x08;
        assert!(matches!(bad(&c3), CodecError::Malformed(_)));
        let mut c4 = c3.clone();
        c4[4] = b'X';
        assert!(matches!(bad(&c4), CodecError::Malformed(_)));
        assert!(matches!(decode(&[0x30, 0xff, 0xff, 0x7f], 1000), Err(CodecError::TooLarge(_))));
        assert_eq!(decode(&[], 10).unwrap(), None);
        assert_eq!(decode(&[0x30], 10).unwrap(), None);
        assert!(Packet::Publish(Publish {
            dup: false,
            qos: 1,
            retain: false,
            topic: "t".into(),
            packet_id: None,
            properties: Properties::new(),
            payload: vec![]
        })
        .encode()
        .is_err());
    }

    #[test]
    fn topic_validation() {
        assert!(valid_topic_name("im/v1/a"));
        assert!(!valid_topic_name("im/+/a"));
        assert!(!valid_topic_name(""));
        assert!(valid_topic_filter("im/+/a/#"));
        assert!(valid_topic_filter("#"));
        assert!(!valid_topic_filter("im/a#"));
        assert!(!valid_topic_filter("im/#/a"));
        assert!(!valid_topic_filter("im/a+"));
        assert!(!valid_topic_filter(""));
        let mut v = Vec::new();
        put_varint(&mut v, VARINT_MAX);
        assert_eq!(read_varint(&v).unwrap(), Some((VARINT_MAX, 4)));
        assert_eq!(read_varint(&[0x80]).unwrap(), None);
    }
}
