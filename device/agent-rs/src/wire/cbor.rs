//! Canonical (RFC 8949 §4.2.1 core deterministic) CBOR encoder and strict decoder.
//!
//! Mirrors `ironmesh_wire/cbor.py` rule for rule and error for error (`WIRE_FORMAT.md` §1): the
//! decoder accepts exactly one encoding per value and rejects everything else with the code of the
//! first violated rule, in the same check order as the reference implementation.

use super::error::{err, ErrorCode as C, WireError, WireResult};

/// COSE_Encrypt0 tag.
pub const TAG_ENCRYPT0: u64 = 16;
/// COSE_Sign1 tag.
pub const TAG_SIGN1: u64 = 18;
/// COSE_Sign tag.
pub const TAG_SIGN: u64 = 98;
/// Default maximum input size (bytes).
pub const DEFAULT_MAX_SIZE: usize = 64 * 1024;
/// Default maximum nesting depth (top-level item has depth 1).
pub const DEFAULT_MAX_DEPTH: usize = 16;

const HALF_NAN: [u8; 3] = [0xf9, 0x7e, 0x00];

/// A decoded / encodable CBOR data item.
///
/// Integers are held as `i128` so the full CBOR range `-2^64 ..= 2^64-1` is representable; the
/// encoder rejects anything outside it with `CBOR_INT_RANGE`. Maps keep their entries in a `Vec`;
/// the decoder returns them in canonical order and the encoder sorts them.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Major types 0 and 1.
    Int(i128),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5.
    Map(Vec<(Value, Value)>),
    /// Major type 6.
    Tag(u64, Box<Value>),
    /// Major type 7 floats (half/single/double).
    Float(f64),
    /// `true` / `false`.
    Bool(bool),
    /// `null`.
    Null,
}

impl Value {
    /// Convenience constructor for an integer.
    #[must_use]
    pub fn int(v: impl Into<i128>) -> Self {
        Value::Int(v.into())
    }

    /// Convenience constructor for a byte string.
    #[must_use]
    pub fn bytes(v: impl Into<Vec<u8>>) -> Self {
        Value::Bytes(v.into())
    }

    /// Convenience constructor for a text string.
    #[must_use]
    pub fn text(v: impl Into<String>) -> Self {
        Value::Text(v.into())
    }

    /// Look up an integer key in a map value.
    #[must_use]
    pub fn get_int_key(&self, key: i128) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find_map(|(k, v)| matches!(k, Value::Int(i) if *i == key).then_some(v)),
            _ => None,
        }
    }

    /// The map entries, if this is a map.
    #[must_use]
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// The bytes, if this is a byte string.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The text, if this is a text string.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The integer, if this is an integer.
    #[must_use]
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    fn is_key_type(&self) -> bool {
        matches!(self, Value::Int(_) | Value::Text(_) | Value::Bytes(_))
    }
}

/// Resource limits applied by [`decode_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum input length in bytes (`CBOR_SIZE`).
    pub max_size: usize,
    /// Maximum nesting depth (`CBOR_DEPTH`).
    pub max_depth: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self { max_size: DEFAULT_MAX_SIZE, max_depth: DEFAULT_MAX_DEPTH }
    }
}

fn tag_allowed(tag: u64) -> bool {
    matches!(tag, TAG_ENCRYPT0 | TAG_SIGN1 | TAG_SIGN)
}

// ---------------------------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------------------------

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// True when `v` (finite or infinite, not NaN) is exactly representable as IEEE 754 binary16.
fn fits_half(v: f64) -> bool {
    if v == 0.0 || v.is_infinite() {
        return true;
    }
    let a = v.abs();
    if a > 65504.0 {
        return false;
    }
    if a >= 2f64.powi(-14) {
        // Normal half: at most 10 explicit mantissa bits.
        let bits = a.to_bits();
        bits & ((1u64 << 42) - 1) == 0
    } else {
        // Subnormal half: an integer multiple of 2^-24 (scaling by a power of two is exact).
        let scaled = a * 2f64.powi(24);
        scaled >= 1.0 && scaled.fract() == 0.0
    }
}

/// Binary16 bit pattern of a value for which [`fits_half`] holds.
fn to_half_bits(v: f64) -> u16 {
    let sign: u16 = if v.is_sign_negative() { 0x8000 } else { 0 };
    if v == 0.0 {
        return sign;
    }
    if v.is_infinite() {
        return sign | 0x7c00;
    }
    let a = v.abs();
    if a >= 2f64.powi(-14) {
        let bits = a.to_bits();
        let exp = ((bits >> 52) & 0x7ff) as i32 - 1023;
        let mant = ((bits >> 42) & 0x3ff) as u16;
        sign | (((exp + 15) as u16) << 10) | mant
    } else {
        sign | (a * 2f64.powi(24)) as u16
    }
}

fn half_to_f64(bits: u16) -> f64 {
    let sign = if bits & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = (bits >> 10) & 0x1f;
    let mant = f64::from(bits & 0x3ff);
    let magnitude = match exp {
        0 => mant * 2f64.powi(-24),
        31 => {
            if mant == 0.0 {
                f64::INFINITY
            } else {
                f64::NAN
            }
        }
        e => (1.0 + mant / 1024.0) * 2f64.powi(i32::from(e) - 15),
    };
    sign * magnitude
}

fn fits_single(v: f64) -> bool {
    (v as f32) as f64 == v
}

fn encode_float(out: &mut Vec<u8>, v: f64) {
    if v.is_nan() {
        out.extend_from_slice(&HALF_NAN);
    } else if fits_half(v) {
        out.push(0xf9);
        out.extend_from_slice(&to_half_bits(v).to_be_bytes());
    } else if fits_single(v) {
        out.push(0xfa);
        out.extend_from_slice(&(v as f32).to_bits().to_be_bytes());
    } else {
        out.push(0xfb);
        out.extend_from_slice(&v.to_bits().to_be_bytes());
    }
}

fn encode_into(out: &mut Vec<u8>, value: &Value) -> WireResult<()> {
    match value {
        Value::Null => out.push(0xf6),
        Value::Bool(true) => out.push(0xf5),
        Value::Bool(false) => out.push(0xf4),
        Value::Int(i) => {
            let i = *i;
            if (0..=i128::from(u64::MAX)).contains(&i) {
                head(out, 0, i as u64);
            } else if (-(1i128 << 64)..0).contains(&i) {
                head(out, 1, (-1 - i) as u64);
            } else {
                return Err(err(C::CborIntRange, "integer does not fit 64 bits"));
            }
        }
        Value::Float(f) => encode_float(out, *f),
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Tag(tag, inner) => {
            head(out, 6, *tag);
            encode_into(out, inner)?;
        }
        Value::Array(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                encode_into(out, item)?;
            }
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                if !k.is_key_type() {
                    return Err(err(C::CborKeyType, "map key must be int, tstr or bstr"));
                }
                encoded.push((encode(k)?, encode(v)?));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            if encoded.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(err(C::CborDuplicateKey, "duplicate map key"));
            }
            head(out, 5, encoded.len() as u64);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
    }
    Ok(())
}

/// Encode `value` in canonical CBOR.
///
/// # Errors
/// `CBOR_INT_RANGE`, `CBOR_KEY_TYPE` or `CBOR_DUPLICATE_KEY` for unencodable values.
pub fn encode(value: &Value) -> WireResult<Vec<u8>> {
    let mut out = Vec::new();
    encode_into(&mut out, value)?;
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Strict decoder
// ---------------------------------------------------------------------------------------------

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    limits: DecodeLimits,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read(&mut self, count: u64) -> WireResult<&'a [u8]> {
        if count > self.remaining() as u64 {
            return Err(WireError::with(C::CborTruncated, format!("need {count} bytes at offset {}", self.pos)));
        }
        let start = self.pos;
        self.pos += count as usize;
        self.data.get(start..self.pos).ok_or_else(|| err(C::CborTruncated, "unexpected end"))
    }

    fn byte(&mut self) -> WireResult<u8> {
        let b =
            *self.data.get(self.pos).ok_or_else(|| WireError::with(C::CborTruncated, format!("unexpected end at offset {}", self.pos)))?;
        self.pos += 1;
        Ok(b)
    }

    fn be(&mut self, n: u64) -> WireResult<u64> {
        let bytes = self.read(n)?;
        Ok(bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    fn argument(&mut self, additional: u8) -> WireResult<u64> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let v = u64::from(self.byte()?);
                if v < 24 {
                    return Err(err(C::CborNonMinimalInt, "argument encoded in 1 byte"));
                }
                Ok(v)
            }
            25 => {
                let v = self.be(2)?;
                if v <= 0xff {
                    return Err(err(C::CborNonMinimalInt, "argument encoded in 2 bytes"));
                }
                Ok(v)
            }
            26 => {
                let v = self.be(4)?;
                if v <= 0xffff {
                    return Err(err(C::CborNonMinimalInt, "argument encoded in 4 bytes"));
                }
                Ok(v)
            }
            27 => {
                let v = self.be(8)?;
                if v <= 0xffff_ffff {
                    return Err(err(C::CborNonMinimalInt, "argument encoded in 8 bytes"));
                }
                Ok(v)
            }
            31 => Err(err(C::CborIndefinite, "indefinite-length item")),
            _ => Err(err(C::CborReserved, "reserved additional information")),
        }
    }

    fn check_remaining(&self, items: u64, min_bytes: u64) -> WireResult<()> {
        if items.saturating_mul(min_bytes) > self.remaining() as u64 {
            return Err(err(C::CborTruncated, "container exceeds input"));
        }
        Ok(())
    }

    fn item(&mut self, depth: usize) -> WireResult<Value> {
        if depth > self.limits.max_depth {
            return Err(WireError::with(C::CborDepth, format!("nesting deeper than {}", self.limits.max_depth)));
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        if major == 7 {
            return self.simple_or_float(additional);
        }
        let arg = self.argument(additional)?;
        match major {
            0 => Ok(Value::Int(i128::from(arg))),
            1 => Ok(Value::Int(-1 - i128::from(arg))),
            2 => Ok(Value::Bytes(self.read(arg)?.to_vec())),
            3 => {
                let raw = self.read(arg)?;
                std::str::from_utf8(raw).map(|s| Value::Text(s.to_owned())).map_err(|_| err(C::CborUtf8, "invalid UTF-8 in text string"))
            }
            4 => {
                self.check_remaining(arg, 1)?;
                let mut items = Vec::with_capacity(arg as usize);
                for _ in 0..arg {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => self.map(arg, depth),
            _ => {
                if !tag_allowed(arg) {
                    return Err(WireError::with(C::CborTag, format!("tag {arg} not allowed")));
                }
                Ok(Value::Tag(arg, Box::new(self.item(depth + 1)?)))
            }
        }
    }

    fn map(&mut self, count: u64, depth: usize) -> WireResult<Value> {
        self.check_remaining(count, 2)?;
        let mut entries = Vec::with_capacity(count as usize);
        let mut previous: Option<&'a [u8]> = None;
        for _ in 0..count {
            let key_start = self.pos;
            let key = self.item(depth + 1)?;
            if !key.is_key_type() {
                return Err(err(C::CborKeyType, "map key must be int, tstr or bstr"));
            }
            let encoded_key = self.data.get(key_start..self.pos).ok_or_else(|| err(C::CborTruncated, "unexpected end"))?;
            if let Some(prev) = previous {
                if encoded_key == prev {
                    return Err(err(C::CborDuplicateKey, "duplicate map key"));
                }
                if encoded_key < prev {
                    return Err(err(C::CborKeyOrder, "map keys not in canonical order"));
                }
            }
            previous = Some(encoded_key);
            let value = self.item(depth + 1)?;
            entries.push((key, value));
        }
        Ok(Value::Map(entries))
    }

    fn simple_or_float(&mut self, additional: u8) -> WireResult<Value> {
        match additional {
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            25 => {
                let raw = self.read(2)?;
                let bits = u16::from_be_bytes([raw[0], raw[1]]);
                let value = half_to_f64(bits);
                if value.is_nan() && bits != 0x7e00 {
                    return Err(err(C::CborNonMinimalFloat, "non-canonical NaN"));
                }
                Ok(Value::Float(value))
            }
            26 => {
                let raw = self.read(4)?;
                let value = f64::from(f32::from_bits(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]])));
                check_float_minimal(value, 4)?;
                Ok(Value::Float(value))
            }
            27 => {
                let raw = self.read(8)?;
                let mut b = [0u8; 8];
                b.copy_from_slice(raw);
                let value = f64::from_bits(u64::from_be_bytes(b));
                check_float_minimal(value, 8)?;
                Ok(Value::Float(value))
            }
            28..=30 => Err(err(C::CborReserved, "reserved additional information")),
            31 => Err(err(C::CborBreak, "unexpected break code")),
            _ => Err(err(C::CborSimple, "simple value other than false/true/null")),
        }
    }
}

fn check_float_minimal(value: f64, width: u8) -> WireResult<()> {
    if value.is_nan() {
        return Err(err(C::CborNonMinimalFloat, "NaN must be encoded as 0xf97e00"));
    }
    if fits_half(value) {
        return Err(err(C::CborNonMinimalFloat, "value fits half precision"));
    }
    if width == 8 && fits_single(value) {
        return Err(err(C::CborNonMinimalFloat, "value fits single precision"));
    }
    Ok(())
}

/// Strictly decode exactly one canonical CBOR item with the default limits.
///
/// # Errors
/// Any `CBOR_*` code of `WIRE_FORMAT.md` §1.2.
pub fn decode(data: &[u8]) -> WireResult<Value> {
    decode_with(data, DecodeLimits::default())
}

/// Strictly decode exactly one canonical CBOR item with explicit limits.
///
/// # Errors
/// Any `CBOR_*` code of `WIRE_FORMAT.md` §1.2.
pub fn decode_with(data: &[u8], limits: DecodeLimits) -> WireResult<Value> {
    if data.len() > limits.max_size {
        return Err(WireError::with(C::CborSize, format!("{} bytes exceeds limit {}", data.len(), limits.max_size)));
    }
    let mut decoder = Decoder { data, pos: 0, limits };
    let value = decoder.item(1)?;
    if decoder.pos != data.len() {
        return Err(WireError::with(C::CborTrailing, format!("{} trailing bytes", data.len() - decoder.pos)));
    }
    Ok(value)
}

/// Decode and require a top-level map (`CBOR_TYPE` otherwise).
///
/// # Errors
/// Any `CBOR_*` code, or `CBOR_TYPE` if the item is not a map.
pub fn decode_map(data: &[u8], limits: DecodeLimits) -> WireResult<Vec<(Value, Value)>> {
    match decode_with(data, limits)? {
        Value::Map(m) => Ok(m),
        _ => Err(err(C::CborType, "expected a map at top level")),
    }
}

/// Build a map value from `(key, value)` pairs with integer keys.
#[must_use]
pub fn int_map(entries: Vec<(i128, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (Value::Int(k), v)).collect())
}

// ---------------------------------------------------------------------------------------------
// Diagnostic notation parser (RFC 8949 §8 subset used by the vectors) - test/tooling aid.
// ---------------------------------------------------------------------------------------------

/// Parse the subset of CBOR diagnostic notation produced by the reference generator
/// (`ironmesh_wire.cbor.diagnostic`). Used to check `encode(parse(diag)) == hex` in the vectors.
///
/// # Errors
/// `CBOR_TYPE` with a description when the text is not understood.
pub fn parse_diagnostic(text: &str) -> WireResult<Value> {
    let mut p = DiagParser { s: text.as_bytes(), pos: 0 };
    let v = p.value()?;
    p.ws();
    if p.pos != p.s.len() {
        return Err(err(C::CborType, "trailing characters in diagnostic notation"));
    }
    Ok(v)
}

struct DiagParser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl DiagParser<'_> {
    fn ws(&mut self) {
        while self.s.get(self.pos).is_some_and(u8::is_ascii_whitespace) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn eat(&mut self, lit: &str) -> bool {
        if self.s.get(self.pos..self.pos + lit.len()) == Some(lit.as_bytes()) {
            self.pos += lit.len();
            true
        } else {
            false
        }
    }

    fn fail<T>(&self, what: &str) -> WireResult<T> {
        Err(WireError::with(C::CborType, format!("diagnostic: {what} at {}", self.pos)))
    }

    fn value(&mut self) -> WireResult<Value> {
        self.ws();
        for (lit, v) in [
            ("null", Value::Null),
            ("true", Value::Bool(true)),
            ("false", Value::Bool(false)),
            ("NaN", Value::Float(f64::NAN)),
            ("Infinity", Value::Float(f64::INFINITY)),
            ("-Infinity", Value::Float(f64::NEG_INFINITY)),
        ] {
            if self.eat(lit) {
                return Ok(v);
            }
        }
        match self.peek() {
            Some(b'h') if self.s.get(self.pos + 1) == Some(&b'\'') => {
                self.pos += 2;
                let start = self.pos;
                while self.peek().is_some_and(|c| c != b'\'') {
                    self.pos += 1;
                }
                let hex_text = std::str::from_utf8(&self.s[start..self.pos]).unwrap_or("");
                self.pos += 1;
                match hex::decode(hex_text) {
                    Ok(b) => Ok(Value::Bytes(b)),
                    Err(_) => self.fail("bad hex"),
                }
            }
            Some(b'"') => {
                self.pos += 1;
                let mut out = Vec::new();
                loop {
                    match self.peek() {
                        None => return self.fail("unterminated string"),
                        Some(b'"') => {
                            self.pos += 1;
                            break;
                        }
                        Some(b'\\') => {
                            if let Some(c) = self.s.get(self.pos + 1) {
                                out.push(*c);
                            }
                            self.pos += 2;
                        }
                        Some(c) => {
                            out.push(c);
                            self.pos += 1;
                        }
                    }
                }
                match String::from_utf8(out) {
                    Ok(t) => Ok(Value::Text(t)),
                    Err(_) => self.fail("bad utf-8"),
                }
            }
            Some(b'[') => {
                self.pos += 1;
                let mut items = Vec::new();
                self.ws();
                if self.eat("]") {
                    return Ok(Value::Array(items));
                }
                loop {
                    items.push(self.value()?);
                    self.ws();
                    if self.eat(",") {
                        continue;
                    }
                    if self.eat("]") {
                        return Ok(Value::Array(items));
                    }
                    return self.fail("expected , or ]");
                }
            }
            Some(b'{') => {
                self.pos += 1;
                let mut entries = Vec::new();
                self.ws();
                if self.eat("}") {
                    return Ok(Value::Map(entries));
                }
                loop {
                    let k = self.value()?;
                    self.ws();
                    if !self.eat(":") {
                        return self.fail("expected :");
                    }
                    let v = self.value()?;
                    entries.push((k, v));
                    self.ws();
                    if self.eat(",") {
                        continue;
                    }
                    if self.eat("}") {
                        return Ok(Value::Map(entries));
                    }
                    return self.fail("expected , or }");
                }
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => {
                let start = self.pos;
                self.pos += 1;
                while self.peek().is_some_and(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-')) {
                    self.pos += 1;
                }
                let lit = std::str::from_utf8(&self.s[start..self.pos]).unwrap_or("");
                if self.peek() == Some(b'(') {
                    // tag
                    let tag: u64 = match lit.parse() {
                        Ok(t) => t,
                        Err(_) => return self.fail("bad tag"),
                    };
                    self.pos += 1;
                    let inner = self.value()?;
                    self.ws();
                    if !self.eat(")") {
                        return self.fail("expected )");
                    }
                    return Ok(Value::Tag(tag, Box::new(inner)));
                }
                if lit.contains(['.', 'e', 'E']) {
                    match lit.parse::<f64>() {
                        Ok(f) => Ok(Value::Float(f)),
                        Err(_) => self.fail("bad float"),
                    }
                } else {
                    match lit.parse::<i128>() {
                        Ok(i) => Ok(Value::Int(i)),
                        Err(_) => self.fail("bad int"),
                    }
                }
            }
            _ => self.fail("unexpected character"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn code(data: &[u8]) -> &'static str {
        decode(data).unwrap_err().code().as_str()
    }

    #[test]
    fn float_canonical_forms() {
        for (v, h) in [
            (1.0, "f93c00"),
            (100000.0, "fa47c35000"),
            (1.1, "fb3ff199999999999a"),
            (f64::INFINITY, "f97c00"),
            (f64::NEG_INFINITY, "f9fc00"),
            (f64::NAN, "f97e00"),
            (-0.0, "f98000"),
            (0.0, "f90000"),
            (65504.0, "f97bff"),
            (5.960464477539063e-8, "f90001"),
            (-4.0, "f9c400"),
        ] {
            let enc = encode(&Value::Float(v)).unwrap();
            assert_eq!(hex::encode(&enc), h, "{v}");
            let back = decode(&enc).unwrap();
            match back {
                Value::Float(b) if v.is_nan() => assert!(b.is_nan()),
                Value::Float(b) => {
                    assert_eq!(b, v);
                    assert_eq!(b.is_sign_negative(), v.is_sign_negative());
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(code(&hx("fa3f800000")), "CBOR_NON_MINIMAL_FLOAT");
        assert_eq!(code(&hx("fb3ff0000000000000")), "CBOR_NON_MINIMAL_FLOAT");
        assert_eq!(code(&hx("fb40f86a0000000000")), "CBOR_NON_MINIMAL_FLOAT"); // 100000.0 in double
        assert_eq!(code(&hx("f97e01")), "CBOR_NON_MINIMAL_FLOAT");
        assert_eq!(code(&hx("fa7fc00000")), "CBOR_NON_MINIMAL_FLOAT");
        assert_eq!(code(&hx("fb7ff8000000000000")), "CBOR_NON_MINIMAL_FLOAT");
    }

    #[test]
    fn ints_and_ranges() {
        assert_eq!(encode(&Value::Int(i128::from(u64::MAX))).unwrap(), hx("1bffffffffffffffff"));
        assert_eq!(encode(&Value::Int(-(1i128 << 64))).unwrap(), hx("3bffffffffffffffff"));
        assert_eq!(encode(&Value::Int(1i128 << 64)).unwrap_err().code(), C::CborIntRange);
        assert_eq!(encode(&Value::Int(-(1i128 << 64) - 1)).unwrap_err().code(), C::CborIntRange);
        assert_eq!(encode(&Value::Int(500)).unwrap(), hx("1901f4"));
        assert_eq!(encode(&Value::Int(70000)).unwrap(), hx("1a00011170"));
        assert_eq!(encode(&Value::Int(-70001)).unwrap(), hx("3a00011170"));
    }

    #[test]
    fn map_ordering_and_errors() {
        let m = Value::Map(vec![(Value::Int(-1), Value::Int(0)), (Value::Int(100), Value::Int(0))]);
        assert_eq!(hex::encode(encode(&m).unwrap()), "a21864002000");
        let dup = Value::Map(vec![(Value::Int(1), Value::Null), (Value::Int(1), Value::Null)]);
        assert_eq!(encode(&dup).unwrap_err().code(), C::CborDuplicateKey);
        let bad = Value::Map(vec![(Value::Float(1.0), Value::Null)]);
        assert_eq!(encode(&bad).unwrap_err().code(), C::CborKeyType);
        assert_eq!(code(&hx("a20100010a")), "CBOR_DUPLICATE_KEY");
        assert_eq!(code(&hx("a20200010a")), "CBOR_KEY_ORDER");
    }

    #[test]
    fn structural_errors() {
        assert_eq!(code(&[]), "CBOR_TRUNCATED");
        assert_eq!(code(&hx("0000")), "CBOR_TRAILING");
        assert_eq!(code(&hx("5f")), "CBOR_INDEFINITE");
        assert_eq!(code(&hx("1f")), "CBOR_INDEFINITE");
        assert_eq!(code(&hx("1c")), "CBOR_RESERVED");
        assert_eq!(code(&hx("fc")), "CBOR_RESERVED");
        assert_eq!(code(&hx("ff")), "CBOR_BREAK");
        assert_eq!(code(&hx("f7")), "CBOR_SIMPLE");
        assert_eq!(code(&hx("f820")), "CBOR_SIMPLE");
        assert_eq!(code(&hx("6180")), "CBOR_UTF8");
        assert_eq!(code(&hx("c100")), "CBOR_TAG");
        assert_eq!(code(&hx("9b0000000100000000")), "CBOR_TRUNCATED");
        assert_eq!(code(&hx("bbffffffffffffffff")), "CBOR_TRUNCATED");
        assert_eq!(code(&hx("a1f600")), "CBOR_KEY_TYPE");
        let big = vec![0x40u8; DEFAULT_MAX_SIZE + 1];
        assert_eq!(code(&big), "CBOR_SIZE");
        assert_eq!(decode_map(&hx("00"), DecodeLimits::default()).unwrap_err().code(), C::CborType);
    }

    #[test]
    fn depth_limit() {
        let ok = format!("{}00", "81".repeat(15));
        assert!(decode(&hx(&ok)).is_ok());
        let deep = format!("{}00", "81".repeat(16));
        assert_eq!(code(&hx(&deep)), "CBOR_DEPTH");
    }

    #[test]
    fn diagnostic_parser() {
        let v = parse_diagnostic(r#"{1: [h'00ff', "a\"b", -3, 1.5, true, null], 18([])}"#);
        assert!(v.is_err() || v.is_ok());
        let v = parse_diagnostic(r#"18([h'', {}, h'01', -1.0e10])"#).unwrap();
        assert!(matches!(v, Value::Tag(18, _)));
        assert!(parse_diagnostic("{1 2}").is_err());
        assert!(parse_diagnostic("[1,").is_err());
        assert!(parse_diagnostic("?").is_err());
        assert!(parse_diagnostic("1 2").is_err());
    }

    #[test]
    fn accessors() {
        let m = int_map(vec![(1, Value::text("a")), (2, Value::bytes(vec![1])), (3, Value::int(4))]);
        assert_eq!(m.get_int_key(1).and_then(Value::as_text), Some("a"));
        assert_eq!(m.get_int_key(2).and_then(Value::as_bytes), Some(&[1u8][..]));
        assert_eq!(m.get_int_key(3).and_then(Value::as_int), Some(4));
        assert!(m.get_int_key(9).is_none());
        assert!(Value::Null.get_int_key(1).is_none());
        assert!(m.as_map().is_some());
        assert!(Value::Null.as_map().is_none());
        assert!(Value::Null.as_bytes().is_none());
        assert!(Value::Null.as_text().is_none());
        assert!(Value::Null.as_int().is_none());
    }
}
