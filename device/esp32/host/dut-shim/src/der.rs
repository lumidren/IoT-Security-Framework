//! Minimal, bounds-checked DER reader: just enough X.509 / PKCS#7 to read an EST certs-only
//! response (RFC 7030 §4.2.3) and to hash a certificate's SubjectPublicKeyInfo for CA pinning.

/// One TLV: tag byte, content, and the full encoding.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

/// Read one TLV from the front of `b`; returns it and the remainder.
pub fn tlv(b: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *b.first()?;
    if tag & 0x1f == 0x1f {
        return None; // multi-byte tags are not used in X.509
    }
    let l0 = *b.get(1)? as usize;
    let (len, hdr) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return None; // indefinite / absurd lengths are not DER
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if end > b.len() {
        return None;
    }
    Some((
        Tlv {
            tag,
            content: &b[hdr..end],
            raw: &b[..end],
        },
        &b[end..],
    ))
}

/// Iterate the children of a constructed TLV.
pub fn children(mut b: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (t, rest) = tlv(b)?;
        out.push(t);
        b = rest;
    }
    Some(out)
}

/// Fields of interest of an X.509 certificate.
#[derive(Clone, Debug)]
pub struct CertInfo {
    pub der: Vec<u8>,
    /// Serial number content octets (may carry a leading 0x00).
    pub serial: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
    pub spki: Vec<u8>,
    pub subject_cn: Option<String>,
    pub is_ca: bool,
    /// Raw issuer / subject Name encodings (self-issued when equal).
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
}

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

fn digits(s: &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u64::from(c - b'0');
    }
    Some(v)
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: u64, d: u64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) to Unix seconds.
pub fn parse_time(t: &Tlv) -> Option<u64> {
    let s = t.content;
    let (year, rest) = match (t.tag, s.len()) {
        (0x17, 13) => {
            let yy = digits(&s[0..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
        }
        (0x18, 15) => (digits(&s[0..4])?, &s[4..]),
        _ => return None,
    };
    if rest.last() != Some(&b'Z') {
        return None;
    }
    let (mo, d, h, mi, se) = (
        digits(&rest[0..2])?,
        digits(&rest[2..4])?,
        digits(&rest[4..6])?,
        digits(&rest[6..8])?,
        digits(&rest[8..10])?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let days = days_from_civil(year as i64, mo, d);
    u64::try_from(days * 86_400 + (h * 3600 + mi * 60 + se) as i64).ok()
}

/// Parse a DER certificate.
pub fn parse_cert(der: &[u8]) -> Option<CertInfo> {
    let (cert, rest) = tlv(der)?;
    if cert.tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let parts = children(cert.content)?;
    let tbs = parts.first()?;
    let f = children(tbs.content)?;
    let mut i = 0;
    if f.first()?.tag == 0xa0 {
        i = 1; // [0] version
    }
    let serial = f.get(i)?;
    let issuer = f.get(i + 2)?;
    let validity = children(f.get(i + 3)?.content)?;
    let subject = f.get(i + 4)?;
    let spki = f.get(i + 5)?;
    if serial.tag != 0x02 || spki.tag != 0x30 || validity.len() != 2 {
        return None;
    }
    let mut cn = None;
    for rdn in children(subject.content)? {
        for atv in children(rdn.content)? {
            let kv = children(atv.content)?;
            if kv.len() == 2 && kv[0].content == OID_CN {
                cn = String::from_utf8(kv[1].content.to_vec()).ok();
            }
        }
    }
    let mut is_ca = false;
    for ext_wrapper in f.iter().skip(i + 6).filter(|t| t.tag == 0xa3) {
        for ext in children(children(ext_wrapper.content)?.first()?.content)? {
            let e = children(ext.content)?;
            if e.first().map(|o| o.content) == Some(OID_BASIC_CONSTRAINTS) {
                let val = e.last()?;
                if let Some((bc, _)) = tlv(val.content) {
                    let inner = children(bc.content)?;
                    is_ca = inner.first().is_some_and(|b| b.tag == 0x01 && b.content == [0xff]);
                }
            }
        }
    }
    Some(CertInfo {
        der: der.to_vec(),
        serial: serial.content.to_vec(),
        not_before: parse_time(&validity[0])?,
        not_after: parse_time(&validity[1])?,
        spki: spki.raw.to_vec(),
        subject_cn: cn,
        is_ca,
        issuer: issuer.raw.to_vec(),
        subject: subject.raw.to_vec(),
    })
}

/// Certificates of a PKCS#7 / CMS SignedData "certs-only" message.
pub fn pkcs7_certs(der: &[u8]) -> Option<Vec<CertInfo>> {
    let (ci, _) = tlv(der)?;
    let ci = children(ci.content)?;
    if ci.first()?.content != OID_SIGNED_DATA {
        return None;
    }
    let explicit = ci.get(1)?;
    let (sd, _) = tlv(explicit.content)?;
    let sd = children(sd.content)?;
    let certs = sd.iter().find(|t| t.tag == 0xa0)?; // [0] IMPLICIT CertificateSet
    let mut out = Vec::new();
    for c in children(certs.content)? {
        out.push(parse_cert(c.raw)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_parsing() {
        let t = Tlv {
            tag: 0x17,
            content: b"260101000000Z",
            raw: &[],
        };
        assert_eq!(parse_time(&t), Some(1_767_225_600));
        let g = Tlv {
            tag: 0x18,
            content: b"20500101000000Z",
            raw: &[],
        };
        assert_eq!(parse_time(&g), Some(2_524_608_000));
        assert_eq!(
            parse_time(&Tlv {
                tag: 0x17,
                content: b"261301000000Z",
                raw: &[]
            }),
            None
        );
    }

    #[test]
    fn rejects_truncated() {
        assert!(tlv(&[0x30, 0x05, 0x01]).is_none());
        assert!(tlv(&[0x30, 0x80]).is_none());
        assert!(parse_cert(&[0x30, 0x00]).is_none());
    }
}
