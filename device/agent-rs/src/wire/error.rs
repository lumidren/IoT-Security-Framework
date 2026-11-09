//! Stable error codes of `device/common/WIRE_FORMAT.md` §8 and `DELTA_FORMAT.md` §6.
//!
//! Every rejection produced by the wire layer carries exactly one [`ErrorCode`]; its
//! [`ErrorCode::as_str`] is the code used verbatim in logs, metrics labels, DUT `rejections` and the
//! conformance vectors.

use std::borrow::Cow;
use std::fmt;

macro_rules! codes {
    ($( $variant:ident => $text:literal ),+ $(,)?) => {
        /// Wire-format error code (1:1 with `WIRE_FORMAT.md` §8 / `DELTA_FORMAT.md` §6).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum ErrorCode {
            $( #[doc = $text] $variant, )+
        }

        impl ErrorCode {
            /// The stable string form, e.g. `"CBOR_TRUNCATED"`.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $( ErrorCode::$variant => $text, )+ }
            }

            /// Every defined code, in specification order.
            pub const ALL: &'static [ErrorCode] = &[ $( ErrorCode::$variant, )+ ];

            /// Parse the stable string form.
            #[must_use]
            pub fn parse(text: &str) -> Option<Self> {
                match text { $( $text => Some(ErrorCode::$variant), )+ _ => None }
            }
        }
    };
}

codes! {
    CborSize => "CBOR_SIZE",
    CborTruncated => "CBOR_TRUNCATED",
    CborTrailing => "CBOR_TRAILING",
    CborIndefinite => "CBOR_INDEFINITE",
    CborReserved => "CBOR_RESERVED",
    CborBreak => "CBOR_BREAK",
    CborNonMinimalInt => "CBOR_NON_MINIMAL_INT",
    CborNonMinimalFloat => "CBOR_NON_MINIMAL_FLOAT",
    CborSimple => "CBOR_SIMPLE",
    CborUtf8 => "CBOR_UTF8",
    CborKeyType => "CBOR_KEY_TYPE",
    CborKeyOrder => "CBOR_KEY_ORDER",
    CborDuplicateKey => "CBOR_DUPLICATE_KEY",
    CborDepth => "CBOR_DEPTH",
    CborTag => "CBOR_TAG",
    CborType => "CBOR_TYPE",
    CborIntRange => "CBOR_INT_RANGE",

    CoseTag => "COSE_TAG",
    CoseStructure => "COSE_STRUCTURE",
    CoseHeader => "COSE_HEADER",
    CoseAlg => "COSE_ALG",
    CoseKid => "COSE_KID",
    CoseKeyType => "COSE_KEY_TYPE",
    CoseSignature => "COSE_SIGNATURE",
    CoseUnknownKey => "COSE_UNKNOWN_KEY",
    CoseDuplicateAlg => "COSE_DUPLICATE_ALG",
    CosePqRequired => "COSE_PQ_REQUIRED",
    CoseDecrypt => "COSE_DECRYPT",

    EnvStructure => "ENV_STRUCTURE",
    EnvType => "ENV_TYPE",
    EnvField => "ENV_FIELD",
    EnvKid => "ENV_KID",
    EnvUnknownKey => "ENV_UNKNOWN_KEY",
    EnvDirection => "ENV_DIRECTION",
    EnvTsSkew => "ENV_TS_SKEW",
    EnvNonce => "ENV_NONCE",
    EnvReplay => "ENV_REPLAY",
    EnvTenant => "ENV_TENANT",

    AttType => "ATT_TYPE",
    AttNonce => "ATT_NONCE",
    AttCsrHash => "ATT_CSR_HASH",
    AttSeType => "ATT_SE_TYPE",
    AttEvidence => "ATT_EVIDENCE",

    MfStructure => "MF_STRUCTURE",
    MfField => "MF_FIELD",
    MfHashMismatch => "MF_HASH_MISMATCH",
    MfSizeMismatch => "MF_SIZE_MISMATCH",
    MfRollback => "MF_ROLLBACK",
    MfProduct => "MF_PRODUCT",
    MfMinVersion => "MF_MIN_VERSION",
    MfNoDelta => "MF_NO_DELTA",

    DeltaMagic => "DELTA_MAGIC",
    DeltaBlockSize => "DELTA_BLOCK_SIZE",
    DeltaTruncated => "DELTA_TRUNCATED",
    DeltaBaseSize => "DELTA_BASE_SIZE",
    DeltaBaseHash => "DELTA_BASE_HASH",
    DeltaTooLarge => "DELTA_TOO_LARGE",
    DeltaOp => "DELTA_OP",
    DeltaBounds => "DELTA_BOUNDS",
    DeltaLiteralLen => "DELTA_LITERAL_LEN",
    DeltaOverflow => "DELTA_OVERFLOW",
    DeltaShort => "DELTA_SHORT",
    DeltaTargetHash => "DELTA_TARGET_HASH",
    DeltaMissingEnd => "DELTA_MISSING_END",
    DeltaTrailing => "DELTA_TRAILING",

    HpkeKey => "HPKE_KEY",
    HpkeOpen => "HPKE_OPEN",
    HpkeDerive => "HPKE_DERIVE",
    HpkeSeq => "HPKE_SEQ",

    IdFormat => "ID_FORMAT",
    TopicFormat => "TOPIC_FORMAT",
    MldsaNotAvailable => "MLDSA_NOT_AVAILABLE",
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A wire-format rejection: a stable [`ErrorCode`] plus a human-readable detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError {
    code: ErrorCode,
    detail: Cow<'static, str>,
}

impl WireError {
    /// Create an error with a static detail message.
    #[must_use]
    pub const fn new(code: ErrorCode, detail: &'static str) -> Self {
        Self { code, detail: Cow::Borrowed(detail) }
    }

    /// Create an error with a formatted detail message.
    #[must_use]
    pub fn with(code: ErrorCode, detail: String) -> Self {
        Self { code, detail: Cow::Owned(detail) }
    }

    /// The stable code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// The human-readable detail (not part of the specification).
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Replace the code, keeping the detail (used where the spec re-labels a nested failure).
    #[must_use]
    pub fn recode(self, code: ErrorCode) -> Self {
        Self { code, detail: self.detail }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            write!(f, "{}", self.code)
        } else {
            write!(f, "{}: {}", self.code, self.detail)
        }
    }
}

impl std::error::Error for WireError {}

/// Result alias used by the whole wire layer.
pub type WireResult<T> = Result<T, WireError>;

/// Shorthand: `err(ErrorCode::X, "detail")`.
pub(crate) const fn err(code: ErrorCode, detail: &'static str) -> WireError {
    WireError::new(code, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for code in ErrorCode::ALL {
            assert_eq!(ErrorCode::parse(code.as_str()), Some(*code));
        }
        assert_eq!(ErrorCode::parse("NOPE"), None);
        assert_eq!(ErrorCode::ALL.len(), 17 + 11 + 10 + 5 + 8 + 14 + 4 + 3);
    }

    #[test]
    fn display_and_recode() {
        let e = WireError::new(ErrorCode::CborSize, "too big");
        assert_eq!(e.to_string(), "CBOR_SIZE: too big");
        assert_eq!(e.detail(), "too big");
        let e = e.recode(ErrorCode::MfStructure);
        assert_eq!(e.code(), ErrorCode::MfStructure);
        assert_eq!(WireError::new(ErrorCode::CborTag, "").to_string(), "CBOR_TAG");
        assert_eq!(WireError::with(ErrorCode::CborTag, "x".into()).detail(), "x");
        assert_eq!(format!("{}", ErrorCode::EnvReplay), "ENV_REPLAY");
    }
}
