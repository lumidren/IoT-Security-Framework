//! ML-DSA-65 verification backend for the host build (the ESP32 build has none and reports
//! `MLDSA_NOT_AVAILABLE`, see `im_crypto_mbedtls.c`).

use crate::err::*;
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

/// FIPS 204 pure-mode verification with an empty context string.
pub fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> i32 {
    let Ok(enc) = EncodedVerifyingKey::<MlDsa65>::try_from(public) else {
        return IM_ERR_COSE_SIGNATURE;
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&enc);
    let Ok(sig) = Signature::<MlDsa65>::try_from(sig) else {
        return IM_ERR_COSE_SIGNATURE;
    };
    if vk.verify_with_context(msg, b"", &sig) {
        IM_OK
    } else {
        IM_ERR_COSE_SIGNATURE
    }
}
