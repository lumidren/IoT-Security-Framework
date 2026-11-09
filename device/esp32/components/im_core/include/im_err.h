/*
 * IronMesh protocol core - error codes.
 *
 * The wire error codes are the stable identifiers of device/common/WIRE_FORMAT.md §8 and
 * DELTA_FORMAT.md §6; im_err_str() returns exactly those strings so logs, the DUT control
 * protocol and the conformance vectors can compare them verbatim. The IM_ERR_* codes after
 * IM__WIRE_LAST are implementation-internal (buffer sizes, storage, transport) and never appear
 * in a wire rejection.
 */
#ifndef IM_ERR_H
#define IM_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

/* X-macro: (enum name, string) */
#define IM_ERR_LIST(X)                                         \
    X(IM_OK, "OK")                                             \
    /* CBOR (WIRE_FORMAT.md §1.2) */                            \
    X(IM_ERR_CBOR_SIZE, "CBOR_SIZE")                           \
    X(IM_ERR_CBOR_TRUNCATED, "CBOR_TRUNCATED")                 \
    X(IM_ERR_CBOR_TRAILING, "CBOR_TRAILING")                   \
    X(IM_ERR_CBOR_INDEFINITE, "CBOR_INDEFINITE")               \
    X(IM_ERR_CBOR_RESERVED, "CBOR_RESERVED")                   \
    X(IM_ERR_CBOR_BREAK, "CBOR_BREAK")                         \
    X(IM_ERR_CBOR_NON_MINIMAL_INT, "CBOR_NON_MINIMAL_INT")     \
    X(IM_ERR_CBOR_NON_MINIMAL_FLOAT, "CBOR_NON_MINIMAL_FLOAT") \
    X(IM_ERR_CBOR_SIMPLE, "CBOR_SIMPLE")                       \
    X(IM_ERR_CBOR_UTF8, "CBOR_UTF8")                           \
    X(IM_ERR_CBOR_KEY_TYPE, "CBOR_KEY_TYPE")                   \
    X(IM_ERR_CBOR_KEY_ORDER, "CBOR_KEY_ORDER")                 \
    X(IM_ERR_CBOR_DUPLICATE_KEY, "CBOR_DUPLICATE_KEY")         \
    X(IM_ERR_CBOR_DEPTH, "CBOR_DEPTH")                         \
    X(IM_ERR_CBOR_TAG, "CBOR_TAG")                             \
    X(IM_ERR_CBOR_TYPE, "CBOR_TYPE")                           \
    X(IM_ERR_CBOR_INT_RANGE, "CBOR_INT_RANGE")                 \
    /* COSE (§2) */                                             \
    X(IM_ERR_COSE_TAG, "COSE_TAG")                             \
    X(IM_ERR_COSE_STRUCTURE, "COSE_STRUCTURE")                 \
    X(IM_ERR_COSE_HEADER, "COSE_HEADER")                       \
    X(IM_ERR_COSE_ALG, "COSE_ALG")                             \
    X(IM_ERR_COSE_KID, "COSE_KID")                             \
    X(IM_ERR_COSE_KEY_TYPE, "COSE_KEY_TYPE")                   \
    X(IM_ERR_COSE_SIGNATURE, "COSE_SIGNATURE")                 \
    X(IM_ERR_COSE_UNKNOWN_KEY, "COSE_UNKNOWN_KEY")             \
    X(IM_ERR_COSE_DUPLICATE_ALG, "COSE_DUPLICATE_ALG")         \
    X(IM_ERR_COSE_PQ_REQUIRED, "COSE_PQ_REQUIRED")             \
    X(IM_ERR_COSE_DECRYPT, "COSE_DECRYPT")                     \
    /* Envelope (§3) */                                         \
    X(IM_ERR_ENV_STRUCTURE, "ENV_STRUCTURE")                   \
    X(IM_ERR_ENV_TYPE, "ENV_TYPE")                             \
    X(IM_ERR_ENV_FIELD, "ENV_FIELD")                           \
    X(IM_ERR_ENV_KID, "ENV_KID")                               \
    X(IM_ERR_ENV_UNKNOWN_KEY, "ENV_UNKNOWN_KEY")               \
    X(IM_ERR_ENV_DIRECTION, "ENV_DIRECTION")                   \
    X(IM_ERR_ENV_TS_SKEW, "ENV_TS_SKEW")                       \
    X(IM_ERR_ENV_NONCE, "ENV_NONCE")                           \
    X(IM_ERR_ENV_REPLAY, "ENV_REPLAY")                         \
    X(IM_ERR_ENV_TENANT, "ENV_TENANT")                         \
    /* Attestation (§4) */                                      \
    X(IM_ERR_ATT_TYPE, "ATT_TYPE")                             \
    X(IM_ERR_ATT_NONCE, "ATT_NONCE")                           \
    X(IM_ERR_ATT_CSR_HASH, "ATT_CSR_HASH")                     \
    X(IM_ERR_ATT_SE_TYPE, "ATT_SE_TYPE")                       \
    X(IM_ERR_ATT_EVIDENCE, "ATT_EVIDENCE")                     \
    /* Manifest (§6) */                                         \
    X(IM_ERR_MF_STRUCTURE, "MF_STRUCTURE")                     \
    X(IM_ERR_MF_FIELD, "MF_FIELD")                             \
    X(IM_ERR_MF_HASH_MISMATCH, "MF_HASH_MISMATCH")             \
    X(IM_ERR_MF_SIZE_MISMATCH, "MF_SIZE_MISMATCH")             \
    X(IM_ERR_MF_ROLLBACK, "MF_ROLLBACK")                       \
    X(IM_ERR_MF_PRODUCT, "MF_PRODUCT")                         \
    X(IM_ERR_MF_MIN_VERSION, "MF_MIN_VERSION")                 \
    X(IM_ERR_MF_NO_DELTA, "MF_NO_DELTA")                       \
    /* Delta (DELTA_FORMAT.md §6) */                            \
    X(IM_ERR_DELTA_MAGIC, "DELTA_MAGIC")                       \
    X(IM_ERR_DELTA_BLOCK_SIZE, "DELTA_BLOCK_SIZE")             \
    X(IM_ERR_DELTA_TRUNCATED, "DELTA_TRUNCATED")               \
    X(IM_ERR_DELTA_BASE_SIZE, "DELTA_BASE_SIZE")               \
    X(IM_ERR_DELTA_BASE_HASH, "DELTA_BASE_HASH")               \
    X(IM_ERR_DELTA_TOO_LARGE, "DELTA_TOO_LARGE")               \
    X(IM_ERR_DELTA_OP, "DELTA_OP")                             \
    X(IM_ERR_DELTA_BOUNDS, "DELTA_BOUNDS")                     \
    X(IM_ERR_DELTA_LITERAL_LEN, "DELTA_LITERAL_LEN")           \
    X(IM_ERR_DELTA_OVERFLOW, "DELTA_OVERFLOW")                 \
    X(IM_ERR_DELTA_SHORT, "DELTA_SHORT")                       \
    X(IM_ERR_DELTA_TARGET_HASH, "DELTA_TARGET_HASH")           \
    X(IM_ERR_DELTA_MISSING_END, "DELTA_MISSING_END")           \
    X(IM_ERR_DELTA_TRAILING, "DELTA_TRAILING")                 \
    /* HPKE (§5) */                                             \
    X(IM_ERR_HPKE_KEY, "HPKE_KEY")                             \
    X(IM_ERR_HPKE_OPEN, "HPKE_OPEN")                           \
    X(IM_ERR_HPKE_DERIVE, "HPKE_DERIVE")                       \
    X(IM_ERR_HPKE_SEQ, "HPKE_SEQ")                             \
    /* Other wire codes */                                      \
    X(IM_ERR_ID_FORMAT, "ID_FORMAT")                           \
    X(IM_ERR_TOPIC_FORMAT, "TOPIC_FORMAT")                     \
    X(IM_ERR_MLDSA_NOT_AVAILABLE, "MLDSA_NOT_AVAILABLE")       \
    /* ---- implementation-internal codes (never on the wire) ---- */ \
    X(IM_ERR_BUFFER, "BUFFER")                                 \
    X(IM_ERR_ARG, "ARG")                                       \
    X(IM_ERR_CRYPTO, "CRYPTO")                                 \
    X(IM_ERR_STORAGE, "STORAGE")                               \
    X(IM_ERR_STATE, "STATE")                                   \
    X(IM_ERR_NOT_FOUND, "NOT_FOUND")                           \
    X(IM_ERR_FULL, "FULL")                                     \
    X(IM_ERR_EMPTY, "EMPTY")                                   \
    X(IM_ERR_MQTT_MALFORMED, "MQTT_MALFORMED")                 \
    X(IM_ERR_MQTT_PROTOCOL, "MQTT_PROTOCOL")                   \
    X(IM_ERR_MQTT_INCOMPLETE, "MQTT_INCOMPLETE")               \
    X(IM_ERR_JSON, "JSON")                                     \
    X(IM_ERR_IO, "IO")                                         \
    X(IM_ERR_UNSUPPORTED, "UNSUPPORTED")                       \
    X(IM_ERR_BUSY, "BUSY")                                     \
    X(IM_ERR_TIMEOUT, "TIMEOUT")

typedef enum {
#define IM_ERR_ENUM_(name, str) name,
    IM_ERR_LIST(IM_ERR_ENUM_)
#undef IM_ERR_ENUM_
    IM_ERR__COUNT
} im_err_t;

/* First implementation-internal code: everything below it is a wire code. */
#define IM__WIRE_LAST IM_ERR_MLDSA_NOT_AVAILABLE

/* Stable string for an error code ("UNKNOWN" for out-of-range values). Never NULL. */
const char *im_err_str(im_err_t err);

/* Non-zero when err is one of the wire codes of WIRE_FORMAT.md §8 / DELTA_FORMAT.md §6. */
int im_err_is_wire(im_err_t err);

/* Propagate a non-OK result. */
#define IM_TRY(expr)                    \
    do {                                \
        im_err_t im_try_err_ = (expr);  \
        if (im_try_err_ != IM_OK) {     \
            return im_try_err_;         \
        }                               \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* IM_ERR_H */
