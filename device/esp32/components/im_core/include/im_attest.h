/*
 * IronMesh protocol core - attestation (contract §3, WIRE_FORMAT.md §4).
 * im_attest_build() is what the device sends in X-IronMesh-Attestation; im_attest_verify() is
 * the server-side check, provided so the conformance vectors can run through the C code and so
 * the device can self-test what it produced.
 */
#ifndef IM_ATTEST_H
#define IM_ATTEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_cose.h"
#include "im_crypto.h"
#include "im_envelope.h"
#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IM_ATT_NONCE_LEN 32u

/* se_type bit mask for verification policies */
#define IM_SE_ATECC608 0x1u
#define IM_SE_TPM2 0x2u
#define IM_SE_OPTEE 0x4u
#define IM_SE_SOFTWARE 0x8u
#define IM_SE_ANY 0xFu

/* Build the signed type-10 envelope: body {nonce, sha256(csr), fw_hash, fw_version,
 * id->se_type, null}, signed ES256 by the current identity key, kid = cert serial. */
im_err_t im_attest_build(const im_identity_t *id, const uint8_t *kid, size_t kid_len,
                         uint64_t seq, uint64_t ts, const uint8_t nonce[32],
                         const uint8_t *csr_der, size_t csr_len, const uint8_t fw_hash[32],
                         const char *fw_version, uint8_t *out, size_t cap, size_t *out_len);

typedef struct {
    const uint8_t *expected_nonce; /* 32 */
    const uint8_t *csr_der;
    size_t csr_len;
    uint64_t now;
    uint64_t max_skew;            /* 0: default 300 */
    const uint8_t *expected_kid;  /* NULL: not checked */
    size_t expected_kid_len;
    unsigned allowed_se_types;    /* 0: any */
    const im_replay_store_t *replay; /* NULL: fresh single-use store */
} im_attest_verify_opts_t;

/* verify_attestation: envelope rules (uplink, key = TLS client key), ATT_TYPE, ENV_KID,
 * ATT_NONCE, ATT_CSR_HASH, ATT_SE_TYPE, ATT_EVIDENCE (TPMS_ATTEST structure). */
im_err_t im_attest_verify(const uint8_t *buf, size_t len, const im_pubkey_t *identity_key,
                          const im_attest_verify_opts_t *opts, im_env_msg_t *msg);

/* Structural TPMS_ATTEST check (magic, type, extraData == nonce, SHA-256 bank {0,2,4,7}). */
im_err_t im_attest_check_tpms(const uint8_t *quote, size_t len, const uint8_t nonce[32]);

#ifdef __cplusplus
}
#endif

#endif /* IM_ATTEST_H */
