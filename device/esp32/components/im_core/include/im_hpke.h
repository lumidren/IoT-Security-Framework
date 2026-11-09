/*
 * IronMesh protocol core - HPKE (RFC 9180) base mode, DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 /
 * AES-128-GCM, recipient side, and the Config unwrap of WIRE_FORMAT.md §5. The recipient's
 * private key never leaves the identity (ECDH is done by the secure element).
 */
#ifndef IM_HPKE_H
#define IM_HPKE_H

#include <stddef.h>
#include <stdint.h>

#include "im_crypto.h"
#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IM_HPKE_INFO_MAX 64u

typedef struct {
    uint8_t key[16];
    uint8_t base_nonce[12];
    uint8_t exporter_secret[32];
    uint64_t seq;
} im_hpke_ctx_t;

/* Decap(enc, skR): HPKE_KEY for a malformed enc (not a valid uncompressed P-256 point). */
im_err_t im_hpke_decap(const im_identity_t *id, const uint8_t enc[65], uint8_t shared[32]);
/* KeySchedule for mode_base. info_len <= IM_HPKE_INFO_MAX. */
im_err_t im_hpke_key_schedule(const uint8_t shared[32], const uint8_t *info, size_t info_len,
                              im_hpke_ctx_t *ctx);
im_err_t im_hpke_setup_base_r(const im_identity_t *id, const uint8_t enc[65], const uint8_t *info,
                              size_t info_len, im_hpke_ctx_t *ctx);
/* Open: ct includes the 16-byte tag; pt receives ct_len - 16 bytes. HPKE_OPEN on failure. */
im_err_t im_hpke_open(im_hpke_ctx_t *ctx, const uint8_t *aad, size_t aad_len, const uint8_t *ct,
                      size_t ct_len, uint8_t *pt);
/* Seal (used by tests to check the vectors): out receives pt_len + 16 bytes. */
im_err_t im_hpke_seal(im_hpke_ctx_t *ctx, const uint8_t *aad, size_t aad_len, const uint8_t *pt,
                      size_t pt_len, uint8_t *out);
im_err_t im_hpke_export(const im_hpke_ctx_t *ctx, const uint8_t *exporter_context,
                        size_t exp_len, uint8_t *out, size_t out_len);
/* DeriveKeyPair private scalar (RFC 9180 §7.1.3) - test vectors only. */
im_err_t im_hpke_derive_sk(const uint8_t *ikm, size_t ikm_len, uint8_t sk[32]);
void im_hpke_ctx_wipe(im_hpke_ctx_t *ctx);

/* WIRE_FORMAT.md §5 unwrap_config: returns the plaintext (a tenant-signed Config Sign1).
 * Codes: CBOR_x / COSE_x (structure), HPKE_KEY, HPKE_OPEN, COSE_DECRYPT, BUFFER. */
im_err_t im_config_unwrap(const uint8_t *buf, size_t len, const im_identity_t *id, uint8_t *pt,
                          size_t cap, size_t *pt_len);

#ifdef __cplusplus
}
#endif

#endif /* IM_HPKE_H */
