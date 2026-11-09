/*
 * IronMesh protocol core - COSE profiles (WIRE_FORMAT.md §2): COSE_Sign1 (envelopes, bundle),
 * COSE_Sign (firmware manifest) and COSE_Encrypt0 (Config). Parsed structures point into the
 * caller's input buffer (zero copy); the input must outlive them.
 */
#ifndef IM_COSE_H
#define IM_COSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_cbor.h"
#include "im_crypto.h"
#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IM_ALG_ES256 (-7)
#define IM_ALG_EDDSA (-8)
#define IM_ALG_MLDSA65 (-49)
#define IM_ALG_A256GCM 3

#define IM_COSE_MAX_KID 255u
#define IM_COSE_SIGN_KID_LEN 8u
#define IM_HPKE_ENC_LEN 65u
#define IM_HPKE_WRAPPED_LEN 48u

typedef enum { IM_KEY_NONE = 0, IM_KEY_P256, IM_KEY_ED25519 } im_key_type_t;

typedef struct {
    im_key_type_t type;
    uint8_t raw[IM_P256_PUB_LEN]; /* P-256: 65-byte point; Ed25519: first 32 bytes */
} im_pubkey_t;

im_err_t im_pubkey_p256(im_pubkey_t *k, const uint8_t *raw, size_t len);
im_err_t im_pubkey_ed25519(im_pubkey_t *k, const uint8_t *raw, size_t len);

typedef struct {
    const uint8_t *protected_raw; /* content of the protected bstr (used verbatim in Sig_structure) */
    size_t protected_len;
    int alg;
    const uint8_t *kid;
    size_t kid_len;
    bool kid_text;
    const uint8_t *payload;
    size_t payload_len;
    const uint8_t *sig;
    size_t sig_len;
} im_sign1_t;

/* §2.2 structural parse, no cryptography. Codes: CBOR_*, COSE_TAG/STRUCTURE/HEADER/ALG/KID/SIGNATURE. */
im_err_t im_cose_sign1_decode(const uint8_t *buf, size_t len, const im_cbor_limits_t *lim,
                              im_sign1_t *out);

/* Verify with key. COSE_ALG if the algorithm does not match the key type, COSE_SIGNATURE on a bad
 * signature. EdDSA needs a work buffer of im_cose_sig1_structure_len() bytes (ES256 streams). */
im_err_t im_cose_sign1_verify(const im_sign1_t *m, const im_pubkey_t *key, uint8_t *work,
                              size_t work_len);
size_t im_cose_sig1_structure_len(size_t protected_len, size_t payload_len);
/* Write Sig_structure ["Signature1", protected, h'', payload] into out. */
im_err_t im_cose_sig1_structure(const uint8_t *prot, size_t prot_len, const uint8_t *payload,
                                size_t payload_len, uint8_t *out, size_t cap, size_t *out_len);

/* A signer: ES256 signers receive the 32-byte SHA-256 of the Sig_structure, EdDSA signers the
 * full Sig_structure. */
typedef struct {
    int alg;
    im_err_t (*sign)(void *ctx, const uint8_t *data, size_t len, uint8_t sig[64]);
    void *ctx;
} im_signer_t;

/* Adapt a device identity (ES256, key in the secure element) to an im_signer_t. */
void im_identity_signer(const im_identity_t *id, im_signer_t *out);

/* Build d2 84 <protected> a0 <payload> <signature>. work is needed only for EdDSA. */
im_err_t im_cose_sign1_encode(const im_signer_t *signer, const uint8_t *kid, size_t kid_len,
                              bool kid_text, const uint8_t *payload, size_t payload_len,
                              uint8_t *work, size_t work_len, uint8_t *out, size_t cap,
                              size_t *out_len);

/* ---- COSE_Sign (manifest) ---------------------------------------------------------------- */

typedef struct {
    const uint8_t *protected_raw;
    size_t protected_len;
    int alg;
    const uint8_t *kid; /* 8 bytes */
    const uint8_t *sig;
    size_t sig_len;
} im_cose_signature_t;

typedef struct {
    const uint8_t *payload;
    size_t payload_len;
    im_cose_signature_t sigs[2];
    size_t nsigs;
} im_sign_t;

im_err_t im_cose_sign_decode(const uint8_t *buf, size_t len, const im_cbor_limits_t *lim,
                             im_sign_t *out);
const im_cose_signature_t *im_cose_sign_find(const im_sign_t *m, int alg);
size_t im_cose_sig_structure_len(size_t sign_protected_len, size_t payload_len);
/* ["Signature", h'', sign_protected, h'', payload] */
im_err_t im_cose_sig_structure(const uint8_t *sign_prot, size_t sign_prot_len,
                               const uint8_t *payload, size_t payload_len, uint8_t *out,
                               size_t cap, size_t *out_len);
/* Build a COSE_Sign with one Ed25519 signer (used by tests / tooling). */
im_err_t im_cose_sign_encode_ed25519(const im_signer_t *signer, const uint8_t kid[8],
                                     const uint8_t *payload, size_t payload_len, uint8_t *work,
                                     size_t work_len, uint8_t *out, size_t cap, size_t *out_len);

/* ---- COSE_Encrypt0 (Config) -------------------------------------------------------------- */

typedef struct {
    const uint8_t *protected_raw;
    size_t protected_len;
    const uint8_t *iv;      /* 12 */
    const uint8_t *enc;     /* 65 */
    const uint8_t *wrapped; /* 48 */
    const uint8_t *ct;      /* ciphertext || tag */
    size_t ct_len;
} im_encrypt0_t;

im_err_t im_cose_encrypt0_decode(const uint8_t *buf, size_t len, const im_cbor_limits_t *lim,
                                 im_encrypt0_t *out);
im_err_t im_cose_encrypt0_encode(const uint8_t iv[12], const uint8_t enc[65],
                                 const uint8_t wrapped[48], const uint8_t *ct, size_t ct_len,
                                 uint8_t *out, size_t cap, size_t *out_len);
/* The fixed Enc_structure 83 68 "Encrypt0" 43 a10103 40 (15 bytes). */
extern const uint8_t IM_ENC_STRUCTURE0[15];

/* kid of a firmware-signing key: SHA-256(raw)[0:8]. */
im_err_t im_cose_key_id(const uint8_t *raw, size_t len, uint8_t kid[8]);

#ifdef __cplusplus
}
#endif

#endif /* IM_COSE_H */
