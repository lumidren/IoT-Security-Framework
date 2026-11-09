/*
 * IronMesh protocol core - firmware manifest (WIRE_FORMAT.md §6, contract §6): decoding, hybrid
 * signature verification against the bundle's fw_signing_pubkeys, and the pure acceptance rules
 * (anti-rollback, product, size/hash, delta pre-checks).
 */
#ifndef IM_MANIFEST_H
#define IM_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_cbor.h"
#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IM_FW_KEYS_MAX 4u

typedef struct {
    const char *product;
    size_t product_len;
    const char *version;
    size_t version_len;
    uint64_t version_code;
    const uint8_t *image_sha256; /* 32 */
    uint64_t image_size;
    uint64_t created_at;
    uint64_t min_version_code;
    bool has_delta;
    const uint8_t *delta_base_sha256;  /* 32 */
    const uint8_t *delta_patch_sha256; /* 32 */
    uint64_t delta_patch_size;
    const char *signing_key_id; /* informational only */
    size_t signing_key_id_len;
} im_manifest_t;

/* Raw trusted keys from the bundle: 32-byte Ed25519 or 1952-byte ML-DSA-65 keys. */
typedef struct {
    const uint8_t *key[IM_FW_KEYS_MAX];
    size_t len[IM_FW_KEYS_MAX];
    size_t n;
} im_fw_keys_t;

/* §6.1: MF_STRUCTURE if not a canonical CBOR map, MF_FIELD for field violations. */
im_err_t im_manifest_decode(const uint8_t *p, size_t n, const im_cbor_limits_t *lim,
                            im_manifest_t *out);

/* Canonical encoding of a manifest (validated by decoding it back): tooling and tests. */
im_err_t im_manifest_encode(const im_manifest_t *m, uint8_t *out, size_t cap, size_t *out_len);

/* §6.3 verify_manifest. work must hold the COSE_Sign Sig_structure (payload + ~40 bytes).
 * *pq_verified (may be NULL) is set when an ML-DSA-65 signature was verified. The manifest
 * fields point into buf. */
im_err_t im_manifest_verify(const uint8_t *buf, size_t len, const im_fw_keys_t *trusted,
                            bool require_pq, const im_cbor_limits_t *lim, uint8_t *work,
                            size_t work_len, im_manifest_t *out, bool *pq_verified);

/* Rules of §6.4 that do not need the image (product, rollback, min version): lets a device
 * reject an update before downloading it. Returns the reason code or IM_OK. */
im_err_t im_manifest_precheck(const im_manifest_t *m, uint64_t current_version_code,
                              const char *product);
/* §6.4 accept_image with the image summarised by its length and SHA-256 (streamed). */
im_err_t im_manifest_accept_image(const im_manifest_t *m, uint64_t image_len,
                                  const uint8_t image_sha256[32], uint64_t current_version_code,
                                  const char *product);
/* Convenience: hashes the bytes. */
im_err_t im_manifest_accept_image_bytes(const im_manifest_t *m, const uint8_t *image,
                                        size_t len, uint64_t current_version_code,
                                        const char *product);
/* §6.4 accept_patch with the patch summarised by its length and SHA-256. */
im_err_t im_manifest_accept_patch(const im_manifest_t *m, uint64_t patch_len,
                                  const uint8_t patch_sha256[32],
                                  const uint8_t current_fw_hash[32]);

#ifdef __cplusplus
}
#endif

#endif /* IM_MANIFEST_H */
