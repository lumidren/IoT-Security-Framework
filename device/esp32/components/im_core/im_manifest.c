/*
 * IronMesh protocol core - firmware manifest (see im_manifest.h). Mirrors
 * ironmesh_wire/manifest.py check by check.
 */
#include "im_manifest.h"

#include <string.h>

#include "im_cose.h"
#include "im_crypto.h"
#include "im_fields.h"
#include "im_ids.h"

#define MF IM_ERR_MF_FIELD

im_err_t im_manifest_decode(const uint8_t *p, size_t n, const im_cbor_limits_t *lim,
                            im_manifest_t *out)
{
    im_cbor_val_t m;
    im_cbor_val_t d;
    memset(out, 0, sizeof *out);
    if (im_cbor_decode(p, n, lim, &m) != IM_OK || m.type != IM_CBOR_MAP) {
        return IM_ERR_MF_STRUCTURE;
    }
    IM_TRY(im_f_expect_keys(&m, 0x3FEu /* 1..9 */, 0, MF, NULL));
    IM_TRY(im_cbor_map_get_int(&m, 8, &d) == IM_OK ? IM_OK : MF);
    if (d.type == IM_CBOR_MAP) {
        IM_TRY(im_f_expect_keys(&d, 0xEu, 0, MF, NULL));
        IM_TRY(im_f_bstr(&d, 1, 32, MF, &out->delta_base_sha256, NULL));
        IM_TRY(im_f_bstr(&d, 2, 32, MF, &out->delta_patch_sha256, NULL));
        IM_TRY(im_f_uint(&d, 3, UINT64_MAX, MF, &out->delta_patch_size));
        out->has_delta = true;
    } else if (d.type != IM_CBOR_NULL) {
        return MF;
    }
    IM_TRY(im_f_tstr(&m, 1, 1, 64, MF, &out->product, &out->product_len));
    if (!im_id_is_product(out->product, out->product_len)) {
        return MF;
    }
    IM_TRY(im_f_tstr(&m, 2, 1, 64, MF, &out->version, &out->version_len));
    if (!im_id_is_semver(out->version, out->version_len)) {
        return MF;
    }
    IM_TRY(im_f_uint(&m, 3, UINT64_MAX, MF, &out->version_code));
    IM_TRY(im_f_bstr(&m, 4, 32, MF, &out->image_sha256, NULL));
    IM_TRY(im_f_uint(&m, 5, UINT64_MAX, MF, &out->image_size));
    IM_TRY(im_f_uint(&m, 6, UINT64_MAX, MF, &out->created_at));
    IM_TRY(im_f_uint(&m, 7, UINT64_MAX, MF, &out->min_version_code));
    IM_TRY(im_f_tstr(&m, 9, 1, 64, MF, &out->signing_key_id, &out->signing_key_id_len));
    if (out->min_version_code > out->version_code) {
        return MF;
    }
    return IM_OK;
}

im_err_t im_manifest_encode(const im_manifest_t *m, uint8_t *out, size_t cap, size_t *out_len)
{
    im_cbor_enc_t e;
    im_manifest_t check;
    size_t n;
    if (m == NULL || out == NULL) {
        return IM_ERR_ARG;
    }
    im_cbor_enc_init(&e, out, cap);
    im_cbor_enc_map(&e, 9);
    im_cbor_enc_uint(&e, 1);
    im_cbor_enc_tstr(&e, m->product, m->product_len);
    im_cbor_enc_uint(&e, 2);
    im_cbor_enc_tstr(&e, m->version, m->version_len);
    im_cbor_enc_uint(&e, 3);
    im_cbor_enc_uint(&e, m->version_code);
    im_cbor_enc_uint(&e, 4);
    im_cbor_enc_bstr(&e, m->image_sha256, 32);
    im_cbor_enc_uint(&e, 5);
    im_cbor_enc_uint(&e, m->image_size);
    im_cbor_enc_uint(&e, 6);
    im_cbor_enc_uint(&e, m->created_at);
    im_cbor_enc_uint(&e, 7);
    im_cbor_enc_uint(&e, m->min_version_code);
    im_cbor_enc_uint(&e, 8);
    if (m->has_delta) {
        im_cbor_enc_map(&e, 3);
        im_cbor_enc_uint(&e, 1);
        im_cbor_enc_bstr(&e, m->delta_base_sha256, 32);
        im_cbor_enc_uint(&e, 2);
        im_cbor_enc_bstr(&e, m->delta_patch_sha256, 32);
        im_cbor_enc_uint(&e, 3);
        im_cbor_enc_uint(&e, m->delta_patch_size);
    } else {
        im_cbor_enc_null(&e);
    }
    im_cbor_enc_uint(&e, 9);
    im_cbor_enc_tstr(&e, m->signing_key_id, m->signing_key_id_len);
    IM_TRY(im_cbor_enc_finish(&e, &n));
    IM_TRY(im_manifest_decode(out, n, NULL, &check));
    if (out_len != NULL) {
        *out_len = n;
    }
    return IM_OK;
}

typedef struct {
    uint8_t kid[8];
    const uint8_t *key;
    size_t len;
} kid_entry_t;

static const kid_entry_t *find_kid(const kid_entry_t *t, size_t n, const uint8_t *kid,
                                   size_t want_len)
{
    const kid_entry_t *hit = NULL;
    for (size_t i = 0; i < n; i++) {
        if (t[i].len == want_len && memcmp(t[i].kid, kid, 8) == 0) {
            hit = &t[i]; /* last one wins, like the reference's dict */
        }
    }
    return hit;
}

static im_err_t verify_one(const im_sign_t *msg, const im_cose_signature_t *sg,
                           const kid_entry_t *key, uint8_t *work, size_t work_len)
{
    size_t n;
    im_err_t err;
    IM_TRY(im_cose_sig_structure(sg->protected_raw, sg->protected_len, msg->payload,
                                 msg->payload_len, work, work_len, &n));
    if (sg->alg == IM_ALG_EDDSA) {
        err = im_crypto_ed25519_verify(key->key, work, n, sg->sig);
    } else {
        err = im_crypto_mldsa65_verify(key->key, key->len, work, n, sg->sig, sg->sig_len);
    }
    if (err == IM_ERR_MLDSA_NOT_AVAILABLE) {
        return err;
    }
    return err == IM_OK ? IM_OK : IM_ERR_COSE_SIGNATURE;
}

im_err_t im_manifest_verify(const uint8_t *buf, size_t len, const im_fw_keys_t *trusted,
                            bool require_pq, const im_cbor_limits_t *lim, uint8_t *work,
                            size_t work_len, im_manifest_t *out, bool *pq_verified)
{
    im_sign_t msg;
    kid_entry_t table[IM_FW_KEYS_MAX];
    size_t nkeys;
    const im_cose_signature_t *ed;
    const im_cose_signature_t *pq;
    const kid_entry_t *k;
    bool pq_ok = false;

    if (trusted == NULL || out == NULL || trusted->n > IM_FW_KEYS_MAX) {
        return IM_ERR_ARG;
    }
    /* 1. structure */
    IM_TRY(im_cose_sign_decode(buf, len, lim, &msg));
    /* 2. index trusted keys by length */
    nkeys = trusted->n;
    for (size_t i = 0; i < nkeys; i++) {
        if (trusted->key[i] == NULL ||
            (trusted->len[i] != IM_ED25519_PUB_LEN && trusted->len[i] != IM_MLDSA65_PUB_LEN)) {
            return IM_ERR_MF_STRUCTURE;
        }
        table[i].key = trusted->key[i];
        table[i].len = trusted->len[i];
        IM_TRY(im_cose_key_id(trusted->key[i], trusted->len[i], table[i].kid));
    }
    /* 3. mandatory Ed25519 */
    ed = im_cose_sign_find(&msg, IM_ALG_EDDSA);
    if (ed == NULL) {
        return IM_ERR_COSE_SIGNATURE;
    }
    k = find_kid(table, nkeys, ed->kid, IM_ED25519_PUB_LEN);
    if (k == NULL) {
        return IM_ERR_COSE_UNKNOWN_KEY;
    }
    IM_TRY(verify_one(&msg, ed, k, work, work_len));
    /* 4./5. ML-DSA-65 */
    pq = im_cose_sign_find(&msg, IM_ALG_MLDSA65);
    if (require_pq) {
        if (pq == NULL) {
            return IM_ERR_COSE_PQ_REQUIRED;
        }
        if (!im_crypto_mldsa65_available()) {
            return IM_ERR_MLDSA_NOT_AVAILABLE;
        }
        k = find_kid(table, nkeys, pq->kid, IM_MLDSA65_PUB_LEN);
        if (k == NULL) {
            return IM_ERR_COSE_UNKNOWN_KEY;
        }
        IM_TRY(verify_one(&msg, pq, k, work, work_len));
        pq_ok = true;
    } else if (pq != NULL && im_crypto_mldsa65_available()) {
        k = find_kid(table, nkeys, pq->kid, IM_MLDSA65_PUB_LEN);
        if (k != NULL) {
            IM_TRY(verify_one(&msg, pq, k, work, work_len));
            pq_ok = true;
        }
    }
    /* 6. payload */
    IM_TRY(im_manifest_decode(msg.payload, msg.payload_len, lim, out));
    if (pq_verified != NULL) {
        *pq_verified = pq_ok;
    }
    return IM_OK;
}

static bool product_eq(const im_manifest_t *m, const char *product)
{
    size_t n = product ? strlen(product) : 0;
    return product != NULL && n == m->product_len && memcmp(m->product, product, n) == 0;
}

im_err_t im_manifest_precheck(const im_manifest_t *m, uint64_t current_version_code,
                              const char *product)
{
    if (!product_eq(m, product)) {
        return IM_ERR_MF_PRODUCT;
    }
    if (m->version_code <= current_version_code) {
        return IM_ERR_MF_ROLLBACK;
    }
    if (current_version_code < m->min_version_code) {
        return IM_ERR_MF_MIN_VERSION;
    }
    return IM_OK;
}

im_err_t im_manifest_accept_image(const im_manifest_t *m, uint64_t image_len,
                                  const uint8_t image_sha256[32], uint64_t current_version_code,
                                  const char *product)
{
    IM_TRY(im_manifest_precheck(m, current_version_code, product));
    if (image_len != m->image_size) {
        return IM_ERR_MF_SIZE_MISMATCH;
    }
    if (!im_ct_equal(image_sha256, m->image_sha256, 32)) {
        return IM_ERR_MF_HASH_MISMATCH;
    }
    return IM_OK;
}

im_err_t im_manifest_accept_image_bytes(const im_manifest_t *m, const uint8_t *image,
                                        size_t len, uint64_t current_version_code,
                                        const char *product)
{
    uint8_t h[32];
    IM_TRY(im_sha256(image, len, h));
    return im_manifest_accept_image(m, len, h, current_version_code, product);
}

im_err_t im_manifest_accept_patch(const im_manifest_t *m, uint64_t patch_len,
                                  const uint8_t patch_sha256[32],
                                  const uint8_t current_fw_hash[32])
{
    if (!m->has_delta) {
        return IM_ERR_MF_NO_DELTA;
    }
    if (!im_ct_equal(m->delta_base_sha256, current_fw_hash, 32)) {
        return IM_ERR_DELTA_BASE_HASH;
    }
    if (patch_len != m->delta_patch_size) {
        return IM_ERR_MF_SIZE_MISMATCH;
    }
    if (!im_ct_equal(patch_sha256, m->delta_patch_sha256, 32)) {
        return IM_ERR_MF_HASH_MISMATCH;
    }
    return IM_OK;
}
