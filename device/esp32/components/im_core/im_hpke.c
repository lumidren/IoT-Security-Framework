/*
 * IronMesh protocol core - HPKE base mode recipient (RFC 9180) and Config unwrap.
 * Mirrors ironmesh_wire/hpke.py. All intermediate secrets are zeroized before returning.
 */
#include "im_hpke.h"

#include <string.h>

#include "im_cose.h"

static const uint8_t k_version[7] = {'H', 'P', 'K', 'E', '-', 'v', '1'};
static const uint8_t k_kem_suite[5] = {'K', 'E', 'M', 0x00, 0x10};
static const uint8_t k_hpke_suite[10] = {'H', 'P', 'K', 'E', 0x00, 0x10, 0x00, 0x01, 0x00, 0x01};
static const uint8_t k_config_info[22] = {'i', 'r', 'o', 'n', 'm', 'e', 's', 'h', '-', 'c', 'o',
                                          'n', 'f', 'i', 'g', '-', 'c', 'e', 'k', '-', 'v', '1'};
static const uint8_t k_p256_n[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};

#define LABEL_MAX 16u
#define EXTRACT_BUF (sizeof k_version + sizeof k_hpke_suite + LABEL_MAX + 64u)
#define EXPAND_BUF (2u + sizeof k_version + sizeof k_hpke_suite + LABEL_MAX + 2u * 65u)

static im_err_t labeled_extract(const uint8_t *salt, size_t salt_len, const uint8_t *suite,
                                size_t suite_len, const char *label, const uint8_t *ikm,
                                size_t ikm_len, uint8_t prk[32])
{
    uint8_t buf[EXTRACT_BUF];
    size_t ll = strlen(label);
    size_t n = 0;
    im_err_t err;
    if (ll > LABEL_MAX || ikm_len > 64u) {
        return IM_ERR_HPKE_DERIVE;
    }
    memcpy(buf, k_version, sizeof k_version);
    n += sizeof k_version;
    memcpy(buf + n, suite, suite_len);
    n += suite_len;
    memcpy(buf + n, label, ll);
    n += ll;
    if (ikm_len) {
        memcpy(buf + n, ikm, ikm_len);
    }
    n += ikm_len;
    err = im_crypto_hkdf_extract(salt, salt_len, buf, n, prk);
    im_secure_zero(buf, sizeof buf);
    return err;
}

static im_err_t labeled_expand(const uint8_t prk[32], const uint8_t *suite, size_t suite_len,
                               const char *label, const uint8_t *info, size_t info_len,
                               uint8_t *out, size_t len)
{
    uint8_t buf[EXPAND_BUF];
    size_t ll = strlen(label);
    size_t n = 0;
    im_err_t err;
    if (ll > LABEL_MAX || info_len > 2u * 65u || len > 255u * 32u) {
        return IM_ERR_HPKE_DERIVE;
    }
    buf[0] = (uint8_t)(len >> 8);
    buf[1] = (uint8_t)len;
    n = 2;
    memcpy(buf + n, k_version, sizeof k_version);
    n += sizeof k_version;
    memcpy(buf + n, suite, suite_len);
    n += suite_len;
    memcpy(buf + n, label, ll);
    n += ll;
    if (info_len) {
        memcpy(buf + n, info, info_len);
    }
    n += info_len;
    err = im_crypto_hkdf_expand(prk, buf, n, out, len);
    im_secure_zero(buf, sizeof buf);
    return err;
}

im_err_t im_hpke_decap(const im_identity_t *id, const uint8_t enc[65], uint8_t shared[32])
{
    uint8_t dh[32];
    uint8_t kem_context[130];
    uint8_t prk[32];
    im_err_t err;
    if (id == NULL || id->ecdh == NULL || id->get_pubkey == NULL || enc == NULL) {
        return IM_ERR_ARG;
    }
    if (enc[0] != 0x04 || im_crypto_p256_point_check(enc) != IM_OK) {
        return IM_ERR_HPKE_KEY;
    }
    memcpy(kem_context, enc, 65);
    IM_TRY(id->get_pubkey(id->ctx, kem_context + 65));
    if (id->ecdh(id->ctx, enc, dh) != IM_OK) {
        im_secure_zero(dh, sizeof dh);
        return IM_ERR_HPKE_KEY;
    }
    err = labeled_extract(NULL, 0, k_kem_suite, sizeof k_kem_suite, "eae_prk", dh, sizeof dh,
                          prk);
    if (err == IM_OK) {
        err = labeled_expand(prk, k_kem_suite, sizeof k_kem_suite, "shared_secret", kem_context,
                             sizeof kem_context, shared, 32);
    }
    im_secure_zero(dh, sizeof dh);
    im_secure_zero(prk, sizeof prk);
    return err;
}

im_err_t im_hpke_key_schedule(const uint8_t shared[32], const uint8_t *info, size_t info_len,
                              im_hpke_ctx_t *ctx)
{
    uint8_t ksc[65];
    uint8_t secret[32];
    im_err_t err;
    if (info_len > IM_HPKE_INFO_MAX || ctx == NULL) {
        return IM_ERR_ARG;
    }
    memset(ctx, 0, sizeof *ctx);
    ksc[0] = 0x00; /* mode_base */
    IM_TRY(labeled_extract(NULL, 0, k_hpke_suite, sizeof k_hpke_suite, "psk_id_hash", NULL, 0,
                           ksc + 1));
    IM_TRY(labeled_extract(NULL, 0, k_hpke_suite, sizeof k_hpke_suite, "info_hash", info,
                           info_len, ksc + 33));
    err = labeled_extract(shared, 32, k_hpke_suite, sizeof k_hpke_suite, "secret", NULL, 0,
                          secret);
    if (err == IM_OK) {
        err = labeled_expand(secret, k_hpke_suite, sizeof k_hpke_suite, "key", ksc, sizeof ksc,
                             ctx->key, sizeof ctx->key);
    }
    if (err == IM_OK) {
        err = labeled_expand(secret, k_hpke_suite, sizeof k_hpke_suite, "base_nonce", ksc,
                             sizeof ksc, ctx->base_nonce, sizeof ctx->base_nonce);
    }
    if (err == IM_OK) {
        err = labeled_expand(secret, k_hpke_suite, sizeof k_hpke_suite, "exp", ksc, sizeof ksc,
                             ctx->exporter_secret, sizeof ctx->exporter_secret);
    }
    im_secure_zero(secret, sizeof secret);
    if (err != IM_OK) {
        im_hpke_ctx_wipe(ctx);
    }
    return err;
}

im_err_t im_hpke_setup_base_r(const im_identity_t *id, const uint8_t enc[65], const uint8_t *info,
                              size_t info_len, im_hpke_ctx_t *ctx)
{
    uint8_t shared[32];
    im_err_t err = im_hpke_decap(id, enc, shared);
    if (err == IM_OK) {
        err = im_hpke_key_schedule(shared, info, info_len, ctx);
    }
    im_secure_zero(shared, sizeof shared);
    return err;
}

static im_err_t next_nonce(const im_hpke_ctx_t *ctx, uint8_t nonce[12])
{
    if (ctx->seq == UINT64_MAX) {
        return IM_ERR_HPKE_SEQ;
    }
    memcpy(nonce, ctx->base_nonce, 12);
    for (unsigned i = 0; i < 8u; i++) {
        nonce[11 - i] ^= (uint8_t)(ctx->seq >> (8u * i));
    }
    return IM_OK;
}

im_err_t im_hpke_open(im_hpke_ctx_t *ctx, const uint8_t *aad, size_t aad_len, const uint8_t *ct,
                      size_t ct_len, uint8_t *pt)
{
    uint8_t nonce[12];
    if (ctx == NULL || ct == NULL || ct_len < IM_GCM_TAG_LEN) {
        return IM_ERR_HPKE_OPEN;
    }
    IM_TRY(next_nonce(ctx, nonce));
    if (im_crypto_aes_gcm_decrypt(ctx->key, sizeof ctx->key, nonce, aad, aad_len, ct,
                                  ct_len - IM_GCM_TAG_LEN, ct + ct_len - IM_GCM_TAG_LEN,
                                  pt) != IM_OK) {
        if (ct_len > IM_GCM_TAG_LEN) {
            im_secure_zero(pt, ct_len - IM_GCM_TAG_LEN);
        }
        return IM_ERR_HPKE_OPEN;
    }
    ctx->seq++;
    return IM_OK;
}

im_err_t im_hpke_seal(im_hpke_ctx_t *ctx, const uint8_t *aad, size_t aad_len, const uint8_t *pt,
                      size_t pt_len, uint8_t *out)
{
    uint8_t nonce[12];
    if (ctx == NULL || out == NULL) {
        return IM_ERR_ARG;
    }
    IM_TRY(next_nonce(ctx, nonce));
    IM_TRY(im_crypto_aes_gcm_encrypt(ctx->key, sizeof ctx->key, nonce, aad, aad_len, pt, pt_len,
                                     out, out + pt_len));
    ctx->seq++;
    return IM_OK;
}

im_err_t im_hpke_export(const im_hpke_ctx_t *ctx, const uint8_t *exporter_context,
                        size_t exp_len, uint8_t *out, size_t out_len)
{
    if (ctx == NULL || exp_len > IM_HPKE_INFO_MAX) {
        return IM_ERR_ARG;
    }
    return labeled_expand(ctx->exporter_secret, k_hpke_suite, sizeof k_hpke_suite, "sec",
                          exporter_context, exp_len, out, out_len);
}

im_err_t im_hpke_derive_sk(const uint8_t *ikm, size_t ikm_len, uint8_t sk[32])
{
    uint8_t prk[32];
    im_err_t err;
    if (ikm_len > 64u) {
        return IM_ERR_HPKE_DERIVE;
    }
    IM_TRY(labeled_extract(NULL, 0, k_kem_suite, sizeof k_kem_suite, "dkp_prk", ikm, ikm_len,
                           prk));
    for (unsigned counter = 0; counter < 256u; counter++) {
        uint8_t c = (uint8_t)counter;
        bool nonzero = false;
        int cmp = 0;
        err = labeled_expand(prk, k_kem_suite, sizeof k_kem_suite, "candidate", &c, 1, sk, 32);
        if (err != IM_OK) {
            break;
        }
        sk[0] &= 0xFFu; /* P-256 bitmask */
        for (unsigned i = 0; i < 32u; i++) {
            if (sk[i] != 0) {
                nonzero = true;
            }
            if (cmp == 0 && sk[i] != k_p256_n[i]) {
                cmp = sk[i] < k_p256_n[i] ? -1 : 1;
            }
        }
        if (nonzero && cmp < 0) {
            im_secure_zero(prk, sizeof prk);
            return IM_OK;
        }
    }
    im_secure_zero(prk, sizeof prk);
    im_secure_zero(sk, 32);
    return IM_ERR_HPKE_DERIVE;
}

void im_hpke_ctx_wipe(im_hpke_ctx_t *ctx)
{
    if (ctx != NULL) {
        im_secure_zero(ctx, sizeof *ctx);
    }
}

im_err_t im_config_unwrap(const uint8_t *buf, size_t len, const im_identity_t *id, uint8_t *pt,
                          size_t cap, size_t *pt_len)
{
    im_encrypt0_t m;
    im_hpke_ctx_t ctx;
    uint8_t cek[32];
    size_t n;
    im_err_t err;

    if (id == NULL || pt_len == NULL) {
        return IM_ERR_ARG;
    }
    IM_TRY(im_cose_encrypt0_decode(buf, len, NULL, &m));
    n = m.ct_len - IM_GCM_TAG_LEN;
    if (pt == NULL || cap < n) {
        return IM_ERR_BUFFER;
    }
    IM_TRY(im_hpke_setup_base_r(id, m.enc, k_config_info, sizeof k_config_info, &ctx));
    err = im_hpke_open(&ctx, IM_ENC_STRUCTURE0, sizeof IM_ENC_STRUCTURE0, m.wrapped,
                       IM_HPKE_WRAPPED_LEN, cek);
    im_hpke_ctx_wipe(&ctx);
    if (err != IM_OK) {
        im_secure_zero(cek, sizeof cek);
        return err;
    }
    err = im_crypto_aes_gcm_decrypt(cek, sizeof cek, m.iv, IM_ENC_STRUCTURE0,
                                    sizeof IM_ENC_STRUCTURE0, m.ct, n, m.ct + n, pt);
    im_secure_zero(cek, sizeof cek);
    if (err != IM_OK) {
        im_secure_zero(pt, n);
        return IM_ERR_COSE_DECRYPT;
    }
    *pt_len = n;
    return IM_OK;
}
