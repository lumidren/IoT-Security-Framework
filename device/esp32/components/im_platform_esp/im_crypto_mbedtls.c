/*
 * im_crypto.h provider for the ESP32: mbedTLS 3.6 (ESP-IDF v5.3, hardware SHA/AES/MPI) for
 * SHA-256, HKDF, ECDSA P-256, AES-GCM and point validation; libsodium (espressif/libsodium) for
 * Ed25519, because mbedTLS 3.6 implements neither legacy nor PSA-builtin Ed25519. No ML-DSA-65
 * backend exists for the ESP32 here: verification reports MLDSA_NOT_AVAILABLE.
 *
 * NOT COMPILED HERE (ESP-IDF not installed on the authoring host). Host equivalent:
 * host/core-tests/src/crypto.rs, exercised by every conformance vector.
 */
#include <string.h>

#include "esp_random.h"
#include "im_crypto.h"
#include "im_esp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "sodium.h"

_Static_assert(sizeof(mbedtls_sha256_context) <= IM_SHA256_CTX_SIZE,
               "IM_SHA256_CTX_SIZE too small for this target's mbedtls_sha256_context");
_Static_assert(_Alignof(mbedtls_sha256_context) <= 8, "context alignment");

esp_err_t im_esp_crypto_init(void)
{
    /* libsodium seeds its RNG from esp_fill_random; verification needs no randomness */
    return sodium_init() < 0 ? ESP_FAIL : ESP_OK;
}

im_err_t im_crypto_sha256_init(im_sha256_ctx_t *ctx)
{
    mbedtls_sha256_context *c = (mbedtls_sha256_context *)(void *)ctx->opaque;
    mbedtls_sha256_init(c);
    return mbedtls_sha256_starts(c, 0) == 0 ? IM_OK : IM_ERR_CRYPTO;
}

im_err_t im_crypto_sha256_update(im_sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    mbedtls_sha256_context *c = (mbedtls_sha256_context *)(void *)ctx->opaque;
    return mbedtls_sha256_update(c, data, len) == 0 ? IM_OK : IM_ERR_CRYPTO;
}

im_err_t im_crypto_sha256_finish(im_sha256_ctx_t *ctx, uint8_t out[IM_SHA256_LEN])
{
    mbedtls_sha256_context *c = (mbedtls_sha256_context *)(void *)ctx->opaque;
    int r = mbedtls_sha256_finish(c, out);
    mbedtls_sha256_free(c);
    return r == 0 ? IM_OK : IM_ERR_CRYPTO;
}

void im_crypto_sha256_free(im_sha256_ctx_t *ctx)
{
    mbedtls_sha256_free((mbedtls_sha256_context *)(void *)ctx->opaque);
    im_secure_zero(ctx->opaque, sizeof ctx->opaque);
}

im_err_t im_crypto_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                                size_t ikm_len, uint8_t prk[IM_SHA256_LEN])
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    static const uint8_t empty = 0;
    return mbedtls_hkdf_extract(md, salt ? salt : &empty, salt_len, ikm ? ikm : &empty, ikm_len,
                                prk) == 0
               ? IM_OK
               : IM_ERR_CRYPTO;
}

im_err_t im_crypto_hkdf_expand(const uint8_t prk[IM_SHA256_LEN], const uint8_t *info,
                               size_t info_len, uint8_t *okm, size_t okm_len)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_hkdf_expand(md, prk, IM_SHA256_LEN, info, info_len, okm, okm_len) == 0
               ? IM_OK
               : IM_ERR_CRYPTO;
}

im_err_t im_crypto_ecdsa_p256_verify(const uint8_t pub[IM_P256_PUB_LEN],
                                     const uint8_t digest[IM_SHA256_LEN],
                                     const uint8_t sig[IM_ES256_SIG_LEN])
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi r;
    mbedtls_mpi s;
    int ret;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_ecp_point_read_binary(&grp, &q, pub, IM_P256_PUB_LEN);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_check_pubkey(&grp, &q);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&r, sig, 32);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&s, sig + 32, 32);
    }
    if (ret == 0) {
        ret = mbedtls_ecdsa_verify(&grp, digest, IM_SHA256_LEN, &q, &r, &s);
    }
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    return ret == 0 ? IM_OK : IM_ERR_COSE_SIGNATURE;
}

im_err_t im_crypto_ed25519_verify(const uint8_t pub[IM_ED25519_PUB_LEN], const uint8_t *msg,
                                  size_t msg_len, const uint8_t sig[IM_ED25519_SIG_LEN])
{
    /* rejects non-canonical S and small-order keys, like ed25519-dalek verify_strict on host */
    return crypto_sign_ed25519_verify_detached(sig, msg, msg_len, pub) == 0
               ? IM_OK
               : IM_ERR_COSE_SIGNATURE;
}

im_err_t im_crypto_mldsa65_verify(const uint8_t *pub, size_t pub_len, const uint8_t *msg,
                                  size_t msg_len, const uint8_t *sig, size_t sig_len)
{
    (void)pub;
    (void)pub_len;
    (void)msg;
    (void)msg_len;
    (void)sig;
    (void)sig_len;
    return IM_ERR_MLDSA_NOT_AVAILABLE;
}

int im_crypto_mldsa65_available(void)
{
    return 0;
}

static im_err_t gcm(int mode, const uint8_t *key, size_t key_len, const uint8_t *iv,
                    const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t len,
                    uint8_t *out, uint8_t *tag)
{
    mbedtls_gcm_context g;
    int ret;
    if (key_len != 16 && key_len != 32) {
        return IM_ERR_ARG;
    }
    mbedtls_gcm_init(&g);
    ret = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, (unsigned int)(key_len * 8));
    if (ret == 0) {
        if (mode == MBEDTLS_GCM_ENCRYPT) {
            ret = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, len, iv, IM_GCM_IV_LEN, aad,
                                            aad_len, in, out, IM_GCM_TAG_LEN, tag);
        } else {
            ret = mbedtls_gcm_auth_decrypt(&g, len, iv, IM_GCM_IV_LEN, aad, aad_len, tag,
                                           IM_GCM_TAG_LEN, in, out);
        }
    }
    mbedtls_gcm_free(&g);
    return ret == 0 ? IM_OK : IM_ERR_CRYPTO;
}

im_err_t im_crypto_aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                                   const uint8_t iv[IM_GCM_IV_LEN], const uint8_t *aad,
                                   size_t aad_len, const uint8_t *in, size_t len, uint8_t *out,
                                   uint8_t tag[IM_GCM_TAG_LEN])
{
    return gcm(MBEDTLS_GCM_ENCRYPT, key, key_len, iv, aad, aad_len, in, len, out, tag);
}

im_err_t im_crypto_aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                                   const uint8_t iv[IM_GCM_IV_LEN], const uint8_t *aad,
                                   size_t aad_len, const uint8_t *in, size_t len,
                                   const uint8_t tag[IM_GCM_TAG_LEN], uint8_t *out)
{
    return gcm(MBEDTLS_GCM_DECRYPT, key, key_len, iv, aad, aad_len, in, len, out,
               (uint8_t *)(uintptr_t)tag);
}

im_err_t im_crypto_p256_point_check(const uint8_t pub[IM_P256_PUB_LEN])
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    int ret;
    if (pub[0] != 0x04) {
        return IM_ERR_CRYPTO;
    }
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_ecp_point_read_binary(&grp, &q, pub, IM_P256_PUB_LEN);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_check_pubkey(&grp, &q);
    }
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    return ret == 0 ? IM_OK : IM_ERR_CRYPTO;
}

im_err_t im_crypto_random(uint8_t *out, size_t len)
{
    /* hardware RNG; entropy is guaranteed once RF (Wi-Fi) or the bootloader RNG source is on */
    esp_fill_random(out, len);
    return IM_OK;
}
