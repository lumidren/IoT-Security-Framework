/*
 * Software identity: P-256 key generated on the device and stored in the *encrypted* NVS
 * partition (NVS encryption; key protection = HMAC eFuse key on chips with the HMAC peripheral,
 * otherwise the flash-encrypted nvs_keys partition). The device reports se_type "software" and
 * the PKI records assurance_level=software (contract section 10) - lower assurance: anyone who can
 * run code on the device can use or read the key. ESP32 DS peripheral (esp_ds) is RSA-only and
 * cannot hold a P-256 key, so it is not used.
 *
 * NOT COMPILED HERE (ESP-IDF v5.3 API: nvs, mbedtls ecp/ecdsa/ecdh).
 */
#include <string.h>

#include "esp_random.h"
#include "im_esp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "nvs.h"

#define NS "ironmesh"
#define KEY_CUR "sw_key"
#define KEY_NEW "sw_key_new"

static uint8_t s_cur[32];
static uint8_t s_new[32];
static bool s_have_cur;
static bool s_have_new;

static int rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}

static esp_err_t load(const char *k, uint8_t out[32], bool *have)
{
    nvs_handle_t h;
    size_t n = 32;
    esp_err_t e = nvs_open(NS, NVS_READONLY, &h);
    if (e != ESP_OK) {
        *have = false;
        return e;
    }
    e = nvs_get_blob(h, k, out, &n);
    nvs_close(h);
    *have = e == ESP_OK && n == 32;
    return e;
}

static esp_err_t save(const char *k, const uint8_t *d, size_t n)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(NS, NVS_READWRITE, &h);
    if (e != ESP_OK) {
        return e;
    }
    e = d ? nvs_set_blob(h, k, d, n) : nvs_erase_key(h, k);
    if (e == ESP_OK || e == ESP_ERR_NVS_NOT_FOUND) {
        e = nvs_commit(h);
    }
    nvs_close(h);
    return e;
}

static esp_err_t generate(uint8_t d[32], uint8_t pub[65])
{
    mbedtls_ecp_keypair kp;
    size_t olen = 0;
    int r;
    mbedtls_ecp_keypair_init(&kp);
    r = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &kp, rng, NULL);
    if (r == 0) {
        r = mbedtls_mpi_write_binary(&kp.MBEDTLS_PRIVATE(d), d, 32);
    }
    if (r == 0 && pub != NULL) {
        r = mbedtls_ecp_point_write_binary(&kp.MBEDTLS_PRIVATE(grp), &kp.MBEDTLS_PRIVATE(Q),
                                           MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, 65);
    }
    mbedtls_ecp_keypair_free(&kp);
    return r == 0 && (pub == NULL || olen == 65) ? ESP_OK : ESP_FAIL;
}

static int keypair(const uint8_t d[32], mbedtls_ecp_keypair *kp)
{
    int r = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, kp, d, 32);
    if (r == 0) {
        r = mbedtls_ecp_mul(&kp->MBEDTLS_PRIVATE(grp), &kp->MBEDTLS_PRIVATE(Q),
                            &kp->MBEDTLS_PRIVATE(d), &kp->MBEDTLS_PRIVATE(grp).G, rng, NULL);
    }
    return r;
}

esp_err_t im_esp_nvs_identity_init(void)
{
    (void)load(KEY_CUR, s_cur, &s_have_cur);
    if (!s_have_cur) {
        /* factory: the key is generated on the device, never on the station */
        if (generate(s_cur, NULL) != ESP_OK || save(KEY_CUR, s_cur, 32) != ESP_OK) {
            return ESP_FAIL;
        }
        s_have_cur = true;
    }
    (void)load(KEY_NEW, s_new, &s_have_new);
    return ESP_OK;
}

static im_err_t sw_pub(void *ctx, uint8_t pub[IM_P256_PUB_LEN])
{
    mbedtls_ecp_keypair kp;
    size_t olen = 0;
    int r;
    (void)ctx;
    mbedtls_ecp_keypair_init(&kp);
    r = keypair(s_cur, &kp);
    if (r == 0) {
        r = mbedtls_ecp_point_write_binary(&kp.MBEDTLS_PRIVATE(grp), &kp.MBEDTLS_PRIVATE(Q),
                                           MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, 65);
    }
    mbedtls_ecp_keypair_free(&kp);
    return r == 0 && olen == 65 ? IM_OK : IM_ERR_CRYPTO;
}

static im_err_t sw_sign(void *ctx, const uint8_t digest[32], uint8_t sig[64])
{
    mbedtls_ecp_keypair kp;
    mbedtls_mpi r;
    mbedtls_mpi s;
    int ret;
    (void)ctx;
    mbedtls_ecp_keypair_init(&kp);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    ret = keypair(s_cur, &kp);
    if (ret == 0) {
        /* RFC 6979 deterministic nonce, blinded with the hardware RNG */
        ret = mbedtls_ecdsa_sign_det_ext(&kp.MBEDTLS_PRIVATE(grp), &r, &s,
                                         &kp.MBEDTLS_PRIVATE(d), digest, 32, MBEDTLS_MD_SHA256,
                                         rng, NULL);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&r, sig, 32);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&s, sig + 32, 32);
    }
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_keypair_free(&kp);
    return ret == 0 ? IM_OK : IM_ERR_CRYPTO;
}

static im_err_t sw_ecdh(void *ctx, const uint8_t peer[IM_P256_PUB_LEN], uint8_t shared[32])
{
    mbedtls_ecp_keypair kp;
    mbedtls_ecp_point p;
    mbedtls_mpi z;
    int r;
    (void)ctx;
    mbedtls_ecp_keypair_init(&kp);
    mbedtls_ecp_point_init(&p);
    mbedtls_mpi_init(&z);
    r = keypair(s_cur, &kp);
    if (r == 0) {
        r = mbedtls_ecp_point_read_binary(&kp.MBEDTLS_PRIVATE(grp), &p, peer, 65);
    }
    if (r == 0) {
        r = mbedtls_ecp_check_pubkey(&kp.MBEDTLS_PRIVATE(grp), &p);
    }
    if (r == 0) {
        r = mbedtls_ecdh_compute_shared(&kp.MBEDTLS_PRIVATE(grp), &z, &p,
                                        &kp.MBEDTLS_PRIVATE(d), rng, NULL);
    }
    if (r == 0) {
        r = mbedtls_mpi_write_binary(&z, shared, 32);
    }
    mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&p);
    mbedtls_ecp_keypair_free(&kp);
    return r == 0 ? IM_OK : IM_ERR_CRYPTO;
}

static const im_identity_t s_identity = {
    .ctx = NULL,
    .get_pubkey = sw_pub,
    .sign_digest = sw_sign,
    .ecdh = sw_ecdh,
    .se_type = "software",
};

const im_identity_t *im_esp_nvs_identity(void)
{
    return &s_identity;
}

esp_err_t im_esp_nvs_new_operational(uint8_t pub[65])
{
    /* the new key is kept separately until the certificate for it arrives */
    if (generate(s_new, pub) != ESP_OK || save(KEY_NEW, s_new, 32) != ESP_OK) {
        return ESP_FAIL;
    }
    s_have_new = true;
    return ESP_OK;
}

void im_esp_nvs_commit(bool use_operational)
{
    if (use_operational && s_have_new) {
        memcpy(s_cur, s_new, 32);
        (void)save(KEY_CUR, s_cur, 32);
    }
    im_secure_zero(s_new, sizeof s_new);
    s_have_new = false;
    (void)save(KEY_NEW, NULL, 0);
}

static esp_err_t pk_from(const uint8_t d[32], mbedtls_pk_context *pk)
{
    int r;
    mbedtls_pk_init(pk);
    r = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (r == 0) {
        r = keypair(d, mbedtls_pk_ec(*pk));
    }
    if (r != 0) {
        mbedtls_pk_free(pk); /* mbedtls zeroizes the private key on free */
    }
    return r == 0 ? ESP_OK : ESP_FAIL;
}

#if !CONFIG_IRONMESH_SE_ATECC608
esp_err_t im_esp_identity_pk(mbedtls_pk_context *pk)
{
    return pk_from(s_cur, pk);
}

esp_err_t im_esp_identity_pending_pk(mbedtls_pk_context *pk)
{
    return s_have_new ? pk_from(s_new, pk) : ESP_ERR_INVALID_STATE;
}
#endif
