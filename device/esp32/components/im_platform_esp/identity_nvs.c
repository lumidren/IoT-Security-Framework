/*
 * Software key store: P-256 keys generated on the device and kept in the *encrypted* NVS
 * partition (NVS encryption; key protection = HMAC eFuse key on chips with the HMAC peripheral,
 * otherwise the flash-encrypted nvs_keys partition). Same slot numbering as the ATECC608B
 * (im_keyslot.h): "sw_k0" bootstrap (generated at the factory, on the device), "sw_k2" and
 * "sw_k3" alternating operational keys. se_type "software" -> assurance_level software
 * (contract section 10): code execution on the MCU means key compromise. The ESP32 DS peripheral
 * (esp_ds) is RSA-only and cannot hold a P-256 key, so it is not used.
 *
 * NOT COMPILED HERE (ESP-IDF v5.3 API: nvs, mbedtls ecp/ecdsa/ecdh).
 */
#include <stdio.h>
#include <string.h>

#include "esp_random.h"
#include "im_esp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "nvs.h"

#define NS "ironmesh"

static uint8_t s_keys[4][32]; /* index = slot; 1 unused */
static bool s_have[4];

static int rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}

static void key_name(uint8_t slot, char out[8])
{
    snprintf(out, 8, "sw_k%u", (unsigned)slot);
}

static esp_err_t load(uint8_t slot)
{
    nvs_handle_t h;
    size_t n = 32;
    char k[8];
    esp_err_t e = nvs_open(NS, NVS_READONLY, &h);
    key_name(slot, k);
    if (e == ESP_OK) {
        e = nvs_get_blob(h, k, s_keys[slot], &n);
        nvs_close(h);
    }
    s_have[slot] = e == ESP_OK && n == 32;
    return e;
}

static esp_err_t save(uint8_t slot)
{
    nvs_handle_t h;
    char k[8];
    esp_err_t e = nvs_open(NS, NVS_READWRITE, &h);
    key_name(slot, k);
    if (e == ESP_OK) {
        e = nvs_set_blob(h, k, s_keys[slot], 32);
        if (e == ESP_OK) {
            e = nvs_commit(h);
        }
        nvs_close(h);
    }
    return e;
}

static int keypair(uint8_t slot, mbedtls_ecp_keypair *kp)
{
    int r;
    if (slot > 3 || !s_have[slot]) {
        return -1;
    }
    r = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, kp, s_keys[slot], 32);
    if (r == 0) {
        r = mbedtls_ecp_mul(&kp->MBEDTLS_PRIVATE(grp), &kp->MBEDTLS_PRIVATE(Q),
                            &kp->MBEDTLS_PRIVATE(d), &kp->MBEDTLS_PRIVATE(grp).G, rng, NULL);
    }
    return r;
}

static esp_err_t generate(uint8_t slot, uint8_t pub[65])
{
    mbedtls_ecp_keypair kp;
    size_t olen = 0;
    int r;
    mbedtls_ecp_keypair_init(&kp);
    r = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &kp, rng, NULL);
    if (r == 0) {
        r = mbedtls_mpi_write_binary(&kp.MBEDTLS_PRIVATE(d), s_keys[slot], 32);
    }
    if (r == 0 && pub != NULL) {
        r = mbedtls_ecp_point_write_binary(&kp.MBEDTLS_PRIVATE(grp), &kp.MBEDTLS_PRIVATE(Q),
                                           MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, 65);
    }
    mbedtls_ecp_keypair_free(&kp);
    if (r != 0 || (pub != NULL && olen != 65)) {
        im_secure_zero(s_keys[slot], 32);
        return ESP_FAIL;
    }
    s_have[slot] = true;
    return save(slot);
}

esp_err_t im_esp_keystore_init(void)
{
    for (uint8_t s = 0; s < 4; s++) {
        if (s != 1) {
            (void)load(s);
        }
    }
    /* factory: the bootstrap key is generated on the device, never on the station */
    return s_have[IM_SLOT_BOOTSTRAP] ? ESP_OK : generate(IM_SLOT_BOOTSTRAP, NULL);
}

static im_err_t sw_pub(void *ctx, uint8_t pub[IM_P256_PUB_LEN])
{
    mbedtls_ecp_keypair kp;
    size_t olen = 0;
    int r;
    (void)ctx;
    mbedtls_ecp_keypair_init(&kp);
    r = keypair(im_esp_signing_slot(), &kp);
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
    ret = keypair(im_esp_signing_slot(), &kp);
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
    r = keypair(im_esp_active_slot(), &kp); /* config is wrapped to the current cert key */
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

const im_identity_t *im_esp_keystore_identity(void)
{
    return &s_identity;
}

esp_err_t im_esp_keystore_genkey(uint8_t slot, uint8_t pub[65])
{
    if ((slot != IM_SLOT_OP_A && slot != IM_SLOT_OP_B) || slot == im_esp_active_slot()) {
        return ESP_ERR_INVALID_ARG; /* never overwrite the key of the live certificate */
    }
    return generate(slot, pub);
}

esp_err_t im_esp_keystore_pk(uint8_t slot, mbedtls_pk_context *pk)
{
    int r;
    mbedtls_pk_init(pk);
    r = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (r == 0) {
        r = keypair(slot, mbedtls_pk_ec(*pk));
    }
    if (r != 0) {
        mbedtls_pk_free(pk); /* mbedTLS zeroizes the private key on free */
    }
    return r == 0 ? ESP_OK : ESP_FAIL;
}
