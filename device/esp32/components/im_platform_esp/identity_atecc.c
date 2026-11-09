/*
 * ATECC608B key store (esp-cryptoauthlib). Hardware assurance: keys are generated inside the
 * chip and never leave it; im_core only sees public keys, signatures and ECDH results.
 *
 *   slot 0     bootstrap key (locked at the factory): first enrollment + post-expiry fallback
 *   slot 2/3   alternating operational keys: renewal runs atcab_genkey on the INACTIVE slot,
 *              so the active slot keeps authenticating TLS and signing the attestation until the
 *              new certificate is committed (im_keyslot.c, platform_storage.c "id_rec")
 *
 * NOT COMPILED HERE (needs ESP-IDF + espressif/esp-cryptoauthlib). Written against
 * cryptoauthlib v3.7 (atcab_* "basic" API) as packaged by esp-cryptoauthlib 0.4.x.
 */
#include <string.h>

#include "atca_mbedtls_wrap.h"
#include "atecc_config.h"
#include "cryptoauthlib.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "im_esp.h"

_Static_assert(IM_ATECC_SLOT_OP_A == IM_SLOT_OP_A && IM_ATECC_SLOT_OP_B == IM_SLOT_OP_B &&
                   IM_ATECC_SLOT_BOOTSTRAP == IM_SLOT_BOOTSTRAP,
               "ATECC slot map must match im_keyslot.h");

static const char *TAG = "im_atecc";
static ATCAIfaceCfg s_cfg;
static SemaphoreHandle_t s_lock;

static ATCA_STATUS locked_call(ATCA_STATUS (*fn)(void *), void *arg)
{
    ATCA_STATUS st;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    st = fn(arg);
    xSemaphoreGive(s_lock);
    return st;
}

static uint16_t cfg16(const uint8_t *cfg, unsigned off, unsigned slot)
{
    return (uint16_t)(cfg[off + 2 * slot] | (cfg[off + 2 * slot + 1] << 8));
}

static esp_err_t check_config_zone(void)
{
    uint8_t cfg[128];
    bool locked = false;
    bool slot0_locked = false;
    if (atcab_is_config_locked(&locked) != ATCA_SUCCESS || !locked) {
        ESP_LOGE(TAG, "config zone not locked: device not factory provisioned");
        return ESP_ERR_INVALID_STATE;
    }
    if (atcab_read_config_zone(cfg) != ATCA_SUCCESS) {
        return ESP_FAIL;
    }
    if (cfg16(cfg, IM_ATECC_CFG_SLOTCONFIG_OFFSET, 0) != IM_ATECC_SLOTCFG_BOOTSTRAP ||
        cfg16(cfg, IM_ATECC_CFG_SLOTCONFIG_OFFSET, 2) != IM_ATECC_SLOTCFG_OPERATIONAL ||
        cfg16(cfg, IM_ATECC_CFG_SLOTCONFIG_OFFSET, 3) != IM_ATECC_SLOTCFG_OPERATIONAL ||
        cfg16(cfg, IM_ATECC_CFG_KEYCONFIG_OFFSET, 2) != IM_ATECC_KEYCFG_OPERATIONAL ||
        cfg16(cfg, IM_ATECC_CFG_KEYCONFIG_OFFSET, 3) != IM_ATECC_KEYCFG_OPERATIONAL) {
        ESP_LOGE(TAG, "unexpected slot configuration for slots 0/2/3");
        return ESP_ERR_INVALID_STATE;
    }
    if (atcab_is_slot_locked(IM_ATECC_SLOT_BOOTSTRAP, &slot0_locked) != ATCA_SUCCESS ||
        !slot0_locked) {
        ESP_LOGE(TAG, "bootstrap slot 0 is not locked");
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_OK;
}

esp_err_t im_esp_keystore_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    if (s_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    s_cfg = cfg_ateccx08a_i2c_default;
    s_cfg.atcai2c.address = CONFIG_IRONMESH_ATECC_I2C_ADDR;
    s_cfg.atcai2c.bus = CONFIG_IRONMESH_I2C_PORT;
    s_cfg.atcai2c.baud = 400000;
    if (atcab_init(&s_cfg) != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "ATECC608B not responding");
        return ESP_FAIL;
    }
    return check_config_zone();
}

typedef struct {
    uint16_t slot;
    const uint8_t *in;
    uint8_t *out;
} op_t;

static ATCA_STATUS do_pub(void *a)
{
    op_t *o = a;
    return atcab_get_pubkey(o->slot, o->out);
}

static ATCA_STATUS do_sign(void *a)
{
    op_t *o = a;
    return atcab_sign(o->slot, o->in, o->out); /* raw r||s = COSE ES256 encoding */
}

static ATCA_STATUS do_ecdh(void *a)
{
    op_t *o = a;
    return atcab_ecdh(o->slot, o->in, o->out);
}

static ATCA_STATUS do_genkey(void *a)
{
    op_t *o = a;
    return atcab_genkey(o->slot, o->out);
}

static im_err_t se_get_pubkey(void *ctx, uint8_t pub[IM_P256_PUB_LEN])
{
    op_t o = {.slot = im_esp_signing_slot(), .out = pub + 1};
    (void)ctx;
    pub[0] = 0x04;
    return locked_call(do_pub, &o) == ATCA_SUCCESS ? IM_OK : IM_ERR_CRYPTO;
}

static im_err_t se_sign(void *ctx, const uint8_t digest[32], uint8_t sig[64])
{
    op_t o = {.slot = im_esp_signing_slot(), .in = digest, .out = sig};
    (void)ctx;
    return locked_call(do_sign, &o) == ATCA_SUCCESS ? IM_OK : IM_ERR_CRYPTO;
}

static im_err_t se_ecdh(void *ctx, const uint8_t peer[IM_P256_PUB_LEN], uint8_t shared[32])
{
    uint8_t active = im_esp_active_slot();
    op_t o = {.slot = active, .in = peer + 1, .out = shared};
    (void)ctx;
    if (active != IM_ATECC_SLOT_OP_A && active != IM_ATECC_SLOT_OP_B) {
        return IM_ERR_CRYPTO; /* slot 0 is not ECDH-capable by configuration */
    }
    return locked_call(do_ecdh, &o) == ATCA_SUCCESS ? IM_OK : IM_ERR_CRYPTO;
}

static const im_identity_t s_identity = {
    .ctx = NULL,
    .get_pubkey = se_get_pubkey,
    .sign_digest = se_sign,
    .ecdh = se_ecdh,
    .se_type = "atecc608",
};

const im_identity_t *im_esp_keystore_identity(void)
{
    return &s_identity;
}

esp_err_t im_esp_keystore_genkey(uint8_t slot, uint8_t pub[65])
{
    op_t o = {.slot = slot, .out = pub + 1};
    if ((slot != IM_ATECC_SLOT_OP_A && slot != IM_ATECC_SLOT_OP_B) ||
        slot == im_esp_active_slot()) {
        return ESP_ERR_INVALID_ARG; /* never overwrite the key of the live certificate */
    }
    pub[0] = 0x04;
    return locked_call(do_genkey, &o) == ATCA_SUCCESS ? ESP_OK : ESP_FAIL;
}

esp_err_t im_esp_keystore_pk(uint8_t slot, mbedtls_pk_context *pk)
{
    /* cryptoauthlib's mbedTLS wrapper: an opaque pk whose sign op runs atcab_sign in-chip */
    return atca_mbedtls_pk_init(pk, slot) == 0 ? ESP_OK : ESP_FAIL;
}
