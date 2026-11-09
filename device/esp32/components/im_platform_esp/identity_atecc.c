/*
 * ATECC608B identity (esp-cryptoauthlib). Hardware assurance: keys are generated inside the
 * chip and never leave it; im_core only ever sees public keys, signatures and ECDH results.
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
#include "nvs.h"

static const char *TAG = "im_atecc";
static ATCAIfaceCfg s_cfg;
static SemaphoreHandle_t s_lock;
static bool s_use_operational; /* slot 2 holds the key of the current certificate */
static uint16_t s_pending_slot = IM_ATECC_SLOT_OPERATIONAL;

#define LOCKED(expr)                                    \
    ({                                                  \
        ATCA_STATUS st_;                                \
        xSemaphoreTake(s_lock, portMAX_DELAY);          \
        st_ = (expr);                                   \
        xSemaphoreGive(s_lock);                         \
        st_;                                            \
    })

static uint16_t current_slot(void)
{
    return s_use_operational ? IM_ATECC_SLOT_OPERATIONAL : IM_ATECC_SLOT_BOOTSTRAP;
}

static esp_err_t check_config_zone(void)
{
    uint8_t cfg[128];
    bool locked = false;
    if (atcab_is_config_locked(&locked) != ATCA_SUCCESS || !locked) {
        ESP_LOGE(TAG, "config zone not locked: device not factory provisioned");
        return ESP_ERR_INVALID_STATE;
    }
    if (atcab_read_config_zone(cfg) != ATCA_SUCCESS) {
        return ESP_FAIL;
    }
    uint16_t sc0 = (uint16_t)(cfg[IM_ATECC_CFG_SLOTCONFIG_OFFSET] |
                              (cfg[IM_ATECC_CFG_SLOTCONFIG_OFFSET + 1] << 8));
    uint16_t sc2 = (uint16_t)(cfg[IM_ATECC_CFG_SLOTCONFIG_OFFSET + 4] |
                              (cfg[IM_ATECC_CFG_SLOTCONFIG_OFFSET + 5] << 8));
    uint16_t kc2 = (uint16_t)(cfg[IM_ATECC_CFG_KEYCONFIG_OFFSET + 4] |
                              (cfg[IM_ATECC_CFG_KEYCONFIG_OFFSET + 5] << 8));
    if (sc0 != IM_ATECC_SLOTCFG_BOOTSTRAP || sc2 != IM_ATECC_SLOTCFG_OPERATIONAL ||
        kc2 != IM_ATECC_KEYCFG_OPERATIONAL) {
        ESP_LOGE(TAG, "unexpected slot configuration (0x%04x 0x%04x 0x%04x)", sc0, sc2, kc2);
        return ESP_ERR_INVALID_STATE;
    }
    bool slot0_locked = false;
    if (atcab_is_slot_locked(IM_ATECC_SLOT_BOOTSTRAP, &slot0_locked) != ATCA_SUCCESS ||
        !slot0_locked) {
        ESP_LOGE(TAG, "bootstrap slot 0 is not locked");
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_OK;
}

esp_err_t im_esp_atecc_init(void)
{
    nvs_handle_t h;
    uint8_t op = 0;
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
    ESP_ERROR_CHECK_WITHOUT_ABORT(check_config_zone());
    if (nvs_open("ironmesh", NVS_READONLY, &h) == ESP_OK) {
        (void)nvs_get_u8(h, "se_op", &op);
        nvs_close(h);
    }
    s_use_operational = op == 1;
    return ESP_OK;
}

static im_err_t pub_of(uint16_t slot, uint8_t pub[65])
{
    pub[0] = 0x04;
    return LOCKED(atcab_get_pubkey(slot, pub + 1)) == ATCA_SUCCESS ? IM_OK : IM_ERR_CRYPTO;
}

static im_err_t se_get_pubkey(void *ctx, uint8_t pub[IM_P256_PUB_LEN])
{
    (void)ctx;
    return pub_of(current_slot(), pub);
}

static im_err_t se_sign(void *ctx, const uint8_t digest[32], uint8_t sig[64])
{
    (void)ctx;
    /* atcab_sign produces raw r||s, exactly the COSE ES256 encoding */
    return LOCKED(atcab_sign(current_slot(), digest, sig)) == ATCA_SUCCESS ? IM_OK
                                                                            : IM_ERR_CRYPTO;
}

static im_err_t se_ecdh(void *ctx, const uint8_t peer[IM_P256_PUB_LEN], uint8_t shared[32])
{
    (void)ctx;
    if (current_slot() != IM_ATECC_SLOT_OPERATIONAL) {
        return IM_ERR_CRYPTO; /* slot 0 is not ECDH-capable by configuration */
    }
    return LOCKED(atcab_ecdh(IM_ATECC_SLOT_OPERATIONAL, peer + 1, shared)) == ATCA_SUCCESS
               ? IM_OK
               : IM_ERR_CRYPTO;
}

static const im_identity_t s_identity = {
    .ctx = NULL,
    .get_pubkey = se_get_pubkey,
    .sign_digest = se_sign,
    .ecdh = se_ecdh,
    .se_type = "atecc608",
};

const im_identity_t *im_esp_atecc_identity(void)
{
    return &s_identity;
}

esp_err_t im_esp_atecc_new_operational(uint8_t pub[65])
{
    /* The layout has ONE operational slot (HARDWARE_SETUP.md: "slot 2 ... regenerated at every
     * enrollment"), so atcab_genkey replaces the key of the still-valid operational cert. The
     * EST client therefore performs simplereenroll over TLS authenticated by the OLD cert only
     * up to this point and switches the identity to bootstrap (slot 0) if enrollment fails
     * afterwards (im_esp_atecc_commit(false)); the PKI accepts Factory-CA re-enrollment
     * (contract section 2). A spare slot (e.g. 3) would avoid the window - see README. */
    s_pending_slot = IM_ATECC_SLOT_OPERATIONAL;
    pub[0] = 0x04;
    return LOCKED(atcab_genkey(IM_ATECC_SLOT_OPERATIONAL, pub + 1)) == ATCA_SUCCESS ? ESP_OK
                                                                                     : ESP_FAIL;
}

void im_esp_atecc_commit(bool use_operational)
{
    nvs_handle_t h;
    s_use_operational = use_operational;
    if (nvs_open("ironmesh", NVS_READWRITE, &h) == ESP_OK) {
        (void)nvs_set_u8(h, "se_op", use_operational ? 1 : 0);
        (void)nvs_commit(h);
        nvs_close(h);
    }
}

esp_err_t im_esp_identity_pk(mbedtls_pk_context *pk)
{
    /* cryptoauthlib's mbedTLS wrapper: an opaque pk whose sign op runs atcab_sign in-chip */
    return atca_mbedtls_pk_init(pk, current_slot()) == 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t im_esp_identity_pending_pk(mbedtls_pk_context *pk)
{
    return atca_mbedtls_pk_init(pk, s_pending_slot) == 0 ? ESP_OK : ESP_FAIL;
}
