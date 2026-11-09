/*
 * IronMesh protocol core - error strings and small crypto helpers built on the provider.
 */
#include <string.h>

#include "im_crypto.h"
#include "im_err.h"

static const char *const k_err_names[] = {
#define IM_ERR_NAME_(name, str) str,
    IM_ERR_LIST(IM_ERR_NAME_)
#undef IM_ERR_NAME_
};

const char *im_err_str(im_err_t err)
{
    if ((unsigned)err >= (unsigned)IM_ERR__COUNT) {
        return "UNKNOWN";
    }
    return k_err_names[err];
}

int im_err_is_wire(im_err_t err)
{
    return err > IM_OK && err <= IM__WIRE_LAST;
}

im_err_t im_sha256(const uint8_t *data, size_t len, uint8_t out[IM_SHA256_LEN])
{
    im_sha256_ctx_t ctx;
    im_err_t err = im_crypto_sha256_init(&ctx);
    if (err != IM_OK) {
        return err;
    }
    err = im_crypto_sha256_update(&ctx, data, len);
    if (err != IM_OK) {
        im_crypto_sha256_free(&ctx);
        return err;
    }
    return im_crypto_sha256_finish(&ctx, out);
}

void im_secure_zero(void *p, size_t len)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len--) {
        *v++ = 0;
    }
}

int im_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff = (uint8_t)(diff | (a[i] ^ b[i]));
    }
    return diff == 0;
}

/* ABI self-description so hosts that mirror these structs (Rust FFI) can verify layouts. */
#include "im_agent.h"
#include "im_mqtt.h"

size_t im_abi_size(int which)
{
    switch (which) {
    case 0:
        return sizeof(im_mqtt_packet_t);
    case 1:
        return sizeof(im_mqtt_props_t);
    case 2:
        return sizeof(im_mqtt_session_t);
    case 3:
        return sizeof(im_ringbuf_t);
    case 4:
        return sizeof(im_ota_config_t);
    case 5:
        return sizeof(im_agent_config_t);
    case 6:
        return sizeof(im_agent_platform_t);
    case 7:
        return sizeof(im_cmd_cache_t);
    case 8:
        return sizeof(im_json_tok_t);
    case 9:
        return sizeof(im_env_msg_t);
    case 10:
        return sizeof(im_manifest_t);
    case 11:
        return sizeof(im_telemetry_t);
    case 12:
        return sizeof(im_ota_notify_t);
    case 13:
        return sizeof(im_rejection_t);
    default:
        return 0;
    }
}
