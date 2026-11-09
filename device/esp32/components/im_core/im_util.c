/*
 * IronMesh protocol core - error strings and small crypto helpers built on the provider.
 */
#include <string.h>

#include "im_crypto.h"
#include "im_err.h"
#include "im_util.h"

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

/* ---- endpoint policy ---------------------------------------------------------------------- */

im_err_t im_est_pins_select(const uint8_t *bundle_pins, size_t n_bundle,
                            const uint8_t *factory_pins, size_t n_factory, uint8_t *out,
                            size_t cap, size_t *n_out)
{
    const uint8_t *src;
    size_t n;
    if (out == NULL || n_out == NULL || cap == 0) {
        return IM_ERR_ARG;
    }
    *n_out = 0;
    if (bundle_pins != NULL && n_bundle > 0) {
        src = bundle_pins; /* enrolled: the signed bundle is authoritative */
        n = n_bundle;
    } else if (factory_pins != NULL && n_factory > 0) {
        src = factory_pins; /* first enrollment: factory-provisioned PKI CA pin */
        n = n_factory;
    } else {
        return IM_ERR_NOT_FOUND;
    }
    if (n > cap) {
        n = cap;
    }
    memcpy(out, src, n * IM_PIN_LEN);
    *n_out = n;
    return IM_OK;
}

bool im_pin_match(const uint8_t spki_sha256[IM_PIN_LEN], const uint8_t *pins, size_t n)
{
    int hit = 0;
    if (spki_sha256 == NULL || pins == NULL) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        hit |= im_ct_equal(spki_sha256, pins + i * IM_PIN_LEN, IM_PIN_LEN);
    }
    return hit != 0;
}

im_err_t im_url_https_host(const char *url, size_t len, const char **host, size_t *host_len)
{
    static const char k_scheme[] = "https://";
    const size_t start = sizeof k_scheme - 1u;
    size_t end = start;
    size_t i;
    if (url == NULL || host == NULL || host_len == NULL || len <= start ||
        memcmp(url, k_scheme, start) != 0) {
        return IM_ERR_ARG;
    }
    while (end < len && url[end] != '/' && url[end] != '?' && url[end] != '#') {
        end++;
    }
    for (i = start; i < end; i++) {
        unsigned char c = (unsigned char)url[i];
        if (c <= 0x20u || c >= 0x7fu || c == '@' || c == '\\') {
            return IM_ERR_ARG;
        }
    }
    if (url[start] == '[') {
        size_t close = start + 1u;
        while (close < end && url[close] != ']') {
            close++;
        }
        if (close >= end || close == start + 1u) {
            return IM_ERR_ARG;
        }
        *host = url + start + 1u;
        *host_len = close - start - 1u;
        i = close + 1u;
    } else {
        i = start;
        while (i < end && url[i] != ':') {
            i++;
        }
        if (i == start) {
            return IM_ERR_ARG;
        }
        *host = url + start;
        *host_len = i - start;
    }
    if (i < end) {
        uint32_t port = 0;
        size_t digits = 0;
        if (url[i] != ':') {
            return IM_ERR_ARG;
        }
        for (i++; i < end; i++) {
            if (url[i] < '0' || url[i] > '9' || ++digits > 5u) {
                return IM_ERR_ARG;
            }
            port = port * 10u + (uint32_t)(url[i] - '0');
        }
        if (digits == 0 || port == 0 || port > 65535u) {
            return IM_ERR_ARG;
        }
    }
    return IM_OK;
}

static unsigned char ascii_lower(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c - 'A' + 'a') : c;
}

bool im_host_allowed(const char *host, size_t host_len, const char *const *allowed, size_t n)
{
    if (host == NULL || host_len == 0 || allowed == NULL) {
        return false;
    }
    for (size_t k = 0; k < n; k++) {
        const char *name = allowed[k];
        size_t j = 0;
        if (name == NULL || strlen(name) != host_len) {
            continue;
        }
        while (j < host_len &&
               ascii_lower((unsigned char)name[j]) == ascii_lower((unsigned char)host[j])) {
            j++;
        }
        if (j == host_len) {
            return true;
        }
    }
    return false;
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
