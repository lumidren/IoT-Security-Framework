/*
 * IronMesh protocol core - identifier validators and the MQTT topic scheme (WIRE_FORMAT.md §7).
 * Hand-written equivalents of the regular expressions in ironmesh_wire/ids.py.
 */
#include "im_ids.h"

#include <string.h>

static bool is_lhex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static bool is_lalnum(char c)
{
    return is_digit(c) || (c >= 'a' && c <= 'z');
}

static bool is_ident_char(char c)
{
    return is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-';
}

static bool uuid_shape(const char *s, size_t n)
{
    if (s == NULL || n != IM_UUID_LEN) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-') {
                return false;
            }
        } else if (!is_lhex(s[i])) {
            return false;
        }
    }
    return true;
}

bool im_id_is_uuid(const char *s, size_t n)
{
    return uuid_shape(s, n);
}

bool im_id_is_uuid4(const char *s, size_t n)
{
    return uuid_shape(s, n) && s[14] == '4' &&
           (s[19] == '8' || s[19] == '9' || s[19] == 'a' || s[19] == 'b');
}

bool im_id_is_device_id(const char *s, size_t n)
{
    if (s == NULL || n != IM_DEVICE_ID_LEN || memcmp(s, "dev-", 4) != 0) {
        return false;
    }
    for (size_t i = 4; i < n; i++) {
        if (!is_lhex(s[i])) {
            return false;
        }
    }
    return true;
}

bool im_id_is_group_slug(const char *s, size_t n)
{
    if (s == NULL || n < 1 || n > 48) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (!is_lalnum(s[i]) && s[i] != '-') {
            return false;
        }
    }
    return true;
}

bool im_id_is_product(const char *s, size_t n)
{
    if (s == NULL || n < 1 || n > 64 || !is_lalnum(s[0])) {
        return false;
    }
    for (size_t i = 1; i < n; i++) {
        if (!is_lalnum(s[i]) && s[i] != '-') {
            return false;
        }
    }
    return true;
}

/* (0|[1-9]\d*) */
static bool semver_num(const char *s, size_t n, size_t *pos)
{
    size_t start = *pos;
    if (start >= n || !is_digit(s[start])) {
        return false;
    }
    if (s[start] == '0') {
        *pos = start + 1;
        return true;
    }
    while (*pos < n && is_digit(s[*pos])) {
        (*pos)++;
    }
    return true;
}

/* dot-separated identifiers; numeric ones (pre-release only) must not have leading zeros */
static bool semver_idents(const char *s, size_t n, size_t *pos, bool prerelease)
{
    for (;;) {
        size_t start = *pos;
        bool all_digits = true;
        while (*pos < n && is_ident_char(s[*pos])) {
            if (!is_digit(s[*pos])) {
                all_digits = false;
            }
            (*pos)++;
        }
        if (*pos == start) {
            return false; /* empty identifier */
        }
        if (prerelease && all_digits && (*pos - start) > 1 && s[start] == '0') {
            return false;
        }
        if (*pos < n && s[*pos] == '.') {
            (*pos)++;
            continue;
        }
        return true;
    }
}

bool im_id_is_semver(const char *s, size_t n)
{
    size_t pos = 0;
    if (s == NULL) {
        return false;
    }
    for (int i = 0; i < 3; i++) {
        if (!semver_num(s, n, &pos)) {
            return false;
        }
        if (i < 2) {
            if (pos >= n || s[pos] != '.') {
                return false;
            }
            pos++;
        }
    }
    if (pos < n && s[pos] == '-') {
        pos++;
        if (!semver_idents(s, n, &pos, true)) {
            return false;
        }
    }
    if (pos < n && s[pos] == '+') {
        pos++;
        if (!semver_idents(s, n, &pos, false)) {
            return false;
        }
    }
    return pos == n;
}

bool im_id_is_firmware_id(const char *s, size_t n)
{
    const char *slash;
    if (s == NULL) {
        return false;
    }
    slash = memchr(s, '/', n);
    if (slash == NULL) {
        return false;
    }
    return im_id_is_product(s, (size_t)(slash - s)) &&
           im_id_is_semver(slash + 1, n - (size_t)(slash - s) - 1);
}

bool im_id_is_device_kid(const uint8_t *kid, size_t n)
{
    return kid != NULL && n >= 1 && n <= IM_MAX_SERIAL_LEN && (n == 1 || kid[0] != 0);
}

bool im_id_is_tenant_kid(const char *kid, size_t n, const char **tenant)
{
    static const char prefix[] = "tenant-cmd-";
    const size_t plen = sizeof prefix - 1u;
    if (kid == NULL || n != plen + IM_UUID_LEN || memcmp(kid, prefix, plen) != 0) {
        return false;
    }
    if (!im_id_is_uuid4(kid + plen, IM_UUID_LEN)) {
        return false;
    }
    if (tenant != NULL) {
        *tenant = kid + plen;
    }
    return true;
}

im_err_t im_id_kid_from_serial(const uint8_t *serial, size_t n, uint8_t *kid, size_t cap,
                               size_t *kid_len)
{
    size_t start = 0;
    size_t len;
    if (serial == NULL || n == 0 || kid == NULL || kid_len == NULL) {
        return IM_ERR_ARG;
    }
    while (start + 1 < n && serial[start] == 0) {
        start++;
    }
    len = n - start;
    if (len > IM_MAX_SERIAL_LEN) {
        return IM_ERR_ID_FORMAT;
    }
    if (len > cap) {
        return IM_ERR_BUFFER;
    }
    memcpy(kid, serial + start, len);
    *kid_len = len;
    return IM_OK;
}

im_err_t im_id_tenant_kid(const char *tenant, size_t n, char *out, size_t cap)
{
    if (!im_id_is_uuid4(tenant, n)) {
        return IM_ERR_ID_FORMAT;
    }
    if (out == NULL || cap < IM_TENANT_KID_LEN + 1u) {
        return IM_ERR_BUFFER;
    }
    memcpy(out, "tenant-cmd-", 11);
    memcpy(out + 11, tenant, IM_UUID_LEN);
    out[IM_TENANT_KID_LEN] = '\0';
    return IM_OK;
}

/* ------------------------------------------------------------------------------------------ */

static const char *const k_suffix[IM_TOPIC__COUNT] = {
    "telemetry", "events",  "shadow/reported", "cmd/ack", "ota/status",
    "shadow/desired", "cmd/req", "ota/notify", "config",
};

static const uint8_t k_type[IM_TOPIC__COUNT] = {1, 2, 3, 6, 8, 4, 5, 7, 9};

const char *im_topic_suffix(im_topic_class_t cls)
{
    return (unsigned)cls < IM_TOPIC__COUNT ? k_suffix[cls] : "";
}

uint8_t im_topic_message_type(im_topic_class_t cls)
{
    return (unsigned)cls < IM_TOPIC__COUNT ? k_type[cls] : 0;
}

bool im_topic_device_publishes(im_topic_class_t cls)
{
    return cls <= IM_TOPIC_OTA_STATUS;
}

bool im_topic_retained_allowed(im_topic_class_t cls)
{
    return cls == IM_TOPIC_SHADOW_DESIRED || cls == IM_TOPIC_OTA_NOTIFY || cls == IM_TOPIC_CONFIG;
}

im_err_t im_topic_build(const char *tenant, const char *device, im_topic_class_t cls, char *out,
                        size_t cap, size_t *out_len)
{
    size_t tl;
    size_t dl;
    size_t sl;
    size_t total;
    if (tenant == NULL || device == NULL || (unsigned)cls >= IM_TOPIC__COUNT) {
        return IM_ERR_ARG;
    }
    tl = strlen(tenant);
    dl = strlen(device);
    if (!im_id_is_uuid4(tenant, tl) || !im_id_is_device_id(device, dl)) {
        return IM_ERR_ID_FORMAT;
    }
    sl = strlen(k_suffix[cls]);
    total = 6u + tl + 1u + dl + 1u + sl; /* "im/v1/" */
    if (out == NULL || cap < total + 1u) {
        return IM_ERR_BUFFER;
    }
    memcpy(out, "im/v1/", 6);
    memcpy(out + 6, tenant, tl);
    out[6 + tl] = '/';
    memcpy(out + 7 + tl, device, dl);
    out[7 + tl + dl] = '/';
    memcpy(out + 8 + tl + dl, k_suffix[cls], sl);
    out[total] = '\0';
    if (out_len != NULL) {
        *out_len = total;
    }
    return IM_OK;
}

im_err_t im_topic_parse(const char *topic, size_t n, im_topic_t *out)
{
    const char *tenant;
    const char *device;
    const char *suffix;
    size_t sl;
    if (topic == NULL || n < 6 || memcmp(topic, "im/v1/", 6) != 0) {
        return IM_ERR_TOPIC_FORMAT;
    }
    /* im/v1/<tenant>/<device>/<suffix>: fixed-length ids make the split unambiguous */
    tenant = topic + 6;
    if (n < 6u + IM_UUID_LEN + 1u + IM_DEVICE_ID_LEN + 2u) {
        return IM_ERR_TOPIC_FORMAT;
    }
    if (tenant[IM_UUID_LEN] != '/' || !im_id_is_uuid4(tenant, IM_UUID_LEN)) {
        return IM_ERR_TOPIC_FORMAT;
    }
    device = tenant + IM_UUID_LEN + 1;
    if (device[IM_DEVICE_ID_LEN] != '/' || !im_id_is_device_id(device, IM_DEVICE_ID_LEN)) {
        return IM_ERR_TOPIC_FORMAT;
    }
    suffix = device + IM_DEVICE_ID_LEN + 1;
    sl = n - (size_t)(suffix - topic);
    for (unsigned i = 0; i < IM_TOPIC__COUNT; i++) {
        if (strlen(k_suffix[i]) == sl && memcmp(k_suffix[i], suffix, sl) == 0) {
            if (out != NULL) {
                out->tenant = tenant;
                out->device = device;
                out->cls = (im_topic_class_t)i;
            }
            return IM_OK;
        }
    }
    return IM_ERR_TOPIC_FORMAT;
}

static bool same_device(const im_topic_t *t, const char *device_id)
{
    return device_id != NULL && strlen(device_id) == IM_DEVICE_ID_LEN &&
           memcmp(t->device, device_id, IM_DEVICE_ID_LEN) == 0;
}

bool im_topic_device_may_publish(const char *topic, size_t n, const char *device_id)
{
    im_topic_t t;
    return im_topic_parse(topic, n, &t) == IM_OK && same_device(&t, device_id) &&
           im_topic_device_publishes(t.cls);
}

bool im_topic_device_may_subscribe(const char *topic, size_t n, const char *device_id)
{
    im_topic_t t;
    return im_topic_parse(topic, n, &t) == IM_OK && same_device(&t, device_id) &&
           !im_topic_device_publishes(t.cls);
}
