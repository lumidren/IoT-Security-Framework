/*
 * IronMesh protocol core - identifiers, key ids and MQTT topics (WIRE_FORMAT.md §3.3, §7).
 * All validators take (pointer, length) because identifiers arrive from the network unterminated.
 */
#ifndef IM_IDS_H
#define IM_IDS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IM_UUID_LEN 36u
#define IM_DEVICE_ID_LEN 20u            /* "dev-" + 16 hex */
#define IM_TENANT_KID_LEN 47u           /* "tenant-cmd-" + uuid */
#define IM_MAX_SERIAL_LEN 20u           /* RFC 5280 §4.1.2.2 */
#define IM_TOPIC_MAX_LEN 96u            /* longest topic: im/v1/<36>/<20>/shadow/reported = 79 */

bool im_id_is_uuid(const char *s, size_t n);        /* any version, lower-case, hyphenated */
bool im_id_is_uuid4(const char *s, size_t n);       /* tenant / campaign id */
bool im_id_is_device_id(const char *s, size_t n);   /* ^dev-[0-9a-f]{16}$ */
bool im_id_is_group_slug(const char *s, size_t n);  /* ^[a-z0-9-]{1,48}$ */
bool im_id_is_product(const char *s, size_t n);     /* ^[a-z0-9][a-z0-9-]{0,63}$ */
bool im_id_is_semver(const char *s, size_t n);      /* SemVer 2.0.0 (ASCII digits) */
bool im_id_is_firmware_id(const char *s, size_t n); /* <product>/<semver> */

/* Device kid: minimal big-endian certificate serial, 1..20 bytes, no leading 0x00. */
bool im_id_is_device_kid(const uint8_t *kid, size_t n);
/* Tenant kid "tenant-cmd-<uuid4>"; on success *tenant points at the uuid inside kid. */
bool im_id_is_tenant_kid(const char *kid, size_t n, const char **tenant);
/* Strip leading zero bytes of a DER INTEGER serial into the minimal kid form. */
im_err_t im_id_kid_from_serial(const uint8_t *serial, size_t n, uint8_t *kid, size_t cap,
                               size_t *kid_len);
/* Build "tenant-cmd-<tenant>" (NUL terminated, cap >= 48). */
im_err_t im_id_tenant_kid(const char *tenant, size_t n, char *out, size_t cap);

typedef enum {
    IM_TOPIC_TELEMETRY = 0,
    IM_TOPIC_EVENTS,
    IM_TOPIC_SHADOW_REPORTED,
    IM_TOPIC_CMD_ACK,
    IM_TOPIC_OTA_STATUS,
    IM_TOPIC_SHADOW_DESIRED,
    IM_TOPIC_CMD_REQ,
    IM_TOPIC_OTA_NOTIFY,
    IM_TOPIC_CONFIG,
    IM_TOPIC__COUNT
} im_topic_class_t;

typedef struct {
    const char *tenant; /* points into the parsed topic */
    const char *device;
    im_topic_class_t cls;
} im_topic_t;

const char *im_topic_suffix(im_topic_class_t cls);
uint8_t im_topic_message_type(im_topic_class_t cls);
bool im_topic_device_publishes(im_topic_class_t cls);   /* uplink topics */
bool im_topic_retained_allowed(im_topic_class_t cls);   /* shadow/desired, ota/notify, config */

/* im/v1/<tenant>/<device>/<suffix> (NUL terminated). ID_FORMAT on invalid ids. */
im_err_t im_topic_build(const char *tenant, const char *device, im_topic_class_t cls, char *out,
                        size_t cap, size_t *out_len);
/* TOPIC_FORMAT unless exactly one of the nine device topics (wildcards included). */
im_err_t im_topic_parse(const char *topic, size_t n, im_topic_t *out);
bool im_topic_device_may_publish(const char *topic, size_t n, const char *device_id);
bool im_topic_device_may_subscribe(const char *topic, size_t n, const char *device_id);

#ifdef __cplusplus
}
#endif

#endif /* IM_IDS_H */
