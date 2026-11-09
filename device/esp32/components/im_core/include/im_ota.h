/*
 * IronMesh protocol core - OTA state machine (contract §5 OtaStatus states, §6 A/B update).
 *
 *   notify -> verify manifest (signatures with the bundle keys, product, anti-rollback,
 *             min_version, slot size, delta base) -> DOWNLOADING
 *   data   -> streamed into the inactive slot (full image) or through the IMDELTA1 applier,
 *             hashing as it goes (no full-image buffering)
 *   done   -> VERIFYING (size + SHA-256 / accept_patch + applier END checks) -> APPLYING
 *             (set boot partition) -> REBOOTING (record persisted)
 *   boot   -> running version == record ? wait for health (120 s) : ROLLED_BACK
 *   health -> mark valid -> SUCCESS;  timeout -> rollback (bootloader reverts) -> ROLLED_BACK
 * Any failure before APPLYING is REJECTED and the active slot is never touched.
 */
#ifndef IM_OTA_H
#define IM_OTA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_crypto.h"
#include "im_delta.h"
#include "im_envelope.h"
#include "im_err.h"
#include "im_manifest.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Small persistent key-value store (NVS on the ESP32). get returns IM_ERR_NOT_FOUND if absent. */
typedef struct {
    im_err_t (*get)(void *ctx, const char *key, uint8_t *buf, size_t cap, size_t *len);
    im_err_t (*set)(void *ctx, const char *key, const uint8_t *data, size_t len);
    im_err_t (*erase)(void *ctx, const char *key);
    void *ctx;
} im_kv_t;

enum {
    IM_OTA_RECEIVED = 0,
    IM_OTA_DOWNLOADING = 1,
    IM_OTA_VERIFYING = 2,
    IM_OTA_APPLYING = 3,
    IM_OTA_REBOOTING = 4,
    IM_OTA_SUCCESS = 5,
    IM_OTA_ROLLED_BACK = 6,
    IM_OTA_REJECTED = 7,
    IM_OTA_IDLE = 100,
    IM_OTA_PENDING_HEALTH = 101
};

enum { IM_BOOT_NORMAL = 0, IM_BOOT_OTA_APPLY = 1, IM_BOOT_ROLLBACK = 2 };

#define IM_OTA_MANIFEST_MAX 4096u
#define IM_OTA_HEALTH_TIMEOUT_MS 120000u

typedef struct {
    im_err_t (*slot_begin)(void *ctx, uint64_t image_size); /* erase the inactive slot */
    im_err_t (*slot_write)(void *ctx, uint64_t off, const uint8_t *d, size_t n);
    im_err_t (*slot_finish)(void *ctx);                     /* close + platform image checks */
    void (*slot_abort)(void *ctx);
    im_err_t (*set_boot)(void *ctx, uint64_t version_code);  /* make the new slot boot once */
    im_err_t (*read_running)(void *ctx, uint64_t off, uint8_t *buf, size_t n);
    im_err_t (*mark_valid)(void *ctx);                      /* cancel rollback */
    im_err_t (*rollback)(void *ctx);                        /* revert to the previous slot */
    /* OtaStatus report (state per contract §5; error is a short reason or NULL). */
    void (*report)(void *ctx, const char *campaign_id, int state, unsigned progress,
                   const char *error, const uint8_t *fw_hash);
    void *ctx;
} im_ota_platform_t;

typedef struct {
    im_ota_platform_t pf;
    im_kv_t kv;
    const char *product;
    uint64_t current_version_code;
    uint8_t current_fw_hash[32];
    uint64_t running_size;
    uint64_t slot_size;
    bool require_pq;
    im_fw_keys_t keys;
    uint8_t *work; /* >= 4096 bytes */
    size_t work_len;
} im_ota_config_t;

typedef struct {
    im_ota_config_t cfg;
    int state;
    char campaign[37];
    uint8_t manifest_buf[IM_OTA_MANIFEST_MAX];
    size_t manifest_len;
    im_manifest_t mf;
    bool is_delta;
    uint64_t received;
    uint64_t expected;
    unsigned last_pct;
    bool hashing;
    im_sha256_ctx_t hash;
    im_delta_t applier;
    uint64_t health_deadline_ms;
    im_err_t last_code;
    const char *last_error;
} im_ota_t;

im_err_t im_ota_init(im_ota_t *ota, const im_ota_config_t *cfg);
/* After boot: detects a pending health check or a bootloader rollback. *reason gets IM_BOOT_*. */
im_err_t im_ota_boot(im_ota_t *ota, uint64_t now_ms, int *reason);
/* A verified OtaNotify arrived. IM_OK: start downloading notify->url; otherwise rejected. */
im_err_t im_ota_on_notify(im_ota_t *ota, const im_ota_notify_t *n);
im_err_t im_ota_on_data(im_ota_t *ota, const uint8_t *data, size_t len);
/* Download finished. IM_OK: the new slot is set to boot; the caller must reboot. */
im_err_t im_ota_on_complete(im_ota_t *ota);
void im_ota_on_failure(im_ota_t *ota, im_err_t err);
/* Health checks passed (MQTT connected + telemetry acked). */
im_err_t im_ota_health_ok(im_ota_t *ota);
/* Drives the health timeout; may call pf.rollback. */
im_err_t im_ota_tick(im_ota_t *ota, uint64_t now_ms);
bool im_ota_busy(const im_ota_t *ota);
/* Short reason string for an error (OtaStatus.error / DUT ota_state.error). */
const char *im_ota_error_name(im_err_t err);
const char *im_ota_state_name(int state);
size_t im_ota_ctx_size(void);

#ifdef __cplusplus
}
#endif

#endif /* IM_OTA_H */
