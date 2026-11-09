/*
 * IronMesh protocol core - OTA state machine (see im_ota.h).
 */
#include "im_ota.h"

#include <string.h>

#define REC_KEY "ota_rec"
#define REC_LEN 48u /* "OTA1" + campaign(36) + version_code(8) */

const char *im_ota_error_name(im_err_t err)
{
    switch (err) {
    case IM_OK:
        return NULL;
    case IM_ERR_COSE_TAG:
        return "unsigned";
    case IM_ERR_COSE_SIGNATURE:
        return "signature";
    case IM_ERR_COSE_UNKNOWN_KEY:
        return "untrusted_key";
    case IM_ERR_COSE_PQ_REQUIRED:
    case IM_ERR_MLDSA_NOT_AVAILABLE:
        return "pq_required";
    case IM_ERR_MF_PRODUCT:
        return "product";
    case IM_ERR_MF_ROLLBACK:
        return "downgrade";
    case IM_ERR_MF_MIN_VERSION:
        return "min_version";
    case IM_ERR_MF_SIZE_MISMATCH:
        return "image_size";
    case IM_ERR_MF_HASH_MISMATCH:
        return "image_hash";
    case IM_ERR_MF_NO_DELTA:
        return "delta";
    case IM_ERR_BUSY:
        return "busy";
    case IM_ERR_TIMEOUT:
        return "health_check";
    case IM_ERR_IO:
    case IM_ERR_STORAGE:
        return "download";
    default:
        if (err >= IM_ERR_DELTA_MAGIC && err <= IM_ERR_DELTA_TRAILING) {
            return "delta";
        }
        if (err >= IM_ERR_CBOR_SIZE && err <= IM_ERR_MF_FIELD) {
            return "manifest";
        }
        return "internal";
    }
}

const char *im_ota_state_name(int state)
{
    static const char *const names[8] = {"received",  "downloading", "verifying",  "applying",
                                         "rebooting", "success",     "rolled_back", "rejected"};
    if (state >= 0 && state < 8) {
        return names[state];
    }
    return state == IM_OTA_PENDING_HEALTH ? "pending_health" : "idle";
}

size_t im_ota_ctx_size(void)
{
    return sizeof(im_ota_t);
}

static void report(im_ota_t *o, int state, const char *error, const uint8_t *hash)
{
    o->state = state;
    if (o->cfg.pf.report != NULL) {
        unsigned pct = state == IM_OTA_DOWNLOADING ? o->last_pct
                       : (state >= IM_OTA_VERIFYING && state <= IM_OTA_SUCCESS) ? 100u
                                                                                 : 0u;
        o->cfg.pf.report(o->cfg.pf.ctx, o->campaign, state, pct, error, hash);
    }
}

static void stop_hash(im_ota_t *o)
{
    if (o->hashing) {
        im_crypto_sha256_free(&o->hash);
        o->hashing = false;
    }
}

static im_err_t reject(im_ota_t *o, im_err_t err, bool slot_open)
{
    stop_hash(o);
    if (o->is_delta) {
        im_delta_abort(&o->applier);
    }
    if (slot_open && o->cfg.pf.slot_abort != NULL) {
        o->cfg.pf.slot_abort(o->cfg.pf.ctx);
    }
    o->last_code = err;
    o->last_error = im_ota_error_name(err);
    report(o, IM_OTA_REJECTED, o->last_error, NULL);
    return err == IM_OK ? IM_ERR_STATE : err;
}

im_err_t im_ota_init(im_ota_t *o, const im_ota_config_t *cfg)
{
    if (o == NULL || cfg == NULL || cfg->product == NULL || cfg->work == NULL ||
        cfg->work_len < 4096u || cfg->pf.slot_write == NULL || cfg->pf.set_boot == NULL) {
        return IM_ERR_ARG;
    }
    memset(o, 0, sizeof *o);
    o->cfg = *cfg;
    o->state = IM_OTA_IDLE;
    return IM_OK;
}

bool im_ota_busy(const im_ota_t *o)
{
    return o->state == IM_OTA_DOWNLOADING || o->state == IM_OTA_VERIFYING ||
           o->state == IM_OTA_APPLYING || o->state == IM_OTA_REBOOTING;
}

static uint64_t be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8u; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

im_err_t im_ota_boot(im_ota_t *o, uint64_t now_ms, int *reason)
{
    uint8_t rec[REC_LEN];
    size_t n = 0;
    uint64_t vc;
    if (reason != NULL) {
        *reason = IM_BOOT_NORMAL;
    }
    if (o->cfg.kv.get == NULL ||
        o->cfg.kv.get(o->cfg.kv.ctx, REC_KEY, rec, sizeof rec, &n) != IM_OK || n != REC_LEN ||
        memcmp(rec, "OTA1", 4) != 0) {
        return IM_OK;
    }
    memcpy(o->campaign, rec + 4, 36);
    o->campaign[36] = '\0';
    vc = be64(rec + 40);
    if (vc == o->cfg.current_version_code) {
        o->state = IM_OTA_PENDING_HEALTH;
        o->health_deadline_ms = now_ms + IM_OTA_HEALTH_TIMEOUT_MS;
        if (reason != NULL) {
            *reason = IM_BOOT_OTA_APPLY;
        }
        return IM_OK;
    }
    /* the bootloader (or our health timeout) reverted to the previous image */
    if (o->cfg.kv.erase != NULL) {
        (void)o->cfg.kv.erase(o->cfg.kv.ctx, REC_KEY);
    }
    o->last_error = "health_check";
    report(o, IM_OTA_ROLLED_BACK, o->last_error, o->cfg.current_fw_hash);
    if (reason != NULL) {
        *reason = IM_BOOT_ROLLBACK;
    }
    return IM_OK;
}

static im_err_t delta_read(void *ctx, uint64_t off, uint8_t *buf, size_t len)
{
    im_ota_t *o = (im_ota_t *)ctx;
    if (o->cfg.pf.read_running == NULL || off > o->cfg.running_size ||
        len > o->cfg.running_size - off) {
        return IM_ERR_DELTA_BOUNDS;
    }
    return o->cfg.pf.read_running(o->cfg.pf.ctx, off, buf, len);
}

static im_err_t delta_write(void *ctx, uint64_t off, const uint8_t *d, size_t len)
{
    im_ota_t *o = (im_ota_t *)ctx;
    return o->cfg.pf.slot_write(o->cfg.pf.ctx, off, d, len);
}

im_err_t im_ota_on_notify(im_ota_t *o, const im_ota_notify_t *n)
{
    im_err_t err;
    if (o == NULL || n == NULL || n->campaign_id == NULL) {
        return IM_ERR_ARG;
    }
    if (im_ota_busy(o) || o->state == IM_OTA_PENDING_HEALTH) {
        return IM_ERR_BUSY; /* not reported: the running campaign keeps its status */
    }
    memset(o->campaign, 0, sizeof o->campaign);
    memcpy(o->campaign, n->campaign_id, 36);
    o->is_delta = false;
    memset(&o->applier, 0, sizeof o->applier);
    o->received = 0;
    o->last_pct = 0;
    o->last_error = NULL;
    report(o, IM_OTA_RECEIVED, NULL, NULL);
    if (n->manifest_len > sizeof o->manifest_buf) {
        return reject(o, IM_ERR_MF_STRUCTURE, false);
    }
    memcpy(o->manifest_buf, n->manifest, n->manifest_len);
    o->manifest_len = n->manifest_len;
    err = im_manifest_verify(o->manifest_buf, o->manifest_len, &o->cfg.keys, o->cfg.require_pq,
                             NULL, o->cfg.work, o->cfg.work_len, &o->mf, NULL);
    if (err == IM_OK) {
        err = im_manifest_precheck(&o->mf, o->cfg.current_version_code, o->cfg.product);
    }
    if (err == IM_OK && o->mf.image_size > o->cfg.slot_size) {
        err = IM_ERR_MF_SIZE_MISMATCH;
    }
    if (err == IM_OK && n->delta_from != NULL) {
        if (!o->mf.has_delta) {
            err = IM_ERR_MF_NO_DELTA;
        } else if (!im_ct_equal(n->delta_from, o->mf.delta_base_sha256, 32) ||
                   !im_ct_equal(o->mf.delta_base_sha256, o->cfg.current_fw_hash, 32)) {
            err = IM_ERR_DELTA_BASE_HASH;
        } else {
            o->is_delta = true;
        }
    }
    if (err != IM_OK) {
        return reject(o, err, false);
    }
    o->expected = o->is_delta ? o->mf.delta_patch_size : o->mf.image_size;
    if (o->cfg.pf.slot_begin != NULL) {
        err = o->cfg.pf.slot_begin(o->cfg.pf.ctx, o->mf.image_size);
        if (err != IM_OK) {
            return reject(o, IM_ERR_STORAGE, false);
        }
    }
    err = im_crypto_sha256_init(&o->hash);
    if (err != IM_OK) {
        return reject(o, err, true);
    }
    o->hashing = true;
    if (o->is_delta) {
        im_delta_io_t io;
        io.read_base = delta_read;
        io.write = delta_write;
        io.ctx = o;
        err = im_delta_init(&o->applier, &io, o->cfg.running_size, o->cfg.slot_size,
                            o->cfg.work, o->cfg.work_len);
        if (err != IM_OK) {
            o->is_delta = false;
            return reject(o, err, true);
        }
    }
    report(o, IM_OTA_DOWNLOADING, NULL, NULL);
    return IM_OK;
}

im_err_t im_ota_on_data(im_ota_t *o, const uint8_t *data, size_t len)
{
    im_err_t err;
    unsigned pct;
    if (o->state != IM_OTA_DOWNLOADING) {
        return IM_ERR_STATE;
    }
    if (len > o->expected - o->received) {
        return reject(o, IM_ERR_MF_SIZE_MISMATCH, true);
    }
    err = im_crypto_sha256_update(&o->hash, data, len);
    if (err == IM_OK) {
        err = o->is_delta ? im_delta_feed(&o->applier, data, len)
                          : o->cfg.pf.slot_write(o->cfg.pf.ctx, o->received, data, len);
    }
    if (err != IM_OK) {
        return reject(o, err, true);
    }
    o->received += len;
    pct = o->expected ? (unsigned)((o->received * 100u) / o->expected) : 100u;
    if (pct >= o->last_pct + 10u) {
        o->last_pct = pct - pct % 10u;
        report(o, IM_OTA_DOWNLOADING, NULL, NULL);
    }
    return IM_OK;
}

void im_ota_on_failure(im_ota_t *o, im_err_t err)
{
    if (o->state == IM_OTA_DOWNLOADING) {
        (void)reject(o, err == IM_OK ? IM_ERR_IO : err, true);
    }
}

im_err_t im_ota_on_complete(im_ota_t *o)
{
    uint8_t digest[32];
    uint8_t rec[REC_LEN];
    im_err_t err;
    if (o->state != IM_OTA_DOWNLOADING) {
        return IM_ERR_STATE;
    }
    report(o, IM_OTA_VERIFYING, NULL, NULL);
    o->hashing = false;
    err = im_crypto_sha256_finish(&o->hash, digest);
    if (err != IM_OK) {
        return reject(o, err, true);
    }
    if (o->is_delta) {
        err = im_manifest_accept_patch(&o->mf, o->received, digest, o->cfg.current_fw_hash);
        if (err == IM_OK) {
            err = im_delta_finish(&o->applier);
        }
        if (err == IM_OK && (!im_ct_equal(o->applier.target_sha256, o->mf.image_sha256, 32) ||
                             o->applier.target_size != o->mf.image_size ||
                             !im_ct_equal(o->applier.base_sha256, o->mf.delta_base_sha256, 32))) {
            err = IM_ERR_MF_HASH_MISMATCH;
        }
        if (err == IM_OK) {
            /* the applier proved SHA-256(output) == target_sha256 == manifest image_sha256 */
            err = im_manifest_accept_image(&o->mf, o->applier.produced, o->applier.target_sha256,
                                           o->cfg.current_version_code, o->cfg.product);
        }
    } else {
        err = im_manifest_accept_image(&o->mf, o->received, digest, o->cfg.current_version_code,
                                       o->cfg.product);
    }
    if (err == IM_OK && o->cfg.pf.slot_finish != NULL) {
        err = o->cfg.pf.slot_finish(o->cfg.pf.ctx);
        if (err != IM_OK) {
            err = IM_ERR_MF_HASH_MISMATCH; /* platform image verification (secure boot) failed */
        }
    }
    if (err != IM_OK) {
        return reject(o, err, true);
    }
    report(o, IM_OTA_APPLYING, NULL, NULL);
    memcpy(rec, "OTA1", 4);
    memcpy(rec + 4, o->campaign, 36);
    for (unsigned i = 0; i < 8u; i++) {
        rec[40 + i] = (uint8_t)(o->mf.version_code >> (56u - 8u * i));
    }
    if (o->cfg.kv.set != NULL && o->cfg.kv.set(o->cfg.kv.ctx, REC_KEY, rec, sizeof rec) != IM_OK) {
        return reject(o, IM_ERR_STORAGE, false);
    }
    err = o->cfg.pf.set_boot(o->cfg.pf.ctx, o->mf.version_code);
    if (err != IM_OK) {
        if (o->cfg.kv.erase != NULL) {
            (void)o->cfg.kv.erase(o->cfg.kv.ctx, REC_KEY);
        }
        return reject(o, IM_ERR_STORAGE, false);
    }
    report(o, IM_OTA_REBOOTING, NULL, NULL);
    return IM_OK;
}

im_err_t im_ota_health_ok(im_ota_t *o)
{
    im_err_t err = IM_OK;
    if (o->state != IM_OTA_PENDING_HEALTH) {
        return IM_ERR_STATE;
    }
    if (o->cfg.pf.mark_valid != NULL) {
        err = o->cfg.pf.mark_valid(o->cfg.pf.ctx);
    }
    if (err != IM_OK) {
        return err;
    }
    if (o->cfg.kv.erase != NULL) {
        (void)o->cfg.kv.erase(o->cfg.kv.ctx, REC_KEY);
    }
    report(o, IM_OTA_SUCCESS, NULL, o->cfg.current_fw_hash);
    return IM_OK;
}

im_err_t im_ota_tick(im_ota_t *o, uint64_t now_ms)
{
    if (o->state == IM_OTA_PENDING_HEALTH && now_ms >= o->health_deadline_ms) {
        o->state = IM_OTA_IDLE;
        o->last_error = "health_check";
        if (o->cfg.pf.rollback != NULL) {
            return o->cfg.pf.rollback(o->cfg.pf.ctx); /* reboots; im_ota_boot reports */
        }
        return IM_ERR_TIMEOUT;
    }
    return IM_OK;
}
