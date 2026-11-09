/*
 * IronMesh protocol core - device agent (see im_agent.h).
 */
#include "im_agent.h"

#include <string.h>

#include "im_attest.h"
#include "im_cose.h"
#include "im_hpke.h"
#include "im_ids.h"

#define KV_PROV "prov"
#define KV_BUNDLE "bundle"
#define KV_SEQ "seq"
#define KV_REPLAY "rpl"
#define RPL_REC (3u + IM_REPLAY_KID_MAX + 8u) /* used, dir, len, stream id, last seq */
#define SEQ_BLOCK 16u
#define BACKOFF_BASE_MS 1000u
#define BACKOFF_CAP_MS 300000u
#define RENEW_BASE_S 60u
#define RENEW_CAP_S (6u * 3600u)
#define EV_MAX 1024u

/* ------------------------------------------------------------------------------------------ */
/* small helpers                                                                               */
/* ------------------------------------------------------------------------------------------ */

static uint64_t now_s(const im_agent_t *a)
{
    return a->pf.now_unix ? a->pf.now_unix(a->pf.ctx) : 0;
}

static uint64_t mono(const im_agent_t *a)
{
    return a->pf.mono_ms ? a->pf.mono_ms(a->pf.ctx) : 0;
}

uint64_t im_agent_uptime_ms(const im_agent_t *a)
{
    return mono(a) - a->boot_ms;
}

static uint64_t rand_below(uint64_t bound)
{
    uint8_t r[8];
    uint64_t v = 0;
    if (bound == 0 || im_crypto_random(r, sizeof r) != IM_OK) {
        return 0;
    }
    for (unsigned i = 0; i < 8u; i++) {
        v = (v << 8) | r[i];
    }
    return v % bound;
}

static void copy_cstr(char *dst, size_t cap, const char *src)
{
    size_t n = src ? strlen(src) : 0;
    if (n >= cap) {
        n = cap - 1u;
    }
    if (n) {
        memcpy(dst, src, n);
    }
    dst[n] = '\0';
}

size_t im_agent_ctx_size(void)
{
    return sizeof(im_agent_t);
}

const char *im_agent_state_name(int state)
{
    static const char *const n[] = {"unprovisioned", "enrolling", "connecting", "connected",
                                    "offline",       "backoff",   "rebooting"};
    return (state >= 0 && state <= IM_ST_REBOOTING) ? n[state] : "unknown";
}

/* ---- events -------------------------------------------------------------------------------- */

typedef struct {
    char buf[EV_MAX];
    im_json_w_t w;
} ev_t;

static void ev_begin(im_agent_t *a, ev_t *e, const char *name)
{
    im_jw_init(&e->w, e->buf, sizeof e->buf);
    im_jw_obj(&e->w);
    im_jw_key(&e->w, "event");
    im_jw_cstr(&e->w, name);
    im_jw_key(&e->w, "at_ms");
    im_jw_u64(&e->w, im_agent_uptime_ms(a));
    im_jw_key(&e->w, "data");
    im_jw_obj(&e->w);
}

static void ev_end(im_agent_t *a, ev_t *e)
{
    size_t n;
    im_jw_obj_end(&e->w);
    im_jw_obj_end(&e->w);
    if (im_jw_finish(&e->w, &n) == IM_OK && a->pf.emit != NULL) {
        a->pf.emit(a->pf.ctx, e->buf, n);
    }
}

static void reject(im_agent_t *a, im_err_t code, const char *topic, size_t topic_len,
                   const char *detail)
{
    ev_t e;
    im_rejection_t *r = &a->rej[a->rej_next % IM_AGENT_REJECTIONS];
    size_t tl = topic_len < sizeof r->topic - 1u ? topic_len : sizeof r->topic - 1u;
    memset(r, 0, sizeof *r);
    r->at_ms = im_agent_uptime_ms(a);
    r->code = code;
    if (topic != NULL && im_utf8_valid((const uint8_t *)topic, tl)) {
        memcpy(r->topic, topic, tl);
    }
    if (detail != NULL) {
        size_t dl = strlen(detail);
        memcpy(r->detail, detail, dl < sizeof r->detail - 1u ? dl : sizeof r->detail - 1u);
    }
    a->rej_next++;
    a->rej_total++;
    if (code == IM_ERR_COSE_SIGNATURE || code == IM_ERR_ENV_UNKNOWN_KEY ||
        code == IM_ERR_ENV_TENANT || code == IM_ERR_ENV_KID) {
        a->auth_failures++;
    }
    ev_begin(a, &e, "message_rejected");
    im_jw_key(&e.w, "topic");
    im_jw_cstr(&e.w, r->topic);
    im_jw_key(&e.w, "code");
    im_jw_cstr(&e.w, im_err_str(code));
    ev_end(a, &e);
}

size_t im_agent_rejections(const im_agent_t *a, uint64_t since_ms, const im_rejection_t **out,
                           size_t max)
{
    size_t n = 0;
    uint32_t avail = a->rej_total < IM_AGENT_REJECTIONS ? a->rej_total : IM_AGENT_REJECTIONS;
    for (uint32_t i = 0; i < avail && n < max; i++) {
        const im_rejection_t *r = &a->rej[(a->rej_next - avail + i) % IM_AGENT_REJECTIONS];
        if (r->at_ms >= since_ms) {
            out[n++] = r;
        }
    }
    return n;
}

/* ---- persistence --------------------------------------------------------------------------- */

static void put64(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8u; i++) {
        p[i] = (uint8_t)(v >> (56u - 8u * i));
    }
}

static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8u; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

static im_err_t kv_set(im_agent_t *a, const char *k, const uint8_t *d, size_t n)
{
    return a->pf.kv.set ? a->pf.kv.set(a->pf.kv.ctx, k, d, n) : IM_ERR_STORAGE;
}

static im_err_t kv_get(im_agent_t *a, const char *k, uint8_t *d, size_t cap, size_t *n)
{
    return a->pf.kv.get ? a->pf.kv.get(a->pf.kv.ctx, k, d, cap, n) : IM_ERR_NOT_FOUND;
}

static im_err_t save_prov(im_agent_t *a)
{
    uint8_t b[37];
    memset(b, 0, sizeof b);
    b[0] = (uint8_t)a->kid_len;
    memcpy(b + 1, a->kid, a->kid_len);
    put64(b + 21, a->cert_not_before);
    put64(b + 29, a->cert_not_after);
    return kv_set(a, KV_PROV, b, sizeof b);
}

static im_err_t replay_persist(void *ctx, const im_replay_entry_t *entry)
{
    im_agent_t *a = (im_agent_t *)ctx;
    uint8_t b[IM_REPLAY_MEM_SLOTS * RPL_REC];
    (void)entry;
    for (unsigned i = 0; i < IM_REPLAY_MEM_SLOTS; i++) {
        const im_replay_entry_t *e = &a->replay.e[i];
        uint8_t *p = b + i * RPL_REC;
        p[0] = e->used ? 1u : 0u;
        p[1] = e->dir;
        p[2] = e->kid_len;
        memcpy(p + 3, e->kid, IM_REPLAY_KID_MAX);
        put64(p + 3 + IM_REPLAY_KID_MAX, e->last_seq);
    }
    return kv_set(a, KV_REPLAY, b, sizeof b);
}

static void load_replay(im_agent_t *a)
{
    uint8_t b[IM_REPLAY_MEM_SLOTS * RPL_REC];
    size_t n = 0;
    if (kv_get(a, KV_REPLAY, b, sizeof b, &n) != IM_OK || n != sizeof b) {
        return;
    }
    for (unsigned i = 0; i < IM_REPLAY_MEM_SLOTS; i++) {
        im_replay_entry_t *e = &a->replay.e[i];
        const uint8_t *p = b + i * RPL_REC;
        if (p[2] > IM_REPLAY_KID_MAX) {
            continue;
        }
        e->used = p[0] != 0;
        e->dir = p[1];
        e->kid_len = p[2];
        memcpy(e->kid, p + 3, IM_REPLAY_KID_MAX);
        e->last_seq = get64(p + 3 + IM_REPLAY_KID_MAX);
    }
}

/* Strictly increasing across reboots: values up to the persisted high-water mark may have been
 * used, so a restart continues above it. The mark is persisted *before* a value is used. */
static im_err_t next_seq(im_agent_t *a, uint64_t *seq)
{
    if (a->seq_out >= a->seq_reserved) {
        uint8_t b[8];
        uint64_t hwm = a->seq_out + SEQ_BLOCK;
        put64(b, hwm);
        IM_TRY(kv_set(a, KV_SEQ, b, sizeof b));
        a->seq_reserved = hwm;
    }
    *seq = a->seq_out++;
    return IM_OK;
}

/* ---- topics --------------------------------------------------------------------------------- */

static im_err_t topic_for(const im_agent_t *a, im_topic_class_t cls, char *out, size_t cap)
{
    return im_topic_build(a->cfg.tenant_id, a->cfg.device_id, cls, out, cap, NULL);
}

static im_pending_pub_t *pend_alloc(im_agent_t *a)
{
    for (unsigned i = 0; i < sizeof a->pend / sizeof a->pend[0]; i++) {
        if (a->pend[i].kind == 0) {
            return &a->pend[i];
        }
    }
    return NULL;
}

static im_pending_pub_t *pend_find(im_agent_t *a, uint16_t id)
{
    for (unsigned i = 0; i < sizeof a->pend / sizeof a->pend[0]; i++) {
        if (a->pend[i].kind != 0 && a->pend[i].msg_id == id) {
            return &a->pend[i];
        }
    }
    return NULL;
}

static im_err_t publish(im_agent_t *a, const char *topic, const uint8_t *p, size_t n, int qos,
                        bool retain, uint8_t kind, uint64_t seq)
{
    uint16_t id = 0;
    im_pending_pub_t *slot;
    if (a->state != IM_ST_CONNECTED || a->pf.mqtt_publish == NULL) {
        return IM_ERR_STATE;
    }
    slot = qos > 0 ? pend_alloc(a) : NULL;
    if (qos > 0 && slot == NULL) {
        return IM_ERR_BUSY;
    }
    IM_TRY(a->pf.mqtt_publish(a->pf.ctx, topic, p, n, qos, retain, &id));
    if (slot != NULL) {
        memset(slot, 0, sizeof *slot);
        slot->msg_id = id;
        slot->kind = kind;
        slot->seq = seq;
        copy_cstr(slot->topic, sizeof slot->topic, topic);
    }
    return IM_OK;
}

/* Sign payload (in a->payload) as an uplink envelope into a->tx. */
static im_err_t sign_uplink(im_agent_t *a, size_t payload_len, size_t *out_len)
{
    const uint8_t *kid = a->provisioned ? a->kid : a->cfg.bootstrap_kid;
    size_t kid_len = a->provisioned ? a->kid_len : a->cfg.bootstrap_kid_len;
    return im_env_sign_uplink(a->pf.identity, kid, kid_len, a->payload, payload_len, a->tx,
                              sizeof a->tx, out_len);
}

/* ------------------------------------------------------------------------------------------ */
/* OTA glue                                                                                    */
/* ------------------------------------------------------------------------------------------ */

#define OTA_FWD(name, ...) a->pf.ota.name ? a->pf.ota.name(a->pf.ota.ctx, __VA_ARGS__) : IM_OK

static im_err_t ota_begin(void *ctx, uint64_t size)
{
    im_agent_t *a = (im_agent_t *)ctx;
    return OTA_FWD(slot_begin, size);
}

static im_err_t ota_write(void *ctx, uint64_t off, const uint8_t *d, size_t n)
{
    im_agent_t *a = (im_agent_t *)ctx;
    return a->pf.ota.slot_write ? a->pf.ota.slot_write(a->pf.ota.ctx, off, d, n) : IM_ERR_IO;
}

static im_err_t ota_finish(void *ctx)
{
    im_agent_t *a = (im_agent_t *)ctx;
    return a->pf.ota.slot_finish ? a->pf.ota.slot_finish(a->pf.ota.ctx) : IM_OK;
}

static void ota_abort(void *ctx)
{
    im_agent_t *a = (im_agent_t *)ctx;
    if (a->pf.ota.slot_abort) {
        a->pf.ota.slot_abort(a->pf.ota.ctx);
    }
}

static im_err_t ota_set_boot(void *ctx, uint64_t vc)
{
    im_agent_t *a = (im_agent_t *)ctx;
    return a->pf.ota.set_boot ? a->pf.ota.set_boot(a->pf.ota.ctx, vc) : IM_ERR_STORAGE;
}

static im_err_t ota_read(void *ctx, uint64_t off, uint8_t *buf, size_t n)
{
    im_agent_t *a = (im_agent_t *)ctx;
    return a->pf.ota.read_running ? a->pf.ota.read_running(a->pf.ota.ctx, off, buf, n)
                                  : IM_ERR_IO;
}

static im_err_t ota_valid(void *ctx)
{
    im_agent_t *a = (im_agent_t *)ctx;
    return a->pf.ota.mark_valid ? a->pf.ota.mark_valid(a->pf.ota.ctx) : IM_OK;
}

static im_err_t ota_rollback(void *ctx)
{
    im_agent_t *a = (im_agent_t *)ctx;
    return a->pf.ota.rollback ? a->pf.ota.rollback(a->pf.ota.ctx) : IM_ERR_UNSUPPORTED;
}

static void ota_report(void *ctx, const char *campaign, int state, unsigned progress,
                       const char *error, const uint8_t *fw_hash)
{
    im_agent_t *a = (im_agent_t *)ctx;
    ev_t e;
    char topic[IM_TOPIC_MAX_LEN];
    im_cbor_enc_t enc;
    uint64_t seq;
    size_t n;
    ev_begin(a, &e, "ota_state");
    im_jw_key(&e.w, "campaign_id");
    im_jw_cstr(&e.w, campaign);
    im_jw_key(&e.w, "state");
    im_jw_cstr(&e.w, im_ota_state_name(state));
    im_jw_key(&e.w, "error");
    im_jw_cstr(&e.w, error);
    ev_end(a, &e);
    if (a->state != IM_ST_CONNECTED || !im_id_is_uuid4(campaign, strlen(campaign)) ||
        next_seq(a, &seq) != IM_OK) {
        return; /* status is best effort; the cloud also sees the version in telemetry */
    }
    im_cbor_enc_init(&enc, a->payload, sizeof a->payload);
    im_env_payload_begin(&enc, seq, now_s(a), IM_MSG_OTA_STATUS, false);
    im_body_ota_status(&enc, campaign, (uint64_t)state, progress > 100u ? 100u : progress, error,
                       fw_hash);
    if (im_env_payload_end(&enc, NULL, &n) == IM_OK && sign_uplink(a, n, &n) == IM_OK &&
        topic_for(a, IM_TOPIC_OTA_STATUS, topic, sizeof topic) == IM_OK) {
        (void)publish(a, topic, a->tx, n, 1, false, 4, seq);
    }
}

static im_err_t ota_setup(im_agent_t *a)
{
    im_ota_config_t oc;
    memset(&oc, 0, sizeof oc);
    oc.pf.slot_begin = ota_begin;
    oc.pf.slot_write = ota_write;
    oc.pf.slot_finish = ota_finish;
    oc.pf.slot_abort = ota_abort;
    oc.pf.set_boot = ota_set_boot;
    oc.pf.read_running = ota_read;
    oc.pf.mark_valid = ota_valid;
    oc.pf.rollback = ota_rollback;
    oc.pf.report = ota_report;
    oc.pf.ctx = a;
    oc.kv = a->pf.kv;
    oc.product = a->cfg.product;
    oc.current_version_code = a->cfg.fw_version_code;
    memcpy(oc.current_fw_hash, a->cfg.fw_hash, 32);
    oc.running_size = a->cfg.fw_size;
    oc.slot_size = a->cfg.slot_size;
    oc.require_pq = a->cfg.require_pq;
    oc.keys.n = a->n_fw_keys;
    for (size_t i = 0; i < a->n_fw_keys; i++) {
        oc.keys.key[i] = a->fw_keys[i];
        oc.keys.len[i] = a->fw_key_len[i];
    }
    oc.work = a->ota_work;
    oc.work_len = sizeof a->ota_work;
    if (a->ota.state != 0 && a->ota.cfg.product != NULL) {
        /* keep the running state machine, refresh the trusted keys only */
        a->ota.cfg.keys = oc.keys;
        return IM_OK;
    }
    return im_ota_init(&a->ota, &oc);
}

/* ------------------------------------------------------------------------------------------ */
/* Bundle                                                                                      */
/* ------------------------------------------------------------------------------------------ */

static im_err_t bundle_keys(im_agent_t *a, const im_cbor_val_t *arr, bool commit, size_t *count)
{
    im_cbor_iter_t iter;
    im_cbor_val_t it;
    size_t nk = 0;
    IM_TRY(im_cbor_iter_init(&iter, arr));
    while (im_cbor_iter_next(&iter, &it) == IM_OK) {
        if (it.type != IM_CBOR_BSTR ||
            (it.arg != IM_ED25519_PUB_LEN && it.arg != IM_MLDSA65_PUB_LEN)) {
            return IM_ERR_ENV_FIELD;
        }
        if (nk < IM_AGENT_FW_KEYS) {
            if (commit) {
                memcpy(a->fw_keys[nk], it.data, (size_t)it.arg);
                a->fw_key_len[nk] = (size_t)it.arg;
            }
            nk++;
        }
    }
    *count = nk;
    return IM_OK;
}

static im_err_t bundle_pins(im_agent_t *a, const im_cbor_val_t *arr, bool commit, size_t *count)
{
    im_cbor_iter_t iter;
    im_cbor_val_t it;
    size_t np = 0;
    if (arr->arg == 0) {
        return IM_ERR_ENV_FIELD;
    }
    IM_TRY(im_cbor_iter_init(&iter, arr));
    while (im_cbor_iter_next(&iter, &it) == IM_OK) {
        if (it.type != IM_CBOR_BSTR || it.arg != 32u) {
            return IM_ERR_ENV_FIELD;
        }
        if (np < IM_AGENT_PINS) {
            if (commit) {
                memcpy(a->pins[np], it.data, 32);
            }
            np++;
        }
    }
    *count = np;
    return IM_OK;
}

im_err_t im_agent_load_bundle(im_agent_t *a, const uint8_t *bundle, size_t len)
{
    im_sign1_t s;
    im_pubkey_t k;
    im_cbor_val_t m;
    im_cbor_val_t tenant;
    im_cbor_val_t keys;
    im_cbor_val_t host;
    im_cbor_val_t port;
    im_cbor_val_t pins;
    size_t nk;
    size_t np;

    if (a == NULL || bundle == NULL || len > IM_AGENT_BUNDLE_MAX || bundle == a->rx) {
        return IM_ERR_ARG;
    }
    /* COSE_Sign1 by the PKI bundle key (kid "pki-bundle", EdDSA), verified with the key that
     * was baked into the firmware at the factory. a->rx is the Sig_structure work buffer. */
    IM_TRY(im_cose_sign1_decode(bundle, len, NULL, &s));
    IM_TRY(im_pubkey_ed25519(&k, a->cfg.bundle_pubkey, 32));
    IM_TRY(im_cose_sign1_verify(&s, &k, a->rx, sizeof a->rx));
    IM_TRY(im_cbor_decode(s.payload, s.payload_len, NULL, &m));
    if (m.type != IM_CBOR_MAP) {
        return IM_ERR_CBOR_TYPE;
    }
    if (im_cbor_map_get_int(&m, 1, &tenant) != IM_OK || tenant.type != IM_CBOR_BSTR ||
        (tenant.arg != 32u && tenant.arg != 0) ||
        im_cbor_map_get_int(&m, 2, &keys) != IM_OK || keys.type != IM_CBOR_ARRAY ||
        im_cbor_map_get_int(&m, 3, &host) != IM_OK || host.type != IM_CBOR_TSTR ||
        host.arg == 0 || host.arg >= IM_AGENT_HOST_MAX ||
        im_cbor_map_get_int(&m, 4, &port) != IM_OK || port.type != IM_CBOR_UINT ||
        port.arg == 0 || port.arg > 65535u || im_cbor_map_get_int(&m, 5, &pins) != IM_OK ||
        pins.type != IM_CBOR_ARRAY) {
        return IM_ERR_ENV_FIELD;
    }
    /* validate everything first, then commit */
    IM_TRY(bundle_keys(a, &keys, false, &nk));
    IM_TRY(bundle_pins(a, &pins, false, &np));
    IM_TRY(bundle_keys(a, &keys, true, &a->n_fw_keys));
    IM_TRY(bundle_pins(a, &pins, true, &a->n_pins));
    a->have_bundle = tenant.arg == 32u;
    if (a->have_bundle) {
        memcpy(a->tenant_pub, tenant.data, 32);
    }
    memcpy(a->broker_host, host.data, (size_t)host.arg);
    a->broker_host[host.arg] = '\0';
    a->broker_port = (uint16_t)port.arg;
    return ota_setup(a);
}

/* ------------------------------------------------------------------------------------------ */
/* Lifecycle                                                                                   */
/* ------------------------------------------------------------------------------------------ */

im_err_t im_agent_init(im_agent_t *a, const im_agent_config_t *cfg, const im_agent_platform_t *pf)
{
    if (a == NULL || cfg == NULL || pf == NULL || pf->identity == NULL ||
        cfg->device_id == NULL || cfg->tenant_id == NULL || cfg->product == NULL ||
        cfg->fw_version == NULL ||
        !im_id_is_device_id(cfg->device_id, strlen(cfg->device_id)) ||
        !im_id_is_uuid4(cfg->tenant_id, strlen(cfg->tenant_id)) ||
        !im_id_is_semver(cfg->fw_version, strlen(cfg->fw_version)) ||
        !im_id_is_device_kid(cfg->bootstrap_kid, cfg->bootstrap_kid_len)) {
        return IM_ERR_ARG;
    }
    memset(a, 0, sizeof *a);
    a->cfg = *cfg;
    a->pf = *pf;
    a->state = IM_ST_UNPROVISIONED;
    a->net_up = true;
    im_replay_mem_init(&a->replay);
    a->replay.persist = replay_persist;
    a->replay.persist_ctx = a;
    im_cmd_cache_init(&a->cmds);
    return IM_OK;
}

static const char *reboot_reason_name(int r)
{
    switch (r) {
    case IM_REBOOT_OTA_APPLY:
        return "ota_apply";
    case IM_REBOOT_ROLLBACK:
        return "rollback";
    case IM_REBOOT_WATCHDOG:
        return "watchdog";
    default:
        return "requested";
    }
}

static void schedule_renewal(im_agent_t *a)
{
    uint64_t life = a->cert_not_after > a->cert_not_before ? a->cert_not_after - a->cert_not_before
                                                           : 0;
    a->renew_at = a->cert_not_before + life / 2u + rand_below(life / 10u + 1u);
    a->renew_attempt = 0;
}

im_err_t im_agent_start(im_agent_t *a)
{
    uint8_t b[37];
    size_t n = 0;
    int ota_reason = IM_BOOT_NORMAL;
    int reason;
    ev_t e;

    a->boot_ms = mono(a);
    /* outbound sequence: continue above the persisted high-water mark */
    if (kv_get(a, KV_SEQ, b, 8, &n) == IM_OK && n == 8) {
        a->seq_out = get64(b) + 1u;
    } else {
        a->seq_out = 1;
    }
    a->seq_reserved = a->seq_out;
    load_replay(a);
    if (kv_get(a, KV_PROV, b, sizeof b, &n) == IM_OK && n == sizeof b && b[0] >= 1 &&
        b[0] <= 20 && im_id_is_device_kid(b + 1, b[0])) {
        a->kid_len = b[0];
        memcpy(a->kid, b + 1, a->kid_len);
        a->cert_not_before = get64(b + 21);
        a->cert_not_after = get64(b + 29);
        a->provisioned = true;
        schedule_renewal(a);
    }
    if (kv_get(a, KV_BUNDLE, a->work, sizeof a->work, &n) == IM_OK) {
        if (im_agent_load_bundle(a, a->work, n) != IM_OK) {
            a->provisioned = false; /* tampered bundle: re-enroll */
        }
    }
    IM_TRY(ota_setup(a));
    a->rb_ok = im_rb_init(&a->rb, &a->pf.storage,
                          a->cfg.ringbuf_slot_size ? a->cfg.ringbuf_slot_size : 512u) == IM_OK;
    (void)im_ota_boot(&a->ota, mono(a), &ota_reason);
    a->state = a->provisioned ? IM_ST_OFFLINE : IM_ST_UNPROVISIONED;
    a->started = true;
    reason = ota_reason == IM_BOOT_OTA_APPLY  ? IM_REBOOT_OTA_APPLY
             : ota_reason == IM_BOOT_ROLLBACK ? IM_REBOOT_ROLLBACK
                                              : a->cfg.boot_reason;
    if (reason != IM_REBOOT_POWER_ON) {
        ev_begin(a, &e, "rebooted");
        im_jw_key(&e.w, "active_slot");
        im_jw_cstr(&e.w, a->cfg.active_slot);
        im_jw_key(&e.w, "version_code");
        im_jw_u64(&e.w, a->cfg.fw_version_code);
        im_jw_key(&e.w, "reason");
        im_jw_cstr(&e.w, reboot_reason_name(reason));
        ev_end(a, &e);
    }
    return IM_OK;
}

/* ------------------------------------------------------------------------------------------ */
/* Enrollment                                                                                  */
/* ------------------------------------------------------------------------------------------ */

im_err_t im_agent_enroll(im_agent_t *a, bool renew)
{
    if (a->pf.est_enroll == NULL) {
        return IM_ERR_UNSUPPORTED;
    }
    if (renew && !a->provisioned) {
        return IM_ERR_STATE;
    }
    if (a->renewing) {
        return IM_ERR_BUSY;
    }
    a->renewing = true;
    if (!renew) {
        a->state = IM_ST_ENROLLING;
    }
    if (a->pf.est_enroll(a->pf.ctx, renew) != IM_OK) {
        a->renewing = false;
        return IM_ERR_IO;
    }
    return IM_OK;
}

im_err_t im_agent_attestation(im_agent_t *a, const uint8_t nonce[32], const uint8_t *csr_der,
                              size_t csr_len, uint8_t *out, size_t cap, size_t *out_len)
{
    /* The attestation is signed by the TLS client key (contract section 3): the operational key
     * while its certificate is valid (simplereenroll), the bootstrap key on first enrollment and
     * after expiry (simpleenroll) - the same rule im_keyslot_plan() applies to key slots. */
    bool op = a->provisioned && now_s(a) < a->cert_not_after;
    const uint8_t *kid = op ? a->kid : a->cfg.bootstrap_kid;
    size_t kid_len = op ? a->kid_len : a->cfg.bootstrap_kid_len;
    uint64_t seq;
    IM_TRY(next_seq(a, &seq));
    return im_attest_build(a->pf.identity, kid, kid_len, seq, now_s(a), nonce, csr_der, csr_len,
                           a->cfg.fw_hash, a->cfg.fw_version, out, cap, out_len);
}

im_err_t im_agent_on_enrolled(im_agent_t *a, const uint8_t *serial, size_t serial_len,
                              uint64_t not_before, uint64_t not_after, const uint8_t *bundle,
                              size_t bundle_len)
{
    uint8_t kid[20];
    size_t kid_len;
    uint8_t old[20];
    size_t old_len = a->kid_len;
    bool was = a->provisioned;
    ev_t e;
    a->renewing = false;
    IM_TRY(im_id_kid_from_serial(serial, serial_len, kid, sizeof kid, &kid_len));
    if (bundle != NULL && bundle_len > 0) {
        IM_TRY(im_agent_load_bundle(a, bundle, bundle_len));
        IM_TRY(kv_set(a, KV_BUNDLE, bundle, bundle_len));
    } else if (!a->have_bundle) {
        return IM_ERR_STATE; /* first enrollment must deliver the trust bundle */
    }
    memcpy(old, a->kid, sizeof old);
    memcpy(a->kid, kid, kid_len);
    a->kid_len = kid_len;
    a->cert_not_before = not_before;
    a->cert_not_after = not_after;
    a->provisioned = true;
    IM_TRY(save_prov(a));
    schedule_renewal(a);
    if (a->state == IM_ST_UNPROVISIONED || a->state == IM_ST_ENROLLING) {
        a->state = IM_ST_OFFLINE;
    }
    if (was) {
        ev_begin(a, &e, "cert_renewed");
        im_jw_key(&e.w, "old_serial_hex");
        im_jw_hex(&e.w, old, old_len);
        im_jw_key(&e.w, "new_serial_hex");
        im_jw_hex(&e.w, a->kid, a->kid_len);
    } else {
        ev_begin(a, &e, "enrolled");
        im_jw_key(&e.w, "cert_serial_hex");
        im_jw_hex(&e.w, a->kid, a->kid_len);
        im_jw_key(&e.w, "se_type");
        im_jw_cstr(&e.w, a->pf.identity->se_type);
    }
    im_jw_key(&e.w, "not_after");
    im_jw_u64(&e.w, not_after);
    ev_end(a, &e);
    return IM_OK;
}

void im_agent_on_enroll_failed(im_agent_t *a, int http_status, const char *reason)
{
    ev_t e;
    bool renew = a->provisioned;
    uint64_t delay;
    a->renewing = false;
    if (a->state == IM_ST_ENROLLING) {
        a->state = a->provisioned ? IM_ST_OFFLINE : IM_ST_UNPROVISIONED;
    }
    if (renew) {
        /* exponential retry until expiry (contract §2) */
        delay = (uint64_t)RENEW_BASE_S << (a->renew_attempt < 12u ? a->renew_attempt : 12u);
        if (delay > RENEW_CAP_S) {
            delay = RENEW_CAP_S;
        }
        a->renew_attempt++;
        a->renew_at = now_s(a) + delay;
    }
    ev_begin(a, &e, renew ? "renew_failed" : "enroll_failed");
    im_jw_key(&e.w, "http_status");
    im_jw_i64(&e.w, http_status);
    im_jw_key(&e.w, "reason");
    im_jw_cstr(&e.w, reason ? reason : "unknown");
    ev_end(a, &e);
}

/* ------------------------------------------------------------------------------------------ */
/* Connection                                                                                  */
/* ------------------------------------------------------------------------------------------ */

static im_err_t start_connect(im_agent_t *a)
{
    if (a->pf.mqtt_connect == NULL) {
        return IM_ERR_UNSUPPORTED;
    }
    a->state = IM_ST_CONNECTING;
    if (a->pf.mqtt_connect(a->pf.ctx, a->broker_host, a->broker_port, a->cfg.device_id) !=
        IM_OK) {
        im_agent_on_connect_failed(a, "network");
        return IM_ERR_IO;
    }
    return IM_OK;
}

im_err_t im_agent_connect(im_agent_t *a)
{
    if (!a->provisioned || a->broker_port == 0) {
        return IM_ERR_STATE;
    }
    if (a->state == IM_ST_CONNECTED || a->state == IM_ST_CONNECTING) {
        return IM_OK;
    }
    a->want_connected = true;
    a->backoff_attempt = 0;
    if (!a->net_up) {
        im_agent_on_connect_failed(a, "network");
        return IM_OK;
    }
    return start_connect(a);
}

im_err_t im_agent_disconnect(im_agent_t *a)
{
    a->want_connected = false;
    if (a->state == IM_ST_CONNECTED || a->state == IM_ST_CONNECTING) {
        if (a->pf.mqtt_disconnect) {
            (void)a->pf.mqtt_disconnect(a->pf.ctx);
        }
        im_agent_on_disconnected(a, "requested", 0);
    }
    if (a->state == IM_ST_BACKOFF) {
        a->state = IM_ST_OFFLINE;
    }
    return IM_OK;
}

void im_agent_set_net(im_agent_t *a, bool up)
{
    a->net_up = up;
    if (!up && (a->state == IM_ST_CONNECTED || a->state == IM_ST_CONNECTING)) {
        if (a->pf.mqtt_disconnect) {
            (void)a->pf.mqtt_disconnect(a->pf.ctx);
        }
        im_agent_on_disconnected(a, "network", 0);
    }
    if (up && a->want_connected && a->state != IM_ST_CONNECTED &&
        a->state != IM_ST_CONNECTING) {
        a->backoff_attempt = 0;
        (void)start_connect(a);
    }
}

static void schedule_backoff(im_agent_t *a)
{
    uint64_t ceil = (uint64_t)BACKOFF_BASE_MS << (a->backoff_attempt < 20u ? a->backoff_attempt : 20u);
    if (ceil > BACKOFF_CAP_MS) {
        ceil = BACKOFF_CAP_MS;
    }
    a->backoff_attempt++;
    a->next_connect_ms = mono(a) + rand_below(ceil + 1u); /* full jitter */
    a->state = IM_ST_BACKOFF;
}

static void flush_next(im_agent_t *a);

void im_agent_on_connected(im_agent_t *a, const char *tls_version, const char *alpn,
                           bool session_present, bool resumed)
{
    static const im_topic_class_t subs[4] = {IM_TOPIC_SHADOW_DESIRED, IM_TOPIC_CMD_REQ,
                                             IM_TOPIC_OTA_NOTIFY, IM_TOPIC_CONFIG};
    ev_t e;
    char topic[IM_TOPIC_MAX_LEN];
    a->state = IM_ST_CONNECTED;
    a->backoff_attempt = 0;
    memset(a->pend, 0, sizeof a->pend);
    a->flushing = false;
    for (unsigned i = 0; i < 4u; i++) {
        uint16_t id;
        if (topic_for(a, subs[i], topic, sizeof topic) == IM_OK && a->pf.mqtt_subscribe) {
            (void)a->pf.mqtt_subscribe(a->pf.ctx, topic, &id);
        }
    }
    ev_begin(a, &e, "connected");
    im_jw_key(&e.w, "broker");
    im_jw_cstr(&e.w, a->broker_host);
    im_jw_key(&e.w, "tls_version");
    im_jw_cstr(&e.w, tls_version ? tls_version : "TLSv1.3");
    im_jw_key(&e.w, "alpn");
    im_jw_cstr(&e.w, alpn ? alpn : "mqtt");
    im_jw_key(&e.w, "session_present");
    im_jw_bool(&e.w, session_present);
    im_jw_key(&e.w, "resumed");
    im_jw_bool(&e.w, resumed);
    ev_end(a, &e);
    flush_next(a);
    if (a->ota.state == IM_OTA_PENDING_HEALTH) {
        uint64_t f;
        uint64_t l;
        (void)im_agent_send_telemetry(a, 1, &f, &l); /* health probe */
    }
}

void im_agent_on_connect_failed(im_agent_t *a, const char *reason)
{
    ev_t e;
    ev_begin(a, &e, "connect_failed");
    im_jw_key(&e.w, "reason");
    im_jw_cstr(&e.w, reason ? reason : "network");
    ev_end(a, &e);
    if (a->want_connected) {
        schedule_backoff(a);
    } else {
        a->state = a->provisioned ? IM_ST_OFFLINE : IM_ST_UNPROVISIONED;
    }
}

void im_agent_on_disconnected(im_agent_t *a, const char *reason, int reason_code)
{
    ev_t e;
    bool was = a->state == IM_ST_CONNECTED || a->state == IM_ST_CONNECTING;
    memset(a->pend, 0, sizeof a->pend);
    a->flushing = false;
    if (!was) {
        return;
    }
    ev_begin(a, &e, "disconnected");
    im_jw_key(&e.w, "reason");
    im_jw_cstr(&e.w, reason ? reason : "network");
    im_jw_key(&e.w, "reason_code");
    im_jw_i64(&e.w, reason_code);
    ev_end(a, &e);
    if (a->want_connected) {
        schedule_backoff(a);
    } else {
        a->state = IM_ST_OFFLINE;
    }
}

/* ------------------------------------------------------------------------------------------ */
/* Telemetry and the offline buffer                                                            */
/* ------------------------------------------------------------------------------------------ */

static im_err_t build_telemetry(im_agent_t *a, uint64_t seq, size_t *out_len)
{
    im_telemetry_t t;
    im_cbor_enc_t enc;
    size_t n;
    memset(&t, 0, sizeof t);
    if (a->pf.sample) {
        a->pf.sample(a->pf.ctx, &t);
    }
    memcpy(t.fw_hash, a->cfg.fw_hash, 32);
    t.fw_version = a->cfg.fw_version;
    t.auth_failures = a->auth_failures;
    t.uptime_s = im_agent_uptime_ms(a) / 1000u;
    im_cbor_enc_init(&enc, a->payload, sizeof a->payload);
    im_env_payload_begin(&enc, seq, now_s(a), IM_MSG_TELEMETRY, false);
    im_body_telemetry(&enc, &t);
    IM_TRY(im_env_payload_end(&enc, NULL, &n));
    return sign_uplink(a, n, out_len);
}

static bool seq_of_envelope(const uint8_t *p, size_t n, uint64_t *seq)
{
    im_sign1_t s;
    im_env_msg_t m;
    if (im_cose_sign1_decode(p, n, NULL, &s) != IM_OK ||
        im_env_decode_payload(s.payload, s.payload_len, NULL, &m) != IM_OK) {
        return false;
    }
    *seq = m.seq;
    return true;
}

static void flush_done(im_agent_t *a)
{
    ev_t e;
    if (a->flush_count == 0) {
        return;
    }
    ev_begin(a, &e, "buffer_flushed");
    im_jw_key(&e.w, "count");
    im_jw_u64(&e.w, a->flush_count);
    im_jw_key(&e.w, "first_seq");
    im_jw_u64(&e.w, a->flush_first);
    im_jw_key(&e.w, "last_seq");
    im_jw_u64(&e.w, a->flush_last);
    ev_end(a, &e);
    a->flush_count = 0;
}

static void flush_next(im_agent_t *a)
{
    size_t n;
    uint64_t seq = 0;
    char topic[IM_TOPIC_MAX_LEN];
    if (a->state != IM_ST_CONNECTED || !a->rb_ok || a->flushing) {
        return;
    }
    if (im_rb_count(&a->rb) == 0) {
        flush_done(a);
        return;
    }
    if (im_rb_peek(&a->rb, a->tx, sizeof a->tx, &n, NULL) != IM_OK) {
        (void)im_rb_pop(&a->rb); /* unreadable record: drop it */
        return;
    }
    (void)seq_of_envelope(a->tx, n, &seq);
    if (topic_for(a, IM_TOPIC_TELEMETRY, topic, sizeof topic) != IM_OK ||
        publish(a, topic, a->tx, n, 1, false, 2, seq) != IM_OK) {
        return;
    }
    a->flushing = true;
    if (a->flush_count == 0) {
        a->flush_first = seq;
    }
    a->flush_last = seq;
    a->flush_count++;
}

im_err_t im_agent_send_telemetry(im_agent_t *a, uint32_t count, uint64_t *first, uint64_t *last)
{
    char topic[IM_TOPIC_MAX_LEN];
    if (!a->started) {
        return IM_ERR_STATE;
    }
    IM_TRY(topic_for(a, IM_TOPIC_TELEMETRY, topic, sizeof topic));
    for (uint32_t i = 0; i < count; i++) {
        uint64_t seq;
        size_t n;
        bool online;
        IM_TRY(next_seq(a, &seq));
        IM_TRY(build_telemetry(a, seq, &n));
        if (i == 0 && first != NULL) {
            *first = seq;
        }
        if (last != NULL) {
            *last = seq;
        }
        /* keep strict ordering: while anything is buffered, new messages queue behind it */
        online = a->state == IM_ST_CONNECTED && (!a->rb_ok || im_rb_count(&a->rb) == 0) &&
                 !a->flushing;
        if (online && publish(a, topic, a->tx, n, 1, false, 1, seq) == IM_OK) {
            continue;
        }
        if (!a->rb_ok) {
            return IM_ERR_STORAGE;
        }
        IM_TRY(im_rb_push(&a->rb, a->tx, n));
    }
    a->last_telemetry_ms = mono(a);
    flush_next(a);
    return IM_OK;
}

im_err_t im_agent_publish_raw(im_agent_t *a, const char *topic, const uint8_t *payload,
                              size_t len, int qos, bool retain)
{
    ev_t e;
    if (a->state != IM_ST_CONNECTED) {
        return IM_ERR_STATE;
    }
    if (qos < 0 || qos > 1) {
        return IM_ERR_ARG;
    }
    if (publish(a, topic, payload, len, qos, retain, 3, 0) != IM_OK) {
        ev_begin(a, &e, "publish_result");
        im_jw_key(&e.w, "topic");
        im_jw_cstr(&e.w, topic);
        im_jw_key(&e.w, "ok");
        im_jw_bool(&e.w, false);
        im_jw_key(&e.w, "reason_code");
        im_jw_i64(&e.w, -1);
        ev_end(a, &e);
        return IM_OK;
    }
    if (qos == 0) {
        ev_begin(a, &e, "publish_result");
        im_jw_key(&e.w, "topic");
        im_jw_cstr(&e.w, topic);
        im_jw_key(&e.w, "ok");
        im_jw_bool(&e.w, true);
        im_jw_key(&e.w, "reason_code");
        im_jw_u64(&e.w, 0);
        ev_end(a, &e);
    }
    return IM_OK;
}

im_err_t im_agent_subscribe_raw(im_agent_t *a, const char *topic)
{
    uint16_t id = 0;
    im_pending_pub_t *slot;
    if (a->state != IM_ST_CONNECTED || a->pf.mqtt_subscribe == NULL) {
        return IM_ERR_STATE;
    }
    slot = pend_alloc(a);
    if (slot == NULL) {
        return IM_ERR_BUSY;
    }
    IM_TRY(a->pf.mqtt_subscribe(a->pf.ctx, topic, &id));
    memset(slot, 0, sizeof *slot);
    slot->msg_id = id;
    slot->kind = 5;
    copy_cstr(slot->topic, sizeof slot->topic, topic);
    return IM_OK;
}

void im_agent_on_puback(im_agent_t *a, uint16_t msg_id, uint8_t reason)
{
    im_pending_pub_t *p = pend_find(a, msg_id);
    ev_t e;
    if (p == NULL) {
        return;
    }
    switch (p->kind) {
    case 1:
        if (reason < 0x80u) {
            a->telemetry_acked = true;
            if (a->ota.state == IM_OTA_PENDING_HEALTH) {
                (void)im_ota_health_ok(&a->ota);
            }
        }
        break;
    case 2:
        a->flushing = false;
        if (reason < 0x80u) {
            (void)im_rb_pop(&a->rb);
        }
        p->kind = 0;
        flush_next(a);
        return;
    case 3:
        ev_begin(a, &e, "publish_result");
        im_jw_key(&e.w, "topic");
        im_jw_cstr(&e.w, p->topic);
        im_jw_key(&e.w, "ok");
        im_jw_bool(&e.w, reason < 0x80u);
        im_jw_key(&e.w, "reason_code");
        im_jw_u64(&e.w, reason);
        ev_end(a, &e);
        break;
    default:
        break;
    }
    p->kind = 0;
}

void im_agent_on_suback(im_agent_t *a, uint16_t msg_id, uint8_t reason)
{
    im_pending_pub_t *p = pend_find(a, msg_id);
    ev_t e;
    if (p == NULL || p->kind != 5) {
        return;
    }
    ev_begin(a, &e, "subscribe_result");
    im_jw_key(&e.w, "topic");
    im_jw_cstr(&e.w, p->topic);
    im_jw_key(&e.w, "granted");
    im_jw_bool(&e.w, reason < 0x80u);
    im_jw_key(&e.w, "reason_code");
    im_jw_u64(&e.w, reason);
    ev_end(a, &e);
    p->kind = 0;
}

/* ------------------------------------------------------------------------------------------ */
/* Inbound messages                                                                            */
/* ------------------------------------------------------------------------------------------ */

static im_err_t resolve_tenant(void *ctx, const uint8_t *kid, size_t kid_len, bool kid_text,
                               im_pubkey_t *out)
{
    im_agent_t *a = (im_agent_t *)ctx;
    char want[IM_TENANT_KID_LEN + 1];
    if (!a->have_bundle || !kid_text ||
        im_id_tenant_kid(a->cfg.tenant_id, strlen(a->cfg.tenant_id), want, sizeof want) != IM_OK ||
        kid_len != IM_TENANT_KID_LEN || memcmp(kid, want, kid_len) != 0) {
        return IM_ERR_NOT_FOUND;
    }
    return im_pubkey_ed25519(out, a->tenant_pub, 32);
}

static void send_ack(im_agent_t *a, const im_command_t *c, const uint8_t *nonce, uint8_t status,
                     const uint8_t *result, size_t result_len, const char *error)
{
    char topic[IM_TOPIC_MAX_LEN];
    char cmd_id[37];
    im_cbor_enc_t enc;
    uint64_t seq;
    size_t n;
    memcpy(cmd_id, c->cmd_id, 36);
    cmd_id[36] = '\0';
    if (next_seq(a, &seq) != IM_OK) {
        return;
    }
    im_cbor_enc_init(&enc, a->payload, sizeof a->payload);
    im_env_payload_begin(&enc, seq, now_s(a), IM_MSG_COMMAND_ACK, true);
    im_body_command_ack(&enc, cmd_id, status, result, result_len, error);
    if (im_env_payload_end(&enc, nonce, &n) == IM_OK && sign_uplink(a, n, &n) == IM_OK &&
        topic_for(a, IM_TOPIC_CMD_ACK, topic, sizeof topic) == IM_OK) {
        (void)publish(a, topic, a->tx, n, 1, false, 4, seq);
    }
}

static void handle_command(im_agent_t *a, const im_env_msg_t *m)
{
    im_command_t c;
    uint8_t status = 0;
    char cached_id[37];
    char cmd_id[37];
    const char *error = NULL;
    uint8_t result[24];
    size_t result_len = 0;
    uint64_t now = now_s(a);
    ev_t e;

    if (im_env_get_command(m, &c) != IM_OK) {
        return;
    }
    memcpy(cmd_id, c.cmd_id, 36);
    cmd_id[36] = '\0';
    if (im_cmd_cache_lookup(&a->cmds, c.idempotency_key, c.idempotency_key_len, now, &status,
                            cached_id) == IM_OK) {
        /* already executed: acknowledge again with the original outcome, do not re-run */
        send_ack(a, &c, m->nonce, status, NULL, 0, NULL);
        return;
    }
    if (c.expires_at < now) {
        status = 3;
        error = "expired";
    } else if (c.name_len == 4 && memcmp(c.name, "ping", 4) == 0) {
        static const uint8_t pong[] = {0xa1, 0x64, 'p', 'o', 'n', 'g', 0xf5};
        memcpy(result, pong, sizeof pong);
        result_len = sizeof pong;
    } else if (c.name_len == 6 && memcmp(c.name, "reboot", 6) == 0) {
        a->reboot_pending = true;
        a->reboot_reason = IM_REBOOT_REQUESTED;
    } else if (c.name_len == 10 && memcmp(c.name, "renew_cert", 10) == 0) {
        if (im_agent_enroll(a, true) != IM_OK) {
            status = 2;
            error = "renew_failed";
        }
    } else if (a->pf.exec_command != NULL) {
        im_err_t r = a->pf.exec_command(a->pf.ctx, c.name, c.name_len, &c.args, &status);
        if (r == IM_ERR_NOT_FOUND) {
            status = 1;
            error = "unknown_command";
        } else if (r != IM_OK) {
            status = 2;
            error = "failed";
        }
    } else {
        status = 1;
        error = "unknown_command";
    }
    (void)im_cmd_cache_store(&a->cmds, c.idempotency_key, c.idempotency_key_len, cmd_id, status,
                             c.expires_at, now);
    send_ack(a, &c, m->nonce, status, result_len ? result : NULL, result_len, error);
    ev_begin(a, &e, "command_executed");
    im_jw_key(&e.w, "cmd_id");
    im_jw_cstr(&e.w, cmd_id);
    im_jw_key(&e.w, "status");
    im_jw_u64(&e.w, status);
    ev_end(a, &e);
}

static void handle_shadow(im_agent_t *a, const im_env_msg_t *m)
{
    im_shadow_t sh;
    char topic[IM_TOPIC_MAX_LEN];
    im_cbor_enc_t enc;
    uint64_t seq;
    size_t n;
    if (im_env_get_shadow(m, &sh) != IM_OK || next_seq(a, &seq) != IM_OK) {
        return;
    }
    /* report the accepted desired state back (devices without actuators mirror it) */
    im_cbor_enc_init(&enc, a->payload, sizeof a->payload);
    im_env_payload_begin(&enc, seq, now_s(a), IM_MSG_SHADOW_REPORTED, false);
    im_body_shadow(&enc, sh.state.raw, sh.state.raw_len, sh.version);
    if (im_env_payload_end(&enc, NULL, &n) == IM_OK && sign_uplink(a, n, &n) == IM_OK &&
        topic_for(a, IM_TOPIC_SHADOW_REPORTED, topic, sizeof topic) == IM_OK) {
        (void)publish(a, topic, a->tx, n, 1, false, 4, seq);
    }
}

void im_agent_on_message(im_agent_t *a, const char *topic, size_t topic_len,
                         const uint8_t *payload, size_t len)
{
    im_topic_t t;
    im_key_resolver_t res;
    im_replay_store_t store;
    im_env_decode_opts_t o;
    im_env_msg_t m;
    const uint8_t *buf = payload;
    size_t blen = len;
    im_err_t err;

    if (im_topic_parse(topic, topic_len, &t) != IM_OK ||
        memcmp(t.tenant, a->cfg.tenant_id, IM_UUID_LEN) != 0 ||
        memcmp(t.device, a->cfg.device_id, IM_DEVICE_ID_LEN) != 0 ||
        im_topic_device_publishes(t.cls)) {
        reject(a, IM_ERR_TOPIC_FORMAT, topic, topic_len, "topic");
        return;
    }
    if (t.cls == IM_TOPIC_CONFIG) {
        size_t pt_len;
        err = im_config_unwrap(payload, len, a->pf.identity, a->rx, sizeof a->rx, &pt_len);
        if (err != IM_OK) {
            reject(a, err, topic, topic_len, "config");
            return;
        }
        buf = a->rx;
        blen = pt_len;
    }
    res.resolve = resolve_tenant;
    res.ctx = a;
    im_replay_mem_store(&a->replay, &store);
    im_env_decode_opts_init(&o);
    o.resolver = &res;
    o.replay = &store;
    o.now = now_s(a);
    o.expected_direction = IM_DIR_DOWNLINK;
    o.expected_tenant = a->cfg.tenant_id;
    o.work = a->work;
    o.work_len = sizeof a->work;
    err = im_env_decode(buf, blen, &o, &m);
    if (err == IM_OK && m.type != im_topic_message_type(t.cls)) {
        err = IM_ERR_ENV_TYPE; /* message type does not belong on this topic */
    }
    if (err != IM_OK) {
        reject(a, err, topic, topic_len, "envelope");
        if (t.cls == IM_TOPIC_CONFIG) {
            im_secure_zero(a->rx, blen);
        }
        return;
    }
    switch (m.type) {
    case IM_MSG_COMMAND:
        handle_command(a, &m);
        break;
    case IM_MSG_SHADOW_DESIRED:
        handle_shadow(a, &m);
        break;
    case IM_MSG_OTA_NOTIFY: {
        im_ota_notify_t n;
        if (im_env_get_ota_notify(&m, &n) == IM_OK && im_ota_on_notify(&a->ota, &n) == IM_OK) {
            if (a->pf.ota_download == NULL ||
                a->pf.ota_download(a->pf.ctx, n.url, n.url_len) != IM_OK) {
                im_ota_on_failure(&a->ota, IM_ERR_IO);
            }
        }
        break;
    }
    case IM_MSG_CONFIG: {
        im_config_t c;
        if (im_env_get_config(&m, &c) == IM_OK && c.version > a->config_version) {
            a->config_version = c.version;
            if (a->pf.apply_config) {
                a->pf.apply_config(a->pf.ctx, c.version, &c.settings);
            }
        }
        im_secure_zero(a->rx, blen); /* plaintext config is not retained */
        break;
    }
    default:
        break;
    }
}

void im_agent_on_ota_data(im_agent_t *a, const uint8_t *data, size_t len)
{
    (void)im_ota_on_data(&a->ota, data, len);
}

void im_agent_on_ota_done(im_agent_t *a, im_err_t err)
{
    if (err != IM_OK) {
        im_ota_on_failure(&a->ota, err);
        return;
    }
    if (im_ota_on_complete(&a->ota) == IM_OK) {
        a->reboot_pending = true;
        a->reboot_reason = IM_REBOOT_OTA_APPLY;
    }
}

im_err_t im_agent_reboot(im_agent_t *a, int reason)
{
    a->reboot_pending = true;
    a->reboot_reason = reason;
    return IM_OK;
}

/* ------------------------------------------------------------------------------------------ */
/* Tick                                                                                        */
/* ------------------------------------------------------------------------------------------ */

void im_agent_tick(im_agent_t *a)
{
    uint64_t now_ms = mono(a);
    if (!a->started) {
        return;
    }
    if (a->reboot_pending) {
        a->reboot_pending = false;
        if (a->pf.mqtt_disconnect && a->state == IM_ST_CONNECTED) {
            (void)a->pf.mqtt_disconnect(a->pf.ctx);
        }
        a->state = IM_ST_REBOOTING;
        if (a->pf.reboot) {
            a->pf.reboot(a->pf.ctx, a->reboot_reason);
        }
        return;
    }
    (void)im_ota_tick(&a->ota, now_ms);
    if (a->state == IM_ST_BACKOFF && a->want_connected && a->net_up &&
        now_ms >= a->next_connect_ms) {
        (void)start_connect(a);
    }
    if (a->provisioned && !a->renewing && a->renew_at != 0 && now_s(a) >= a->renew_at) {
        bool expired = now_s(a) >= a->cert_not_after;
        a->renew_at = now_s(a) + RENEW_BASE_S; /* guard until the result arrives */
        (void)im_agent_enroll(a, !expired);
    }
    if (a->state == IM_ST_CONNECTED && a->cfg.telemetry_interval_s != 0 &&
        now_ms - a->last_telemetry_ms >= (uint64_t)a->cfg.telemetry_interval_s * 1000u) {
        uint64_t f;
        uint64_t l;
        (void)im_agent_send_telemetry(a, 1, &f, &l);
    }
}

im_err_t im_agent_ota_version(const im_agent_t *a, char *out, size_t cap)
{
    if (a == NULL || out == NULL || a->ota.mf.version == NULL || a->ota.mf.version_len >= cap) {
        return IM_ERR_NOT_FOUND;
    }
    memcpy(out, a->ota.mf.version, a->ota.mf.version_len);
    out[a->ota.mf.version_len] = '\0';
    return IM_OK;
}
