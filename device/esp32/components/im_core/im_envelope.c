/*
 * IronMesh protocol core - envelope codec and verification (WIRE_FORMAT.md §3).
 * Mirrors ironmesh_wire/envelope.py; see im_envelope.h.
 */
#include "im_envelope.h"

#include <string.h>

#include "im_fields.h"
#include "im_ids.h"

#define MAX_NAME 64u
#define MAX_URL 2048u
#define MAX_ERROR 1024u

im_direction_t im_msg_direction(uint8_t type)
{
    switch (type) {
    case IM_MSG_SHADOW_DESIRED:
    case IM_MSG_COMMAND:
    case IM_MSG_OTA_NOTIFY:
    case IM_MSG_CONFIG:
        return IM_DIR_DOWNLINK;
    default:
        return IM_DIR_UPLINK;
    }
}

bool im_msg_retainable(uint8_t type)
{
    return type == IM_MSG_SHADOW_DESIRED || type == IM_MSG_OTA_NOTIFY || type == IM_MSG_CONFIG;
}

im_err_t im_env_replay_stream(const uint8_t *kid, size_t kid_len, im_direction_t dir,
                              uint8_t type, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = kid_len;
    if (kid == NULL || out == NULL || out_len == NULL) {
        return IM_ERR_ARG;
    }
    if (n > cap) {
        return IM_ERR_BUFFER;
    }
    memcpy(out, kid, kid_len);
    if (dir == IM_DIR_DOWNLINK) {
        /* "<tenant kid>/<type>" with the type in decimal (WIRE_FORMAT.md §3.6 step 11) */
        char t[4];
        size_t tl = 0;
        if (type >= 10u) {
            t[tl++] = (char)('0' + type / 10u);
        }
        t[tl++] = (char)('0' + type % 10u);
        if (cap - n < tl + 1u) {
            return IM_ERR_BUFFER;
        }
        out[n++] = '/';
        memcpy(out + n, t, tl);
        n += tl;
    }
    *out_len = n;
    return IM_OK;
}

void im_env_decode_opts_init(im_env_decode_opts_t *o)
{
    memset(o, 0, sizeof *o);
    o->max_skew = IM_MAX_SKEW_DEFAULT;
    o->expected_direction = -1;
}

/* ------------------------------------------------------------------------------------------ */
/* Body validation (§3.4)                                                                      */
/* ------------------------------------------------------------------------------------------ */

#define EF IM_ERR_ENV_FIELD

static im_err_t semver_field(const im_cbor_val_t *m, int64_t key)
{
    const char *s;
    size_t n;
    IM_TRY(im_f_tstr(m, key, 1, MAX_NAME, EF, &s, &n));
    return im_id_is_semver(s, n) ? IM_OK : EF;
}

static im_err_t uuid_field(const im_cbor_val_t *m, int64_t key, bool v4)
{
    const char *s;
    size_t n;
    IM_TRY(im_f_tstr(m, key, 36, 36, EF, &s, &n));
    if (v4 ? !im_id_is_uuid4(s, n) : !im_id_is_uuid(s, n)) {
        return EF;
    }
    return IM_OK;
}

static im_err_t v_telemetry(const im_cbor_val_t *m)
{
    uint32_t present;
    IM_TRY(im_f_expect_keys(m, 0x3FEu /* 1..9 */, 0xFC00u /* 10..15 */, EF, &present));
    IM_TRY(im_f_float(m, 1, EF, NULL));
    IM_TRY(im_f_float(m, 2, EF, NULL));
    IM_TRY(im_f_uint(m, 3, UINT64_MAX, EF, NULL));
    IM_TRY(im_f_uint(m, 4, UINT64_MAX, EF, NULL));
    IM_TRY(im_f_float(m, 5, EF, NULL));
    IM_TRY(im_f_uint(m, 6, UINT64_MAX, EF, NULL));
    IM_TRY(im_f_uint(m, 7, UINT64_MAX, EF, NULL));
    IM_TRY(im_f_bstr(m, 8, 32, EF, NULL, NULL));
    IM_TRY(semver_field(m, 9));
    if (im_f_has(present, 10)) {
        IM_TRY(im_f_uint(m, 10, UINT64_MAX, EF, NULL));
    }
    if (im_f_has(present, 11)) {
        IM_TRY(im_f_tstr_list(m, 11, 10, EF));
    }
    if (im_f_has(present, 12)) {
        IM_TRY(im_f_int(m, 12, EF, NULL));
    }
    if (im_f_has(present, 13)) {
        IM_TRY(im_f_uint(m, 13, UINT64_MAX, EF, NULL));
    }
    if (im_f_has(present, 14)) {
        IM_TRY(im_f_float(m, 14, EF, NULL));
    }
    if (im_f_has(present, 15)) {
        IM_TRY(im_f_float(m, 15, EF, NULL));
    }
    return IM_OK;
}

static im_err_t v_event(const im_cbor_val_t *m)
{
    IM_TRY(im_f_expect_keys(m, 0xEu, 0, EF, NULL));
    IM_TRY(im_f_tstr(m, 1, 1, MAX_NAME, EF, NULL, NULL));
    IM_TRY(im_f_uint(m, 2, 4, EF, NULL));
    return im_f_appmap(m, 3, EF, NULL);
}

static im_err_t v_shadow(const im_cbor_val_t *m)
{
    IM_TRY(im_f_expect_keys(m, 0x6u, 0, EF, NULL));
    IM_TRY(im_f_appmap(m, 1, EF, NULL));
    return im_f_uint(m, 2, UINT64_MAX, EF, NULL);
}

static im_err_t v_command(const im_cbor_val_t *m)
{
    IM_TRY(im_f_expect_keys(m, 0x3Eu, 0, EF, NULL));
    IM_TRY(uuid_field(m, 1, false));
    IM_TRY(im_f_tstr(m, 2, 1, MAX_NAME, EF, NULL, NULL));
    IM_TRY(im_f_appmap(m, 3, EF, NULL));
    IM_TRY(im_f_tstr(m, 4, 1, 128, EF, NULL, NULL));
    return im_f_uint(m, 5, UINT64_MAX, EF, NULL);
}

static im_err_t v_command_ack(const im_cbor_val_t *m)
{
    uint32_t present;
    IM_TRY(im_f_expect_keys(m, 0x6u, 0x18u, EF, &present));
    IM_TRY(uuid_field(m, 1, false));
    IM_TRY(im_f_uint(m, 2, 3, EF, NULL));
    if (im_f_has(present, 3)) {
        IM_TRY(im_f_appmap(m, 3, EF, NULL));
    }
    if (im_f_has(present, 4)) {
        IM_TRY(im_f_tstr(m, 4, 1, MAX_ERROR, EF, NULL, NULL));
    }
    return IM_OK;
}

static im_err_t v_ota_notify(const im_cbor_val_t *m)
{
    size_t n;
    const uint8_t *p;
    IM_TRY(im_f_expect_keys(m, 0x1Eu, 0, EF, NULL));
    IM_TRY(im_f_bstr(m, 2, SIZE_MAX, EF, &p, &n));
    if (n == 0) {
        return EF;
    }
    IM_TRY(uuid_field(m, 1, true));
    IM_TRY(im_f_tstr(m, 3, 1, MAX_URL, EF, NULL, NULL));
    return im_f_bstr_or_null(m, 4, 32, EF, &p);
}

static im_err_t v_ota_status(const im_cbor_val_t *m)
{
    uint32_t present;
    IM_TRY(im_f_expect_keys(m, 0xEu, 0x30u, EF, &present));
    IM_TRY(uuid_field(m, 1, true));
    IM_TRY(im_f_uint(m, 2, 7, EF, NULL));
    IM_TRY(im_f_uint(m, 3, 100, EF, NULL));
    if (im_f_has(present, 4)) {
        IM_TRY(im_f_tstr(m, 4, 1, MAX_ERROR, EF, NULL, NULL));
    }
    if (im_f_has(present, 5)) {
        IM_TRY(im_f_bstr(m, 5, 32, EF, NULL, NULL));
    }
    return IM_OK;
}

static im_err_t v_config(const im_cbor_val_t *m)
{
    IM_TRY(im_f_expect_keys(m, 0x6u, 0, EF, NULL));
    IM_TRY(im_f_uint(m, 1, UINT64_MAX, EF, NULL));
    return im_f_appmap(m, 2, EF, NULL);
}

static im_err_t v_tpm2_evidence(const im_cbor_val_t *m)
{
    size_t n1;
    size_t n2;
    size_t n3;
    IM_TRY(im_f_expect_keys(m, 0xEu, 0, EF, NULL));
    IM_TRY(im_f_bstr(m, 1, SIZE_MAX, EF, NULL, &n1));
    IM_TRY(im_f_bstr(m, 2, SIZE_MAX, EF, NULL, &n2));
    IM_TRY(im_f_bstr(m, 3, SIZE_MAX, EF, NULL, &n3));
    return (n1 == 0 || n2 == 0 || n3 == 0) ? EF : IM_OK;
}

static const char *const k_se_types[4] = {"atecc608", "tpm2", "optee", "software"};

static im_err_t v_attestation(const im_cbor_val_t *m)
{
    const char *se;
    size_t se_len;
    bool known = false;
    bool tpm2;
    im_cbor_val_t ev;
    IM_TRY(im_f_expect_keys(m, 0x7Eu, 0, EF, NULL));
    IM_TRY(im_f_tstr(m, 5, 1, 16, EF, &se, &se_len));
    for (unsigned i = 0; i < 4u; i++) {
        if (strlen(k_se_types[i]) == se_len && memcmp(k_se_types[i], se, se_len) == 0) {
            known = true;
        }
    }
    if (!known) {
        return EF;
    }
    tpm2 = se_len == 4 && memcmp(se, "tpm2", 4) == 0;
    IM_TRY(im_cbor_map_get_int(m, 6, &ev) == IM_OK ? IM_OK : EF);
    if (ev.type == IM_CBOR_MAP) {
        IM_TRY(v_tpm2_evidence(&ev));
    } else if (ev.type != IM_CBOR_NULL) {
        return EF;
    }
    if (tpm2 != (ev.type == IM_CBOR_MAP)) {
        return EF;
    }
    IM_TRY(im_f_bstr(m, 1, 32, EF, NULL, NULL));
    IM_TRY(im_f_bstr(m, 2, 32, EF, NULL, NULL));
    IM_TRY(im_f_bstr(m, 3, 32, EF, NULL, NULL));
    return semver_field(m, 4);
}

static im_err_t validate_body(uint8_t type, const im_cbor_val_t *m)
{
    switch (type) {
    case IM_MSG_TELEMETRY:
        return v_telemetry(m);
    case IM_MSG_EVENT:
        return v_event(m);
    case IM_MSG_SHADOW_REPORTED:
    case IM_MSG_SHADOW_DESIRED:
        return v_shadow(m);
    case IM_MSG_COMMAND:
        return v_command(m);
    case IM_MSG_COMMAND_ACK:
        return v_command_ack(m);
    case IM_MSG_OTA_NOTIFY:
        return v_ota_notify(m);
    case IM_MSG_OTA_STATUS:
        return v_ota_status(m);
    case IM_MSG_CONFIG:
        return v_config(m);
    case IM_MSG_ATTESTATION:
        return v_attestation(m);
    default:
        return IM_ERR_ENV_TYPE;
    }
}

/* ------------------------------------------------------------------------------------------ */
/* Payload                                                                                     */
/* ------------------------------------------------------------------------------------------ */

im_err_t im_env_decode_payload(const uint8_t *p, size_t n, const im_cbor_limits_t *lim,
                               im_env_msg_t *msg)
{
    im_cbor_val_t m;
    im_cbor_val_t v;
    im_cbor_val_t k;
    im_cbor_iter_t it;
    uint32_t present;
    uint64_t type;

    IM_TRY(im_cbor_decode(p, n, lim, &m));
    if (m.type != IM_CBOR_MAP) {
        return IM_ERR_CBOR_TYPE;
    }
    IM_TRY(im_f_expect_keys(&m, 0x1Eu, 0x20u, IM_ERR_ENV_STRUCTURE, &present));
    IM_TRY(im_f_uint(&m, 1, UINT64_MAX, EF, &msg->seq));
    IM_TRY(im_f_uint(&m, 2, UINT64_MAX, EF, &msg->ts));
    IM_TRY(im_cbor_map_get_int(&m, 3, &v));
    if (v.type != IM_CBOR_UINT || v.arg < 1u || v.arg > 10u) {
        return IM_ERR_ENV_TYPE;
    }
    type = v.arg;
    IM_TRY(im_cbor_map_get_int(&m, 4, &msg->body));
    if (msg->body.type != IM_CBOR_MAP) {
        return IM_ERR_ENV_STRUCTURE;
    }
    IM_TRY(im_cbor_iter_init(&it, &msg->body));
    while (im_cbor_iter_next(&it, &k) == IM_OK) {
        if (!im_cbor_is_int(&k)) {
            return EF;
        }
        IM_TRY(im_cbor_iter_next(&it, &v));
    }
    IM_TRY(validate_body((uint8_t)type, &msg->body));
    msg->nonce = NULL;
    if (im_f_has(present, 5)) {
        IM_TRY(im_cbor_map_get_int(&m, 5, &v));
        /* The spec requires absence; an explicit null is rejected (see README: the Python
         * reference treats null as absent). */
        if (v.type != IM_CBOR_BSTR) {
            return IM_ERR_ENV_NONCE;
        }
        if (v.arg != IM_NONCE_LEN) {
            return IM_ERR_ENV_NONCE;
        }
        msg->nonce = v.data;
    }
    if (type == IM_MSG_COMMAND || type == IM_MSG_COMMAND_ACK) {
        if (msg->nonce == NULL) {
            return IM_ERR_ENV_NONCE;
        }
    } else if (msg->nonce != NULL) {
        return IM_ERR_ENV_NONCE;
    }
    msg->type = (uint8_t)type;
    msg->payload = p;
    msg->payload_len = n;
    return IM_OK;
}

im_err_t im_env_check_header_profile(int alg, const uint8_t *kid, size_t kid_len, bool kid_text,
                                     im_direction_t dir)
{
    if (dir == IM_DIR_UPLINK) {
        if (kid_text || !im_id_is_device_kid(kid, kid_len)) {
            return IM_ERR_ENV_KID;
        }
        if (alg != IM_ALG_ES256) {
            return IM_ERR_ENV_DIRECTION;
        }
    } else {
        if (!kid_text || !im_id_is_tenant_kid((const char *)kid, kid_len, NULL)) {
            return IM_ERR_ENV_KID;
        }
        if (alg != IM_ALG_EDDSA) {
            return IM_ERR_ENV_DIRECTION;
        }
    }
    return IM_OK;
}

im_err_t im_env_decode(const uint8_t *buf, size_t len, const im_env_decode_opts_t *o,
                       im_env_msg_t *msg)
{
    im_sign1_t s;
    im_direction_t dir;
    im_pubkey_t key;
    uint64_t skew;
    uint64_t max_skew;
    im_err_t err;

    if (o == NULL || msg == NULL || o->resolver == NULL || o->resolver->resolve == NULL ||
        o->replay == NULL || o->replay->check_and_record == NULL) {
        return IM_ERR_ARG;
    }
    memset(msg, 0, sizeof *msg);
    /* 1. structure */
    IM_TRY(im_cose_sign1_decode(buf, len, o->limits, &s));
    /* 2. header profile of the kid's direction */
    dir = s.kid_text ? IM_DIR_DOWNLINK : IM_DIR_UPLINK;
    IM_TRY(im_env_check_header_profile(s.alg, s.kid, s.kid_len, s.kid_text, dir));
    /* 3. expected direction */
    if (o->expected_direction >= 0 && (int)dir != o->expected_direction) {
        return IM_ERR_ENV_DIRECTION;
    }
    /* 4. tenant */
    if (o->expected_tenant != NULL && dir == IM_DIR_DOWNLINK) {
        const char *tenant = NULL;
        (void)im_id_is_tenant_kid((const char *)s.kid, s.kid_len, &tenant);
        if (tenant == NULL || strlen(o->expected_tenant) != IM_UUID_LEN ||
            memcmp(tenant, o->expected_tenant, IM_UUID_LEN) != 0) {
            return IM_ERR_ENV_TENANT;
        }
    }
    /* 5. key */
    memset(&key, 0, sizeof key);
    err = o->resolver->resolve(o->resolver->ctx, s.kid, s.kid_len, s.kid_text, &key);
    if (err == IM_ERR_NOT_FOUND) {
        return IM_ERR_ENV_UNKNOWN_KEY;
    }
    IM_TRY(err);
    /* 6. signature */
    IM_TRY(im_cose_sign1_verify(&s, &key, o->work, o->work_len));
    /* 7. payload */
    IM_TRY(im_env_decode_payload(s.payload, s.payload_len, o->limits, msg));
    /* 8. type direction */
    if (im_msg_direction(msg->type) != dir) {
        return IM_ERR_ENV_DIRECTION;
    }
    /* 9. timestamp window */
    max_skew = o->max_skew ? o->max_skew : IM_MAX_SKEW_DEFAULT;
    if (dir == IM_DIR_DOWNLINK && im_msg_retainable(msg->type)) {
        /* retained messages may be old; only a future-dated one is rejected */
        skew = msg->ts > o->now ? msg->ts - o->now : 0;
    } else {
        skew = o->now >= msg->ts ? o->now - msg->ts : msg->ts - o->now;
    }
    if (skew > max_skew) {
        return IM_ERR_ENV_TS_SKEW;
    }
    /* 10. nonce echo */
    if (o->expected_nonce != NULL &&
        (msg->type != IM_MSG_COMMAND_ACK || msg->nonce == NULL ||
         !im_ct_equal(msg->nonce, o->expected_nonce, IM_NONCE_LEN))) {
        return IM_ERR_ENV_NONCE;
    }
    /* 11. replay (only after every other check passed), per replay stream */
    {
        uint8_t stream[IM_REPLAY_STREAM_MAX];
        size_t stream_len;
        IM_TRY(im_env_replay_stream(s.kid, s.kid_len, dir, msg->type, stream, sizeof stream,
                                    &stream_len));
        IM_TRY(o->replay->check_and_record(o->replay->ctx, stream, stream_len, dir, msg->seq));
    }
    msg->direction = dir;
    msg->kid = s.kid;
    msg->kid_len = s.kid_len;
    msg->kid_text = s.kid_text;
    return IM_OK;
}

/* ------------------------------------------------------------------------------------------ */
/* Typed accessors                                                                             */
/* ------------------------------------------------------------------------------------------ */

im_err_t im_env_get_command(const im_env_msg_t *m, im_command_t *out)
{
    const char *s;
    size_t n;
    if (m->type != IM_MSG_COMMAND) {
        return IM_ERR_ENV_TYPE;
    }
    IM_TRY(im_f_tstr(&m->body, 1, 36, 36, EF, &out->cmd_id, &n));
    IM_TRY(im_f_tstr(&m->body, 2, 1, MAX_NAME, EF, &out->name, &out->name_len));
    IM_TRY(im_f_appmap(&m->body, 3, EF, &out->args));
    IM_TRY(im_f_tstr(&m->body, 4, 1, 128, EF, &s, &n));
    out->idempotency_key = s;
    out->idempotency_key_len = n;
    return im_f_uint(&m->body, 5, UINT64_MAX, EF, &out->expires_at);
}

im_err_t im_env_get_command_ack(const im_env_msg_t *m, im_command_ack_t *out)
{
    size_t n;
    memset(out, 0, sizeof *out);
    if (m->type != IM_MSG_COMMAND_ACK) {
        return IM_ERR_ENV_TYPE;
    }
    IM_TRY(im_f_tstr(&m->body, 1, 36, 36, EF, &out->cmd_id, &n));
    IM_TRY(im_f_uint(&m->body, 2, 3, EF, &out->status));
    out->has_result = im_f_appmap(&m->body, 3, EF, &out->result) == IM_OK;
    if (im_f_tstr(&m->body, 4, 1, MAX_ERROR, EF, &out->error, &out->error_len) != IM_OK) {
        out->error = NULL;
        out->error_len = 0;
    }
    return IM_OK;
}

im_err_t im_env_get_ota_notify(const im_env_msg_t *m, im_ota_notify_t *out)
{
    size_t n;
    if (m->type != IM_MSG_OTA_NOTIFY) {
        return IM_ERR_ENV_TYPE;
    }
    IM_TRY(im_f_tstr(&m->body, 1, 36, 36, EF, &out->campaign_id, &n));
    IM_TRY(im_f_bstr(&m->body, 2, SIZE_MAX, EF, &out->manifest, &out->manifest_len));
    IM_TRY(im_f_tstr(&m->body, 3, 1, MAX_URL, EF, &out->url, &out->url_len));
    return im_f_bstr_or_null(&m->body, 4, 32, EF, &out->delta_from);
}

im_err_t im_env_get_config(const im_env_msg_t *m, im_config_t *out)
{
    if (m->type != IM_MSG_CONFIG) {
        return IM_ERR_ENV_TYPE;
    }
    IM_TRY(im_f_uint(&m->body, 1, UINT64_MAX, EF, &out->version));
    return im_f_appmap(&m->body, 2, EF, &out->settings);
}

im_err_t im_env_get_shadow(const im_env_msg_t *m, im_shadow_t *out)
{
    if (m->type != IM_MSG_SHADOW_DESIRED && m->type != IM_MSG_SHADOW_REPORTED) {
        return IM_ERR_ENV_TYPE;
    }
    IM_TRY(im_f_appmap(&m->body, 1, EF, &out->state));
    return im_f_uint(&m->body, 2, UINT64_MAX, EF, &out->version);
}

im_err_t im_env_get_attestation(const im_env_msg_t *m, im_attestation_t *out)
{
    im_cbor_val_t ev;
    memset(out, 0, sizeof *out);
    if (m->type != IM_MSG_ATTESTATION) {
        return IM_ERR_ENV_TYPE;
    }
    IM_TRY(im_f_bstr(&m->body, 1, 32, EF, &out->nonce, NULL));
    IM_TRY(im_f_bstr(&m->body, 2, 32, EF, &out->csr_hash, NULL));
    IM_TRY(im_f_bstr(&m->body, 3, 32, EF, &out->fw_hash, NULL));
    IM_TRY(im_f_tstr(&m->body, 4, 1, MAX_NAME, EF, &out->fw_version, &out->fw_version_len));
    IM_TRY(im_f_tstr(&m->body, 5, 1, 16, EF, &out->se_type, &out->se_type_len));
    IM_TRY(im_cbor_map_get_int(&m->body, 6, &ev));
    out->has_evidence = ev.type == IM_CBOR_MAP;
    out->evidence = ev;
    return IM_OK;
}

/* ------------------------------------------------------------------------------------------ */
/* Encoding                                                                                    */
/* ------------------------------------------------------------------------------------------ */

void im_env_payload_begin(im_cbor_enc_t *e, uint64_t seq, uint64_t ts, uint8_t type,
                          bool has_nonce)
{
    im_cbor_enc_map(e, has_nonce ? 5u : 4u);
    im_cbor_enc_uint(e, 1);
    im_cbor_enc_uint(e, seq);
    im_cbor_enc_uint(e, 2);
    im_cbor_enc_uint(e, ts);
    im_cbor_enc_uint(e, 3);
    im_cbor_enc_uint(e, type);
    im_cbor_enc_uint(e, 4);
}

im_err_t im_env_payload_end(im_cbor_enc_t *e, const uint8_t *nonce, size_t *len)
{
    im_env_msg_t check;
    size_t n;
    if (nonce != NULL) {
        im_cbor_enc_uint(e, 5);
        im_cbor_enc_bstr(e, nonce, IM_NONCE_LEN);
    }
    IM_TRY(im_cbor_enc_finish(e, &n));
    if (e->buf != NULL) {
        /* never emit something a receiver would reject */
        IM_TRY(im_env_decode_payload(e->buf, n, NULL, &check));
    }
    if (len != NULL) {
        *len = n;
    }
    return IM_OK;
}

void im_body_telemetry(im_cbor_enc_t *e, const im_telemetry_t *t)
{
    uint64_t n = 9;
    n += t->has_proc_count + (t->top_procs != NULL) + t->has_rssi + t->has_free_heap +
         t->has_lat + t->has_lon;
    im_cbor_enc_map(e, n);
    im_cbor_enc_uint(e, 1);
    im_cbor_enc_float(e, t->cpu_pct);
    im_cbor_enc_uint(e, 2);
    im_cbor_enc_float(e, t->mem_pct);
    im_cbor_enc_uint(e, 3);
    im_cbor_enc_uint(e, t->net_rx_bytes);
    im_cbor_enc_uint(e, 4);
    im_cbor_enc_uint(e, t->net_tx_bytes);
    im_cbor_enc_uint(e, 5);
    im_cbor_enc_float(e, t->temp_c);
    im_cbor_enc_uint(e, 6);
    im_cbor_enc_uint(e, t->uptime_s);
    im_cbor_enc_uint(e, 7);
    im_cbor_enc_uint(e, t->auth_failures);
    im_cbor_enc_uint(e, 8);
    im_cbor_enc_bstr(e, t->fw_hash, 32);
    im_cbor_enc_uint(e, 9);
    im_cbor_enc_cstr(e, t->fw_version);
    if (t->has_proc_count) {
        im_cbor_enc_uint(e, 10);
        im_cbor_enc_uint(e, t->proc_count);
    }
    if (t->top_procs != NULL) {
        im_cbor_enc_uint(e, 11);
        im_cbor_enc_array(e, t->n_top_procs);
        for (size_t i = 0; i < t->n_top_procs; i++) {
            im_cbor_enc_cstr(e, t->top_procs[i]);
        }
    }
    if (t->has_rssi) {
        im_cbor_enc_uint(e, 12);
        im_cbor_enc_int(e, t->rssi);
    }
    if (t->has_free_heap) {
        im_cbor_enc_uint(e, 13);
        im_cbor_enc_uint(e, t->free_heap);
    }
    if (t->has_lat) {
        im_cbor_enc_uint(e, 14);
        im_cbor_enc_float(e, t->lat);
    }
    if (t->has_lon) {
        im_cbor_enc_uint(e, 15);
        im_cbor_enc_float(e, t->lon);
    }
}

static void enc_appmap(im_cbor_enc_t *e, const uint8_t *m, size_t n)
{
    if (m == NULL || n == 0) {
        im_cbor_enc_map(e, 0);
    } else {
        im_cbor_enc_raw(e, m, n);
    }
}

void im_body_event(im_cbor_enc_t *e, const char *name, uint64_t severity, const uint8_t *data,
                   size_t data_len)
{
    im_cbor_enc_map(e, 3);
    im_cbor_enc_uint(e, 1);
    im_cbor_enc_cstr(e, name);
    im_cbor_enc_uint(e, 2);
    im_cbor_enc_uint(e, severity);
    im_cbor_enc_uint(e, 3);
    enc_appmap(e, data, data_len);
}

void im_body_shadow(im_cbor_enc_t *e, const uint8_t *state, size_t state_len, uint64_t version)
{
    im_cbor_enc_map(e, 2);
    im_cbor_enc_uint(e, 1);
    enc_appmap(e, state, state_len);
    im_cbor_enc_uint(e, 2);
    im_cbor_enc_uint(e, version);
}

void im_body_command(im_cbor_enc_t *e, const char *cmd_id, const char *name,
                     const uint8_t *args, size_t args_len, const char *idem_key,
                     uint64_t expires_at)
{
    im_cbor_enc_map(e, 5);
    im_cbor_enc_uint(e, 1);
    im_cbor_enc_cstr(e, cmd_id);
    im_cbor_enc_uint(e, 2);
    im_cbor_enc_cstr(e, name);
    im_cbor_enc_uint(e, 3);
    enc_appmap(e, args, args_len);
    im_cbor_enc_uint(e, 4);
    im_cbor_enc_cstr(e, idem_key);
    im_cbor_enc_uint(e, 5);
    im_cbor_enc_uint(e, expires_at);
}

void im_body_command_ack(im_cbor_enc_t *e, const char *cmd_id, uint64_t status,
                         const uint8_t *result, size_t result_len, const char *error)
{
    im_cbor_enc_map(e, 2u + (result != NULL) + (error != NULL));
    im_cbor_enc_uint(e, 1);
    im_cbor_enc_cstr(e, cmd_id);
    im_cbor_enc_uint(e, 2);
    im_cbor_enc_uint(e, status);
    if (result != NULL) {
        im_cbor_enc_uint(e, 3);
        enc_appmap(e, result, result_len);
    }
    if (error != NULL) {
        im_cbor_enc_uint(e, 4);
        im_cbor_enc_cstr(e, error);
    }
}

void im_body_ota_notify(im_cbor_enc_t *e, const char *campaign_id, const uint8_t *manifest,
                        size_t manifest_len, const char *url, const uint8_t *delta_from)
{
    im_cbor_enc_map(e, 4);
    im_cbor_enc_uint(e, 1);
    im_cbor_enc_cstr(e, campaign_id);
    im_cbor_enc_uint(e, 2);
    im_cbor_enc_bstr(e, manifest, manifest_len);
    im_cbor_enc_uint(e, 3);
    im_cbor_enc_cstr(e, url);
    im_cbor_enc_uint(e, 4);
    if (delta_from != NULL) {
        im_cbor_enc_bstr(e, delta_from, 32);
    } else {
        im_cbor_enc_null(e);
    }
}

void im_body_ota_status(im_cbor_enc_t *e, const char *campaign_id, uint64_t state,
                        uint64_t progress_pct, const char *error, const uint8_t *fw_hash)
{
    im_cbor_enc_map(e, 3u + (error != NULL) + (fw_hash != NULL));
    im_cbor_enc_uint(e, 1);
    im_cbor_enc_cstr(e, campaign_id);
    im_cbor_enc_uint(e, 2);
    im_cbor_enc_uint(e, state);
    im_cbor_enc_uint(e, 3);
    im_cbor_enc_uint(e, progress_pct);
    if (error != NULL) {
        im_cbor_enc_uint(e, 4);
        im_cbor_enc_cstr(e, error);
    }
    if (fw_hash != NULL) {
        im_cbor_enc_uint(e, 5);
        im_cbor_enc_bstr(e, fw_hash, 32);
    }
}

void im_body_config(im_cbor_enc_t *e, uint64_t version, const uint8_t *settings,
                    size_t settings_len)
{
    im_cbor_enc_map(e, 2);
    im_cbor_enc_uint(e, 1);
    im_cbor_enc_uint(e, version);
    im_cbor_enc_uint(e, 2);
    enc_appmap(e, settings, settings_len);
}

void im_body_attestation(im_cbor_enc_t *e, const uint8_t nonce[32], const uint8_t csr_hash[32],
                         const uint8_t fw_hash[32], const char *fw_version, const char *se_type)
{
    im_cbor_enc_map(e, 6);
    im_cbor_enc_uint(e, 1);
    im_cbor_enc_bstr(e, nonce, 32);
    im_cbor_enc_uint(e, 2);
    im_cbor_enc_bstr(e, csr_hash, 32);
    im_cbor_enc_uint(e, 3);
    im_cbor_enc_bstr(e, fw_hash, 32);
    im_cbor_enc_uint(e, 4);
    im_cbor_enc_cstr(e, fw_version);
    im_cbor_enc_uint(e, 5);
    im_cbor_enc_cstr(e, se_type);
    im_cbor_enc_uint(e, 6);
    im_cbor_enc_null(e);
}

im_err_t im_env_sign_uplink(const im_identity_t *id, const uint8_t *kid, size_t kid_len,
                            const uint8_t *payload, size_t payload_len, uint8_t *out, size_t cap,
                            size_t *out_len)
{
    im_signer_t signer;
    im_env_msg_t check;
    if (id == NULL) {
        return IM_ERR_ARG;
    }
    IM_TRY(im_env_check_header_profile(IM_ALG_ES256, kid, kid_len, false, IM_DIR_UPLINK));
    IM_TRY(im_env_decode_payload(payload, payload_len, NULL, &check));
    if (im_msg_direction(check.type) != IM_DIR_UPLINK) {
        return IM_ERR_ENV_DIRECTION;
    }
    im_identity_signer(id, &signer);
    return im_cose_sign1_encode(&signer, kid, kid_len, false, payload, payload_len, NULL, 0, out,
                                cap, out_len);
}

/* ------------------------------------------------------------------------------------------ */
/* In-memory replay store                                                                      */
/* ------------------------------------------------------------------------------------------ */

void im_replay_mem_init(im_replay_mem_t *s)
{
    memset(s, 0, sizeof *s);
}

static im_replay_entry_t *replay_find(im_replay_mem_t *s, const uint8_t *kid, size_t kid_len,
                                      im_direction_t dir)
{
    for (unsigned i = 0; i < IM_REPLAY_MEM_SLOTS; i++) {
        im_replay_entry_t *e = &s->e[i];
        if (e->used && e->dir == (uint8_t)dir && e->kid_len == kid_len &&
            memcmp(e->kid, kid, kid_len) == 0) {
            return e;
        }
    }
    return NULL;
}

static im_err_t replay_mem_cb(void *ctx, const uint8_t *kid, size_t kid_len, im_direction_t dir,
                              uint64_t seq)
{
    im_replay_mem_t *s = (im_replay_mem_t *)ctx;
    im_replay_entry_t *e;
    im_replay_entry_t saved;
    if (kid == NULL || kid_len == 0 || kid_len > IM_REPLAY_KID_MAX) {
        return IM_ERR_ARG;
    }
    e = replay_find(s, kid, kid_len, dir);
    if (e != NULL) {
        if (seq <= e->last_seq) {
            return IM_ERR_ENV_REPLAY;
        }
    } else {
        for (unsigned i = 0; i < IM_REPLAY_MEM_SLOTS && e == NULL; i++) {
            if (!s->e[i].used) {
                e = &s->e[i];
            }
        }
        if (e == NULL) {
            return IM_ERR_FULL; /* fail closed: never evict a sender's window */
        }
        memset(e, 0, sizeof *e);
        e->dir = (uint8_t)dir;
        e->kid_len = (uint8_t)kid_len;
        memcpy(e->kid, kid, kid_len);
    }
    saved = *e;
    e->used = true;
    e->last_seq = seq;
    if (s->persist != NULL) {
        im_err_t err = s->persist(s->persist_ctx, e);
        if (err != IM_OK) {
            *e = saved; /* not durable -> not accepted */
            return err;
        }
    }
    return IM_OK;
}

void im_replay_mem_store(im_replay_mem_t *s, im_replay_store_t *out)
{
    out->check_and_record = replay_mem_cb;
    out->ctx = s;
}

bool im_replay_mem_last(const im_replay_mem_t *s, const uint8_t *kid, size_t kid_len,
                        im_direction_t dir, uint64_t *seq)
{
    for (unsigned i = 0; i < IM_REPLAY_MEM_SLOTS; i++) {
        const im_replay_entry_t *e = &s->e[i];
        if (e->used && e->dir == (uint8_t)dir && e->kid_len == kid_len &&
            memcmp(e->kid, kid, kid_len) == 0) {
            *seq = e->last_seq;
            return true;
        }
    }
    return false;
}
