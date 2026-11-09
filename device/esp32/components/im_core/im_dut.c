/*
 * IronMesh protocol core - DUT control protocol dispatcher (conformance/DUT_PROTOCOL.md).
 *
 * Shared by the host shim (stdio, target "esp32-host") and the HIL firmware build
 * (USB-Serial/JTAG with the "@@IM " prefix, only with CONFIG_IRONMESH_DUT_CONTROL). This file is
 * a test hook: production images are built without it (see tools/check_prod_config.py).
 */
#include <string.h>

#include "im_agent.h"

#define MAX_TOKS 64u

static void resp_begin(im_json_w_t *w, char *out, size_t cap, uint64_t id, bool ok)
{
    im_jw_init(w, out, cap);
    im_jw_obj(w);
    im_jw_key(w, "id");
    im_jw_u64(w, id);
    im_jw_key(w, "ok");
    im_jw_bool(w, ok);
}

static im_err_t resp_error(char *out, size_t cap, size_t *out_len, uint64_t id, const char *code,
                           const char *message)
{
    im_json_w_t w;
    resp_begin(&w, out, cap, id, false);
    im_jw_key(&w, "error");
    im_jw_obj(&w);
    im_jw_key(&w, "code");
    im_jw_cstr(&w, code);
    im_jw_key(&w, "message");
    im_jw_cstr(&w, message);
    im_jw_obj_end(&w);
    im_jw_obj_end(&w);
    return im_jw_finish(&w, out_len);
}

static const char *agent_err_code(im_err_t e)
{
    switch (e) {
    case IM_ERR_BUSY:
        return "busy";
    case IM_ERR_UNSUPPORTED:
        return "unsupported";
    case IM_ERR_ARG:
        return "invalid_args";
    case IM_ERR_STATE:
        return "busy";
    default:
        return "internal";
    }
}

im_err_t im_dut_handle(im_agent_t *a, const im_dut_hooks_t *hooks, const char *line, size_t len,
                       char *out, size_t cap, size_t *out_len)
{
    im_json_tok_t toks[MAX_TOKS];
    im_json_t j;
    im_json_w_t w;
    uint64_t id = 0;
    int t_id;
    int t_op;
    int args;
    char op[32];
    size_t oplen;
    im_err_t err = IM_OK;

    if (a == NULL || line == NULL || out == NULL) {
        return IM_ERR_ARG;
    }
    if (len > 65536u) {
        return resp_error(out, cap, out_len, 0, "invalid_args", "line too long");
    }
    if (im_json_parse(&j, line, len, toks, MAX_TOKS) != IM_OK || toks[0].type != IM_JSON_OBJ) {
        return resp_error(out, cap, out_len, 0, "invalid_args", "malformed request");
    }
    t_id = im_json_get(&j, 0, "id");
    if (t_id < 0 || !im_json_u64(&j, t_id, &id)) {
        return resp_error(out, cap, out_len, 0, "invalid_args", "id must be a u64");
    }
    t_op = im_json_get(&j, 0, "op");
    if (t_op < 0 || !im_json_str(&j, t_op, op, sizeof op, &oplen)) {
        return resp_error(out, cap, out_len, id, "invalid_args", "op must be a string");
    }
    args = im_json_get(&j, 0, "args");
    if (args >= 0 && toks[args].type != IM_JSON_OBJ) {
        return resp_error(out, cap, out_len, id, "invalid_args", "args must be an object");
    }

    if (strcmp(op, "hello") == 0) {
        resp_begin(&w, out, cap, id, true);
        im_jw_key(&w, "result");
        im_jw_obj(&w);
        im_jw_key(&w, "target");
        im_jw_cstr(&w, a->cfg.target ? a->cfg.target : "esp32");
        im_jw_key(&w, "fw_version");
        im_jw_cstr(&w, a->cfg.fw_version);
        im_jw_key(&w, "fw_version_code");
        im_jw_u64(&w, a->cfg.fw_version_code);
        im_jw_key(&w, "se_type");
        im_jw_cstr(&w, a->pf.identity->se_type);
        im_jw_key(&w, "device_id");
        im_jw_cstr(&w, a->cfg.device_id);
        im_jw_key(&w, "tenant_id");
        im_jw_cstr(&w, a->cfg.tenant_id);
        im_jw_key(&w, "protocol_version");
        im_jw_u64(&w, 1);
        im_jw_obj_end(&w);
        im_jw_obj_end(&w);
        return im_jw_finish(&w, out_len);
    }
    if (strcmp(op, "status") == 0) {
        const char *active = a->cfg.active_slot;
        const char *pending = NULL;
        if (hooks != NULL && hooks->slots != NULL) {
            hooks->slots(hooks->ctx, NULL, &active, &pending);
        }
        resp_begin(&w, out, cap, id, true);
        im_jw_key(&w, "result");
        im_jw_obj(&w);
        im_jw_key(&w, "state");
        im_jw_cstr(&w, im_agent_state_name(a->state));
        im_jw_key(&w, "cert_serial_hex");
        if (a->provisioned) {
            im_jw_hex(&w, a->kid, a->kid_len);
        } else {
            im_jw_null(&w);
        }
        im_jw_key(&w, "cert_not_after");
        if (a->provisioned) {
            im_jw_u64(&w, a->cert_not_after);
        } else {
            im_jw_null(&w);
        }
        im_jw_key(&w, "seq_out");
        im_jw_u64(&w, a->seq_out);
        im_jw_key(&w, "buffered");
        im_jw_u64(&w, a->rb_ok ? im_rb_count(&a->rb) : 0);
        im_jw_key(&w, "active_slot");
        im_jw_cstr(&w, active);
        im_jw_key(&w, "pending_slot");
        im_jw_cstr(&w, pending);
        im_jw_key(&w, "version_code");
        im_jw_u64(&w, a->cfg.fw_version_code);
        im_jw_key(&w, "connected_broker");
        if (a->state == IM_ST_CONNECTED) {
            im_jw_cstr(&w, a->broker_host);
        } else {
            im_jw_null(&w);
        }
        im_jw_obj_end(&w);
        im_jw_obj_end(&w);
        return im_jw_finish(&w, out_len);
    }
    if (strcmp(op, "ota_slots") == 0) {
        const char *active = a->cfg.active_slot;
        const char *pending = NULL;
        resp_begin(&w, out, cap, id, true);
        im_jw_key(&w, "result");
        im_jw_obj(&w);
        im_jw_key(&w, "slots");
        im_jw_arr(&w);
        if (hooks != NULL && hooks->slots != NULL) {
            hooks->slots(hooks->ctx, &w, &active, &pending);
        }
        im_jw_arr_end(&w);
        im_jw_key(&w, "active_slot");
        im_jw_cstr(&w, active);
        im_jw_key(&w, "pending_slot");
        im_jw_cstr(&w, pending);
        im_jw_obj_end(&w);
        im_jw_obj_end(&w);
        return im_jw_finish(&w, out_len);
    }
    if (strcmp(op, "send_telemetry") == 0) {
        uint64_t count = 0;
        uint64_t first = 0;
        uint64_t last = 0;
        int t = args >= 0 ? im_json_get(&j, args, "count") : -1;
        if (t < 0 || !im_json_u64(&j, t, &count) || count == 0 || count > 10000u) {
            return resp_error(out, cap, out_len, id, "invalid_args", "count must be 1..10000");
        }
        if (!a->provisioned) {
            return resp_error(out, cap, out_len, id, "not_provisioned", "enroll first");
        }
        err = im_agent_send_telemetry(a, (uint32_t)count, &first, &last);
        if (err != IM_OK) {
            return resp_error(out, cap, out_len, id, agent_err_code(err), im_err_str(err));
        }
        resp_begin(&w, out, cap, id, true);
        im_jw_key(&w, "result");
        im_jw_obj(&w);
        im_jw_key(&w, "first_seq");
        im_jw_u64(&w, first);
        im_jw_key(&w, "last_seq");
        im_jw_u64(&w, last);
        im_jw_obj_end(&w);
        im_jw_obj_end(&w);
        return im_jw_finish(&w, out_len);
    }
    if (strcmp(op, "rejections") == 0) {
        const im_rejection_t *items[IM_AGENT_REJECTIONS];
        uint64_t since = 0;
        size_t n;
        int t = args >= 0 ? im_json_get(&j, args, "since_ms") : -1;
        if (t >= 0 && !im_json_u64(&j, t, &since)) {
            return resp_error(out, cap, out_len, id, "invalid_args", "since_ms must be a u64");
        }
        n = im_agent_rejections(a, since, items, IM_AGENT_REJECTIONS);
        resp_begin(&w, out, cap, id, true);
        im_jw_key(&w, "result");
        im_jw_obj(&w);
        im_jw_key(&w, "items");
        im_jw_arr(&w);
        for (size_t i = 0; i < n; i++) {
            im_jw_obj(&w);
            im_jw_key(&w, "at_ms");
            im_jw_u64(&w, items[i]->at_ms);
            im_jw_key(&w, "code");
            im_jw_cstr(&w, im_err_str(items[i]->code));
            im_jw_key(&w, "topic");
            im_jw_cstr(&w, items[i]->topic);
            im_jw_key(&w, "detail");
            im_jw_cstr(&w, items[i]->detail);
            im_jw_obj_end(&w);
        }
        im_jw_arr_end(&w);
        im_jw_obj_end(&w);
        im_jw_obj_end(&w);
        return im_jw_finish(&w, out_len);
    }

    /* ops with an empty result */
    if (strcmp(op, "enroll") == 0) {
        err = im_agent_enroll(a, false);
    } else if (strcmp(op, "renew") == 0) {
        if (!a->provisioned) {
            return resp_error(out, cap, out_len, id, "not_provisioned", "enroll first");
        }
        err = im_agent_enroll(a, true);
    } else if (strcmp(op, "connect") == 0) {
        if (!a->provisioned) {
            return resp_error(out, cap, out_len, id, "not_provisioned", "enroll first");
        }
        err = im_agent_connect(a);
    } else if (strcmp(op, "disconnect") == 0) {
        err = im_agent_disconnect(a);
    } else if (strcmp(op, "net_down") == 0) {
        im_agent_set_net(a, false);
    } else if (strcmp(op, "net_up") == 0) {
        im_agent_set_net(a, true);
    } else if (strcmp(op, "reboot") == 0) {
        err = im_agent_reboot(a, IM_REBOOT_REQUESTED);
    } else if (strcmp(op, "set_clock") == 0) {
        uint64_t unix_s;
        int t = args >= 0 ? im_json_get(&j, args, "unix_s") : -1;
        if (hooks == NULL || hooks->set_clock == NULL) {
            return resp_error(out, cap, out_len, id, "unsupported", "host targets only");
        }
        if (t < 0 || !im_json_u64(&j, t, &unix_s)) {
            return resp_error(out, cap, out_len, id, "invalid_args", "unix_s must be a u64");
        }
        err = hooks->set_clock(hooks->ctx, unix_s);
    } else if (strcmp(op, "subscribe_raw") == 0) {
        char topic[256];
        int t = args >= 0 ? im_json_get(&j, args, "topic") : -1;
        if (t < 0 || !im_json_str(&j, t, topic, sizeof topic, NULL) || topic[0] == '\0') {
            return resp_error(out, cap, out_len, id, "invalid_args", "topic required");
        }
        err = im_agent_subscribe_raw(a, topic);
    } else if (strcmp(op, "publish_raw") == 0) {
        char topic[256];
        size_t b64_len;
        size_t plen;
        uint64_t qos = 1;
        bool retain = false;
        int tt = args >= 0 ? im_json_get(&j, args, "topic") : -1;
        int tp = args >= 0 ? im_json_get(&j, args, "payload_b64") : -1;
        int tq = args >= 0 ? im_json_get(&j, args, "qos") : -1;
        int tr = args >= 0 ? im_json_get(&j, args, "retain") : -1;
        if (tt < 0 || !im_json_str(&j, tt, topic, sizeof topic, NULL) || topic[0] == '\0' ||
            tp < 0 || !im_json_str(&j, tp, (char *)a->rx, sizeof a->rx, &b64_len) ||
            (tq >= 0 && (!im_json_u64(&j, tq, &qos) || qos > 1u)) ||
            (tr >= 0 && !im_json_bool(&j, tr, &retain)) ||
            im_b64_decode((const char *)a->rx, b64_len, a->work, sizeof a->work, &plen) !=
                IM_OK) {
            return resp_error(out, cap, out_len, id, "invalid_args",
                              "topic, payload_b64 (<= 6 KiB), qos 0|1, retain bool");
        }
        err = im_agent_publish_raw(a, topic, a->work, plen, (int)qos, retain);
    } else {
        return resp_error(out, cap, out_len, id, "unsupported", "unknown op");
    }
    if (err != IM_OK) {
        return resp_error(out, cap, out_len, id, agent_err_code(err), im_err_str(err));
    }
    resp_begin(&w, out, cap, id, true);
    im_jw_key(&w, "result");
    im_jw_obj(&w);
    im_jw_obj_end(&w);
    im_jw_obj_end(&w);
    return im_jw_finish(&w, out_len);
}
