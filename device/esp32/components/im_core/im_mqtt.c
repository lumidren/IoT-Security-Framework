/*
 * IronMesh protocol core - MQTT 5.0 codec and client session (see im_mqtt.h).
 * Section references are to the OASIS MQTT Version 5.0 specification.
 */
#include "im_mqtt.h"

#include <string.h>

#include "im_cbor.h" /* im_utf8_valid */

/* ------------------------------------------------------------------------------------------ */
/* Reader                                                                                      */
/* ------------------------------------------------------------------------------------------ */

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t pos;
} rd_t;

#define MAL IM_ERR_MQTT_MALFORMED
#define PROTO IM_ERR_MQTT_PROTOCOL

static im_err_t rd_u8(rd_t *r, uint8_t *v)
{
    if (r->len - r->pos < 1) {
        return MAL;
    }
    *v = r->p[r->pos++];
    return IM_OK;
}

static im_err_t rd_u16(rd_t *r, uint16_t *v)
{
    if (r->len - r->pos < 2) {
        return MAL;
    }
    *v = (uint16_t)((r->p[r->pos] << 8) | r->p[r->pos + 1]);
    r->pos += 2;
    return IM_OK;
}

static im_err_t rd_u32(rd_t *r, uint32_t *v)
{
    if (r->len - r->pos < 4) {
        return MAL;
    }
    *v = ((uint32_t)r->p[r->pos] << 24) | ((uint32_t)r->p[r->pos + 1] << 16) |
         ((uint32_t)r->p[r->pos + 2] << 8) | r->p[r->pos + 3];
    r->pos += 4;
    return IM_OK;
}

/* §1.5.5 Variable Byte Integer, minimal encoding required */
static im_err_t rd_vbi(rd_t *r, uint32_t *v)
{
    uint32_t value = 0;
    uint32_t mult = 1;
    for (unsigned i = 0; i < 4u; i++) {
        uint8_t b;
        IM_TRY(rd_u8(r, &b));
        value += (uint32_t)(b & 0x7Fu) * mult;
        if ((b & 0x80u) == 0) {
            if (i > 0 && b == 0) {
                return MAL; /* non-minimal */
            }
            *v = value;
            return IM_OK;
        }
        mult *= 128u;
    }
    return MAL;
}

static im_err_t rd_bin(rd_t *r, const uint8_t **p, uint16_t *n)
{
    IM_TRY(rd_u16(r, n));
    if (r->len - r->pos < *n) {
        return MAL;
    }
    *p = r->p + r->pos;
    r->pos += *n;
    return IM_OK;
}

bool im_mqtt_utf8_ok(const char *s, size_t n)
{
    if (n > 0 && memchr(s, 0, n) != NULL) {
        return false;
    }
    return im_utf8_valid((const uint8_t *)s, n);
}

static im_err_t rd_str(rd_t *r, const char **s, uint16_t *n)
{
    const uint8_t *p;
    IM_TRY(rd_bin(r, &p, n));
    if (!im_mqtt_utf8_ok((const char *)p, *n)) {
        return MAL;
    }
    *s = (const char *)p;
    return IM_OK;
}

/* ------------------------------------------------------------------------------------------ */
/* Properties (§2.2.2.2)                                                                       */
/* ------------------------------------------------------------------------------------------ */

enum { PT_BYTE = 1, PT_U16, PT_U32, PT_VBI, PT_STR, PT_BIN, PT_PAIR };
#define WILL_PSEUDO 15u /* will properties inside CONNECT */
#define PK(t) (1u << (t))

typedef struct {
    uint8_t id;
    uint8_t kind;
    uint16_t allowed; /* bit per packet type */
} prop_def_t;

static const prop_def_t k_props[] = {
    {0x01, PT_BYTE, PK(IM_MQTT_PUBLISH) | PK(WILL_PSEUDO)},
    {0x02, PT_U32, PK(IM_MQTT_PUBLISH) | PK(WILL_PSEUDO)},
    {0x03, PT_STR, PK(IM_MQTT_PUBLISH) | PK(WILL_PSEUDO)},
    {0x08, PT_STR, PK(IM_MQTT_PUBLISH) | PK(WILL_PSEUDO)},
    {0x09, PT_BIN, PK(IM_MQTT_PUBLISH) | PK(WILL_PSEUDO)},
    {0x0B, PT_VBI, PK(IM_MQTT_PUBLISH) | PK(IM_MQTT_SUBSCRIBE)},
    {0x11, PT_U32, PK(IM_MQTT_CONNECT) | PK(IM_MQTT_CONNACK) | PK(IM_MQTT_DISCONNECT)},
    {0x12, PT_STR, PK(IM_MQTT_CONNACK)},
    {0x13, PT_U16, PK(IM_MQTT_CONNACK)},
    {0x15, PT_STR, PK(IM_MQTT_CONNECT) | PK(IM_MQTT_CONNACK)},
    {0x16, PT_BIN, PK(IM_MQTT_CONNECT) | PK(IM_MQTT_CONNACK)},
    {0x17, PT_BYTE, PK(IM_MQTT_CONNECT)},
    {0x18, PT_U32, PK(WILL_PSEUDO)},
    {0x19, PT_BYTE, PK(IM_MQTT_CONNECT)},
    {0x1A, PT_STR, PK(IM_MQTT_CONNACK)},
    {0x1C, PT_STR, PK(IM_MQTT_CONNACK) | PK(IM_MQTT_DISCONNECT)},
    {0x1F, PT_STR,
     PK(IM_MQTT_CONNACK) | PK(IM_MQTT_PUBACK) | PK(IM_MQTT_SUBACK) | PK(IM_MQTT_DISCONNECT)},
    {0x21, PT_U16, PK(IM_MQTT_CONNECT) | PK(IM_MQTT_CONNACK)},
    {0x22, PT_U16, PK(IM_MQTT_CONNECT) | PK(IM_MQTT_CONNACK)},
    {0x23, PT_U16, PK(IM_MQTT_PUBLISH)},
    {0x24, PT_BYTE, PK(IM_MQTT_CONNACK)},
    {0x25, PT_BYTE, PK(IM_MQTT_CONNACK)},
    {0x26, PT_PAIR, 0xFFFFu},
    {0x27, PT_U32, PK(IM_MQTT_CONNECT) | PK(IM_MQTT_CONNACK)},
    {0x28, PT_BYTE, PK(IM_MQTT_CONNACK)},
    {0x29, PT_BYTE, PK(IM_MQTT_CONNACK)},
    {0x2A, PT_BYTE, PK(IM_MQTT_CONNACK)},
};

static const prop_def_t *prop_def(uint32_t id)
{
    for (size_t i = 0; i < sizeof k_props / sizeof k_props[0]; i++) {
        if (k_props[i].id == id) {
            return &k_props[i];
        }
    }
    return NULL;
}

static im_err_t parse_props(rd_t *r, unsigned pkt, im_mqtt_props_t *pr)
{
    uint32_t plen;
    size_t end;
    uint64_t seen = 0;
    IM_TRY(rd_vbi(r, &plen));
    if (plen > r->len - r->pos) {
        return MAL;
    }
    end = r->pos + plen;
    while (r->pos < end) {
        uint32_t id;
        const prop_def_t *d;
        uint8_t b = 0;
        uint16_t w = 0;
        uint32_t dw = 0;
        const char *s = NULL;
        const uint8_t *bin = NULL;
        uint16_t n = 0;
        rd_t sub;
        sub.p = r->p;
        sub.len = end;
        sub.pos = r->pos;
        IM_TRY(rd_vbi(&sub, &id));
        d = prop_def(id);
        if (d == NULL || (d->allowed & PK(pkt)) == 0) {
            return MAL;
        }
        if (id != 0x26 && !(id == 0x0B && pkt == IM_MQTT_PUBLISH)) {
            if (seen & ((uint64_t)1u << id)) {
                return PROTO; /* single-use property repeated */
            }
            seen |= (uint64_t)1u << id;
        }
        switch (d->kind) {
        case PT_BYTE:
            IM_TRY(rd_u8(&sub, &b));
            break;
        case PT_U16:
            IM_TRY(rd_u16(&sub, &w));
            break;
        case PT_U32:
            IM_TRY(rd_u32(&sub, &dw));
            break;
        case PT_VBI:
            IM_TRY(rd_vbi(&sub, &dw));
            break;
        case PT_STR:
            IM_TRY(rd_str(&sub, &s, &n));
            break;
        case PT_BIN:
            IM_TRY(rd_bin(&sub, &bin, &n));
            break;
        default: { /* PT_PAIR */
            const char *k;
            uint16_t kn;
            IM_TRY(rd_str(&sub, &k, &kn));
            IM_TRY(rd_str(&sub, &s, &n));
            if (pr->n_user < IM_MQTT_MAX_USER_PROPS) {
                pr->user[pr->n_user].key = k;
                pr->user[pr->n_user].key_len = kn;
                pr->user[pr->n_user].val = s;
                pr->user[pr->n_user].val_len = n;
                pr->n_user++;
            }
            pr->n_user_all++;
            break;
        }
        }
        r->pos = sub.pos;
        switch (id) {
        case 0x01:
            if (b > 1) {
                return PROTO;
            }
            pr->has_payload_format = true;
            pr->payload_format = b;
            break;
        case 0x02:
            pr->has_message_expiry = true;
            pr->message_expiry = dw;
            break;
        case 0x03:
            pr->content_type = s;
            pr->content_type_len = n;
            break;
        case 0x08:
            if (n > 0 && (memchr(s, '+', n) || memchr(s, '#', n))) {
                return PROTO;
            }
            pr->response_topic = s;
            pr->response_topic_len = n;
            break;
        case 0x09:
            pr->correlation = bin;
            pr->correlation_len = n;
            break;
        case 0x0B:
            if (dw == 0) {
                return PROTO;
            }
            if (pr->n_sub_ids < IM_MQTT_MAX_SUB_IDS) {
                pr->sub_ids[pr->n_sub_ids++] = dw;
            }
            break;
        case 0x11:
            pr->has_session_expiry = true;
            pr->session_expiry = dw;
            break;
        case 0x12:
            pr->assigned_client_id = s;
            pr->assigned_client_id_len = n;
            break;
        case 0x13:
            pr->has_server_keep_alive = true;
            pr->server_keep_alive = w;
            break;
        case 0x15:
            pr->auth_method = s;
            pr->auth_method_len = n;
            break;
        case 0x16:
            pr->auth_data = bin;
            pr->auth_data_len = n;
            break;
        case 0x17:
            if (b > 1) {
                return PROTO;
            }
            pr->has_request_problem_info = true;
            pr->request_problem_info = b;
            break;
        case 0x18:
            pr->has_will_delay = true;
            pr->will_delay = dw;
            break;
        case 0x19:
            if (b > 1) {
                return PROTO;
            }
            pr->has_request_response_info = true;
            pr->request_response_info = b;
            break;
        case 0x1A:
            pr->response_info = s;
            pr->response_info_len = n;
            break;
        case 0x1C:
            pr->server_reference = s;
            pr->server_reference_len = n;
            break;
        case 0x1F:
            pr->reason_string = s;
            pr->reason_string_len = n;
            break;
        case 0x21:
            if (w == 0) {
                return PROTO;
            }
            pr->has_receive_maximum = true;
            pr->receive_maximum = w;
            break;
        case 0x22:
            pr->has_topic_alias_maximum = true;
            pr->topic_alias_maximum = w;
            break;
        case 0x23:
            if (w == 0) {
                return PROTO;
            }
            pr->has_topic_alias = true;
            pr->topic_alias = w;
            break;
        case 0x24:
            if (b > 1) {
                return PROTO;
            }
            pr->has_maximum_qos = true;
            pr->maximum_qos = b;
            break;
        case 0x25:
            if (b > 1) {
                return PROTO;
            }
            pr->has_retain_available = true;
            pr->retain_available = b;
            break;
        case 0x27:
            if (dw == 0) {
                return PROTO;
            }
            pr->has_maximum_packet_size = true;
            pr->maximum_packet_size = dw;
            break;
        case 0x28:
            if (b > 1) {
                return PROTO;
            }
            pr->has_wildcard_available = true;
            pr->wildcard_available = b;
            break;
        case 0x29:
            if (b > 1) {
                return PROTO;
            }
            pr->has_sub_id_available = true;
            pr->sub_id_available = b;
            break;
        case 0x2A:
            if (b > 1) {
                return PROTO;
            }
            pr->has_shared_available = true;
            pr->shared_available = b;
            break;
        default: /* user property handled above */
            break;
        }
    }
    return IM_OK;
}

/* ------------------------------------------------------------------------------------------ */
/* Reason codes (§2.4)                                                                         */
/* ------------------------------------------------------------------------------------------ */

static bool in_set(uint8_t v, const uint8_t *set, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (set[i] == v) {
            return true;
        }
    }
    return false;
}

static const uint8_t k_connack_rc[] = {0x00, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
                                       0x87, 0x88, 0x89, 0x8A, 0x8C, 0x90, 0x95, 0x97,
                                       0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9F};
static const uint8_t k_puback_rc[] = {0x00, 0x10, 0x80, 0x83, 0x87, 0x90, 0x91, 0x97, 0x99};
static const uint8_t k_suback_rc[] = {0x00, 0x01, 0x02, 0x80, 0x83, 0x87,
                                      0x8F, 0x91, 0x97, 0x9E, 0xA1, 0xA2};
static const uint8_t k_disconnect_rc[] = {0x00, 0x04, 0x80, 0x81, 0x82, 0x83, 0x87, 0x89,
                                          0x8B, 0x8D, 0x8E, 0x8F, 0x90, 0x93, 0x94, 0x95,
                                          0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
                                          0x9E, 0x9F, 0xA0, 0xA1, 0xA2};

/* ------------------------------------------------------------------------------------------ */
/* Decoder                                                                                     */
/* ------------------------------------------------------------------------------------------ */

im_err_t im_mqtt_frame(const uint8_t *buf, size_t len, size_t max_packet, size_t *frame_len)
{
    uint32_t rl = 0;
    uint32_t mult = 1;
    size_t i;
    if (buf == NULL || frame_len == NULL) {
        return IM_ERR_ARG;
    }
    for (i = 1;; i++) {
        uint8_t b;
        if (i > 4u) {
            return MAL;
        }
        if (i >= len) {
            return IM_ERR_MQTT_INCOMPLETE;
        }
        b = buf[i];
        rl += (uint32_t)(b & 0x7Fu) * mult;
        if ((b & 0x80u) == 0) {
            if (i > 1 && b == 0) {
                return MAL;
            }
            break;
        }
        mult *= 128u;
    }
    if ((size_t)rl + i + 1u > max_packet) {
        return PROTO;
    }
    if (len < (size_t)rl + i + 1u) {
        return IM_ERR_MQTT_INCOMPLETE;
    }
    *frame_len = (size_t)rl + i + 1u;
    return IM_OK;
}

static bool has_wildcard(const char *s, size_t n)
{
    return n > 0 && (memchr(s, '+', n) != NULL || memchr(s, '#', n) != NULL);
}

static im_err_t dec_connect(rd_t *r, im_mqtt_packet_t *out)
{
    const char *name;
    uint16_t nlen;
    uint8_t level;
    uint8_t cf;
    IM_TRY(rd_str(r, &name, &nlen));
    if (nlen != 4 || memcmp(name, "MQTT", 4) != 0) {
        return PROTO;
    }
    IM_TRY(rd_u8(r, &level));
    if (level != 5) {
        return PROTO;
    }
    IM_TRY(rd_u8(r, &cf));
    if (cf & 0x01u) {
        return MAL; /* reserved */
    }
    out->clean_start = (cf & 0x02u) != 0;
    out->has_will = (cf & 0x04u) != 0;
    if (((cf >> 3) & 3u) == 3u || (!out->has_will && (cf & 0x38u) != 0)) {
        return MAL;
    }
    out->has_password = (cf & 0x40u) != 0;
    IM_TRY(rd_u16(r, &out->keep_alive));
    IM_TRY(parse_props(r, IM_MQTT_CONNECT, &out->props));
    IM_TRY(rd_str(r, &out->client_id, &out->client_id_len));
    if (out->has_will) {
        im_mqtt_props_t will;
        const char *wt;
        uint16_t wtl;
        const uint8_t *wp;
        uint16_t wpl;
        memset(&will, 0, sizeof will);
        IM_TRY(parse_props(r, WILL_PSEUDO, &will));
        IM_TRY(rd_str(r, &wt, &wtl));
        if (wtl == 0 || has_wildcard(wt, wtl)) {
            return PROTO;
        }
        IM_TRY(rd_bin(r, &wp, &wpl));
    }
    if (cf & 0x80u) {
        IM_TRY(rd_str(r, &out->username, &out->username_len));
    }
    if (out->has_password) {
        const uint8_t *pw;
        uint16_t pwl;
        IM_TRY(rd_bin(r, &pw, &pwl));
    }
    return IM_OK;
}

im_err_t im_mqtt_decode(const uint8_t *frame, size_t len, im_mqtt_packet_t *out)
{
    size_t flen;
    size_t hdr;
    rd_t r;
    uint8_t type;
    uint8_t flags;
    im_err_t err;

    if (frame == NULL || out == NULL) {
        return IM_ERR_ARG;
    }
    memset(out, 0, sizeof *out);
    err = im_mqtt_frame(frame, len, SIZE_MAX, &flen);
    if (err == IM_ERR_MQTT_INCOMPLETE) {
        return MAL;
    }
    IM_TRY(err);
    if (flen != len) {
        return MAL;
    }
    hdr = 2;
    while ((frame[hdr - 1] & 0x80u) != 0) {
        hdr++;
    }
    type = frame[0] >> 4;
    flags = frame[0] & 0x0Fu;
    out->type = type;
    out->flags = flags;
    r.p = frame;
    r.len = len;
    r.pos = hdr;

    switch (type) {
    case IM_MQTT_CONNECT:
        if (flags != 0) {
            return MAL;
        }
        IM_TRY(dec_connect(&r, out));
        break;
    case IM_MQTT_CONNACK: {
        uint8_t ack;
        if (flags != 0) {
            return MAL;
        }
        IM_TRY(rd_u8(&r, &ack));
        if (ack & 0xFEu) {
            return MAL;
        }
        out->session_present = (ack & 1u) != 0;
        IM_TRY(rd_u8(&r, &out->reason_code));
        if (!in_set(out->reason_code, k_connack_rc, sizeof k_connack_rc)) {
            return MAL;
        }
        if (out->reason_code != 0 && out->session_present) {
            return PROTO;
        }
        IM_TRY(parse_props(&r, IM_MQTT_CONNACK, &out->props));
        break;
    }
    case IM_MQTT_PUBLISH:
        out->qos = (uint8_t)((flags >> 1) & 3u);
        out->dup = (flags & 8u) != 0;
        out->retain = (flags & 1u) != 0;
        if (out->qos == 3u || (out->qos == 0 && out->dup)) {
            return MAL;
        }
        IM_TRY(rd_str(&r, &out->topic, &out->topic_len));
        if (has_wildcard(out->topic, out->topic_len)) {
            return PROTO;
        }
        if (out->qos > 0) {
            IM_TRY(rd_u16(&r, &out->packet_id));
            if (out->packet_id == 0) {
                return PROTO;
            }
        }
        IM_TRY(parse_props(&r, IM_MQTT_PUBLISH, &out->props));
        if (out->topic_len == 0 && !out->props.has_topic_alias) {
            return PROTO;
        }
        out->payload = frame + r.pos;
        out->payload_len = len - r.pos;
        r.pos = len;
        break;
    case IM_MQTT_PUBACK:
        if (flags != 0) {
            return MAL;
        }
        IM_TRY(rd_u16(&r, &out->packet_id));
        if (out->packet_id == 0) {
            return PROTO;
        }
        if (r.pos < len) {
            IM_TRY(rd_u8(&r, &out->reason_code));
            if (!in_set(out->reason_code, k_puback_rc, sizeof k_puback_rc)) {
                return MAL;
            }
        }
        if (r.pos < len) {
            IM_TRY(parse_props(&r, IM_MQTT_PUBACK, &out->props));
        }
        break;
    case IM_MQTT_SUBSCRIBE: {
        size_t n = 0;
        if (flags != 2u) {
            return MAL;
        }
        IM_TRY(rd_u16(&r, &out->packet_id));
        if (out->packet_id == 0) {
            return PROTO;
        }
        IM_TRY(parse_props(&r, IM_MQTT_SUBSCRIBE, &out->props));
        if (r.pos >= len) {
            return PROTO; /* at least one filter */
        }
        while (r.pos < len) {
            const char *f;
            uint16_t fl;
            uint8_t opt;
            IM_TRY(rd_str(&r, &f, &fl));
            IM_TRY(rd_u8(&r, &opt));
            if (fl == 0 || (opt & 0xC0u) != 0 || (opt & 3u) == 3u || ((opt >> 4) & 3u) == 3u) {
                return MAL;
            }
            if (n == 0) {
                out->filter = f;
                out->filter_len = fl;
                out->reason_codes = r.p + r.pos - 1;
            }
            n++;
        }
        out->n_reason_codes = n;
        break;
    }
    case IM_MQTT_SUBACK:
        if (flags != 0) {
            return MAL;
        }
        IM_TRY(rd_u16(&r, &out->packet_id));
        if (out->packet_id == 0) {
            return PROTO;
        }
        IM_TRY(parse_props(&r, IM_MQTT_SUBACK, &out->props));
        if (r.pos >= len) {
            return PROTO;
        }
        out->reason_codes = frame + r.pos;
        out->n_reason_codes = len - r.pos;
        for (size_t i = r.pos; i < len; i++) {
            if (!in_set(frame[i], k_suback_rc, sizeof k_suback_rc)) {
                return MAL;
            }
        }
        r.pos = len;
        break;
    case IM_MQTT_PINGREQ:
    case IM_MQTT_PINGRESP:
        if (flags != 0 || len != hdr) {
            return MAL;
        }
        break;
    case IM_MQTT_DISCONNECT:
        if (flags != 0) {
            return MAL;
        }
        if (r.pos < len) {
            IM_TRY(rd_u8(&r, &out->reason_code));
            if (!in_set(out->reason_code, k_disconnect_rc, sizeof k_disconnect_rc)) {
                return MAL;
            }
        }
        if (r.pos < len) {
            IM_TRY(parse_props(&r, IM_MQTT_DISCONNECT, &out->props));
        }
        break;
    case 0:
    case 15:
        return MAL;
    default:
        return PROTO; /* QoS 2 flow, UNSUBSCRIBE, AUTH: not used by IronMesh devices */
    }
    if (r.pos != len) {
        return MAL;
    }
    return IM_OK;
}

/* ------------------------------------------------------------------------------------------ */
/* Encoders                                                                                    */
/* ------------------------------------------------------------------------------------------ */

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    bool err;
} wr_t;

static void w_bytes(wr_t *w, const void *p, size_t n)
{
    if (w->err || n > w->cap - w->len) {
        w->err = true;
        return;
    }
    if (n) {
        memcpy(w->buf + w->len, p, n);
    }
    w->len += n;
}

static void w_u8(wr_t *w, uint8_t v)
{
    w_bytes(w, &v, 1);
}

static void w_u16(wr_t *w, uint16_t v)
{
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    w_bytes(w, b, 2);
}

static void w_u32(wr_t *w, uint32_t v)
{
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    w_bytes(w, b, 4);
}

static size_t vbi_encode(uint32_t v, uint8_t out[4])
{
    size_t n = 0;
    do {
        uint8_t b = (uint8_t)(v % 128u);
        v /= 128u;
        if (v > 0) {
            b |= 0x80u;
        }
        out[n++] = b;
    } while (v > 0 && n < 4);
    return n;
}

static void w_vbi(wr_t *w, uint32_t v)
{
    uint8_t b[4];
    w_bytes(w, b, vbi_encode(v, b));
}

static void w_str(wr_t *w, const char *s, size_t n)
{
    if (n > 0xFFFFu || (n > 0 && !im_mqtt_utf8_ok(s, n))) {
        w->err = true;
        return;
    }
    w_u16(w, (uint16_t)n);
    w_bytes(w, s, n);
}

/* Body was written at buf+5; move it behind the real fixed header. */
static im_err_t finish(wr_t *w, uint8_t first, size_t *out_len)
{
    size_t body;
    uint8_t h[5];
    size_t hl;
    if (w->err) {
        return IM_ERR_BUFFER;
    }
    body = w->len - 5u;
    if (body > IM_MQTT_VBI_MAX) {
        return IM_ERR_BUFFER;
    }
    h[0] = first;
    hl = 1u + vbi_encode((uint32_t)body, h + 1);
    memmove(w->buf + hl, w->buf + 5, body);
    memcpy(w->buf, h, hl);
    *out_len = hl + body;
    return IM_OK;
}

static bool w_begin(wr_t *w, uint8_t *out, size_t cap)
{
    w->buf = out;
    w->cap = cap;
    w->len = 0;
    w->err = out == NULL || cap < 5;
    if (!w->err) {
        w->len = 5;
    }
    return !w->err;
}

static size_t user_props_len(const im_mqtt_user_prop_t *u, size_t n)
{
    size_t t = 0;
    for (size_t i = 0; i < n; i++) {
        t += 1u + 2u + u[i].key_len + 2u + u[i].val_len;
    }
    return t;
}

static void w_user_props(wr_t *w, const im_mqtt_user_prop_t *u, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        w_u8(w, 0x26);
        w_str(w, u[i].key, u[i].key_len);
        w_str(w, u[i].val, u[i].val_len);
    }
}

im_err_t im_mqtt_enc_connect(const im_mqtt_connect_t *c, uint8_t *out, size_t cap, size_t *len)
{
    wr_t w;
    size_t plen = 0;
    uint8_t flags = 0;
    if (c == NULL || c->client_id == NULL || len == NULL || !w_begin(&w, out, cap)) {
        return IM_ERR_ARG;
    }
    w_str(&w, "MQTT", 4);
    w_u8(&w, 5);
    if (c->clean_start) {
        flags |= 0x02u;
    }
    if (c->username != NULL) {
        flags |= 0x80u;
    }
    w_u8(&w, flags);
    w_u16(&w, c->keep_alive);
    if (c->session_expiry) {
        plen += 5;
    }
    if (c->receive_maximum) {
        plen += 3;
    }
    if (c->maximum_packet_size) {
        plen += 5;
    }
    plen += 2; /* request problem information = 1 */
    plen += user_props_len(c->user, c->n_user);
    w_vbi(&w, (uint32_t)plen);
    if (c->session_expiry) {
        w_u8(&w, 0x11);
        w_u32(&w, c->session_expiry);
    }
    if (c->receive_maximum) {
        w_u8(&w, 0x21);
        w_u16(&w, c->receive_maximum);
    }
    if (c->maximum_packet_size) {
        w_u8(&w, 0x27);
        w_u32(&w, c->maximum_packet_size);
    }
    w_u8(&w, 0x17);
    w_u8(&w, 1);
    w_user_props(&w, c->user, c->n_user);
    w_str(&w, c->client_id, strlen(c->client_id));
    if (c->username != NULL) {
        w_str(&w, c->username, strlen(c->username));
    }
    return finish(&w, (uint8_t)(IM_MQTT_CONNECT << 4), len);
}

im_err_t im_mqtt_enc_publish(const char *topic, size_t topic_len, uint8_t qos, bool retain,
                             bool dup, uint16_t packet_id, const im_mqtt_user_prop_t *user,
                             size_t n_user, const uint8_t *payload, size_t payload_len,
                             uint8_t *out, size_t cap, size_t *len)
{
    wr_t w;
    uint8_t first;
    size_t plen = user_props_len(user, n_user);
    if (topic == NULL || topic_len == 0 || qos > 1u || has_wildcard(topic, topic_len) ||
        (qos == 1u && packet_id == 0) || (qos == 0 && dup) || len == NULL ||
        !w_begin(&w, out, cap)) {
        return IM_ERR_ARG;
    }
    w_str(&w, topic, topic_len);
    if (qos > 0) {
        w_u16(&w, packet_id);
    }
    w_vbi(&w, (uint32_t)plen);
    w_user_props(&w, user, n_user);
    w_bytes(&w, payload, payload_len);
    first = (uint8_t)((IM_MQTT_PUBLISH << 4) | (dup ? 8u : 0u) | (unsigned)(qos << 1) |
                      (retain ? 1u : 0u));
    return finish(&w, first, len);
}

im_err_t im_mqtt_enc_puback(uint16_t packet_id, uint8_t reason, uint8_t *out, size_t cap,
                            size_t *len)
{
    wr_t w;
    if (packet_id == 0 || len == NULL || !w_begin(&w, out, cap)) {
        return IM_ERR_ARG;
    }
    w_u16(&w, packet_id);
    if (reason != 0) {
        w_u8(&w, reason);
    }
    return finish(&w, (uint8_t)(IM_MQTT_PUBACK << 4), len);
}

im_err_t im_mqtt_enc_subscribe(uint16_t packet_id, const char *filter, size_t filter_len,
                               uint8_t options, uint8_t *out, size_t cap, size_t *len)
{
    wr_t w;
    if (packet_id == 0 || filter == NULL || filter_len == 0 || len == NULL ||
        !w_begin(&w, out, cap)) {
        return IM_ERR_ARG;
    }
    w_u16(&w, packet_id);
    w_vbi(&w, 0);
    w_str(&w, filter, filter_len);
    w_u8(&w, options);
    return finish(&w, (uint8_t)((IM_MQTT_SUBSCRIBE << 4) | 2u), len);
}

static im_err_t enc_empty(uint8_t type, uint8_t *out, size_t cap, size_t *len)
{
    if (out == NULL || cap < 2 || len == NULL) {
        return IM_ERR_BUFFER;
    }
    out[0] = (uint8_t)(type << 4);
    out[1] = 0;
    *len = 2;
    return IM_OK;
}

im_err_t im_mqtt_enc_pingreq(uint8_t *out, size_t cap, size_t *len)
{
    return enc_empty(IM_MQTT_PINGREQ, out, cap, len);
}

im_err_t im_mqtt_enc_pingresp(uint8_t *out, size_t cap, size_t *len)
{
    return enc_empty(IM_MQTT_PINGRESP, out, cap, len);
}

im_err_t im_mqtt_enc_disconnect(uint8_t reason, uint8_t *out, size_t cap, size_t *len)
{
    wr_t w;
    if (reason == 0) {
        return enc_empty(IM_MQTT_DISCONNECT, out, cap, len);
    }
    if (len == NULL || !w_begin(&w, out, cap)) {
        return IM_ERR_ARG;
    }
    w_u8(&w, reason);
    return finish(&w, (uint8_t)(IM_MQTT_DISCONNECT << 4), len);
}

im_err_t im_mqtt_enc_connack(bool session_present, uint8_t reason, uint16_t receive_maximum,
                             uint8_t *out, size_t cap, size_t *len)
{
    wr_t w;
    if (len == NULL || !w_begin(&w, out, cap)) {
        return IM_ERR_ARG;
    }
    w_u8(&w, session_present ? 1u : 0u);
    w_u8(&w, reason);
    if (receive_maximum) {
        w_vbi(&w, 3);
        w_u8(&w, 0x21);
        w_u16(&w, receive_maximum);
    } else {
        w_vbi(&w, 0);
    }
    return finish(&w, (uint8_t)(IM_MQTT_CONNACK << 4), len);
}

im_err_t im_mqtt_enc_suback(uint16_t packet_id, const uint8_t *codes, size_t n, uint8_t *out,
                            size_t cap, size_t *len)
{
    wr_t w;
    if (packet_id == 0 || codes == NULL || n == 0 || len == NULL || !w_begin(&w, out, cap)) {
        return IM_ERR_ARG;
    }
    w_u16(&w, packet_id);
    w_vbi(&w, 0);
    w_bytes(&w, codes, n);
    return finish(&w, (uint8_t)(IM_MQTT_SUBACK << 4), len);
}

/* ------------------------------------------------------------------------------------------ */
/* Session                                                                                     */
/* ------------------------------------------------------------------------------------------ */

void im_mqtt_session_init(im_mqtt_session_t *s, const im_mqtt_session_cb_t *cb)
{
    memset(s, 0, sizeof *s);
    s->cb = *cb;
    s->next_pid = 1;
    s->receive_maximum = 65535u;
}

void im_mqtt_session_reset(im_mqtt_session_t *s)
{
    s->connected = false;
    s->awaiting_connack = false;
    s->rx_len = 0;
    s->ping_outstanding = false;
    memset(s->inflight, 0, sizeof s->inflight);
}

size_t im_mqtt_session_inflight(const im_mqtt_session_t *s)
{
    size_t n = 0;
    for (unsigned i = 0; i < IM_MQTT_INFLIGHT; i++) {
        if (s->inflight[i] != 0) {
            n++;
        }
    }
    return n;
}

static im_err_t sess_send(im_mqtt_session_t *s, size_t n, uint64_t now_ms)
{
    if (s->cb.send == NULL) {
        return IM_ERR_STATE;
    }
    IM_TRY(s->cb.send(s->cb.ctx, s->tx, n));
    s->last_tx_ms = now_ms;
    return IM_OK;
}

im_err_t im_mqtt_session_connect(im_mqtt_session_t *s, const im_mqtt_connect_t *c,
                                 uint64_t now_ms)
{
    size_t n;
    im_mqtt_session_reset(s);
    IM_TRY(im_mqtt_enc_connect(c, s->tx, sizeof s->tx, &n));
    s->keep_alive = c->keep_alive;
    s->awaiting_connack = true;
    return sess_send(s, n, now_ms);
}

static void sess_fail(im_mqtt_session_t *s, uint8_t reason)
{
    size_t n;
    if ((s->connected || s->awaiting_connack) &&
        im_mqtt_enc_disconnect(reason, s->tx, sizeof s->tx, &n) == IM_OK && s->cb.send) {
        (void)s->cb.send(s->cb.ctx, s->tx, n);
    }
    im_mqtt_session_reset(s);
    if (s->cb.on_disconnect) {
        s->cb.on_disconnect(s->cb.ctx, reason, false);
    }
}

static im_err_t sess_handle(im_mqtt_session_t *s, const im_mqtt_packet_t *p, uint64_t now_ms)
{
    size_t n;
    switch (p->type) {
    case IM_MQTT_CONNACK:
        if (!s->awaiting_connack) {
            return PROTO;
        }
        s->awaiting_connack = false;
        s->connected = p->reason_code == 0;
        s->receive_maximum = p->props.has_receive_maximum ? p->props.receive_maximum : 65535u;
        if (p->props.has_server_keep_alive) {
            s->keep_alive = p->props.server_keep_alive;
        }
        if (s->cb.on_connack) {
            s->cb.on_connack(s->cb.ctx, p->session_present, p->reason_code);
        }
        if (!s->connected) {
            im_mqtt_session_reset(s);
        }
        return IM_OK;
    case IM_MQTT_PUBLISH:
        if (!s->connected || p->qos > 1u || p->props.has_topic_alias) {
            return PROTO;
        }
        if (s->cb.on_publish) {
            s->cb.on_publish(s->cb.ctx, p);
        }
        if (p->qos == 1u) {
            IM_TRY(im_mqtt_enc_puback(p->packet_id, 0, s->tx, sizeof s->tx, &n));
            IM_TRY(sess_send(s, n, now_ms));
        }
        return IM_OK;
    case IM_MQTT_PUBACK:
        if (!s->connected) {
            return PROTO;
        }
        for (unsigned i = 0; i < IM_MQTT_INFLIGHT; i++) {
            if (s->inflight[i] == p->packet_id) {
                s->inflight[i] = 0;
                if (s->cb.on_puback) {
                    s->cb.on_puback(s->cb.ctx, p->packet_id, p->reason_code);
                }
                break;
            }
        }
        return IM_OK;
    case IM_MQTT_SUBACK:
        if (!s->connected) {
            return PROTO;
        }
        if (s->cb.on_suback) {
            s->cb.on_suback(s->cb.ctx, p->packet_id, p->reason_codes[0]);
        }
        return IM_OK;
    case IM_MQTT_PINGRESP:
        s->ping_outstanding = false;
        return IM_OK;
    case IM_MQTT_DISCONNECT:
        im_mqtt_session_reset(s);
        if (s->cb.on_disconnect) {
            s->cb.on_disconnect(s->cb.ctx, p->reason_code, true);
        }
        return IM_OK;
    default:
        return PROTO; /* client-to-server packets from the broker */
    }
}

im_err_t im_mqtt_session_input(im_mqtt_session_t *s, const uint8_t *data, size_t len,
                               uint64_t now_ms)
{
    if (len > sizeof s->rx - s->rx_len) {
        sess_fail(s, 0x95); /* packet too large */
        return IM_ERR_MQTT_PROTOCOL;
    }
    memcpy(s->rx + s->rx_len, data, len);
    s->rx_len += len;
    for (;;) {
        size_t flen;
        im_mqtt_packet_t p;
        im_err_t err = im_mqtt_frame(s->rx, s->rx_len, sizeof s->rx, &flen);
        if (err == IM_ERR_MQTT_INCOMPLETE) {
            return IM_OK;
        }
        if (err == IM_OK) {
            err = im_mqtt_decode(s->rx, flen, &p);
        }
        if (err == IM_OK) {
            err = sess_handle(s, &p, now_ms);
        }
        if (err != IM_OK) {
            sess_fail(s, err == IM_ERR_MQTT_MALFORMED ? 0x81 : 0x82);
            return err;
        }
        if (s->rx_len == 0) {
            return IM_OK; /* session was reset by the handler */
        }
        memmove(s->rx, s->rx + flen, s->rx_len - flen);
        s->rx_len -= flen;
    }
}

im_err_t im_mqtt_session_publish(im_mqtt_session_t *s, const char *topic, const uint8_t *payload,
                                 size_t len, uint8_t qos, bool retain,
                                 const im_mqtt_user_prop_t *user, size_t n_user,
                                 uint16_t *packet_id, uint64_t now_ms)
{
    size_t n;
    int slot = -1;
    uint16_t pid = 0;
    if (!s->connected) {
        return IM_ERR_STATE;
    }
    if (qos == 1u) {
        size_t limit = s->receive_maximum < IM_MQTT_INFLIGHT ? s->receive_maximum
                                                             : IM_MQTT_INFLIGHT;
        if (im_mqtt_session_inflight(s) >= limit) {
            return IM_ERR_BUSY;
        }
        for (unsigned i = 0; i < IM_MQTT_INFLIGHT; i++) {
            if (s->inflight[i] == 0) {
                slot = (int)i;
                break;
            }
        }
        for (;;) {
            bool used = false;
            pid = s->next_pid++;
            if (s->next_pid == 0) {
                s->next_pid = 1;
            }
            for (unsigned i = 0; i < IM_MQTT_INFLIGHT; i++) {
                used = used || s->inflight[i] == pid;
            }
            if (pid != 0 && !used) {
                break;
            }
        }
    }
    IM_TRY(im_mqtt_enc_publish(topic, strlen(topic), qos, retain, false, pid, user, n_user,
                               payload, len, s->tx, sizeof s->tx, &n));
    IM_TRY(sess_send(s, n, now_ms));
    if (slot >= 0) {
        s->inflight[slot] = pid;
    }
    if (packet_id != NULL) {
        *packet_id = pid;
    }
    return IM_OK;
}

im_err_t im_mqtt_session_subscribe(im_mqtt_session_t *s, const char *filter, uint8_t qos,
                                   uint16_t *packet_id, uint64_t now_ms)
{
    size_t n;
    uint16_t pid;
    if (!s->connected) {
        return IM_ERR_STATE;
    }
    pid = s->next_pid++;
    if (s->next_pid == 0) {
        s->next_pid = 1;
    }
    IM_TRY(im_mqtt_enc_subscribe(pid, filter, strlen(filter), qos, s->tx, sizeof s->tx, &n));
    IM_TRY(sess_send(s, n, now_ms));
    if (packet_id != NULL) {
        *packet_id = pid;
    }
    return IM_OK;
}

im_err_t im_mqtt_session_disconnect(im_mqtt_session_t *s, uint8_t reason)
{
    size_t n;
    im_err_t err = IM_OK;
    if (s->connected) {
        err = im_mqtt_enc_disconnect(reason, s->tx, sizeof s->tx, &n);
        if (err == IM_OK) {
            err = sess_send(s, n, s->last_tx_ms);
        }
    }
    im_mqtt_session_reset(s);
    return err;
}

im_err_t im_mqtt_session_tick(im_mqtt_session_t *s, uint64_t now_ms)
{
    size_t n;
    uint64_t ka = (uint64_t)s->keep_alive * 1000u;
    if (!s->connected || ka == 0) {
        return IM_OK;
    }
    if (s->ping_outstanding && now_ms - s->ping_sent_ms > ka + ka / 2u) {
        im_mqtt_session_reset(s);
        if (s->cb.on_disconnect) {
            s->cb.on_disconnect(s->cb.ctx, 0x8D, false); /* keep alive timeout */
        }
        return IM_ERR_TIMEOUT;
    }
    if (!s->ping_outstanding && now_ms - s->last_tx_ms >= ka) {
        IM_TRY(im_mqtt_enc_pingreq(s->tx, sizeof s->tx, &n));
        IM_TRY(sess_send(s, n, now_ms));
        s->ping_outstanding = true;
        s->ping_sent_ms = now_ms;
    }
    return IM_OK;
}
