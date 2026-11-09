/*
 * IronMesh protocol core - command idempotency cache, base64 and a bounded JSON subset
 * (see im_util.h). The JSON parser is RFC 8259 strict with recursion bounded by
 * IM_JSON_MAX_DEPTH and a caller-provided token array (no allocation).
 */
#include <string.h>

#include "im_cbor.h"
#include "im_crypto.h"
#include "im_util.h"

/* ------------------------------------------------------------------------------------------ */
/* Command idempotency cache                                                                   */
/* ------------------------------------------------------------------------------------------ */

void im_cmd_cache_init(im_cmd_cache_t *c)
{
    memset(c, 0, sizeof *c);
}

static im_err_t key_hash(const char *key, size_t n, uint8_t out[16])
{
    uint8_t d[32];
    IM_TRY(im_sha256((const uint8_t *)key, n, d));
    memcpy(out, d, 16);
    return IM_OK;
}

im_err_t im_cmd_cache_lookup(im_cmd_cache_t *c, const char *key, size_t key_len, uint64_t now,
                             uint8_t *status, char cmd_id[37])
{
    uint8_t h[16];
    IM_TRY(key_hash(key, key_len, h));
    for (unsigned i = 0; i < IM_CMD_CACHE_SLOTS; i++) {
        im_cmd_entry_t *e = &c->e[i];
        if (!e->used) {
            continue;
        }
        if (e->keep_until < now) {
            e->used = false; /* expired */
            continue;
        }
        if (memcmp(e->key_hash, h, 16) == 0) {
            e->lru = ++c->tick;
            if (status != NULL) {
                *status = e->status;
            }
            if (cmd_id != NULL) {
                memcpy(cmd_id, e->cmd_id, 37);
            }
            return IM_OK;
        }
    }
    return IM_ERR_NOT_FOUND;
}

im_err_t im_cmd_cache_store(im_cmd_cache_t *c, const char *key, size_t key_len,
                            const char *cmd_id, uint8_t status, uint64_t expires_at,
                            uint64_t now)
{
    uint8_t h[16];
    im_cmd_entry_t *slot = NULL;
    IM_TRY(key_hash(key, key_len, h));
    for (unsigned i = 0; i < IM_CMD_CACHE_SLOTS && slot == NULL; i++) {
        if (c->e[i].used && memcmp(c->e[i].key_hash, h, 16) == 0) {
            slot = &c->e[i];
        }
    }
    for (unsigned i = 0; i < IM_CMD_CACHE_SLOTS && slot == NULL; i++) {
        if (!c->e[i].used || c->e[i].keep_until < now) {
            slot = &c->e[i];
        }
    }
    if (slot == NULL) {
        slot = &c->e[0];
        for (unsigned i = 1; i < IM_CMD_CACHE_SLOTS; i++) {
            if (c->e[i].lru < slot->lru) {
                slot = &c->e[i];
            }
        }
    }
    memset(slot, 0, sizeof *slot);
    slot->used = true;
    memcpy(slot->key_hash, h, 16);
    if (cmd_id != NULL) {
        size_t n = strlen(cmd_id);
        memcpy(slot->cmd_id, cmd_id, n > 36 ? 36 : n);
    }
    slot->status = status;
    slot->keep_until = (expires_at > now ? expires_at : now) + IM_CMD_RETAIN_S;
    slot->lru = ++c->tick;
    return IM_OK;
}

/* ------------------------------------------------------------------------------------------ */
/* base64                                                                                      */
/* ------------------------------------------------------------------------------------------ */

static const char k_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t im_b64_encoded_len(size_t n)
{
    return ((n + 2u) / 3u) * 4u;
}

im_err_t im_b64_encode(const uint8_t *in, size_t n, char *out, size_t cap, size_t *out_len)
{
    size_t need = im_b64_encoded_len(n);
    size_t o = 0;
    if (out == NULL || cap < need + 1u || (in == NULL && n != 0)) {
        return IM_ERR_BUFFER;
    }
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) {
            v |= (uint32_t)in[i + 1] << 8;
        }
        if (i + 2 < n) {
            v |= in[i + 2];
        }
        out[o++] = k_b64[(v >> 18) & 63u];
        out[o++] = k_b64[(v >> 12) & 63u];
        out[o++] = i + 1 < n ? k_b64[(v >> 6) & 63u] : '=';
        out[o++] = i + 2 < n ? k_b64[v & 63u] : '=';
    }
    out[o] = '\0';
    if (out_len != NULL) {
        *out_len = o;
    }
    return IM_OK;
}

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

im_err_t im_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t o = 0;
    if ((in == NULL && n != 0) || n % 4u != 0) {
        return IM_ERR_ARG;
    }
    for (size_t i = 0; i < n; i += 4) {
        int v[4];
        unsigned pad = 0;
        uint32_t x;
        for (unsigned k = 0; k < 4u; k++) {
            char c = in[i + k];
            if (c == '=') {
                if (i + 4 != n || k < 2) {
                    return IM_ERR_ARG;
                }
                pad++;
                v[k] = 0;
            } else {
                if (pad) {
                    return IM_ERR_ARG; /* data after padding */
                }
                v[k] = b64_val(c);
                if (v[k] < 0) {
                    return IM_ERR_ARG;
                }
            }
        }
        x = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) | ((uint32_t)v[2] << 6) |
            (uint32_t)v[3];
        if ((pad == 1 && (x & 0xFFu)) || (pad == 2 && (x & 0xFFFFu))) {
            return IM_ERR_ARG; /* non-canonical trailing bits */
        }
        if (cap - o < 3u - pad || o > cap) {
            return IM_ERR_BUFFER;
        }
        out[o++] = (uint8_t)(x >> 16);
        if (pad < 2) {
            out[o++] = (uint8_t)(x >> 8);
        }
        if (pad < 1) {
            out[o++] = (uint8_t)x;
        }
    }
    if (out_len != NULL) {
        *out_len = o;
    }
    return IM_OK;
}

/* ------------------------------------------------------------------------------------------ */
/* JSON parser                                                                                 */
/* ------------------------------------------------------------------------------------------ */

typedef struct {
    const char *s;
    size_t n;
    size_t pos;
    im_json_tok_t *t;
    size_t max;
    size_t cnt;
} jp_t;

static void ws(jp_t *p)
{
    while (p->pos < p->n &&
           (p->s[p->pos] == ' ' || p->s[p->pos] == '\t' || p->s[p->pos] == '\n' ||
            p->s[p->pos] == '\r')) {
        p->pos++;
    }
}

static int hexv(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static bool hex4(const char *s, uint32_t *v)
{
    *v = 0;
    for (int i = 0; i < 4; i++) {
        int h = hexv(s[i]);
        if (h < 0) {
            return false;
        }
        *v = (*v << 4) | (uint32_t)h;
    }
    return true;
}

static im_err_t new_tok(jp_t *p, uint8_t type, size_t *idx)
{
    if (p->cnt >= p->max || p->pos > UINT32_MAX) {
        return IM_ERR_JSON;
    }
    *idx = p->cnt++;
    memset(&p->t[*idx], 0, sizeof p->t[*idx]);
    p->t[*idx].type = type;
    p->t[*idx].start = (uint32_t)p->pos;
    return IM_OK;
}

static im_err_t p_string(jp_t *p)
{
    size_t idx;
    IM_TRY(new_tok(p, IM_JSON_STR, &idx));
    p->pos++; /* opening quote */
    p->t[idx].start = (uint32_t)p->pos;
    while (p->pos < p->n) {
        unsigned char c = (unsigned char)p->s[p->pos];
        if (c == '"') {
            p->t[idx].end = (uint32_t)p->pos;
            p->t[idx].span = 1;
            p->pos++;
            return IM_OK;
        }
        if (c < 0x20u) {
            return IM_ERR_JSON;
        }
        if (c == '\\') {
            char e;
            if (p->n - p->pos < 2) {
                return IM_ERR_JSON;
            }
            e = p->s[p->pos + 1];
            if (e == 'u') {
                uint32_t u;
                if (p->n - p->pos < 6 || !hex4(p->s + p->pos + 2, &u)) {
                    return IM_ERR_JSON;
                }
                p->pos += 6;
                if (u >= 0xDC00u && u <= 0xDFFFu) {
                    return IM_ERR_JSON; /* lone low surrogate */
                }
                if (u >= 0xD800u && u <= 0xDBFFu) {
                    uint32_t lo;
                    if (p->n - p->pos < 6 || p->s[p->pos] != '\\' || p->s[p->pos + 1] != 'u' ||
                        !hex4(p->s + p->pos + 2, &lo) || lo < 0xDC00u || lo > 0xDFFFu) {
                        return IM_ERR_JSON;
                    }
                    p->pos += 6;
                }
                continue;
            }
            if (e != '"' && e != '\\' && e != '/' && e != 'b' && e != 'f' && e != 'n' &&
                e != 'r' && e != 't') {
                return IM_ERR_JSON;
            }
            p->pos += 2;
            continue;
        }
        p->pos++;
    }
    return IM_ERR_JSON;
}

static bool digit(char c)
{
    return c >= '0' && c <= '9';
}

static im_err_t p_number(jp_t *p)
{
    size_t idx;
    IM_TRY(new_tok(p, IM_JSON_NUM, &idx));
    if (p->s[p->pos] == '-') {
        p->pos++;
    }
    if (p->pos >= p->n || !digit(p->s[p->pos])) {
        return IM_ERR_JSON;
    }
    if (p->s[p->pos] == '0') {
        p->pos++;
    } else {
        while (p->pos < p->n && digit(p->s[p->pos])) {
            p->pos++;
        }
    }
    if (p->pos < p->n && p->s[p->pos] == '.') {
        p->pos++;
        if (p->pos >= p->n || !digit(p->s[p->pos])) {
            return IM_ERR_JSON;
        }
        while (p->pos < p->n && digit(p->s[p->pos])) {
            p->pos++;
        }
    }
    if (p->pos < p->n && (p->s[p->pos] == 'e' || p->s[p->pos] == 'E')) {
        p->pos++;
        if (p->pos < p->n && (p->s[p->pos] == '+' || p->s[p->pos] == '-')) {
            p->pos++;
        }
        if (p->pos >= p->n || !digit(p->s[p->pos])) {
            return IM_ERR_JSON;
        }
        while (p->pos < p->n && digit(p->s[p->pos])) {
            p->pos++;
        }
    }
    p->t[idx].end = (uint32_t)p->pos;
    p->t[idx].span = 1;
    return IM_OK;
}

static im_err_t p_lit(jp_t *p, const char *lit, uint8_t type)
{
    size_t idx;
    size_t n = strlen(lit);
    if (p->n - p->pos < n || memcmp(p->s + p->pos, lit, n) != 0) {
        return IM_ERR_JSON;
    }
    IM_TRY(new_tok(p, type, &idx));
    p->pos += n;
    p->t[idx].end = (uint32_t)p->pos;
    p->t[idx].span = 1;
    return IM_OK;
}

static im_err_t p_value(jp_t *p, unsigned depth);

static im_err_t p_container(jp_t *p, unsigned depth, bool obj)
{
    size_t idx;
    char close = obj ? '}' : ']';
    IM_TRY(new_tok(p, obj ? IM_JSON_OBJ : IM_JSON_ARR, &idx));
    p->pos++;
    ws(p);
    if (p->pos < p->n && p->s[p->pos] == close) {
        p->pos++;
    } else {
        for (;;) {
            ws(p);
            if (obj) {
                if (p->pos >= p->n || p->s[p->pos] != '"') {
                    return IM_ERR_JSON;
                }
                IM_TRY(p_string(p));
                ws(p);
                if (p->pos >= p->n || p->s[p->pos] != ':') {
                    return IM_ERR_JSON;
                }
                p->pos++;
            }
            IM_TRY(p_value(p, depth + 1u));
            p->t[idx].size++;
            ws(p);
            if (p->pos < p->n && p->s[p->pos] == ',') {
                p->pos++;
                continue;
            }
            if (p->pos < p->n && p->s[p->pos] == close) {
                p->pos++;
                break;
            }
            return IM_ERR_JSON;
        }
    }
    p->t[idx].end = (uint32_t)p->pos;
    p->t[idx].span = (uint32_t)(p->cnt - idx);
    return IM_OK;
}

/* recursion bounded by IM_JSON_MAX_DEPTH */
static im_err_t p_value(jp_t *p, unsigned depth)
{
    char c;
    if (depth > IM_JSON_MAX_DEPTH) {
        return IM_ERR_JSON;
    }
    ws(p);
    if (p->pos >= p->n) {
        return IM_ERR_JSON;
    }
    c = p->s[p->pos];
    switch (c) {
    case '{':
        return p_container(p, depth, true);
    case '[':
        return p_container(p, depth, false);
    case '"':
        return p_string(p);
    case 't':
        return p_lit(p, "true", IM_JSON_TRUE);
    case 'f':
        return p_lit(p, "false", IM_JSON_FALSE);
    case 'n':
        return p_lit(p, "null", IM_JSON_NULL);
    default:
        if (c == '-' || digit(c)) {
            return p_number(p);
        }
        return IM_ERR_JSON;
    }
}

im_err_t im_json_parse(im_json_t *j, const char *js, size_t len, im_json_tok_t *toks,
                       size_t max_toks)
{
    jp_t p;
    if (j == NULL || js == NULL || toks == NULL || max_toks == 0 || len > UINT32_MAX) {
        return IM_ERR_ARG;
    }
    if (!im_utf8_valid((const uint8_t *)js, len)) {
        return IM_ERR_JSON;
    }
    p.s = js;
    p.n = len;
    p.pos = 0;
    p.t = toks;
    p.max = max_toks;
    p.cnt = 0;
    IM_TRY(p_value(&p, 1u));
    ws(&p);
    if (p.pos != len) {
        return IM_ERR_JSON;
    }
    j->js = js;
    j->len = len;
    j->tok = toks;
    j->ntok = p.cnt;
    return IM_OK;
}

static size_t utf8_put(uint32_t cp, char *out)
{
    if (cp < 0x80u) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800u) {
        out[0] = (char)(0xC0u | (cp >> 6));
        out[1] = (char)(0x80u | (cp & 0x3Fu));
        return 2;
    }
    if (cp < 0x10000u) {
        out[0] = (char)(0xE0u | (cp >> 12));
        out[1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[2] = (char)(0x80u | (cp & 0x3Fu));
        return 3;
    }
    out[0] = (char)(0xF0u | (cp >> 18));
    out[1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
    out[2] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
    out[3] = (char)(0x80u | (cp & 0x3Fu));
    return 4;
}

bool im_json_str(const im_json_t *j, int tok, char *out, size_t cap, size_t *len)
{
    const im_json_tok_t *t;
    size_t o = 0;
    if (tok < 0 || (size_t)tok >= j->ntok || out == NULL || cap == 0) {
        return false;
    }
    t = &j->tok[tok];
    if (t->type != IM_JSON_STR) {
        return false;
    }
    for (size_t i = t->start; i < t->end;) {
        char c = j->js[i];
        char tmp[4];
        size_t k = 1;
        if (c != '\\') {
            tmp[0] = c;
            i++;
        } else {
            char e = j->js[i + 1];
            uint32_t cp;
            switch (e) {
            case 'b':
                tmp[0] = '\b';
                break;
            case 'f':
                tmp[0] = '\f';
                break;
            case 'n':
                tmp[0] = '\n';
                break;
            case 'r':
                tmp[0] = '\r';
                break;
            case 't':
                tmp[0] = '\t';
                break;
            case 'u':
                (void)hex4(j->js + i + 2, &cp);
                i += 6;
                if (cp >= 0xD800u && cp <= 0xDBFFu) {
                    uint32_t lo;
                    (void)hex4(j->js + i + 2, &lo);
                    i += 6;
                    cp = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
                }
                if (cp == 0) {
                    return false; /* would truncate a C string */
                }
                k = utf8_put(cp, tmp);
                if (cap - o <= k) {
                    return false;
                }
                memcpy(out + o, tmp, k);
                o += k;
                continue;
            default:
                tmp[0] = e; /* " \ / */
                break;
            }
            i += 2;
        }
        if (cap - o <= k) {
            return false;
        }
        memcpy(out + o, tmp, k);
        o += k;
    }
    out[o] = '\0';
    if (len != NULL) {
        *len = o;
    }
    return true;
}

int im_json_get(const im_json_t *j, int obj, const char *key)
{
    size_t idx;
    char kb[64];
    if (obj < 0 || (size_t)obj >= j->ntok || j->tok[obj].type != IM_JSON_OBJ || key == NULL) {
        return -1;
    }
    idx = (size_t)obj + 1u;
    for (uint32_t m = 0; m < j->tok[obj].size; m++) {
        size_t val = idx + 1u;
        size_t kl;
        if (val >= j->ntok) {
            return -1;
        }
        if (im_json_str(j, (int)idx, kb, sizeof kb, &kl) && strcmp(kb, key) == 0) {
            return (int)val;
        }
        idx = val + j->tok[val].span;
    }
    return -1;
}

bool im_json_u64(const im_json_t *j, int tok, uint64_t *out)
{
    const im_json_tok_t *t;
    uint64_t v = 0;
    if (tok < 0 || (size_t)tok >= j->ntok) {
        return false;
    }
    t = &j->tok[tok];
    if (t->type != IM_JSON_NUM) {
        return false;
    }
    for (size_t i = t->start; i < t->end; i++) {
        char c = j->js[i];
        if (!digit(c) || v > (UINT64_MAX - (uint64_t)(c - '0')) / 10u) {
            return false;
        }
        v = v * 10u + (uint64_t)(c - '0');
    }
    *out = v;
    return true;
}

bool im_json_bool(const im_json_t *j, int tok, bool *out)
{
    if (tok < 0 || (size_t)tok >= j->ntok) {
        return false;
    }
    if (j->tok[tok].type == IM_JSON_TRUE) {
        *out = true;
        return true;
    }
    if (j->tok[tok].type == IM_JSON_FALSE) {
        *out = false;
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------------------------------ */
/* JSON writer                                                                                 */
/* ------------------------------------------------------------------------------------------ */

static void jw_put(im_json_w_t *w, const char *s, size_t n)
{
    if (w->err || n >= w->cap - w->len) {
        w->err = true;
        return;
    }
    memcpy(w->buf + w->len, s, n);
    w->len += n;
}

static void jw_sep(im_json_w_t *w)
{
    if (w->after_key) {
        w->after_key = false;
        return;
    }
    if (!w->first[w->depth]) {
        jw_put(w, ",", 1);
    }
    w->first[w->depth] = false;
}

void im_jw_init(im_json_w_t *w, char *buf, size_t cap)
{
    memset(w, 0, sizeof *w);
    w->buf = buf;
    w->cap = cap;
    w->err = buf == NULL || cap == 0;
    w->first[0] = true;
}

static void jw_open(im_json_w_t *w, const char *c)
{
    jw_sep(w);
    jw_put(w, c, 1);
    if (w->depth >= IM_JSON_MAX_DEPTH) {
        w->err = true;
        return;
    }
    w->depth++;
    w->first[w->depth] = true;
}

static void jw_close(im_json_w_t *w, const char *c)
{
    if (w->depth == 0) {
        w->err = true;
        return;
    }
    w->depth--;
    jw_put(w, c, 1);
}

void im_jw_obj(im_json_w_t *w)
{
    jw_open(w, "{");
}

void im_jw_obj_end(im_json_w_t *w)
{
    jw_close(w, "}");
}

void im_jw_arr(im_json_w_t *w)
{
    jw_open(w, "[");
}

void im_jw_arr_end(im_json_w_t *w)
{
    jw_close(w, "]");
}

static void jw_quoted(im_json_w_t *w, const char *s, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    if (n > 0 && !im_utf8_valid((const uint8_t *)s, n)) {
        w->err = true;
        return;
    }
    jw_put(w, "\"", 1);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            char e[2] = {'\\', (char)c};
            jw_put(w, e, 2);
        } else if (c == '\n') {
            jw_put(w, "\\n", 2);
        } else if (c == '\r') {
            jw_put(w, "\\r", 2);
        } else if (c == '\t') {
            jw_put(w, "\\t", 2);
        } else if (c < 0x20u || c == 0x7Fu) {
            char e[6] = {'\\', 'u', '0', '0', hx[c >> 4], hx[c & 15u]};
            jw_put(w, e, 6);
        } else {
            jw_put(w, (const char *)&s[i], 1);
        }
    }
    jw_put(w, "\"", 1);
}

void im_jw_key(im_json_w_t *w, const char *k)
{
    jw_sep(w);
    jw_quoted(w, k, strlen(k));
    jw_put(w, ":", 1);
    w->after_key = true;
}

void im_jw_str(im_json_w_t *w, const char *s, size_t n)
{
    jw_sep(w);
    jw_quoted(w, s, n);
}

void im_jw_cstr(im_json_w_t *w, const char *s)
{
    if (s == NULL) {
        im_jw_null(w);
        return;
    }
    im_jw_str(w, s, strlen(s));
}

void im_jw_hex(im_json_w_t *w, const uint8_t *p, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    jw_sep(w);
    jw_put(w, "\"", 1);
    for (size_t i = 0; i < n; i++) {
        char b[2] = {hx[p[i] >> 4], hx[p[i] & 15u]};
        jw_put(w, b, 2);
    }
    jw_put(w, "\"", 1);
}

void im_jw_u64(im_json_w_t *w, uint64_t v)
{
    char b[24];
    size_t n = 0;
    char r[24];
    do {
        r[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    } while (v > 0);
    for (size_t i = 0; i < n; i++) {
        b[i] = r[n - 1 - i];
    }
    jw_sep(w);
    jw_put(w, b, n);
}

void im_jw_i64(im_json_w_t *w, int64_t v)
{
    if (v < 0) {
        uint64_t m = (uint64_t)(-(v + 1)) + 1u;
        char b[24];
        size_t n = 0;
        char r[24];
        do {
            r[n++] = (char)('0' + (m % 10u));
            m /= 10u;
        } while (m > 0);
        b[0] = '-';
        for (size_t i = 0; i < n; i++) {
            b[i + 1] = r[n - 1 - i];
        }
        jw_sep(w);
        jw_put(w, b, n + 1);
    } else {
        im_jw_u64(w, (uint64_t)v);
    }
}

void im_jw_bool(im_json_w_t *w, bool v)
{
    jw_sep(w);
    if (v) {
        jw_put(w, "true", 4);
    } else {
        jw_put(w, "false", 5);
    }
}

void im_jw_null(im_json_w_t *w)
{
    jw_sep(w);
    jw_put(w, "null", 4);
}

im_err_t im_jw_finish(im_json_w_t *w, size_t *len)
{
    if (w->err || w->depth != 0 || w->len >= w->cap) {
        return IM_ERR_BUFFER;
    }
    w->buf[w->len] = '\0';
    if (len != NULL) {
        *len = w->len;
    }
    return IM_OK;
}
