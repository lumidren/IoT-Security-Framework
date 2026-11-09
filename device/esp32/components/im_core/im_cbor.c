/*
 * IronMesh protocol core - canonical CBOR encoder and strict decoder (WIRE_FORMAT.md §1).
 *
 * The validator mirrors the Python reference (ironmesh_wire/cbor.py) check by check so that the
 * first violation found yields the same error code. Recursion depth is bounded by
 * IM_CBOR_MAX_DEPTH (16); the reader/skip paths are iterative.
 */
#include "im_cbor.h"

#include <string.h>

const im_cbor_limits_t IM_CBOR_DEFAULT_LIMITS = {IM_CBOR_DEFAULT_MAX_SIZE, IM_CBOR_MAX_DEPTH};

/* ------------------------------------------------------------------------------------------ */
/* Float helpers (exact conversions, no reliance on FPU rounding behaviour)                    */
/* ------------------------------------------------------------------------------------------ */

static uint64_t dbits(double d)
{
    uint64_t u;
    memcpy(&u, &d, sizeof u);
    return u;
}

static double bitsd(uint64_t u)
{
    double d;
    memcpy(&d, &u, sizeof d);
    return d;
}

static bool double_is_nan(double d)
{
    uint64_t b = dbits(d);
    return ((b >> 52) & 0x7FFu) == 0x7FFu && (b & 0xFFFFFFFFFFFFFull) != 0;
}

bool im_cbor_double_to_half(double d, uint16_t *half)
{
    uint64_t b = dbits(d);
    uint16_t sign = (uint16_t)((b >> 63) << 15);
    unsigned exp = (unsigned)((b >> 52) & 0x7FFu);
    uint64_t mant = b & 0xFFFFFFFFFFFFFull;
    int e;

    if (exp == 0x7FFu) {
        if (mant != 0) {
            return false; /* NaN is handled by the callers */
        }
        *half = (uint16_t)(sign | 0x7C00u);
        return true;
    }
    if (exp == 0) {
        if (mant == 0) {
            *half = sign;
            return true;
        }
        return false; /* double subnormals are far below half range */
    }
    e = (int)exp - 1023;
    if (e >= -14 && e <= 15) {
        if ((mant & ((1ull << 42) - 1u)) != 0) {
            return false;
        }
        *half = (uint16_t)(sign | (uint16_t)((unsigned)(e + 15) << 10) | (uint16_t)(mant >> 42));
        return true;
    }
    if (e >= -24 && e < -14) {
        uint64_t full = (1ull << 52) | mant;
        unsigned s = (unsigned)(28 - e); /* 43..52 */
        if ((full & ((1ull << s) - 1u)) != 0) {
            return false;
        }
        *half = (uint16_t)(sign | (uint16_t)(full >> s));
        return true;
    }
    return false;
}

bool im_cbor_double_to_single(double d, uint32_t *single)
{
    uint64_t b = dbits(d);
    uint32_t sign = (uint32_t)((b >> 63) << 31);
    unsigned exp = (unsigned)((b >> 52) & 0x7FFu);
    uint64_t mant = b & 0xFFFFFFFFFFFFFull;
    int e;

    if (exp == 0x7FFu) {
        if (mant != 0) {
            return false;
        }
        *single = sign | 0x7F800000u;
        return true;
    }
    if (exp == 0) {
        if (mant == 0) {
            *single = sign;
            return true;
        }
        return false;
    }
    e = (int)exp - 1023;
    if (e >= -126 && e <= 127) {
        if ((mant & ((1ull << 29) - 1u)) != 0) {
            return false;
        }
        *single = sign | ((uint32_t)(e + 127) << 23) | (uint32_t)(mant >> 29);
        return true;
    }
    if (e >= -149 && e < -126) {
        uint64_t full = (1ull << 52) | mant;
        unsigned s = (unsigned)(-e - 97); /* 30..52 */
        if ((full & ((1ull << s) - 1u)) != 0) {
            return false;
        }
        *single = sign | (uint32_t)(full >> s);
        return true;
    }
    return false;
}

double im_cbor_half_to_double(uint16_t h)
{
    uint64_t sign = (uint64_t)(h >> 15) << 63;
    unsigned exp = (h >> 10) & 0x1Fu;
    uint64_t mant = h & 0x3FFu;
    uint64_t b;

    if (exp == 0) {
        if (mant == 0) {
            b = sign;
        } else {
            int e = -14;
            while ((mant & 0x400u) == 0) {
                mant <<= 1;
                e--;
            }
            mant &= 0x3FFu;
            b = sign | ((uint64_t)(e + 1023) << 52) | (mant << 42);
        }
    } else if (exp == 31u) {
        b = sign | (0x7FFull << 52) | (mant << 42);
    } else {
        b = sign | ((uint64_t)((int)exp - 15 + 1023) << 52) | (mant << 42);
    }
    return bitsd(b);
}

static double single_to_double(uint32_t s)
{
    float f;
    memcpy(&f, &s, sizeof f);
    return (double)f; /* exact for every non-NaN single */
}

/* ------------------------------------------------------------------------------------------ */
/* UTF-8                                                                                       */
/* ------------------------------------------------------------------------------------------ */

static bool cont(uint8_t c)
{
    return (c & 0xC0u) == 0x80u;
}

bool im_utf8_valid(const uint8_t *s, size_t len)
{
    size_t i = 0;
    while (i < len) {
        uint8_t c = s[i];
        size_t need;
        uint8_t lo = 0x80u;
        uint8_t hi = 0xBFu;
        if (c < 0x80u) {
            i++;
            continue;
        }
        if (c >= 0xC2u && c <= 0xDFu) {
            need = 1;
        } else if (c == 0xE0u) {
            need = 2;
            lo = 0xA0u;
        } else if ((c >= 0xE1u && c <= 0xECu) || c == 0xEEu || c == 0xEFu) {
            need = 2;
        } else if (c == 0xEDu) {
            need = 2;
            hi = 0x9Fu; /* no surrogates */
        } else if (c == 0xF0u) {
            need = 3;
            lo = 0x90u;
        } else if (c >= 0xF1u && c <= 0xF3u) {
            need = 3;
        } else if (c == 0xF4u) {
            need = 3;
            hi = 0x8Fu; /* <= U+10FFFF */
        } else {
            return false;
        }
        if (len - i - 1 < need) {
            return false;
        }
        if (s[i + 1] < lo || s[i + 1] > hi) {
            return false;
        }
        for (size_t k = 2; k <= need; k++) {
            if (!cont(s[i + k])) {
                return false;
            }
        }
        i += need + 1;
    }
    return true;
}

size_t im_utf8_count(const uint8_t *s, size_t len)
{
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        if (!cont(s[i])) {
            n++;
        }
    }
    return n;
}

/* ------------------------------------------------------------------------------------------ */
/* Strict decoder (validation)                                                                 */
/* ------------------------------------------------------------------------------------------ */

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
    unsigned max_depth;
} dec_t;

static im_err_t d_byte(dec_t *d, uint8_t *b)
{
    if (d->pos >= d->len) {
        return IM_ERR_CBOR_TRUNCATED;
    }
    *b = d->buf[d->pos++];
    return IM_OK;
}

static im_err_t d_take(dec_t *d, uint64_t n, const uint8_t **p)
{
    if (n > (uint64_t)(d->len - d->pos)) {
        return IM_ERR_CBOR_TRUNCATED;
    }
    *p = d->buf + d->pos;
    d->pos += (size_t)n;
    return IM_OK;
}

static uint64_t be_read(const uint8_t *p, unsigned n)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

static im_err_t d_arg(dec_t *d, unsigned ai, uint64_t *arg)
{
    const uint8_t *p;
    if (ai < 24u) {
        *arg = ai;
        return IM_OK;
    }
    switch (ai) {
    case 24u:
        IM_TRY(d_take(d, 1, &p));
        *arg = p[0];
        return *arg < 24u ? IM_ERR_CBOR_NON_MINIMAL_INT : IM_OK;
    case 25u:
        IM_TRY(d_take(d, 2, &p));
        *arg = be_read(p, 2);
        return *arg <= 0xFFu ? IM_ERR_CBOR_NON_MINIMAL_INT : IM_OK;
    case 26u:
        IM_TRY(d_take(d, 4, &p));
        *arg = be_read(p, 4);
        return *arg <= 0xFFFFu ? IM_ERR_CBOR_NON_MINIMAL_INT : IM_OK;
    case 27u:
        IM_TRY(d_take(d, 8, &p));
        *arg = be_read(p, 8);
        return *arg <= 0xFFFFFFFFull ? IM_ERR_CBOR_NON_MINIMAL_INT : IM_OK;
    case 31u:
        return IM_ERR_CBOR_INDEFINITE;
    default:
        return IM_ERR_CBOR_RESERVED;
    }
}

static im_err_t d_simple(dec_t *d, unsigned ai)
{
    const uint8_t *p;
    switch (ai) {
    case 20u:
    case 21u:
    case 22u:
        return IM_OK;
    case 25u: {
        uint16_t h;
        IM_TRY(d_take(d, 2, &p));
        h = (uint16_t)be_read(p, 2);
        if ((h & 0x7C00u) == 0x7C00u && (h & 0x3FFu) != 0 && h != 0x7E00u) {
            return IM_ERR_CBOR_NON_MINIMAL_FLOAT;
        }
        return IM_OK;
    }
    case 26u: {
        uint32_t s;
        uint16_t h;
        IM_TRY(d_take(d, 4, &p));
        s = (uint32_t)be_read(p, 4);
        if ((s & 0x7F800000u) == 0x7F800000u && (s & 0x7FFFFFu) != 0) {
            return IM_ERR_CBOR_NON_MINIMAL_FLOAT; /* NaN */
        }
        if (im_cbor_double_to_half(single_to_double(s), &h)) {
            return IM_ERR_CBOR_NON_MINIMAL_FLOAT;
        }
        return IM_OK;
    }
    case 27u: {
        double v;
        uint16_t h;
        uint32_t s;
        IM_TRY(d_take(d, 8, &p));
        v = bitsd(be_read(p, 8));
        if (double_is_nan(v)) {
            return IM_ERR_CBOR_NON_MINIMAL_FLOAT;
        }
        if (im_cbor_double_to_half(v, &h) || im_cbor_double_to_single(v, &s)) {
            return IM_ERR_CBOR_NON_MINIMAL_FLOAT;
        }
        return IM_OK;
    }
    case 28u:
    case 29u:
    case 30u:
        return IM_ERR_CBOR_RESERVED;
    case 31u:
        return IM_ERR_CBOR_BREAK;
    default:
        return IM_ERR_CBOR_SIMPLE; /* 0..19, 23 (undefined), 24 (two-byte simple) */
    }
}

static int bytes_cmp(const uint8_t *a, size_t al, const uint8_t *b, size_t bl)
{
    size_t n = al < bl ? al : bl;
    int c = n ? memcmp(a, b, n) : 0;
    if (c != 0) {
        return c;
    }
    if (al == bl) {
        return 0;
    }
    return al < bl ? -1 : 1;
}

static bool tag_allowed(uint64_t tag)
{
    return tag == IM_CBOR_TAG_ENCRYPT0 || tag == IM_CBOR_TAG_SIGN1 || tag == IM_CBOR_TAG_SIGN;
}

/* Recursion is bounded by d->max_depth (<= IM_CBOR_MAX_DEPTH). */
static im_err_t d_item(dec_t *d, unsigned depth, bool *key_type)
{
    uint8_t ib;
    unsigned major;
    unsigned ai;
    uint64_t arg;
    const uint8_t *p;
    bool k;

    *key_type = false;
    if (depth > d->max_depth) {
        return IM_ERR_CBOR_DEPTH;
    }
    IM_TRY(d_byte(d, &ib));
    major = ib >> 5;
    ai = ib & 0x1Fu;
    if (major == 7u) {
        return d_simple(d, ai);
    }
    IM_TRY(d_arg(d, ai, &arg));
    switch (major) {
    case 0u:
    case 1u:
        *key_type = true;
        return IM_OK;
    case 2u:
        IM_TRY(d_take(d, arg, &p));
        *key_type = true;
        return IM_OK;
    case 3u:
        IM_TRY(d_take(d, arg, &p));
        if (!im_utf8_valid(p, (size_t)arg)) {
            return IM_ERR_CBOR_UTF8;
        }
        *key_type = true;
        return IM_OK;
    case 4u:
        if (arg > (uint64_t)(d->len - d->pos)) {
            return IM_ERR_CBOR_TRUNCATED;
        }
        for (uint64_t i = 0; i < arg; i++) {
            IM_TRY(d_item(d, depth + 1u, &k));
        }
        return IM_OK;
    case 5u: {
        const uint8_t *prev = NULL;
        size_t prev_len = 0;
        if (arg > (uint64_t)(d->len - d->pos) / 2u) {
            return IM_ERR_CBOR_TRUNCATED;
        }
        for (uint64_t i = 0; i < arg; i++) {
            size_t key_start = d->pos;
            size_t key_len;
            IM_TRY(d_item(d, depth + 1u, &k));
            if (!k) {
                return IM_ERR_CBOR_KEY_TYPE;
            }
            key_len = d->pos - key_start;
            if (prev != NULL) {
                int c = bytes_cmp(d->buf + key_start, key_len, prev, prev_len);
                if (c == 0) {
                    return IM_ERR_CBOR_DUPLICATE_KEY;
                }
                if (c < 0) {
                    return IM_ERR_CBOR_KEY_ORDER;
                }
            }
            prev = d->buf + key_start;
            prev_len = key_len;
            IM_TRY(d_item(d, depth + 1u, &k));
        }
        return IM_OK;
    }
    default: /* 6: tag */
        if (!tag_allowed(arg)) {
            return IM_ERR_CBOR_TAG;
        }
        return d_item(d, depth + 1u, &k);
    }
}

im_err_t im_cbor_validate(const uint8_t *buf, size_t len, const im_cbor_limits_t *lim)
{
    dec_t d;
    bool k;
    if (lim == NULL) {
        lim = &IM_CBOR_DEFAULT_LIMITS;
    }
    if (len > lim->max_size) {
        return IM_ERR_CBOR_SIZE;
    }
    if (buf == NULL && len != 0) {
        return IM_ERR_ARG;
    }
    d.buf = buf;
    d.len = len;
    d.pos = 0;
    d.max_depth = lim->max_depth > IM_CBOR_MAX_DEPTH ? IM_CBOR_MAX_DEPTH : lim->max_depth;
    IM_TRY(d_item(&d, 1u, &k));
    if (d.pos != len) {
        return IM_ERR_CBOR_TRAILING;
    }
    return IM_OK;
}

im_err_t im_cbor_decode(const uint8_t *buf, size_t len, const im_cbor_limits_t *lim,
                        im_cbor_val_t *top)
{
    IM_TRY(im_cbor_validate(buf, len, lim));
    return im_cbor_parse(buf, buf + len, top);
}

/* ------------------------------------------------------------------------------------------ */
/* Reader over validated input (bounds-checked, iterative)                                     */
/* ------------------------------------------------------------------------------------------ */

static im_err_t r_head(const uint8_t **pp, const uint8_t *end, unsigned *major, unsigned *ai,
                       uint64_t *arg)
{
    const uint8_t *p = *pp;
    unsigned n;
    if (p >= end) {
        return IM_ERR_CBOR_TRUNCATED;
    }
    *major = p[0] >> 5;
    *ai = p[0] & 0x1Fu;
    p++;
    if (*major == 7u) {
        /* simple/float: the "argument" bytes are the float payload */
        n = (*ai == 24u) ? 1u : (*ai == 25u) ? 2u : (*ai == 26u) ? 4u : (*ai == 27u) ? 8u : 0u;
    } else if (*ai < 24u) {
        n = 0;
    } else if (*ai <= 27u) {
        n = 1u << (*ai - 24u);
    } else {
        return IM_ERR_CBOR_INDEFINITE;
    }
    if ((size_t)(end - p) < n) {
        return IM_ERR_CBOR_TRUNCATED;
    }
    *arg = n ? be_read(p, n) : *ai;
    *pp = p + n;
    return IM_OK;
}

static im_err_t r_skip(const uint8_t *p, const uint8_t *end, const uint8_t **next)
{
    uint64_t pending = 1;
    while (pending > 0) {
        unsigned major;
        unsigned ai;
        uint64_t arg;
        size_t avail;
        IM_TRY(r_head(&p, end, &major, &ai, &arg));
        pending--;
        avail = (size_t)(end - p);
        switch (major) {
        case 2u:
        case 3u:
            if (arg > avail) {
                return IM_ERR_CBOR_TRUNCATED;
            }
            p += (size_t)arg;
            break;
        case 4u:
            if (arg > avail) {
                return IM_ERR_CBOR_TRUNCATED;
            }
            pending += arg;
            break;
        case 5u:
            if (arg > avail / 2u) {
                return IM_ERR_CBOR_TRUNCATED;
            }
            pending += 2u * arg;
            break;
        case 6u:
            pending += 1u;
            break;
        default:
            break;
        }
        /* every pending item needs at least one byte */
        if (pending > (uint64_t)(end - p)) {
            return IM_ERR_CBOR_TRUNCATED;
        }
    }
    *next = p;
    return IM_OK;
}

im_err_t im_cbor_parse(const uint8_t *p, const uint8_t *end, im_cbor_val_t *v)
{
    unsigned major;
    unsigned ai;
    uint64_t arg;
    const uint8_t *start = p;
    const uint8_t *next;

    if (p == NULL || end == NULL || v == NULL || p > end) {
        return IM_ERR_ARG;
    }
    memset(v, 0, sizeof *v);
    IM_TRY(r_head(&p, end, &major, &ai, &arg));
    v->raw = start;
    v->arg = arg;
    v->data = p;
    switch (major) {
    case 0u:
        v->type = IM_CBOR_UINT;
        break;
    case 1u:
        v->type = IM_CBOR_NINT;
        break;
    case 2u:
    case 3u:
        v->type = major == 2u ? IM_CBOR_BSTR : IM_CBOR_TSTR;
        if (arg > (uint64_t)(end - p)) {
            return IM_ERR_CBOR_TRUNCATED;
        }
        v->raw_len = (size_t)(p - start) + (size_t)arg;
        return IM_OK;
    case 4u:
    case 5u:
    case 6u:
        v->type = major == 4u ? IM_CBOR_ARRAY : major == 5u ? IM_CBOR_MAP : IM_CBOR_TAG;
        IM_TRY(r_skip(start, end, &next));
        v->raw_len = (size_t)(next - start);
        return IM_OK;
    default:
        switch (ai) {
        case 20u:
            v->type = IM_CBOR_FALSE;
            break;
        case 21u:
            v->type = IM_CBOR_TRUE;
            break;
        case 22u:
            v->type = IM_CBOR_NULL;
            break;
        case 25u:
            v->type = IM_CBOR_FLOAT;
            v->f = im_cbor_half_to_double((uint16_t)arg);
            break;
        case 26u:
            v->type = IM_CBOR_FLOAT;
            v->f = single_to_double((uint32_t)arg);
            break;
        case 27u:
            v->type = IM_CBOR_FLOAT;
            v->f = bitsd(arg);
            break;
        default:
            return IM_ERR_CBOR_SIMPLE;
        }
        break;
    }
    v->raw_len = (size_t)(p - start);
    return IM_OK;
}

im_err_t im_cbor_iter_init(im_cbor_iter_t *it, const im_cbor_val_t *c)
{
    if (it == NULL || c == NULL) {
        return IM_ERR_ARG;
    }
    switch (c->type) {
    case IM_CBOR_ARRAY:
        it->remaining = c->arg;
        break;
    case IM_CBOR_MAP:
        if (c->arg > UINT64_MAX / 2u) {
            return IM_ERR_CBOR_TRUNCATED;
        }
        it->remaining = 2u * c->arg;
        break;
    case IM_CBOR_TAG:
        it->remaining = 1u;
        break;
    default:
        return IM_ERR_CBOR_TYPE;
    }
    it->p = c->data;
    it->end = c->raw + c->raw_len;
    return IM_OK;
}

im_err_t im_cbor_iter_next(im_cbor_iter_t *it, im_cbor_val_t *v)
{
    if (it->remaining == 0) {
        return IM_ERR_NOT_FOUND;
    }
    IM_TRY(im_cbor_parse(it->p, it->end, v));
    it->p += v->raw_len;
    it->remaining--;
    return IM_OK;
}

static bool int_key_matches(const im_cbor_val_t *k, int64_t key)
{
    if (key >= 0) {
        return k->type == IM_CBOR_UINT && k->arg == (uint64_t)key;
    }
    return k->type == IM_CBOR_NINT && k->arg == (uint64_t)(-(key + 1));
}

im_err_t im_cbor_map_get_int(const im_cbor_val_t *map, int64_t key, im_cbor_val_t *out)
{
    im_cbor_iter_t it;
    im_cbor_val_t k;
    if (map == NULL || map->type != IM_CBOR_MAP) {
        return IM_ERR_CBOR_TYPE;
    }
    IM_TRY(im_cbor_iter_init(&it, map));
    while (im_cbor_iter_next(&it, &k) == IM_OK) {
        IM_TRY(im_cbor_iter_next(&it, out));
        if (int_key_matches(&k, key)) {
            return IM_OK;
        }
    }
    return IM_ERR_NOT_FOUND;
}

im_err_t im_cbor_map_get_str(const im_cbor_val_t *map, const char *key, im_cbor_val_t *out)
{
    im_cbor_iter_t it;
    im_cbor_val_t k;
    if (map == NULL || map->type != IM_CBOR_MAP || key == NULL) {
        return IM_ERR_CBOR_TYPE;
    }
    IM_TRY(im_cbor_iter_init(&it, map));
    while (im_cbor_iter_next(&it, &k) == IM_OK) {
        IM_TRY(im_cbor_iter_next(&it, out));
        if (k.type == IM_CBOR_TSTR && im_cbor_str_eq(&k, key)) {
            return IM_OK;
        }
    }
    return IM_ERR_NOT_FOUND;
}

bool im_cbor_is_int(const im_cbor_val_t *v)
{
    return v->type == IM_CBOR_UINT || v->type == IM_CBOR_NINT;
}

bool im_cbor_get_int64(const im_cbor_val_t *v, int64_t *out)
{
    if (v->type == IM_CBOR_UINT && v->arg <= (uint64_t)INT64_MAX) {
        *out = (int64_t)v->arg;
        return true;
    }
    if (v->type == IM_CBOR_NINT && v->arg <= (uint64_t)INT64_MAX) {
        *out = -1 - (int64_t)v->arg;
        return true;
    }
    return false;
}

bool im_cbor_str_eq(const im_cbor_val_t *v, const char *s)
{
    size_t n;
    if ((v->type != IM_CBOR_TSTR && v->type != IM_CBOR_BSTR) || s == NULL) {
        return false;
    }
    n = strlen(s);
    return v->arg == (uint64_t)n && (n == 0 || memcmp(v->data, s, n) == 0);
}

/* ------------------------------------------------------------------------------------------ */
/* Encoder                                                                                     */
/* ------------------------------------------------------------------------------------------ */

void im_cbor_enc_init(im_cbor_enc_t *e, uint8_t *buf, size_t cap)
{
    e->buf = buf;
    e->cap = buf ? cap : 0;
    e->len = 0;
    e->err = IM_OK;
}

static void enc_put(im_cbor_enc_t *e, const uint8_t *p, size_t n)
{
    if (e->err != IM_OK) {
        return;
    }
    if (n > SIZE_MAX - e->len) {
        e->err = IM_ERR_BUFFER;
        return;
    }
    if (e->buf != NULL) {
        if (n > e->cap - e->len) {
            e->err = IM_ERR_BUFFER;
            return;
        }
        if (n) {
            memcpy(e->buf + e->len, p, n);
        }
    }
    e->len += n;
}

size_t im_cbor_head(unsigned major, uint64_t arg, uint8_t out[9])
{
    uint8_t mt = (uint8_t)((major & 7u) << 5);
    if (arg < 24u) {
        out[0] = (uint8_t)(mt | (uint8_t)arg);
        return 1;
    }
    if (arg <= 0xFFu) {
        out[0] = (uint8_t)(mt | 24u);
        out[1] = (uint8_t)arg;
        return 2;
    }
    if (arg <= 0xFFFFu) {
        out[0] = (uint8_t)(mt | 25u);
        out[1] = (uint8_t)(arg >> 8);
        out[2] = (uint8_t)arg;
        return 3;
    }
    if (arg <= 0xFFFFFFFFull) {
        out[0] = (uint8_t)(mt | 26u);
        for (unsigned i = 0; i < 4u; i++) {
            out[1 + i] = (uint8_t)(arg >> (24u - 8u * i));
        }
        return 5;
    }
    out[0] = (uint8_t)(mt | 27u);
    for (unsigned i = 0; i < 8u; i++) {
        out[1 + i] = (uint8_t)(arg >> (56u - 8u * i));
    }
    return 9;
}

void im_cbor_enc_head(im_cbor_enc_t *e, unsigned major, uint64_t arg)
{
    uint8_t h[9];
    size_t n = im_cbor_head(major, arg, h);
    enc_put(e, h, n);
}

void im_cbor_enc_uint(im_cbor_enc_t *e, uint64_t v)
{
    im_cbor_enc_head(e, 0, v);
}

void im_cbor_enc_nint_arg(im_cbor_enc_t *e, uint64_t arg)
{
    im_cbor_enc_head(e, 1, arg);
}

void im_cbor_enc_int(im_cbor_enc_t *e, int64_t v)
{
    if (v >= 0) {
        im_cbor_enc_head(e, 0, (uint64_t)v);
    } else {
        im_cbor_enc_head(e, 1, (uint64_t)(-(v + 1)));
    }
}

void im_cbor_enc_bstr(im_cbor_enc_t *e, const uint8_t *p, size_t n)
{
    im_cbor_enc_head(e, 2, n);
    enc_put(e, p, n);
}

void im_cbor_enc_tstr(im_cbor_enc_t *e, const char *p, size_t n)
{
    if (e->err == IM_OK && n > 0 && !im_utf8_valid((const uint8_t *)p, n)) {
        e->err = IM_ERR_CBOR_UTF8;
        return;
    }
    im_cbor_enc_head(e, 3, n);
    enc_put(e, (const uint8_t *)p, n);
}

void im_cbor_enc_cstr(im_cbor_enc_t *e, const char *s)
{
    im_cbor_enc_tstr(e, s, s ? strlen(s) : 0);
}

void im_cbor_enc_array(im_cbor_enc_t *e, uint64_t n)
{
    im_cbor_enc_head(e, 4, n);
}

void im_cbor_enc_map(im_cbor_enc_t *e, uint64_t pairs)
{
    im_cbor_enc_head(e, 5, pairs);
}

void im_cbor_enc_tag(im_cbor_enc_t *e, uint64_t tag)
{
    im_cbor_enc_head(e, 6, tag);
}

void im_cbor_enc_float(im_cbor_enc_t *e, double v)
{
    uint8_t out[9];
    uint16_t h;
    uint32_t s;
    if (double_is_nan(v)) {
        out[0] = 0xF9u;
        out[1] = 0x7Eu;
        out[2] = 0x00u;
        enc_put(e, out, 3);
        return;
    }
    if (im_cbor_double_to_half(v, &h)) {
        out[0] = 0xF9u;
        out[1] = (uint8_t)(h >> 8);
        out[2] = (uint8_t)h;
        enc_put(e, out, 3);
        return;
    }
    if (im_cbor_double_to_single(v, &s)) {
        out[0] = 0xFAu;
        for (unsigned i = 0; i < 4u; i++) {
            out[1 + i] = (uint8_t)(s >> (24u - 8u * i));
        }
        enc_put(e, out, 5);
        return;
    }
    {
        uint64_t b = dbits(v);
        out[0] = 0xFBu;
        for (unsigned i = 0; i < 8u; i++) {
            out[1 + i] = (uint8_t)(b >> (56u - 8u * i));
        }
        enc_put(e, out, 9);
    }
}

void im_cbor_enc_bool(im_cbor_enc_t *e, bool v)
{
    uint8_t b = v ? 0xF5u : 0xF4u;
    enc_put(e, &b, 1);
}

void im_cbor_enc_null(im_cbor_enc_t *e)
{
    uint8_t b = 0xF6u;
    enc_put(e, &b, 1);
}

void im_cbor_enc_raw(im_cbor_enc_t *e, const uint8_t *p, size_t n)
{
    enc_put(e, p, n);
}

im_err_t im_cbor_enc_finish(const im_cbor_enc_t *e, size_t *len)
{
    if (e->err != IM_OK) {
        return e->err;
    }
    if (len != NULL) {
        *len = e->len;
    }
    return IM_OK;
}

static im_err_t reencode(const im_cbor_val_t *v, im_cbor_enc_t *e, unsigned depth)
{
    im_cbor_iter_t it;
    im_cbor_val_t c;
    if (depth > IM_CBOR_MAX_DEPTH) {
        return IM_ERR_CBOR_DEPTH;
    }
    switch (v->type) {
    case IM_CBOR_UINT:
        im_cbor_enc_uint(e, v->arg);
        break;
    case IM_CBOR_NINT:
        im_cbor_enc_nint_arg(e, v->arg);
        break;
    case IM_CBOR_BSTR:
        im_cbor_enc_bstr(e, v->data, (size_t)v->arg);
        break;
    case IM_CBOR_TSTR:
        im_cbor_enc_tstr(e, (const char *)v->data, (size_t)v->arg);
        break;
    case IM_CBOR_ARRAY:
    case IM_CBOR_MAP:
    case IM_CBOR_TAG:
        if (v->type == IM_CBOR_ARRAY) {
            im_cbor_enc_array(e, v->arg);
        } else if (v->type == IM_CBOR_MAP) {
            im_cbor_enc_map(e, v->arg);
        } else {
            im_cbor_enc_tag(e, v->arg);
        }
        IM_TRY(im_cbor_iter_init(&it, v));
        while (im_cbor_iter_next(&it, &c) == IM_OK) {
            IM_TRY(reencode(&c, e, depth + 1u));
        }
        break;
    case IM_CBOR_FLOAT:
        im_cbor_enc_float(e, v->f);
        break;
    case IM_CBOR_FALSE:
        im_cbor_enc_bool(e, false);
        break;
    case IM_CBOR_TRUE:
        im_cbor_enc_bool(e, true);
        break;
    default:
        im_cbor_enc_null(e);
        break;
    }
    return e->err;
}

im_err_t im_cbor_reencode(const im_cbor_val_t *v, im_cbor_enc_t *e)
{
    return reencode(v, e, 1u);
}

im_err_t im_cbor_sort_map_entries(im_cbor_entry_t *entries, size_t n)
{
    for (size_t i = 1; i < n; i++) {
        im_cbor_entry_t cur = entries[i];
        size_t j = i;
        while (j > 0) {
            int c = bytes_cmp(entries[j - 1].key, entries[j - 1].key_len, cur.key, cur.key_len);
            if (c == 0) {
                return IM_ERR_CBOR_DUPLICATE_KEY;
            }
            if (c < 0) {
                break;
            }
            entries[j] = entries[j - 1];
            j--;
        }
        entries[j] = cur;
    }
    return IM_OK;
}
