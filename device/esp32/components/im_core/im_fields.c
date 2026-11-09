/*
 * IronMesh protocol core - typed map accessors (see im_fields.h).
 */
#include "im_fields.h"

im_err_t im_f_expect_keys(const im_cbor_val_t *m, uint32_t required, uint32_t optional,
                          im_err_t err, uint32_t *present)
{
    im_cbor_iter_t it;
    im_cbor_val_t k;
    im_cbor_val_t v;
    uint32_t seen = 0;
    bool unknown = false;

    if (m->type != IM_CBOR_MAP) {
        return err;
    }
    IM_TRY(im_cbor_iter_init(&it, m));
    while (im_cbor_iter_next(&it, &k) == IM_OK) {
        IM_TRY(im_cbor_iter_next(&it, &v));
        if (k.type != IM_CBOR_UINT || k.arg > 31u) {
            unknown = true;
            continue;
        }
        seen |= (uint32_t)1u << k.arg;
    }
    if ((required & ~seen) != 0) {
        return err; /* missing */
    }
    if (unknown || (seen & ~(required | optional)) != 0) {
        return err; /* unknown */
    }
    if (present != NULL) {
        *present = seen;
    }
    return IM_OK;
}

bool im_f_has(uint32_t present, unsigned key)
{
    return key < 32u && (present & ((uint32_t)1u << key)) != 0;
}

im_err_t im_f_uint(const im_cbor_val_t *m, int64_t key, uint64_t max, im_err_t err,
                   uint64_t *out)
{
    im_cbor_val_t v;
    if (im_cbor_map_get_int(m, key, &v) != IM_OK || v.type != IM_CBOR_UINT || v.arg > max) {
        return err;
    }
    if (out != NULL) {
        *out = v.arg;
    }
    return IM_OK;
}

im_err_t im_f_int(const im_cbor_val_t *m, int64_t key, im_err_t err, int64_t *out)
{
    im_cbor_val_t v;
    int64_t x;
    if (im_cbor_map_get_int(m, key, &v) != IM_OK || !im_cbor_get_int64(&v, &x)) {
        return err;
    }
    if (out != NULL) {
        *out = x;
    }
    return IM_OK;
}

im_err_t im_f_float(const im_cbor_val_t *m, int64_t key, im_err_t err, double *out)
{
    im_cbor_val_t v;
    if (im_cbor_map_get_int(m, key, &v) != IM_OK || v.type != IM_CBOR_FLOAT) {
        return err;
    }
    if (out != NULL) {
        *out = v.f;
    }
    return IM_OK;
}

im_err_t im_f_tstr(const im_cbor_val_t *m, int64_t key, size_t min_cp, size_t max_cp,
                   im_err_t err, const char **s, size_t *n)
{
    im_cbor_val_t v;
    size_t cp;
    if (im_cbor_map_get_int(m, key, &v) != IM_OK || v.type != IM_CBOR_TSTR) {
        return err;
    }
    cp = im_utf8_count(v.data, (size_t)v.arg);
    if (cp < min_cp || cp > max_cp) {
        return err;
    }
    if (s != NULL) {
        *s = (const char *)v.data;
    }
    if (n != NULL) {
        *n = (size_t)v.arg;
    }
    return IM_OK;
}

im_err_t im_f_bstr(const im_cbor_val_t *m, int64_t key, size_t want_len, im_err_t err,
                   const uint8_t **p, size_t *n)
{
    im_cbor_val_t v;
    if (im_cbor_map_get_int(m, key, &v) != IM_OK || v.type != IM_CBOR_BSTR) {
        return err;
    }
    if (want_len != SIZE_MAX && v.arg != (uint64_t)want_len) {
        return err;
    }
    if (p != NULL) {
        *p = v.data;
    }
    if (n != NULL) {
        *n = (size_t)v.arg;
    }
    return IM_OK;
}

bool im_f_is_appmap(const im_cbor_val_t *v)
{
    im_cbor_iter_t it;
    im_cbor_val_t k;
    im_cbor_val_t x;
    if (v->type != IM_CBOR_MAP || im_cbor_iter_init(&it, v) != IM_OK) {
        return false;
    }
    while (im_cbor_iter_next(&it, &k) == IM_OK) {
        if (k.type != IM_CBOR_TSTR || im_cbor_iter_next(&it, &x) != IM_OK) {
            return false;
        }
    }
    return true;
}

im_err_t im_f_appmap(const im_cbor_val_t *m, int64_t key, im_err_t err, im_cbor_val_t *out)
{
    im_cbor_val_t v;
    if (im_cbor_map_get_int(m, key, &v) != IM_OK || !im_f_is_appmap(&v)) {
        return err;
    }
    if (out != NULL) {
        *out = v;
    }
    return IM_OK;
}

im_err_t im_f_tstr_list(const im_cbor_val_t *m, int64_t key, uint64_t max_items, im_err_t err)
{
    im_cbor_val_t v;
    im_cbor_val_t x;
    im_cbor_iter_t it;
    if (im_cbor_map_get_int(m, key, &v) != IM_OK || v.type != IM_CBOR_ARRAY ||
        v.arg > max_items) {
        return err;
    }
    IM_TRY(im_cbor_iter_init(&it, &v));
    while (im_cbor_iter_next(&it, &x) == IM_OK) {
        if (x.type != IM_CBOR_TSTR) {
            return err;
        }
    }
    return IM_OK;
}

im_err_t im_f_bstr_or_null(const im_cbor_val_t *m, int64_t key, size_t want_len, im_err_t err,
                           const uint8_t **p)
{
    im_cbor_val_t v;
    if (im_cbor_map_get_int(m, key, &v) != IM_OK) {
        return err;
    }
    if (v.type == IM_CBOR_NULL) {
        *p = NULL;
        return IM_OK;
    }
    if (v.type != IM_CBOR_BSTR || v.arg != (uint64_t)want_len) {
        return err;
    }
    *p = v.data;
    return IM_OK;
}
