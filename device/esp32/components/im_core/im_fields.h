/*
 * IronMesh protocol core - typed accessors for integer-keyed CBOR maps (internal).
 * Mirrors ironmesh_wire/fields.py: every accessor reports the caller-chosen error code.
 */
#ifndef IM_FIELDS_H
#define IM_FIELDS_H

#include <stdbool.h>
#include <stdint.h>

#include "im_cbor.h"
#include "im_err.h"

#define IM_KEYMASK(k) ((uint32_t)1u << (k))
#define IM_KEYRANGE(a, b) ((((uint32_t)1u << ((b) + 1u)) - 1u) & ~(((uint32_t)1u << (a)) - 1u)) /* b <= 30 */

/* All keys must be unsigned ints 0..31; required present, nothing outside required|optional. */
im_err_t im_f_expect_keys(const im_cbor_val_t *m, uint32_t required, uint32_t optional,
                          im_err_t err, uint32_t *present);
bool im_f_has(uint32_t present, unsigned key);
im_err_t im_f_uint(const im_cbor_val_t *m, int64_t key, uint64_t max, im_err_t err,
                   uint64_t *out);
im_err_t im_f_int(const im_cbor_val_t *m, int64_t key, im_err_t err, int64_t *out);
im_err_t im_f_float(const im_cbor_val_t *m, int64_t key, im_err_t err, double *out);
/* length in code points (Python len(str)) */
im_err_t im_f_tstr(const im_cbor_val_t *m, int64_t key, size_t min_cp, size_t max_cp,
                   im_err_t err, const char **s, size_t *n);
/* want_len == SIZE_MAX: any length */
im_err_t im_f_bstr(const im_cbor_val_t *m, int64_t key, size_t want_len, im_err_t err,
                   const uint8_t **p, size_t *n);
/* free-form application map: every key a tstr */
im_err_t im_f_appmap(const im_cbor_val_t *m, int64_t key, im_err_t err, im_cbor_val_t *out);
im_err_t im_f_tstr_list(const im_cbor_val_t *m, int64_t key, uint64_t max_items, im_err_t err);
/* key present; null -> *p = NULL; else bstr of want_len */
im_err_t im_f_bstr_or_null(const im_cbor_val_t *m, int64_t key, size_t want_len, im_err_t err,
                           const uint8_t **p);
bool im_f_is_appmap(const im_cbor_val_t *v);

#endif /* IM_FIELDS_H */
