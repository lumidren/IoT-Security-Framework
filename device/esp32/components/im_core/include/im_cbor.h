/*
 * IronMesh protocol core - canonical CBOR (WIRE_FORMAT.md §1).
 *
 * Decoding is two-phase and allocation-free:
 *   1. im_cbor_validate() runs the strict decoder of §1.2 over the whole input and reports the
 *      exact error code the Python reference reports (same check order);
 *   2. im_cbor_parse()/im_cbor_iter_*() navigate the *validated* buffer zero-copy. The reader
 *      still bounds-checks every access, so misuse on unvalidated input cannot read out of range.
 *
 * The encoder writes into a caller buffer with a sticky error (IM_ERR_BUFFER on overflow); with
 * a NULL buffer it only measures. Map keys must be emitted in canonical order by the caller
 * (im_cbor_sort_map_entries() helps for application maps).
 */
#ifndef IM_CBOR_H
#define IM_CBOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IM_CBOR_MAX_DEPTH 16u           /* hard cap; also the default (§1.2) */
#define IM_CBOR_DEFAULT_MAX_SIZE 65536u /* default max_size (§1.2) */

#define IM_CBOR_TAG_ENCRYPT0 16u
#define IM_CBOR_TAG_SIGN1 18u
#define IM_CBOR_TAG_SIGN 98u

typedef struct {
    size_t max_size;   /* inputs longer than this are CBOR_SIZE */
    unsigned max_depth; /* clamped to IM_CBOR_MAX_DEPTH */
} im_cbor_limits_t;

extern const im_cbor_limits_t IM_CBOR_DEFAULT_LIMITS;

typedef enum {
    IM_CBOR_UINT = 0,
    IM_CBOR_NINT,
    IM_CBOR_BSTR,
    IM_CBOR_TSTR,
    IM_CBOR_ARRAY,
    IM_CBOR_MAP,
    IM_CBOR_TAG,
    IM_CBOR_FLOAT,
    IM_CBOR_FALSE,
    IM_CBOR_TRUE,
    IM_CBOR_NULL
} im_cbor_type_t;

typedef struct {
    im_cbor_type_t type;
    uint64_t arg;        /* UINT value; NINT argument (value = -1 - arg); string length;
                            ARRAY/MAP item count (pairs for maps); TAG number */
    double f;            /* FLOAT value */
    const uint8_t *data; /* BSTR/TSTR content; ARRAY/MAP/TAG first child */
    const uint8_t *raw;  /* first byte of the encoded item */
    size_t raw_len;      /* length of the whole encoded item, children included */
} im_cbor_val_t;

/* Strictly validate that buf is exactly one canonical CBOR item (§1.2). lim may be NULL. */
im_err_t im_cbor_validate(const uint8_t *buf, size_t len, const im_cbor_limits_t *lim);

/* Validate, then parse the top-level item into *top. */
im_err_t im_cbor_decode(const uint8_t *buf, size_t len, const im_cbor_limits_t *lim,
                        im_cbor_val_t *top);

/* Parse the item at p (must lie in [p, end)) of an already validated buffer. */
im_err_t im_cbor_parse(const uint8_t *p, const uint8_t *end, im_cbor_val_t *v);

/* Iteration over the children of an ARRAY, MAP (key, value, key, value...) or TAG. */
typedef struct {
    const uint8_t *p;
    const uint8_t *end;
    uint64_t remaining;
} im_cbor_iter_t;

im_err_t im_cbor_iter_init(im_cbor_iter_t *it, const im_cbor_val_t *container);
/* IM_ERR_NOT_FOUND when exhausted. */
im_err_t im_cbor_iter_next(im_cbor_iter_t *it, im_cbor_val_t *v);

/* Map lookups (IM_ERR_NOT_FOUND when absent). */
im_err_t im_cbor_map_get_int(const im_cbor_val_t *map, int64_t key, im_cbor_val_t *out);
im_err_t im_cbor_map_get_str(const im_cbor_val_t *map, const char *key, im_cbor_val_t *out);

/* Value helpers. */
bool im_cbor_is_int(const im_cbor_val_t *v);
/* Integer value as int64 (false if it does not fit). */
bool im_cbor_get_int64(const im_cbor_val_t *v, int64_t *out);
/* Compare a TSTR/BSTR value with bytes. */
bool im_cbor_str_eq(const im_cbor_val_t *v, const char *s);

/* UTF-8 helpers (strict: no overlongs, no surrogates, <= U+10FFFF). */
bool im_utf8_valid(const uint8_t *s, size_t len);
/* Number of code points of a valid UTF-8 string (Python len(str)). */
size_t im_utf8_count(const uint8_t *s, size_t len);

/* ---- encoder ---------------------------------------------------------------------------- */

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t len;
    im_err_t err;
} im_cbor_enc_t;

void im_cbor_enc_init(im_cbor_enc_t *e, uint8_t *buf, size_t cap);
void im_cbor_enc_head(im_cbor_enc_t *e, unsigned major, uint64_t arg);
void im_cbor_enc_uint(im_cbor_enc_t *e, uint64_t v);
void im_cbor_enc_int(im_cbor_enc_t *e, int64_t v);
void im_cbor_enc_nint_arg(im_cbor_enc_t *e, uint64_t arg); /* value = -1 - arg */
void im_cbor_enc_bstr(im_cbor_enc_t *e, const uint8_t *p, size_t n);
void im_cbor_enc_tstr(im_cbor_enc_t *e, const char *p, size_t n);
void im_cbor_enc_cstr(im_cbor_enc_t *e, const char *s);
void im_cbor_enc_array(im_cbor_enc_t *e, uint64_t n);
void im_cbor_enc_map(im_cbor_enc_t *e, uint64_t pairs);
void im_cbor_enc_tag(im_cbor_enc_t *e, uint64_t tag);
void im_cbor_enc_float(im_cbor_enc_t *e, double v); /* shortest exact form, NaN = f97e00 */
void im_cbor_enc_bool(im_cbor_enc_t *e, bool v);
void im_cbor_enc_null(im_cbor_enc_t *e);
void im_cbor_enc_raw(im_cbor_enc_t *e, const uint8_t *p, size_t n);
im_err_t im_cbor_enc_finish(const im_cbor_enc_t *e, size_t *len);

/* Encode the head (initial byte + argument) into out[9]; returns its length. */
size_t im_cbor_head(unsigned major, uint64_t arg, uint8_t out[9]);

/* Re-encode a parsed value canonically (used to check decode/encode round trips). */
im_err_t im_cbor_reencode(const im_cbor_val_t *v, im_cbor_enc_t *e);

/* A map entry whose key and value are already encoded, for building application maps. */
typedef struct {
    const uint8_t *key;
    size_t key_len;
    const uint8_t *val;
    size_t val_len;
} im_cbor_entry_t;

/* Sort entries in canonical (bytewise) key order; IM_ERR_CBOR_DUPLICATE_KEY on duplicates. */
im_err_t im_cbor_sort_map_entries(im_cbor_entry_t *entries, size_t n);

/* Float helpers exposed for tests: exact conversion to half / single. */
bool im_cbor_double_to_half(double d, uint16_t *half);
bool im_cbor_double_to_single(double d, uint32_t *single);
double im_cbor_half_to_double(uint16_t h);

#ifdef __cplusplus
}
#endif

#endif /* IM_CBOR_H */
