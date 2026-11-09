/*
 * IronMesh protocol core - small bounded utilities: command idempotency cache, base64, and the
 * JSON subset used by the DUT control protocol (conformance/DUT_PROTOCOL.md).
 */
#ifndef IM_UTIL_H
#define IM_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* sizeof() of selected public structs (0: packet, 1: props, ... see im_util.c) for FFI checks. */
size_t im_abi_size(int which);

/* ---- endpoint policy (threat model T-29 EST pinning, T-60 artifact host allowlist) --------- */

#define IM_PIN_LEN 32u /* SHA-256 of a CA certificate's SubjectPublicKeyInfo */

/* SPKI pins for the EST server, exactly like MQTT: the trust bundle's ca_pins once a bundle is
 * loaded (after the first enrollment), otherwise the factory-provisioned PKI CA pin(s). Pins are
 * flat arrays of n * IM_PIN_LEN bytes; at most cap pins are copied to out. IM_ERR_NOT_FOUND when
 * neither set has a pin: the caller must then refuse to connect (fail closed). */
im_err_t im_est_pins_select(const uint8_t *bundle_pins, size_t n_bundle,
                            const uint8_t *factory_pins, size_t n_factory, uint8_t *out,
                            size_t cap, size_t *n_out);
/* true if spki_sha256 equals one of the n pins (flat array). */
bool im_pin_match(const uint8_t spki_sha256[IM_PIN_LEN], const uint8_t *pins, size_t n);

/* Host of an https URL "https://" host [":" port] [("/" | "?" | "#") ...]. Rejects other schemes,
 * userinfo ('@'), an empty host, control/space characters and bad ports; an IPv6 literal is
 * returned without its brackets. host points into url (not NUL terminated). */
im_err_t im_url_https_host(const char *url, size_t len, const char **host, size_t *host_len);
/* ASCII case-insensitive exact match of host against n NUL-terminated names; NULL or empty
 * names never match (an empty allowlist allows nothing). */
bool im_host_allowed(const char *host, size_t host_len, const char *const *allowed, size_t n);

/* ---- command idempotency cache ----------------------------------------------------------- */

#define IM_CMD_CACHE_SLOTS 16u
#define IM_CMD_RETAIN_S 600u /* keep entries this long after expires_at */

typedef struct {
    bool used;
    uint8_t key_hash[16]; /* SHA-256(idempotency_key)[0:16] */
    char cmd_id[37];
    uint8_t status;
    uint64_t keep_until;
    uint32_t lru;
} im_cmd_entry_t;

typedef struct {
    im_cmd_entry_t e[IM_CMD_CACHE_SLOTS];
    uint32_t tick;
} im_cmd_cache_t;

void im_cmd_cache_init(im_cmd_cache_t *c);
/* IM_OK with the cached status when the key was already executed; IM_ERR_NOT_FOUND otherwise. */
im_err_t im_cmd_cache_lookup(im_cmd_cache_t *c, const char *key, size_t key_len, uint64_t now,
                             uint8_t *status, char cmd_id[37]);
im_err_t im_cmd_cache_store(im_cmd_cache_t *c, const char *key, size_t key_len,
                            const char *cmd_id, uint8_t status, uint64_t expires_at,
                            uint64_t now);

/* ---- base64 (RFC 4648, standard alphabet, padded) ------------------------------------------ */

size_t im_b64_encoded_len(size_t n); /* without terminator */
im_err_t im_b64_encode(const uint8_t *in, size_t n, char *out, size_t cap, size_t *out_len);
/* Strict: rejects non-alphabet characters, bad padding and non-zero trailing bits. */
im_err_t im_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap, size_t *out_len);

/* ---- JSON subset ---------------------------------------------------------------------------- */

#define IM_JSON_MAX_DEPTH 8u

enum { IM_JSON_OBJ = 1, IM_JSON_ARR, IM_JSON_STR, IM_JSON_NUM, IM_JSON_TRUE, IM_JSON_FALSE,
       IM_JSON_NULL };

typedef struct {
    uint8_t type;
    uint32_t start; /* STR: after the opening quote; others: first char */
    uint32_t end;   /* STR: at the closing quote; others: one past the last char */
    uint32_t size;  /* OBJ: number of members; ARR: number of elements */
    uint32_t span;  /* number of tokens in this subtree including itself */
} im_json_tok_t;

typedef struct {
    const char *js;
    size_t len;
    im_json_tok_t *tok;
    size_t ntok;
} im_json_t;

/* Parse exactly one JSON value (RFC 8259) with bounded depth and token count. */
im_err_t im_json_parse(im_json_t *j, const char *js, size_t len, im_json_tok_t *toks,
                       size_t max_toks);
/* Member lookup in the object at token index obj: token index of the value or -1. */
int im_json_get(const im_json_t *j, int obj, const char *key);
bool im_json_u64(const im_json_t *j, int tok, uint64_t *out);
bool im_json_bool(const im_json_t *j, int tok, bool *out);
/* Unescape a string token into out (UTF-8, NUL terminated). */
bool im_json_str(const im_json_t *j, int tok, char *out, size_t cap, size_t *len);

typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    bool err;
    uint8_t depth;
    bool first[IM_JSON_MAX_DEPTH + 1];
    bool after_key;
} im_json_w_t;

void im_jw_init(im_json_w_t *w, char *buf, size_t cap);
void im_jw_obj(im_json_w_t *w);
void im_jw_obj_end(im_json_w_t *w);
void im_jw_arr(im_json_w_t *w);
void im_jw_arr_end(im_json_w_t *w);
void im_jw_key(im_json_w_t *w, const char *k);
void im_jw_str(im_json_w_t *w, const char *s, size_t n);
void im_jw_cstr(im_json_w_t *w, const char *s);
void im_jw_hex(im_json_w_t *w, const uint8_t *p, size_t n);
void im_jw_u64(im_json_w_t *w, uint64_t v);
void im_jw_i64(im_json_w_t *w, int64_t v);
void im_jw_bool(im_json_w_t *w, bool v);
void im_jw_null(im_json_w_t *w);
/* NUL terminates; IM_ERR_BUFFER on overflow. */
im_err_t im_jw_finish(im_json_w_t *w, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* IM_UTIL_H */
