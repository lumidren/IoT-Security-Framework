/*
 * IronMesh protocol core - COSE_Sign1 / COSE_Sign / COSE_Encrypt0 (WIRE_FORMAT.md §2).
 * Check order follows ironmesh_wire/cose.py so the first failure yields the reference code.
 */
#include "im_cose.h"

#include <string.h>

const uint8_t IM_ENC_STRUCTURE0[15] = {0x83, 0x68, 'E',  'n',  'c',  'r',  'y', 'p',
                                       't',  '0',  0x43, 0xa1, 0x01, 0x03, 0x40};

static const uint8_t k_p256_n[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};

im_err_t im_pubkey_p256(im_pubkey_t *k, const uint8_t *raw, size_t len)
{
    if (k == NULL || raw == NULL || len != IM_P256_PUB_LEN || raw[0] != 0x04) {
        return IM_ERR_COSE_KEY_TYPE;
    }
    memset(k, 0, sizeof *k);
    k->type = IM_KEY_P256;
    memcpy(k->raw, raw, len);
    return IM_OK;
}

im_err_t im_pubkey_ed25519(im_pubkey_t *k, const uint8_t *raw, size_t len)
{
    if (k == NULL || raw == NULL || len != IM_ED25519_PUB_LEN) {
        return IM_ERR_COSE_KEY_TYPE;
    }
    memset(k, 0, sizeof *k);
    k->type = IM_KEY_ED25519;
    memcpy(k->raw, raw, len);
    return IM_OK;
}

/* ------------------------------------------------------------------------------------------ */
/* Output sink: an encoder and/or a running SHA-256                                            */
/* ------------------------------------------------------------------------------------------ */

typedef struct {
    im_cbor_enc_t *enc;
    im_sha256_ctx_t *sha;
    im_err_t err;
} sink_t;

static void sink_put(sink_t *s, const uint8_t *p, size_t n)
{
    if (s->err != IM_OK) {
        return;
    }
    if (s->enc != NULL) {
        im_cbor_enc_raw(s->enc, p, n);
        s->err = s->enc->err;
    }
    if (s->err == IM_OK && s->sha != NULL && n > 0) {
        s->err = im_crypto_sha256_update(s->sha, p, n);
    }
}

static void sink_head(sink_t *s, unsigned major, uint64_t arg)
{
    uint8_t h[9];
    size_t n = im_cbor_head(major, arg, h);
    sink_put(s, h, n);
}

static void sink_bstr(sink_t *s, const uint8_t *p, size_t n)
{
    sink_head(s, 2, n);
    sink_put(s, p, n);
}

static const uint8_t k_sig1_prefix[12] = {0x84, 0x6a, 'S', 'i', 'g', 'n',
                                          'a',  't',  'u', 'r', 'e', '1'};
static const uint8_t k_sig_prefix[11] = {0x85, 0x69, 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e'};
static const uint8_t k_empty_bstr = 0x40;

static void emit_sig1(sink_t *s, const uint8_t *prot, size_t plen, const uint8_t *payload,
                      size_t paylen)
{
    sink_put(s, k_sig1_prefix, sizeof k_sig1_prefix);
    sink_bstr(s, prot, plen);
    sink_put(s, &k_empty_bstr, 1);
    sink_bstr(s, payload, paylen);
}

static void emit_sig(sink_t *s, const uint8_t *sprot, size_t splen, const uint8_t *payload,
                     size_t paylen)
{
    sink_put(s, k_sig_prefix, sizeof k_sig_prefix);
    sink_put(s, &k_empty_bstr, 1);
    sink_bstr(s, sprot, splen);
    sink_put(s, &k_empty_bstr, 1);
    sink_bstr(s, payload, paylen);
}

static size_t head_len(uint64_t arg)
{
    uint8_t h[9];
    return im_cbor_head(2, arg, h);
}

size_t im_cose_sig1_structure_len(size_t protected_len, size_t payload_len)
{
    return sizeof k_sig1_prefix + head_len(protected_len) + protected_len + 1u +
           head_len(payload_len) + payload_len;
}

size_t im_cose_sig_structure_len(size_t sign_protected_len, size_t payload_len)
{
    return sizeof k_sig_prefix + 1u + head_len(sign_protected_len) + sign_protected_len + 1u +
           head_len(payload_len) + payload_len;
}

im_err_t im_cose_sig1_structure(const uint8_t *prot, size_t prot_len, const uint8_t *payload,
                                size_t payload_len, uint8_t *out, size_t cap, size_t *out_len)
{
    im_cbor_enc_t e;
    sink_t s = {&e, NULL, IM_OK};
    im_cbor_enc_init(&e, out, cap);
    emit_sig1(&s, prot, prot_len, payload, payload_len);
    if (s.err != IM_OK) {
        return s.err;
    }
    return im_cbor_enc_finish(&e, out_len);
}

im_err_t im_cose_sig_structure(const uint8_t *sign_prot, size_t sign_prot_len,
                               const uint8_t *payload, size_t payload_len, uint8_t *out,
                               size_t cap, size_t *out_len)
{
    im_cbor_enc_t e;
    sink_t s = {&e, NULL, IM_OK};
    im_cbor_enc_init(&e, out, cap);
    emit_sig(&s, sign_prot, sign_prot_len, payload, payload_len);
    if (s.err != IM_OK) {
        return s.err;
    }
    return im_cbor_enc_finish(&e, out_len);
}

/* ------------------------------------------------------------------------------------------ */
/* Header parsing                                                                              */
/* ------------------------------------------------------------------------------------------ */

static im_err_t parse_protected(const uint8_t *p, size_t n, const im_cbor_limits_t *lim,
                                const int *algs, size_t nalgs, int *alg, const uint8_t **kid,
                                size_t *kid_len, bool *kid_text)
{
    im_cbor_val_t h;
    im_cbor_val_t a;
    im_cbor_val_t k;
    int64_t av;
    bool ok = false;

    if (n == 0) {
        return IM_ERR_COSE_HEADER;
    }
    IM_TRY(im_cbor_decode(p, n, lim, &h));
    if (h.type != IM_CBOR_MAP || h.arg != 2u || im_cbor_map_get_int(&h, 1, &a) != IM_OK ||
        im_cbor_map_get_int(&h, 4, &k) != IM_OK) {
        return IM_ERR_COSE_HEADER;
    }
    if (!im_cbor_get_int64(&a, &av)) {
        return IM_ERR_COSE_ALG;
    }
    for (size_t i = 0; i < nalgs; i++) {
        if (av == algs[i]) {
            ok = true;
        }
    }
    if (!ok) {
        return IM_ERR_COSE_ALG;
    }
    if ((k.type != IM_CBOR_BSTR && k.type != IM_CBOR_TSTR) || k.arg < 1u ||
        k.arg > IM_COSE_MAX_KID) {
        return IM_ERR_COSE_KID;
    }
    *alg = (int)av;
    *kid = k.data;
    *kid_len = (size_t)k.arg;
    *kid_text = k.type == IM_CBOR_TSTR;
    return IM_OK;
}

static im_err_t tagged_array(const uint8_t *buf, size_t len, const im_cbor_limits_t *lim,
                             uint64_t tag, uint64_t n, im_cbor_val_t *items)
{
    im_cbor_val_t top;
    im_cbor_val_t arr;
    im_cbor_iter_t it;
    IM_TRY(im_cbor_decode(buf, len, lim, &top));
    if (top.type != IM_CBOR_TAG || top.arg != tag) {
        return IM_ERR_COSE_TAG;
    }
    IM_TRY(im_cbor_iter_init(&it, &top));
    IM_TRY(im_cbor_iter_next(&it, &arr));
    if (arr.type != IM_CBOR_ARRAY || arr.arg != n) {
        return IM_ERR_COSE_STRUCTURE;
    }
    IM_TRY(im_cbor_iter_init(&it, &arr));
    for (uint64_t i = 0; i < n; i++) {
        IM_TRY(im_cbor_iter_next(&it, &items[i]));
    }
    return IM_OK;
}

static bool is_empty_map(const im_cbor_val_t *v)
{
    return v->type == IM_CBOR_MAP && v->arg == 0;
}

/* ------------------------------------------------------------------------------------------ */
/* COSE_Sign1                                                                                  */
/* ------------------------------------------------------------------------------------------ */

im_err_t im_cose_sign1_decode(const uint8_t *buf, size_t len, const im_cbor_limits_t *lim,
                              im_sign1_t *out)
{
    static const int algs[2] = {IM_ALG_ES256, IM_ALG_EDDSA};
    im_cbor_val_t el[4];
    if (out == NULL) {
        return IM_ERR_ARG;
    }
    memset(out, 0, sizeof *out);
    IM_TRY(tagged_array(buf, len, lim, IM_CBOR_TAG_SIGN1, 4, el));
    if (el[0].type != IM_CBOR_BSTR) {
        return IM_ERR_COSE_STRUCTURE;
    }
    if (!is_empty_map(&el[1])) {
        return IM_ERR_COSE_HEADER;
    }
    if (el[2].type != IM_CBOR_BSTR || el[3].type != IM_CBOR_BSTR) {
        return IM_ERR_COSE_STRUCTURE; /* detached (nil) payloads included */
    }
    IM_TRY(parse_protected(el[0].data, (size_t)el[0].arg, lim, algs, 2, &out->alg, &out->kid,
                           &out->kid_len, &out->kid_text));
    if (el[3].arg != IM_ES256_SIG_LEN) {
        return IM_ERR_COSE_SIGNATURE;
    }
    out->protected_raw = el[0].data;
    out->protected_len = (size_t)el[0].arg;
    out->payload = el[2].data;
    out->payload_len = (size_t)el[2].arg;
    out->sig = el[3].data;
    out->sig_len = (size_t)el[3].arg;
    return IM_OK;
}

static bool scalar_in_range(const uint8_t s[32])
{
    bool nonzero = false;
    for (size_t i = 0; i < 32; i++) {
        if (s[i] != 0) {
            nonzero = true;
        }
    }
    if (!nonzero) {
        return false;
    }
    for (size_t i = 0; i < 32; i++) {
        if (s[i] != k_p256_n[i]) {
            return s[i] < k_p256_n[i];
        }
    }
    return false; /* == n */
}

static im_err_t verify_es256_digest(const im_pubkey_t *key, const uint8_t digest[32],
                                    const uint8_t *sig)
{
    if (!scalar_in_range(sig) || !scalar_in_range(sig + 32)) {
        return IM_ERR_COSE_SIGNATURE;
    }
    if (im_crypto_ecdsa_p256_verify(key->raw, digest, sig) != IM_OK) {
        return IM_ERR_COSE_SIGNATURE;
    }
    return IM_OK;
}

im_err_t im_cose_sign1_verify(const im_sign1_t *m, const im_pubkey_t *key, uint8_t *work,
                              size_t work_len)
{
    if (m == NULL || key == NULL) {
        return IM_ERR_ARG;
    }
    if (key->type != IM_KEY_P256 && key->type != IM_KEY_ED25519) {
        return IM_ERR_COSE_KEY_TYPE;
    }
    if ((key->type == IM_KEY_P256 && m->alg != IM_ALG_ES256) ||
        (key->type == IM_KEY_ED25519 && m->alg != IM_ALG_EDDSA)) {
        return IM_ERR_COSE_ALG;
    }
    if (m->sig_len != IM_ES256_SIG_LEN) {
        return IM_ERR_COSE_SIGNATURE;
    }
    if (m->alg == IM_ALG_ES256) {
        im_sha256_ctx_t sha;
        uint8_t digest[32];
        sink_t s = {NULL, &sha, IM_OK};
        IM_TRY(im_crypto_sha256_init(&sha));
        emit_sig1(&s, m->protected_raw, m->protected_len, m->payload, m->payload_len);
        if (s.err != IM_OK) {
            im_crypto_sha256_free(&sha);
            return s.err;
        }
        IM_TRY(im_crypto_sha256_finish(&sha, digest));
        return verify_es256_digest(key, digest, m->sig);
    } else {
        size_t n;
        IM_TRY(im_cose_sig1_structure(m->protected_raw, m->protected_len, m->payload,
                                      m->payload_len, work, work_len, &n));
        if (im_crypto_ed25519_verify(key->raw, work, n, m->sig) != IM_OK) {
            return IM_ERR_COSE_SIGNATURE;
        }
        return IM_OK;
    }
}

static im_err_t identity_sign_cb(void *ctx, const uint8_t *data, size_t len, uint8_t sig[64])
{
    const im_identity_t *id = (const im_identity_t *)ctx;
    if (id == NULL || id->sign_digest == NULL || len != IM_SHA256_LEN) {
        return IM_ERR_ARG;
    }
    return id->sign_digest(id->ctx, data, sig);
}

void im_identity_signer(const im_identity_t *id, im_signer_t *out)
{
    out->alg = IM_ALG_ES256;
    out->sign = identity_sign_cb;
    out->ctx = (void *)(uintptr_t)id;
}

static im_err_t build_protected(int alg, const uint8_t *kid, size_t kid_len, bool kid_text,
                                uint8_t *out, size_t cap, size_t *out_len)
{
    im_cbor_enc_t e;
    if (kid == NULL || kid_len < 1 || kid_len > IM_COSE_MAX_KID) {
        return IM_ERR_COSE_KID;
    }
    im_cbor_enc_init(&e, out, cap);
    im_cbor_enc_map(&e, 2);
    im_cbor_enc_uint(&e, 1);
    im_cbor_enc_int(&e, alg);
    im_cbor_enc_uint(&e, 4);
    if (kid_text) {
        im_cbor_enc_tstr(&e, (const char *)kid, kid_len);
    } else {
        im_cbor_enc_bstr(&e, kid, kid_len);
    }
    return im_cbor_enc_finish(&e, out_len);
}

im_err_t im_cose_sign1_encode(const im_signer_t *signer, const uint8_t *kid, size_t kid_len,
                              bool kid_text, const uint8_t *payload, size_t payload_len,
                              uint8_t *work, size_t work_len, uint8_t *out, size_t cap,
                              size_t *out_len)
{
    uint8_t prot[8 + IM_COSE_MAX_KID];
    size_t plen;
    uint8_t sig[64];
    im_cbor_enc_t e;
    sink_t s;
    im_err_t err;

    if (signer == NULL || signer->sign == NULL || (payload == NULL && payload_len != 0)) {
        return IM_ERR_ARG;
    }
    if (signer->alg != IM_ALG_ES256 && signer->alg != IM_ALG_EDDSA) {
        return IM_ERR_COSE_ALG;
    }
    IM_TRY(build_protected(signer->alg, kid, kid_len, kid_text, prot, sizeof prot, &plen));
    if (signer->alg == IM_ALG_ES256) {
        im_sha256_ctx_t sha;
        uint8_t digest[32];
        s.enc = NULL;
        s.sha = &sha;
        s.err = IM_OK;
        IM_TRY(im_crypto_sha256_init(&sha));
        emit_sig1(&s, prot, plen, payload, payload_len);
        if (s.err != IM_OK) {
            im_crypto_sha256_free(&sha);
            return s.err;
        }
        IM_TRY(im_crypto_sha256_finish(&sha, digest));
        err = signer->sign(signer->ctx, digest, sizeof digest, sig);
    } else {
        size_t n;
        IM_TRY(im_cose_sig1_structure(prot, plen, payload, payload_len, work, work_len, &n));
        err = signer->sign(signer->ctx, work, n, sig);
    }
    if (err != IM_OK) {
        return err;
    }
    im_cbor_enc_init(&e, out, cap);
    im_cbor_enc_tag(&e, IM_CBOR_TAG_SIGN1);
    im_cbor_enc_array(&e, 4);
    im_cbor_enc_bstr(&e, prot, plen);
    im_cbor_enc_map(&e, 0);
    im_cbor_enc_bstr(&e, payload, payload_len);
    im_cbor_enc_bstr(&e, sig, sizeof sig);
    return im_cbor_enc_finish(&e, out_len);
}

/* ------------------------------------------------------------------------------------------ */
/* COSE_Sign                                                                                   */
/* ------------------------------------------------------------------------------------------ */

im_err_t im_cose_sign_decode(const uint8_t *buf, size_t len, const im_cbor_limits_t *lim,
                             im_sign_t *out)
{
    static const int algs[2] = {IM_ALG_EDDSA, IM_ALG_MLDSA65};
    im_cbor_val_t el[4];
    im_cbor_iter_t it;
    im_cbor_val_t entry;

    if (out == NULL) {
        return IM_ERR_ARG;
    }
    memset(out, 0, sizeof *out);
    IM_TRY(tagged_array(buf, len, lim, IM_CBOR_TAG_SIGN, 4, el));
    if (el[0].type != IM_CBOR_BSTR) {
        return IM_ERR_COSE_STRUCTURE;
    }
    if (el[0].arg != 0) {
        return IM_ERR_COSE_HEADER;
    }
    if (!is_empty_map(&el[1])) {
        return IM_ERR_COSE_HEADER;
    }
    if (el[2].type != IM_CBOR_BSTR) {
        return IM_ERR_COSE_STRUCTURE;
    }
    if (el[3].type != IM_CBOR_ARRAY || el[3].arg == 0) {
        return IM_ERR_COSE_STRUCTURE;
    }
    out->payload = el[2].data;
    out->payload_len = (size_t)el[2].arg;
    IM_TRY(im_cbor_iter_init(&it, &el[3]));
    while (im_cbor_iter_next(&it, &entry) == IM_OK) {
        im_cbor_val_t f[3];
        im_cbor_iter_t fit;
        im_cose_signature_t sg;
        bool kid_text;
        size_t kid_len;
        size_t want;

        if (entry.type != IM_CBOR_ARRAY || entry.arg != 3u) {
            return IM_ERR_COSE_STRUCTURE;
        }
        IM_TRY(im_cbor_iter_init(&fit, &entry));
        for (int i = 0; i < 3; i++) {
            IM_TRY(im_cbor_iter_next(&fit, &f[i]));
        }
        if (f[0].type != IM_CBOR_BSTR) {
            return IM_ERR_COSE_STRUCTURE;
        }
        if (!is_empty_map(&f[1])) {
            return IM_ERR_COSE_HEADER;
        }
        if (f[2].type != IM_CBOR_BSTR) {
            return IM_ERR_COSE_STRUCTURE;
        }
        memset(&sg, 0, sizeof sg);
        IM_TRY(parse_protected(f[0].data, (size_t)f[0].arg, lim, algs, 2, &sg.alg, &sg.kid,
                               &kid_len, &kid_text));
        if (kid_text || kid_len != IM_COSE_SIGN_KID_LEN) {
            return IM_ERR_COSE_KID;
        }
        for (size_t i = 0; i < out->nsigs; i++) {
            if (out->sigs[i].alg == sg.alg) {
                return IM_ERR_COSE_DUPLICATE_ALG;
            }
        }
        want = sg.alg == IM_ALG_EDDSA ? IM_ED25519_SIG_LEN : IM_MLDSA65_SIG_LEN;
        if (f[2].arg != want) {
            return IM_ERR_COSE_SIGNATURE;
        }
        if (out->nsigs >= 2u) {
            return IM_ERR_COSE_DUPLICATE_ALG; /* unreachable: only two algorithms exist */
        }
        sg.protected_raw = f[0].data;
        sg.protected_len = (size_t)f[0].arg;
        sg.sig = f[2].data;
        sg.sig_len = (size_t)f[2].arg;
        out->sigs[out->nsigs++] = sg;
    }
    return IM_OK;
}

const im_cose_signature_t *im_cose_sign_find(const im_sign_t *m, int alg)
{
    for (size_t i = 0; i < m->nsigs; i++) {
        if (m->sigs[i].alg == alg) {
            return &m->sigs[i];
        }
    }
    return NULL;
}

im_err_t im_cose_sign_encode_ed25519(const im_signer_t *signer, const uint8_t kid[8],
                                     const uint8_t *payload, size_t payload_len, uint8_t *work,
                                     size_t work_len, uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t prot[16];
    size_t plen;
    size_t n;
    uint8_t sig[64];
    im_cbor_enc_t e;
    if (signer == NULL || signer->alg != IM_ALG_EDDSA) {
        return IM_ERR_COSE_ALG;
    }
    IM_TRY(build_protected(IM_ALG_EDDSA, kid, 8, false, prot, sizeof prot, &plen));
    IM_TRY(im_cose_sig_structure(prot, plen, payload, payload_len, work, work_len, &n));
    IM_TRY(signer->sign(signer->ctx, work, n, sig));
    im_cbor_enc_init(&e, out, cap);
    im_cbor_enc_tag(&e, IM_CBOR_TAG_SIGN);
    im_cbor_enc_array(&e, 4);
    im_cbor_enc_bstr(&e, NULL, 0);
    im_cbor_enc_map(&e, 0);
    im_cbor_enc_bstr(&e, payload, payload_len);
    im_cbor_enc_array(&e, 1);
    im_cbor_enc_array(&e, 3);
    im_cbor_enc_bstr(&e, prot, plen);
    im_cbor_enc_map(&e, 0);
    im_cbor_enc_bstr(&e, sig, sizeof sig);
    return im_cbor_enc_finish(&e, out_len);
}

/* ------------------------------------------------------------------------------------------ */
/* COSE_Encrypt0                                                                               */
/* ------------------------------------------------------------------------------------------ */

im_err_t im_cose_encrypt0_decode(const uint8_t *buf, size_t len, const im_cbor_limits_t *lim,
                                 im_encrypt0_t *out)
{
    im_cbor_val_t el[3];
    im_cbor_val_t hdr;
    im_cbor_val_t alg;
    im_cbor_val_t iv;
    im_cbor_val_t hpke;
    im_cbor_val_t enc;
    im_cbor_val_t wrapped;

    if (out == NULL) {
        return IM_ERR_ARG;
    }
    memset(out, 0, sizeof *out);
    IM_TRY(tagged_array(buf, len, lim, IM_CBOR_TAG_ENCRYPT0, 3, el));
    if (el[0].type != IM_CBOR_BSTR) {
        return IM_ERR_COSE_STRUCTURE;
    }
    if (el[0].arg == 0) {
        return IM_ERR_COSE_HEADER;
    }
    IM_TRY(im_cbor_decode(el[0].data, (size_t)el[0].arg, lim, &hdr));
    if (hdr.type != IM_CBOR_MAP || hdr.arg != 1u || im_cbor_map_get_int(&hdr, 1, &alg) != IM_OK) {
        return IM_ERR_COSE_HEADER;
    }
    if (alg.type != IM_CBOR_UINT || alg.arg != (uint64_t)IM_ALG_A256GCM) {
        return IM_ERR_COSE_ALG;
    }
    if (el[1].type != IM_CBOR_MAP || el[1].arg != 2u ||
        im_cbor_map_get_int(&el[1], 5, &iv) != IM_OK ||
        im_cbor_map_get_int(&el[1], -70000, &hpke) != IM_OK) {
        return IM_ERR_COSE_HEADER;
    }
    if (iv.type != IM_CBOR_BSTR || iv.arg != IM_GCM_IV_LEN) {
        return IM_ERR_COSE_HEADER;
    }
    if (hpke.type != IM_CBOR_MAP || hpke.arg != 2u ||
        im_cbor_map_get_int(&hpke, 1, &enc) != IM_OK ||
        im_cbor_map_get_int(&hpke, 2, &wrapped) != IM_OK) {
        return IM_ERR_COSE_HEADER;
    }
    if (enc.type != IM_CBOR_BSTR || enc.arg != IM_HPKE_ENC_LEN) {
        return IM_ERR_COSE_HEADER;
    }
    if (wrapped.type != IM_CBOR_BSTR || wrapped.arg != IM_HPKE_WRAPPED_LEN) {
        return IM_ERR_COSE_HEADER;
    }
    if (el[2].type != IM_CBOR_BSTR || el[2].arg < IM_GCM_TAG_LEN) {
        return IM_ERR_COSE_STRUCTURE;
    }
    out->protected_raw = el[0].data;
    out->protected_len = (size_t)el[0].arg;
    out->iv = iv.data;
    out->enc = enc.data;
    out->wrapped = wrapped.data;
    out->ct = el[2].data;
    out->ct_len = (size_t)el[2].arg;
    return IM_OK;
}

im_err_t im_cose_encrypt0_encode(const uint8_t iv[12], const uint8_t enc[65],
                                 const uint8_t wrapped[48], const uint8_t *ct, size_t ct_len,
                                 uint8_t *out, size_t cap, size_t *out_len)
{
    static const uint8_t prot[3] = {0xa1, 0x01, 0x03};
    im_cbor_enc_t e;
    if (ct_len < IM_GCM_TAG_LEN) {
        return IM_ERR_COSE_STRUCTURE;
    }
    im_cbor_enc_init(&e, out, cap);
    im_cbor_enc_tag(&e, IM_CBOR_TAG_ENCRYPT0);
    im_cbor_enc_array(&e, 3);
    im_cbor_enc_bstr(&e, prot, sizeof prot);
    im_cbor_enc_map(&e, 2);
    im_cbor_enc_uint(&e, 5);
    im_cbor_enc_bstr(&e, iv, IM_GCM_IV_LEN);
    im_cbor_enc_int(&e, -70000);
    im_cbor_enc_map(&e, 2);
    im_cbor_enc_uint(&e, 1);
    im_cbor_enc_bstr(&e, enc, IM_HPKE_ENC_LEN);
    im_cbor_enc_uint(&e, 2);
    im_cbor_enc_bstr(&e, wrapped, IM_HPKE_WRAPPED_LEN);
    im_cbor_enc_bstr(&e, ct, ct_len);
    return im_cbor_enc_finish(&e, out_len);
}

im_err_t im_cose_key_id(const uint8_t *raw, size_t len, uint8_t kid[8])
{
    uint8_t d[32];
    IM_TRY(im_sha256(raw, len, d));
    memcpy(kid, d, 8);
    return IM_OK;
}
