/*
 * IronMesh protocol core - attestation build/verify (see im_attest.h, ironmesh_wire/attestation.py).
 */
#include "im_attest.h"

#include <string.h>

#include "im_ids.h"

#define ATT_PAYLOAD_MAX 320u

im_err_t im_attest_build(const im_identity_t *id, const uint8_t *kid, size_t kid_len,
                         uint64_t seq, uint64_t ts, const uint8_t nonce[32],
                         const uint8_t *csr_der, size_t csr_len, const uint8_t fw_hash[32],
                         const char *fw_version, uint8_t *out, size_t cap, size_t *out_len)
{
    uint8_t payload[ATT_PAYLOAD_MAX];
    uint8_t csr_hash[32];
    im_cbor_enc_t e;
    size_t n;
    if (id == NULL || id->se_type == NULL || nonce == NULL || fw_hash == NULL ||
        fw_version == NULL) {
        return IM_ERR_ARG;
    }
    IM_TRY(im_sha256(csr_der, csr_len, csr_hash));
    im_cbor_enc_init(&e, payload, sizeof payload);
    im_env_payload_begin(&e, seq, ts, IM_MSG_ATTESTATION, false);
    im_body_attestation(&e, nonce, csr_hash, fw_hash, fw_version, id->se_type);
    IM_TRY(im_env_payload_end(&e, NULL, &n));
    return im_env_sign_uplink(id, kid, kid_len, payload, n, out, cap, out_len);
}

typedef struct {
    const im_pubkey_t *key;
} fixed_resolver_t;

static im_err_t fixed_resolve(void *ctx, const uint8_t *kid, size_t kid_len, bool kid_text,
                              im_pubkey_t *out)
{
    (void)kid;
    (void)kid_len;
    (void)kid_text;
    *out = *((const fixed_resolver_t *)ctx)->key;
    return IM_OK;
}

static im_err_t single_use_store(void *ctx, const uint8_t *kid, size_t kid_len,
                                 im_direction_t dir, uint64_t seq)
{
    (void)ctx;
    (void)kid;
    (void)kid_len;
    (void)dir;
    (void)seq;
    return IM_OK; /* empty store: the first message is always accepted */
}

static unsigned se_bit(const char *s, size_t n)
{
    static const char *const names[4] = {"atecc608", "tpm2", "optee", "software"};
    for (unsigned i = 0; i < 4u; i++) {
        if (strlen(names[i]) == n && memcmp(names[i], s, n) == 0) {
            return 1u << i;
        }
    }
    return 0;
}

im_err_t im_attest_verify(const uint8_t *buf, size_t len, const im_pubkey_t *identity_key,
                          const im_attest_verify_opts_t *o, im_env_msg_t *msg)
{
    fixed_resolver_t fr;
    im_key_resolver_t resolver;
    im_replay_store_t fresh;
    im_env_decode_opts_t eo;
    im_attestation_t att;
    uint8_t csr_hash[32];

    if (identity_key == NULL || o == NULL || msg == NULL || o->expected_nonce == NULL) {
        return IM_ERR_ARG;
    }
    fr.key = identity_key;
    resolver.resolve = fixed_resolve;
    resolver.ctx = &fr;
    fresh.check_and_record = single_use_store;
    fresh.ctx = NULL;
    im_env_decode_opts_init(&eo);
    eo.resolver = &resolver;
    eo.replay = o->replay != NULL ? o->replay : &fresh;
    eo.now = o->now;
    eo.max_skew = o->max_skew;
    eo.expected_direction = IM_DIR_UPLINK;
    IM_TRY(im_env_decode(buf, len, &eo, msg));
    if (msg->type != IM_MSG_ATTESTATION) {
        return IM_ERR_ATT_TYPE;
    }
    if (o->expected_kid != NULL &&
        (msg->kid_len != o->expected_kid_len ||
         memcmp(msg->kid, o->expected_kid, o->expected_kid_len) != 0)) {
        return IM_ERR_ENV_KID;
    }
    IM_TRY(im_env_get_attestation(msg, &att));
    if (!im_ct_equal(att.nonce, o->expected_nonce, 32)) {
        return IM_ERR_ATT_NONCE;
    }
    IM_TRY(im_sha256(o->csr_der, o->csr_len, csr_hash));
    if (!im_ct_equal(att.csr_hash, csr_hash, 32)) {
        return IM_ERR_ATT_CSR_HASH;
    }
    if (o->allowed_se_types != 0 &&
        (se_bit(att.se_type, att.se_type_len) & o->allowed_se_types) == 0) {
        return IM_ERR_ATT_SE_TYPE;
    }
    if (att.has_evidence) {
        im_cbor_val_t q;
        IM_TRY(im_cbor_map_get_int(&att.evidence, 1, &q));
        IM_TRY(im_attest_check_tpms(q.data, (size_t)q.arg, o->expected_nonce));
    }
    return IM_OK;
}

static uint64_t be(const uint8_t *p, unsigned n)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

im_err_t im_attest_check_tpms(const uint8_t *q, size_t len, const uint8_t nonce[32])
{
    size_t pos = 6;
    size_t sz;
    uint64_t count;
    const uint8_t *extra;
    size_t extra_len;
    bool pcr_ok = false;

    if (q == NULL || len < 6) {
        return IM_ERR_ATT_EVIDENCE;
    }
    if (be(q, 4) != 0xFF544347u || be(q + 4, 2) != 0x8018u) {
        return IM_ERR_ATT_EVIDENCE;
    }
    /* qualifiedSigner (TPM2B) */
    if (len - pos < 2) {
        return IM_ERR_ATT_EVIDENCE;
    }
    sz = (size_t)be(q + pos, 2);
    pos += 2;
    if (len - pos < sz) {
        return IM_ERR_ATT_EVIDENCE;
    }
    pos += sz;
    /* extraData (TPM2B) */
    if (len - pos < 2) {
        return IM_ERR_ATT_EVIDENCE;
    }
    sz = (size_t)be(q + pos, 2);
    pos += 2;
    if (len - pos < sz) {
        return IM_ERR_ATT_EVIDENCE;
    }
    extra = q + pos;
    extra_len = sz;
    pos += sz;
    /* clockInfo (17) + firmwareVersion (8) + pcrSelect count (4) */
    if (len - pos < 29) {
        return IM_ERR_ATT_EVIDENCE;
    }
    pos += 25;
    count = be(q + pos, 4);
    pos += 4;
    for (uint64_t i = 0; i < count; i++) {
        uint32_t hash_alg;
        size_t nsel;
        uint32_t bits = 0;
        bool exact = true;
        if (len - pos < 3) {
            return IM_ERR_ATT_EVIDENCE;
        }
        hash_alg = (uint32_t)be(q + pos, 2);
        nsel = q[pos + 2];
        pos += 3;
        if (len - pos < nsel) {
            return IM_ERR_ATT_EVIDENCE;
        }
        for (size_t b = 0; b < nsel; b++) {
            if (b < 4) {
                bits |= (uint32_t)q[pos + b] << (8u * b);
            } else if (q[pos + b] != 0) {
                exact = false;
            }
        }
        pos += nsel;
        if (hash_alg == 0x000Bu && exact && bits == 0x95u /* {0,2,4,7} */) {
            pcr_ok = true;
        }
    }
    /* pcrDigest (TPM2B) */
    if (len - pos < 2) {
        return IM_ERR_ATT_EVIDENCE;
    }
    sz = (size_t)be(q + pos, 2);
    pos += 2;
    if (len - pos < sz || pos + sz != len) {
        return IM_ERR_ATT_EVIDENCE;
    }
    if (extra_len != 32u || !im_ct_equal(extra, nonce, 32)) {
        return IM_ERR_ATT_EVIDENCE;
    }
    return pcr_ok ? IM_OK : IM_ERR_ATT_EVIDENCE;
}
