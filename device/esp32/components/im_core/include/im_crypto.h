/*
 * IronMesh protocol core - cryptography provider interface.
 *
 * im_core performs NO cryptography itself: every primitive below is implemented by the platform
 * (components/im_platform_esp/im_crypto_mbedtls.c on the ESP32, Rust callbacks in the host
 * build). Operations that use the device's private key go through an im_identity_t so the key
 * can live in a secure element (ATECC608 slot) and is never exported.
 *
 * Conventions: every function returns IM_OK on success. Verification functions return
 * IM_ERR_COSE_SIGNATURE for a signature that does not verify; any other failure is
 * IM_ERR_CRYPTO. AEAD decryption returns IM_ERR_CRYPTO on an authentication failure (the caller
 * maps it to HPKE_OPEN / COSE_DECRYPT). Implementations must be constant time where the
 * underlying library allows it and must not retain pointers after returning.
 */
#ifndef IM_CRYPTO_H
#define IM_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IM_SHA256_LEN 32u
#define IM_P256_PUB_LEN 65u     /* SEC1 uncompressed point 04 || X || Y */
#define IM_P256_SCALAR_LEN 32u
#define IM_ES256_SIG_LEN 64u    /* r || s */
#define IM_ED25519_PUB_LEN 32u
#define IM_ED25519_SIG_LEN 64u
#define IM_MLDSA65_PUB_LEN 1952u
#define IM_MLDSA65_SIG_LEN 3309u
#define IM_GCM_IV_LEN 12u
#define IM_GCM_TAG_LEN 16u

/* Opaque, suitably aligned storage for a platform SHA-256 context. The platform stores its
 * native context in place (mbedtls_sha256_context, sha2::Sha256, ...) and must statically assert
 * that it fits. */
#define IM_SHA256_CTX_SIZE 256u
typedef union {
    uint64_t align_[IM_SHA256_CTX_SIZE / 8u];
    uint8_t opaque[IM_SHA256_CTX_SIZE];
} im_sha256_ctx_t;

/* ---- provided by the platform ------------------------------------------------------------ */

im_err_t im_crypto_sha256_init(im_sha256_ctx_t *ctx);
im_err_t im_crypto_sha256_update(im_sha256_ctx_t *ctx, const uint8_t *data, size_t len);
/* Writes the digest and releases the context. */
im_err_t im_crypto_sha256_finish(im_sha256_ctx_t *ctx, uint8_t out[IM_SHA256_LEN]);
/* Releases a context that will not be finished (error paths). Safe after finish. */
void im_crypto_sha256_free(im_sha256_ctx_t *ctx);

/* HKDF-SHA256 (RFC 5869). salt may be NULL/0 (treated as HashLen zero bytes). */
im_err_t im_crypto_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                                size_t ikm_len, uint8_t prk[IM_SHA256_LEN]);
im_err_t im_crypto_hkdf_expand(const uint8_t prk[IM_SHA256_LEN], const uint8_t *info,
                               size_t info_len, uint8_t *okm, size_t okm_len);

/* ECDSA P-256 / SHA-256 verification of a raw r||s signature over a SHA-256 digest.
 * pub is the 65-byte uncompressed point. r/s range checks are done by im_core beforehand. */
im_err_t im_crypto_ecdsa_p256_verify(const uint8_t pub[IM_P256_PUB_LEN],
                                     const uint8_t digest[IM_SHA256_LEN],
                                     const uint8_t sig[IM_ES256_SIG_LEN]);

/* Ed25519 (RFC 8032, PureEdDSA) verification. */
im_err_t im_crypto_ed25519_verify(const uint8_t pub[IM_ED25519_PUB_LEN], const uint8_t *msg,
                                  size_t msg_len, const uint8_t sig[IM_ED25519_SIG_LEN]);

/* ML-DSA-65 (FIPS 204, pure, empty context) verification. Platforms without a backend return
 * IM_ERR_MLDSA_NOT_AVAILABLE (the ESP32 build does). */
im_err_t im_crypto_mldsa65_verify(const uint8_t *pub, size_t pub_len, const uint8_t *msg,
                                  size_t msg_len, const uint8_t *sig, size_t sig_len);
/* Non-zero when an ML-DSA-65 backend is linked (WIRE_FORMAT.md §6.3 step 4 ordering). */
int im_crypto_mldsa65_available(void);

/* AES-GCM with a 12-byte IV and 16-byte tag; key_len is 16 or 32. out may equal in. */
im_err_t im_crypto_aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                                   const uint8_t iv[IM_GCM_IV_LEN], const uint8_t *aad,
                                   size_t aad_len, const uint8_t *in, size_t len, uint8_t *out,
                                   uint8_t tag[IM_GCM_TAG_LEN]);
im_err_t im_crypto_aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                                   const uint8_t iv[IM_GCM_IV_LEN], const uint8_t *aad,
                                   size_t aad_len, const uint8_t *in, size_t len,
                                   const uint8_t tag[IM_GCM_TAG_LEN], uint8_t *out);

/* Returns IM_OK iff pub is a valid uncompressed P-256 point (on the curve, not infinity). */
im_err_t im_crypto_p256_point_check(const uint8_t pub[IM_P256_PUB_LEN]);

/* Cryptographically secure random bytes (ESP32: esp_fill_random with RF/bootloader entropy). */
im_err_t im_crypto_random(uint8_t *out, size_t len);

/* ---- device identity (private key operations, implemented per key store) ---------------- */

typedef struct im_identity {
    void *ctx;
    /* 65-byte uncompressed public key of the current identity key. */
    im_err_t (*get_pubkey)(void *ctx, uint8_t pub[IM_P256_PUB_LEN]);
    /* ECDSA P-256 over a 32-byte digest, raw r||s output (ATECC: atcab_sign). */
    im_err_t (*sign_digest)(void *ctx, const uint8_t digest[IM_SHA256_LEN],
                            uint8_t sig[IM_ES256_SIG_LEN]);
    /* ECDH P-256 with peer point; writes the 32-byte shared X coordinate (ATECC: atcab_ecdh). */
    im_err_t (*ecdh)(void *ctx, const uint8_t peer[IM_P256_PUB_LEN], uint8_t shared[32]);
    /* "atecc608" or "software" (contract §3 se_type). */
    const char *se_type;
} im_identity_t;

/* ---- helpers implemented by im_core on top of the provider ------------------------------- */

im_err_t im_sha256(const uint8_t *data, size_t len, uint8_t out[IM_SHA256_LEN]);

/* Zeroize memory in a way the compiler cannot elide. */
void im_secure_zero(void *p, size_t len);

/* Constant-time comparison: returns 1 when equal. */
int im_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* IM_CRYPTO_H */
