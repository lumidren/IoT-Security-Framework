/*
 * IronMesh protocol core - message envelope (WIRE_FORMAT.md §3): payload codec, typed body
 * validation, signing and the verification algorithm of §3.6 including the replay window and
 * timestamp skew. Decoded messages point into the caller's buffer.
 */
#ifndef IM_ENVELOPE_H
#define IM_ENVELOPE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_cbor.h"
#include "im_cose.h"
#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { IM_DIR_UPLINK = 0, IM_DIR_DOWNLINK = 1 } im_direction_t;

enum {
    IM_MSG_TELEMETRY = 1,
    IM_MSG_EVENT = 2,
    IM_MSG_SHADOW_REPORTED = 3,
    IM_MSG_SHADOW_DESIRED = 4,
    IM_MSG_COMMAND = 5,
    IM_MSG_COMMAND_ACK = 6,
    IM_MSG_OTA_NOTIFY = 7,
    IM_MSG_OTA_STATUS = 8,
    IM_MSG_CONFIG = 9,
    IM_MSG_ATTESTATION = 10
};

#define IM_NONCE_LEN 16u
#define IM_MAX_SKEW_DEFAULT 300u

im_direction_t im_msg_direction(uint8_t type);
/* Downlink ShadowDesired / OtaNotify / Config: may be retained, so only ts - now <= max_skew. */
bool im_msg_retainable(uint8_t type);

/* Replay stream id (§3.6 step 11): the device kid for uplink, "<tenant kid>/<type>" for
 * downlink. This is the key handed to im_replay_store_t.check_and_record. */
#define IM_REPLAY_STREAM_MAX 52u
im_err_t im_env_replay_stream(const uint8_t *kid, size_t kid_len, im_direction_t dir,
                              uint8_t type, uint8_t *out, size_t cap, size_t *out_len);

/* Resolves a sender kid to its public key; returns IM_ERR_NOT_FOUND for an unknown sender. */
typedef struct {
    im_err_t (*resolve)(void *ctx, const uint8_t *kid, size_t kid_len, bool kid_text,
                        im_pubkey_t *out);
    void *ctx;
} im_key_resolver_t;

/* Atomically accept seq iff it is strictly greater than the last accepted value for the replay
 * stream (see im_env_replay_stream; passed as kid) (or none exists) and record it: IM_OK;
 * otherwise IM_ERR_ENV_REPLAY and the
 * store is unchanged. Any other code is a storage failure (the message is rejected). */
typedef struct {
    im_err_t (*check_and_record)(void *ctx, const uint8_t *kid, size_t kid_len,
                                 im_direction_t dir, uint64_t seq);
    void *ctx;
} im_replay_store_t;

typedef struct {
    const im_key_resolver_t *resolver;
    const im_replay_store_t *replay;
    uint64_t now;
    uint64_t max_skew;              /* 0 means IM_MAX_SKEW_DEFAULT */
    int expected_direction;         /* -1: any, else im_direction_t */
    const char *expected_tenant;    /* NULL or 36-char tenant uuid */
    const uint8_t *expected_nonce;  /* NULL or 16 bytes */
    const im_cbor_limits_t *limits; /* NULL: defaults */
    uint8_t *work;                  /* EdDSA Sig_structure buffer (>= payload + ~80 bytes) */
    size_t work_len;
} im_env_decode_opts_t;

void im_env_decode_opts_init(im_env_decode_opts_t *o);

typedef struct {
    uint64_t seq;
    uint64_t ts;
    uint8_t type;
    im_direction_t direction;
    const uint8_t *kid;
    size_t kid_len;
    bool kid_text;
    const uint8_t *nonce; /* 16 bytes or NULL */
    im_cbor_val_t body;   /* validated integer-keyed body map */
    const uint8_t *payload;
    size_t payload_len;
} im_env_msg_t;

/* Full §3.6 verification. The first failing step determines the code. */
im_err_t im_env_decode(const uint8_t *buf, size_t len, const im_env_decode_opts_t *opts,
                       im_env_msg_t *msg);
/* §3.1/§3.4 payload parse and validation only (no crypto, no replay). */
im_err_t im_env_decode_payload(const uint8_t *p, size_t n, const im_cbor_limits_t *lim,
                               im_env_msg_t *msg);
/* §3.3: ENV_KID / ENV_DIRECTION for the header profile of a direction. */
im_err_t im_env_check_header_profile(int alg, const uint8_t *kid, size_t kid_len, bool kid_text,
                                     im_direction_t dir);

/* ---- typed body accessors (on a validated message) --------------------------------------- */

typedef struct {
    const char *cmd_id; /* 36 chars, not terminated */
    const char *name;
    size_t name_len;
    im_cbor_val_t args;
    const char *idempotency_key;
    size_t idempotency_key_len;
    uint64_t expires_at;
} im_command_t;

typedef struct {
    const char *campaign_id; /* 36 */
    const uint8_t *manifest;
    size_t manifest_len;
    const char *url;
    size_t url_len;
    const uint8_t *delta_from; /* 32 or NULL */
} im_ota_notify_t;

typedef struct {
    uint64_t version;
    im_cbor_val_t settings;
} im_config_t;

typedef struct {
    im_cbor_val_t state;
    uint64_t version;
} im_shadow_t;

typedef struct {
    const char *cmd_id;
    uint64_t status;
    bool has_result;
    im_cbor_val_t result;
    const char *error;
    size_t error_len;
} im_command_ack_t;

typedef struct {
    const uint8_t *nonce;    /* 32 */
    const uint8_t *csr_hash; /* 32 */
    const uint8_t *fw_hash;  /* 32 */
    const char *fw_version;
    size_t fw_version_len;
    const char *se_type;
    size_t se_type_len;
    bool has_evidence;
    im_cbor_val_t evidence;
} im_attestation_t;

im_err_t im_env_get_command(const im_env_msg_t *m, im_command_t *out);
im_err_t im_env_get_command_ack(const im_env_msg_t *m, im_command_ack_t *out);
im_err_t im_env_get_ota_notify(const im_env_msg_t *m, im_ota_notify_t *out);
im_err_t im_env_get_config(const im_env_msg_t *m, im_config_t *out);
im_err_t im_env_get_shadow(const im_env_msg_t *m, im_shadow_t *out);
im_err_t im_env_get_attestation(const im_env_msg_t *m, im_attestation_t *out);

/* ---- payload / body encoding -------------------------------------------------------------- */

/* Begin {1: seq, 2: ts, 3: type, 4: <body follows>}; then encode the body; then end. */
void im_env_payload_begin(im_cbor_enc_t *e, uint64_t seq, uint64_t ts, uint8_t type,
                          bool has_nonce);
/* Writes 5: nonce if non-NULL, then validates the whole payload like a receiver would. */
im_err_t im_env_payload_end(im_cbor_enc_t *e, const uint8_t *nonce, size_t *len);

typedef struct {
    double cpu_pct;
    double mem_pct;
    uint64_t net_rx_bytes;
    uint64_t net_tx_bytes;
    double temp_c;
    uint64_t uptime_s;
    uint64_t auth_failures;
    uint8_t fw_hash[32];
    const char *fw_version;
    bool has_proc_count;
    uint64_t proc_count;
    const char *const *top_procs; /* NULL: absent */
    size_t n_top_procs;
    bool has_rssi;
    int64_t rssi;
    bool has_free_heap;
    uint64_t free_heap;
    bool has_lat;
    double lat;
    bool has_lon;
    double lon;
} im_telemetry_t;

void im_body_telemetry(im_cbor_enc_t *e, const im_telemetry_t *t);
/* AppMaps are passed pre-encoded (a canonical CBOR map with text keys); NULL means {}. */
void im_body_event(im_cbor_enc_t *e, const char *name, uint64_t severity, const uint8_t *data,
                   size_t data_len);
void im_body_shadow(im_cbor_enc_t *e, const uint8_t *state, size_t state_len, uint64_t version);
void im_body_command(im_cbor_enc_t *e, const char *cmd_id, const char *name,
                     const uint8_t *args, size_t args_len, const char *idem_key,
                     uint64_t expires_at);
/* result may be NULL (absent); error may be NULL (absent). */
void im_body_command_ack(im_cbor_enc_t *e, const char *cmd_id, uint64_t status,
                         const uint8_t *result, size_t result_len, const char *error);
void im_body_ota_notify(im_cbor_enc_t *e, const char *campaign_id, const uint8_t *manifest,
                        size_t manifest_len, const char *url, const uint8_t *delta_from);
/* error / fw_hash may be NULL (absent). */
void im_body_ota_status(im_cbor_enc_t *e, const char *campaign_id, uint64_t state,
                        uint64_t progress_pct, const char *error, const uint8_t *fw_hash);
void im_body_config(im_cbor_enc_t *e, uint64_t version, const uint8_t *settings,
                    size_t settings_len);
void im_body_attestation(im_cbor_enc_t *e, const uint8_t nonce[32], const uint8_t csr_hash[32],
                         const uint8_t fw_hash[32], const char *fw_version, const char *se_type);

/* Sign a payload as an uplink envelope with the device identity (ES256, kid = serial). */
im_err_t im_env_sign_uplink(const im_identity_t *id, const uint8_t *kid, size_t kid_len,
                            const uint8_t *payload, size_t payload_len, uint8_t *out, size_t cap,
                            size_t *out_len);

/* ---- fixed-size in-memory replay store (device side) ------------------------------------- */

/* A device tracks one tenant: 4 downlink streams (types 4, 5, 7, 9) plus headroom for a
 * tenant-key rotation (old + new kid) = 8 fixed slots; the store fails closed when full. */
#define IM_REPLAY_MEM_SLOTS 8u
#define IM_REPLAY_KID_MAX IM_REPLAY_STREAM_MAX

typedef struct {
    bool used;
    uint8_t dir;
    uint8_t kid_len;
    uint8_t kid[IM_REPLAY_KID_MAX];
    uint64_t last_seq;
} im_replay_entry_t;

typedef struct {
    im_replay_entry_t e[IM_REPLAY_MEM_SLOTS];
    /* Optional durability hook: called after an entry changed; a failure rejects the message. */
    im_err_t (*persist)(void *ctx, const im_replay_entry_t *entry);
    void *persist_ctx;
} im_replay_mem_t;

void im_replay_mem_init(im_replay_mem_t *s);
void im_replay_mem_store(im_replay_mem_t *s, im_replay_store_t *out);
/* last accepted seq; false when none */
bool im_replay_mem_last(const im_replay_mem_t *s, const uint8_t *kid, size_t kid_len,
                        im_direction_t dir, uint64_t *seq);

#ifdef __cplusplus
}
#endif

#endif /* IM_ENVELOPE_H */
