/*
 * IronMesh protocol core - device agent.
 *
 * All device-side protocol logic lives here so the ESP32 firmware and the host shim run the
 * same code: credential/bundle bookkeeping, persistent outbound sequence numbers, telemetry
 * signing, the offline ring buffer and its in-order flush, inbound verification (topic ACL,
 * COSE, tenant, skew, replay, HPKE for config), command execution with idempotency, the OTA
 * state machine, certificate renewal scheduling and the reconnect backoff.
 *
 * The platform supplies time, a key-value store, flash storage, the identity, an MQTT client and
 * an EST client through im_agent_platform_t and reports asynchronous results back through the
 * im_agent_on_* functions. Events for the DUT control protocol are produced as JSON lines.
 * The agent is single-threaded: every entry point must be called from the same task.
 */
#ifndef IM_AGENT_H
#define IM_AGENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_crypto.h"
#include "im_envelope.h"
#include "im_err.h"
#include "im_ids.h"
#include "im_ota.h"
#include "im_ringbuf.h"
#include "im_util.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    IM_ST_UNPROVISIONED = 0,
    IM_ST_ENROLLING,
    IM_ST_CONNECTING,
    IM_ST_CONNECTED,
    IM_ST_OFFLINE,
    IM_ST_BACKOFF,
    IM_ST_REBOOTING
};

/* reboot reasons (DUT "rebooted" event) */
enum { IM_REBOOT_REQUESTED = 0, IM_REBOOT_OTA_APPLY, IM_REBOOT_ROLLBACK, IM_REBOOT_WATCHDOG,
       IM_REBOOT_POWER_ON };

#define IM_AGENT_FW_KEYS 3u
#define IM_AGENT_FW_KEY_MAX 1952u
#define IM_AGENT_PINS 4u
#define IM_AGENT_HOST_MAX 128u
#define IM_AGENT_REJECTIONS 32u
#define IM_AGENT_TX 2048u
#define IM_AGENT_RX 8320u
#define IM_AGENT_BUNDLE_MAX 8192u

typedef struct {
    const char *device_id;  /* dev-<16 hex> */
    const char *tenant_id;  /* uuid4 */
    const char *product;
    const char *fw_version; /* semver */
    uint64_t fw_version_code;
    uint8_t fw_hash[32];
    uint64_t fw_size;
    uint64_t slot_size;
    uint8_t bundle_pubkey[32]; /* PKI bundle Ed25519 key baked in at the factory */
    bool require_pq;
    uint32_t telemetry_interval_s; /* 0: only on request */
    uint32_t ringbuf_slot_size;    /* e.g. 512 */
    const uint8_t *bootstrap_kid;  /* serial of the bootstrap certificate */
    size_t bootstrap_kid_len;
    const char *target;            /* "esp32-host" / "esp32-hil" */
    int boot_reason;               /* IM_REBOOT_* as seen by the platform */
    const char *active_slot;       /* e.g. "ota_0" */
} im_agent_config_t;

typedef struct im_agent im_agent_t;

typedef struct {
    void *ctx;
    const im_identity_t *identity;
    uint64_t (*now_unix)(void *ctx);
    uint64_t (*mono_ms)(void *ctx);
    im_kv_t kv;
    im_storage_t storage; /* offline buffer partition */
    /* MQTT client: connect/subscribe/publish complete asynchronously via im_agent_on_*. */
    im_err_t (*mqtt_connect)(void *ctx, const char *host, uint16_t port, const char *client_id);
    im_err_t (*mqtt_disconnect)(void *ctx);
    im_err_t (*mqtt_publish)(void *ctx, const char *topic, const uint8_t *payload, size_t len,
                             int qos, bool retain, uint16_t *msg_id);
    im_err_t (*mqtt_subscribe)(void *ctx, const char *topic, uint16_t *msg_id);
    /* EST enrollment (renew=false: bootstrap simpleenroll; true: simplereenroll). */
    im_err_t (*est_enroll)(void *ctx, bool renew);
    /* OTA: the slot operations plus an asynchronous download of url. */
    im_ota_platform_t ota;
    im_err_t (*ota_download)(void *ctx, const char *url, size_t url_len);
    /* Telemetry sample (agent fills fw fields and auth failures). */
    void (*sample)(void *ctx, im_telemetry_t *t);
    /* Optional extra commands; return IM_ERR_NOT_FOUND for unknown names. */
    im_err_t (*exec_command)(void *ctx, const char *name, size_t name_len, const im_cbor_val_t *args,
                             uint8_t *status);
    /* Apply a verified config map (settings). */
    void (*apply_config)(void *ctx, uint64_t version, const im_cbor_val_t *settings);
    /* One JSON event line (no prefix, no newline). */
    void (*emit)(void *ctx, const char *line, size_t len);
    /* Reboot now (after flushing state). */
    void (*reboot)(void *ctx, int reason);
} im_agent_platform_t;

typedef struct {
    uint64_t at_ms;
    im_err_t code;
    char topic[IM_TOPIC_MAX_LEN];
    char detail[32];
} im_rejection_t;

typedef struct {
    uint16_t msg_id;
    uint8_t kind; /* 1 live telemetry, 2 buffered flush, 3 raw, 4 other */
    uint64_t seq;
    char topic[IM_TOPIC_MAX_LEN];
} im_pending_pub_t;

struct im_agent {
    im_agent_config_t cfg;
    im_agent_platform_t pf;
    int state;
    bool started;
    /* credentials */
    bool provisioned;
    uint8_t kid[20];
    size_t kid_len;
    uint64_t cert_not_before;
    uint64_t cert_not_after;
    uint64_t renew_at;
    uint32_t renew_attempt;
    bool renewing;
    /* bundle */
    bool have_bundle;
    uint8_t tenant_pub[32];
    uint8_t fw_keys[IM_AGENT_FW_KEYS][IM_AGENT_FW_KEY_MAX];
    size_t fw_key_len[IM_AGENT_FW_KEYS];
    size_t n_fw_keys;
    char broker_host[IM_AGENT_HOST_MAX];
    uint16_t broker_port;
    uint8_t pins[IM_AGENT_PINS][32];
    size_t n_pins;
    /* sequence numbers */
    uint64_t seq_out;
    uint64_t seq_reserved;
    /* stores */
    im_replay_mem_t replay;
    im_ringbuf_t rb;
    bool rb_ok;
    im_cmd_cache_t cmds;
    im_ota_t ota;
    uint8_t ota_work[4096];
    /* connection */
    bool want_connected;
    bool net_up;
    uint32_t backoff_attempt;
    uint64_t next_connect_ms;
    uint64_t last_telemetry_ms;
    bool telemetry_acked;
    im_pending_pub_t pend[16];
    bool flushing;
    uint16_t flush_msg_id;
    uint32_t flush_count;
    uint64_t flush_first;
    uint64_t flush_last;
    /* diagnostics */
    uint32_t auth_failures;
    uint64_t boot_ms;
    im_rejection_t rej[IM_AGENT_REJECTIONS];
    uint32_t rej_next;
    uint32_t rej_total;
    uint64_t config_version;
    bool reboot_pending;
    int reboot_reason;
    /* scratch */
    uint8_t tx[IM_AGENT_TX];
    uint8_t payload[IM_AGENT_TX];
    uint8_t rx[IM_AGENT_RX];
    uint8_t work[IM_AGENT_BUNDLE_MAX];
};

size_t im_agent_ctx_size(void);
im_err_t im_agent_init(im_agent_t *a, const im_agent_config_t *cfg, const im_agent_platform_t *pf);
/* Load persisted state, mount the ring buffer, run the OTA boot check, emit "rebooted". */
im_err_t im_agent_start(im_agent_t *a);
/* Periodic work (call every ~100 ms): reconnect backoff, renewal, telemetry, OTA health. */
void im_agent_tick(im_agent_t *a);

/* ---- requests (DUT ops / application) ------------------------------------------------------ */
im_err_t im_agent_enroll(im_agent_t *a, bool renew);
im_err_t im_agent_connect(im_agent_t *a);
im_err_t im_agent_disconnect(im_agent_t *a);
void im_agent_set_net(im_agent_t *a, bool up);
im_err_t im_agent_send_telemetry(im_agent_t *a, uint32_t count, uint64_t *first, uint64_t *last);
im_err_t im_agent_publish_raw(im_agent_t *a, const char *topic, const uint8_t *payload,
                              size_t len, int qos, bool retain);
im_err_t im_agent_subscribe_raw(im_agent_t *a, const char *topic);
im_err_t im_agent_reboot(im_agent_t *a, int reason);

/* ---- enrollment helpers for the platform's EST client -------------------------------------- */
/* Attestation header value (COSE bytes) for the CSR, signed by the current identity key. */
im_err_t im_agent_attestation(im_agent_t *a, const uint8_t nonce[32], const uint8_t *csr_der,
                              size_t csr_len, uint8_t *out, size_t cap, size_t *out_len);
/* Successful (re-)enrollment: new serial/validity and the X-IronMesh-Bundle (may be NULL). */
im_err_t im_agent_on_enrolled(im_agent_t *a, const uint8_t *serial, size_t serial_len,
                              uint64_t not_before, uint64_t not_after, const uint8_t *bundle,
                              size_t bundle_len);
void im_agent_on_enroll_failed(im_agent_t *a, int http_status, const char *reason);
/* Verify an X-IronMesh-Bundle COSE_Sign1 with the factory bundle key and load it. */
im_err_t im_agent_load_bundle(im_agent_t *a, const uint8_t *bundle, size_t len);

/* ---- transport callbacks -------------------------------------------------------------------- */
void im_agent_on_connected(im_agent_t *a, const char *tls_version, const char *alpn,
                           bool session_present, bool resumed);
void im_agent_on_connect_failed(im_agent_t *a, const char *reason);
void im_agent_on_disconnected(im_agent_t *a, const char *reason, int reason_code);
void im_agent_on_puback(im_agent_t *a, uint16_t msg_id, uint8_t reason);
void im_agent_on_suback(im_agent_t *a, uint16_t msg_id, uint8_t reason);
void im_agent_on_message(im_agent_t *a, const char *topic, size_t topic_len,
                         const uint8_t *payload, size_t len);
void im_agent_on_ota_data(im_agent_t *a, const uint8_t *data, size_t len);
void im_agent_on_ota_done(im_agent_t *a, im_err_t err);

/* ---- introspection --------------------------------------------------------------------------- */
const char *im_agent_state_name(int state);
size_t im_agent_rejections(const im_agent_t *a, uint64_t since_ms, const im_rejection_t **out,
                           size_t max);
uint64_t im_agent_uptime_ms(const im_agent_t *a);
/* semver of the manifest of the current/last OTA campaign (for the platform's slot table). */
im_err_t im_agent_ota_version(const im_agent_t *a, char *out, size_t cap);

/* DUT control protocol (conformance/DUT_PROTOCOL.md): handle one request line, write the
 * response line (no newline) into out. Platform specific ops go through hooks. */
typedef struct {
    im_err_t (*set_clock)(void *ctx, uint64_t unix_s); /* NULL: unsupported */
    /* active/pending slot names (pending may be NULL) and per-slot info for ota_slots */
    void (*slots)(void *ctx, im_json_w_t *w, const char **active, const char **pending);
    void *ctx;
} im_dut_hooks_t;

im_err_t im_dut_handle(im_agent_t *a, const im_dut_hooks_t *hooks, const char *line, size_t len,
                       char *out, size_t cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* IM_AGENT_H */
