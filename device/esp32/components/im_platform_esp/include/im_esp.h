/*
 * IronMesh ESP32 platform layer (ESP-IDF v5.3): everything im_core needs from the device.
 *
 * NOT COMPILED IN THIS REPOSITORY'S HOST CI - written against the ESP-IDF v5.3 API and built by
 * the HIL job (`idf.py build`). The protocol logic it serves (components/im_core) is compiled
 * and tested on the host (host/core-tests, host/dut-shim).
 *
 * Threading: the agent (im_agent_t) is single threaded. Every callback here that originates in
 * another task (esp-mqtt event task, OTA download task, DUT reader) posts an event to the agent
 * task's bounded queue (main/app_main.c) instead of calling the agent directly.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_transport.h"
#include "im_agent.h"
#include "im_crypto.h"
#include "mbedtls/pk.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- crypto provider (im_crypto_mbedtls.c) ----------------------------------------------- */
esp_err_t im_esp_crypto_init(void);

/* ---- identities ---------------------------------------------------------------------------- */
/* ATECC608B: slot 0 bootstrap key (locked at the factory), slot 2 operational key. */
esp_err_t im_esp_atecc_init(void);
const im_identity_t *im_esp_atecc_identity(void);
/* Generate a fresh operational key in slot 2 (atcab_genkey) for a new enrollment. */
esp_err_t im_esp_atecc_new_operational(uint8_t pub[65]);
/* After a successful enrollment: slot 2 becomes the identity; on failure fall back to slot 0. */
void im_esp_atecc_commit(bool use_operational);

/* Software key in encrypted NVS ("software" assurance, contract section 10). */
esp_err_t im_esp_nvs_identity_init(void);
const im_identity_t *im_esp_nvs_identity(void);
esp_err_t im_esp_nvs_new_operational(uint8_t pub[65]);
void im_esp_nvs_commit(bool use_operational);

/* The active identity's TLS client key as an mbedTLS pk context (ATECC: opaque, signs in the
 * secure element; software: the decrypted NVS key, zeroized on free). */
esp_err_t im_esp_identity_pk(mbedtls_pk_context *pk);
/* The identity that a new CSR is generated for (pending until commit). */
esp_err_t im_esp_identity_pending_pk(mbedtls_pk_context *pk);

/* ---- persistent storage (platform_storage.c) -------------------------------------------- */
esp_err_t im_esp_kv_init(im_kv_t *kv);          /* encrypted NVS namespace "ironmesh" */
esp_err_t im_esp_storage_init(im_storage_t *st); /* "storage" partition (offline buffer) */

/* Current certificate (DER) for TLS client auth: bootstrap from esp_secure_cert until the first
 * enrollment, then the operational cert stored in NVS. */
esp_err_t im_esp_client_cert(const uint8_t **der, size_t *len);
esp_err_t im_esp_store_operational_cert(const uint8_t *der, size_t len);
esp_err_t im_esp_bootstrap_serial(uint8_t *serial, size_t cap, size_t *len);

/* ---- TLS transport (im_tls.c) ---------------------------------------------------------- */
typedef struct {
    const char *alpn;        /* "mqtt" for the broker, NULL for EST */
    bool pin_required;       /* broker: only CA certs whose SPKI SHA-256 is pinned are anchors */
    const uint8_t (*pins)[32];
    size_t n_pins;
} im_tls_opts_t;

/* An esp_transport (for esp-mqtt) doing TLS 1.3 with mbedTLS directly, so the client key can
 * live in ATECC slot 2 (esp-tls' secure-element hook is fixed to slot 0). */
esp_transport_handle_t im_tls_transport_new(const im_tls_opts_t *opts);
/* Result of the last handshake, for the DUT "connected" / "connect_failed" events. */
const char *im_tls_last_failure(void); /* tls_pin_mismatch, tls_handshake, cert_rejected, ... */
bool im_tls_last_resumed(void);

/* ---- EST (est_client.c), MQTT (mqtt_transport.c), OTA (ota_ab.c) ------------------------ */
esp_err_t im_esp_est_enroll(im_agent_t *agent, bool renew);
esp_err_t im_esp_mqtt_init(im_agent_t *agent);
im_err_t im_esp_mqtt_connect(void *ctx, const char *host, uint16_t port, const char *client_id);
im_err_t im_esp_mqtt_disconnect(void *ctx);
im_err_t im_esp_mqtt_publish(void *ctx, const char *topic, const uint8_t *payload, size_t len,
                             int qos, bool retain, uint16_t *msg_id);
im_err_t im_esp_mqtt_subscribe(void *ctx, const char *topic, uint16_t *msg_id);

void im_esp_ota_platform(im_ota_platform_t *pf);
im_err_t im_esp_ota_download(void *ctx, const char *url, size_t url_len);
/* Running image facts for the agent configuration. */
esp_err_t im_esp_running_image(uint64_t *size, uint8_t sha256[32], const char **slot_name);
int im_esp_boot_reason(void);

/* ---- telemetry, hardening, DUT --------------------------------------------------------- */
void im_esp_telemetry_sample(void *ctx, im_telemetry_t *t);
void im_esp_hardening_init(void);

#if CONFIG_IRONMESH_DUT_CONTROL
void im_esp_dut_start(void);
/* Called on the agent task for one received line; writes response + events with "@@IM ". */
void im_esp_dut_handle_line(im_agent_t *agent, const char *line, size_t len);
void im_esp_dut_emit(const char *line, size_t len);
#endif

/* ---- agent task queue (main/app_main.c) ------------------------------------------------- */
typedef enum {
    IM_EV_TICK = 0,
    IM_EV_MQTT_CONNECTED,
    IM_EV_MQTT_CONNECT_FAILED,
    IM_EV_MQTT_DISCONNECTED,
    IM_EV_MQTT_DATA,
    IM_EV_MQTT_PUBACK,
    IM_EV_MQTT_SUBACK,
    IM_EV_OTA_DATA,
    IM_EV_OTA_DONE,
    IM_EV_DUT_LINE,
    IM_EV_ENROLL
} im_ev_type_t;

typedef struct {
    im_ev_type_t type;
    int code;         /* msg id, reason code, im_err_t, renew flag */
    bool flag;        /* session present */
    char *topic;      /* heap copy (freed by the agent task) */
    size_t topic_len;
    uint8_t *data;    /* heap copy (freed by the agent task) */
    size_t len;
} im_ev_t;

/* Post an event to the agent task (bounded queue; blocks up to timeout_ms, then drops and
 * frees the payload). Returns false when dropped. */
bool im_esp_post(const im_ev_t *ev, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
