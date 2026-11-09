/*
 * IronMesh protocol core - MQTT 5.0 packet codec (OASIS MQTT 5.0) for the packets a device uses:
 * CONNECT, CONNACK, PUBLISH, PUBACK, SUBSCRIBE, SUBACK, PINGREQ, PINGRESP, DISCONNECT, including
 * properties. The decoder is strict (minimal variable byte integers, reserved flags, per-packet
 * property sets, no duplicate single-use properties, valid UTF-8 without U+0000, no wildcards in
 * PUBLISH topics) and zero-copy: decoded strings point into the frame.
 *
 * im_mqtt_session_t (bottom) is a small client state machine over a byte transport used by the
 * host shim; the ESP32 firmware uses esp-mqtt instead (components/im_platform_esp/mqtt_transport.c).
 */
#ifndef IM_MQTT_H
#define IM_MQTT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "im_err.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    IM_MQTT_CONNECT = 1,
    IM_MQTT_CONNACK = 2,
    IM_MQTT_PUBLISH = 3,
    IM_MQTT_PUBACK = 4,
    IM_MQTT_SUBSCRIBE = 8,
    IM_MQTT_SUBACK = 9,
    IM_MQTT_PINGREQ = 12,
    IM_MQTT_PINGRESP = 13,
    IM_MQTT_DISCONNECT = 14
};

#define IM_MQTT_MAX_USER_PROPS 4u
#define IM_MQTT_MAX_SUB_IDS 4u
#define IM_MQTT_MAX_REASONS 8u
#define IM_MQTT_VBI_MAX 268435455u

typedef struct {
    const char *key;
    uint16_t key_len;
    const char *val;
    uint16_t val_len;
} im_mqtt_user_prop_t;

/* Parsed properties; has_* flags tell which were present. */
typedef struct {
    bool has_payload_format;
    uint8_t payload_format;
    bool has_message_expiry;
    uint32_t message_expiry;
    const char *content_type;
    uint16_t content_type_len;
    const char *response_topic;
    uint16_t response_topic_len;
    const uint8_t *correlation;
    uint16_t correlation_len;
    uint32_t sub_ids[IM_MQTT_MAX_SUB_IDS];
    uint8_t n_sub_ids;
    bool has_session_expiry;
    uint32_t session_expiry;
    const char *assigned_client_id;
    uint16_t assigned_client_id_len;
    bool has_server_keep_alive;
    uint16_t server_keep_alive;
    const char *auth_method;
    uint16_t auth_method_len;
    const uint8_t *auth_data;
    uint16_t auth_data_len;
    bool has_request_problem_info;
    uint8_t request_problem_info;
    bool has_will_delay;
    uint32_t will_delay;
    bool has_request_response_info;
    uint8_t request_response_info;
    const char *response_info;
    uint16_t response_info_len;
    const char *server_reference;
    uint16_t server_reference_len;
    const char *reason_string;
    uint16_t reason_string_len;
    bool has_receive_maximum;
    uint16_t receive_maximum;
    bool has_topic_alias_maximum;
    uint16_t topic_alias_maximum;
    bool has_topic_alias;
    uint16_t topic_alias;
    bool has_maximum_qos;
    uint8_t maximum_qos;
    bool has_retain_available;
    uint8_t retain_available;
    im_mqtt_user_prop_t user[IM_MQTT_MAX_USER_PROPS];
    uint8_t n_user;      /* stored (first IM_MQTT_MAX_USER_PROPS) */
    uint16_t n_user_all; /* present in the packet */
    bool has_maximum_packet_size;
    uint32_t maximum_packet_size;
    bool has_wildcard_available;
    uint8_t wildcard_available;
    bool has_sub_id_available;
    uint8_t sub_id_available;
    bool has_shared_available;
    uint8_t shared_available;
} im_mqtt_props_t;

typedef struct {
    uint8_t type;
    uint8_t flags;
    /* CONNACK */
    bool session_present;
    /* CONNACK / PUBACK / DISCONNECT */
    uint8_t reason_code;
    /* PUBLISH */
    uint8_t qos;
    bool retain;
    bool dup;
    const char *topic;
    uint16_t topic_len;
    const uint8_t *payload;
    size_t payload_len;
    /* PUBLISH / PUBACK / SUBSCRIBE / SUBACK */
    uint16_t packet_id;
    /* SUBACK reason codes, SUBSCRIBE options */
    const uint8_t *reason_codes;
    size_t n_reason_codes;
    /* SUBSCRIBE: first filter (count in n_reason_codes) */
    const char *filter;
    uint16_t filter_len;
    /* CONNECT */
    uint16_t keep_alive;
    bool clean_start;
    const char *client_id;
    uint16_t client_id_len;
    const char *username;
    uint16_t username_len;
    bool has_password;
    bool has_will;
    im_mqtt_props_t props;
} im_mqtt_packet_t;

/* Find the length of the first complete frame in a byte stream. IM_ERR_MQTT_INCOMPLETE when
 * more bytes are needed, IM_ERR_MQTT_MALFORMED for a bad length, IM_ERR_MQTT_PROTOCOL when the
 * frame exceeds max_packet. */
im_err_t im_mqtt_frame(const uint8_t *buf, size_t len, size_t max_packet, size_t *frame_len);

/* Decode exactly one complete frame. */
im_err_t im_mqtt_decode(const uint8_t *frame, size_t len, im_mqtt_packet_t *out);

/* ---- encoders (client side, plus the server packets for tests/simulators) ---------------- */

typedef struct {
    const char *client_id;
    uint16_t keep_alive;
    bool clean_start;
    uint32_t session_expiry;
    uint16_t receive_maximum;
    uint32_t maximum_packet_size;
    const char *username; /* NULL: none */
    const im_mqtt_user_prop_t *user;
    size_t n_user;
} im_mqtt_connect_t;

im_err_t im_mqtt_enc_connect(const im_mqtt_connect_t *c, uint8_t *out, size_t cap, size_t *len);
im_err_t im_mqtt_enc_publish(const char *topic, size_t topic_len, uint8_t qos, bool retain,
                             bool dup, uint16_t packet_id, const im_mqtt_user_prop_t *user,
                             size_t n_user, const uint8_t *payload, size_t payload_len,
                             uint8_t *out, size_t cap, size_t *len);
im_err_t im_mqtt_enc_puback(uint16_t packet_id, uint8_t reason, uint8_t *out, size_t cap,
                            size_t *len);
/* One topic filter per call; options = QoS | (no_local<<2) | (rap<<3) | (retain handling<<4). */
im_err_t im_mqtt_enc_subscribe(uint16_t packet_id, const char *filter, size_t filter_len,
                               uint8_t options, uint8_t *out, size_t cap, size_t *len);
im_err_t im_mqtt_enc_pingreq(uint8_t *out, size_t cap, size_t *len);
im_err_t im_mqtt_enc_pingresp(uint8_t *out, size_t cap, size_t *len);
im_err_t im_mqtt_enc_disconnect(uint8_t reason, uint8_t *out, size_t cap, size_t *len);
im_err_t im_mqtt_enc_connack(bool session_present, uint8_t reason, uint16_t receive_maximum,
                             uint8_t *out, size_t cap, size_t *len);
im_err_t im_mqtt_enc_suback(uint16_t packet_id, const uint8_t *codes, size_t n, uint8_t *out,
                            size_t cap, size_t *len);

/* Valid MQTT UTF-8 string (well-formed, no U+0000). */
bool im_mqtt_utf8_ok(const char *s, size_t n);

/* ---- client session over a byte transport (host shim) ---------------------------------- */

#define IM_MQTT_SESSION_RX 16384u
#define IM_MQTT_INFLIGHT 32u

typedef struct im_mqtt_session im_mqtt_session_t;

typedef struct {
    im_err_t (*send)(void *ctx, const uint8_t *data, size_t len);
    void (*on_connack)(void *ctx, bool session_present, uint8_t reason);
    void (*on_publish)(void *ctx, const im_mqtt_packet_t *p);
    void (*on_puback)(void *ctx, uint16_t packet_id, uint8_t reason);
    void (*on_suback)(void *ctx, uint16_t packet_id, uint8_t reason);
    void (*on_disconnect)(void *ctx, uint8_t reason, bool by_peer);
    void *ctx;
} im_mqtt_session_cb_t;

struct im_mqtt_session {
    im_mqtt_session_cb_t cb;
    uint8_t rx[IM_MQTT_SESSION_RX];
    size_t rx_len;
    uint8_t tx[IM_MQTT_SESSION_RX];
    bool connected;
    bool awaiting_connack;
    uint16_t keep_alive;
    uint16_t next_pid;
    uint16_t inflight[IM_MQTT_INFLIGHT];
    uint16_t receive_maximum; /* broker's */
    uint64_t last_tx_ms;
    uint64_t ping_sent_ms;
    bool ping_outstanding;
};

void im_mqtt_session_init(im_mqtt_session_t *s, const im_mqtt_session_cb_t *cb);
im_err_t im_mqtt_session_connect(im_mqtt_session_t *s, const im_mqtt_connect_t *c,
                                 uint64_t now_ms);
/* Feed received transport bytes; dispatches callbacks; protocol errors close the session. */
im_err_t im_mqtt_session_input(im_mqtt_session_t *s, const uint8_t *data, size_t len,
                               uint64_t now_ms);
im_err_t im_mqtt_session_publish(im_mqtt_session_t *s, const char *topic, const uint8_t *payload,
                                 size_t len, uint8_t qos, bool retain,
                                 const im_mqtt_user_prop_t *user, size_t n_user,
                                 uint16_t *packet_id, uint64_t now_ms);
im_err_t im_mqtt_session_subscribe(im_mqtt_session_t *s, const char *filter, uint8_t qos,
                                   uint16_t *packet_id, uint64_t now_ms);
im_err_t im_mqtt_session_disconnect(im_mqtt_session_t *s, uint8_t reason);
/* Keep-alive: PINGREQ when idle; IM_ERR_TIMEOUT when the broker stopped answering. */
im_err_t im_mqtt_session_tick(im_mqtt_session_t *s, uint64_t now_ms);
/* Forget the connection (transport lost). */
void im_mqtt_session_reset(im_mqtt_session_t *s);
size_t im_mqtt_session_inflight(const im_mqtt_session_t *s);

#ifdef __cplusplus
}
#endif

#endif /* IM_MQTT_H */
