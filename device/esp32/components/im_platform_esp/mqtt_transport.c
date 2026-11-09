/*
 * MQTT 5 client for the agent: esp-mqtt (ESP-IDF v5.3) over the IronMesh TLS 1.3 transport
 * (im_tls.c: ALPN mqtt, SPKI pinning from the trust bundle, client key in the SE).
 * Session settings per contract section 4: clean_start=false, session expiry 7 days, receive
 * maximum 32, keep-alive 60 s; reconnects are driven by the agent's backoff (base 1 s, factor 2,
 * cap 300 s, full jitter), so esp-mqtt's own auto-reconnect is disabled.
 *
 * esp-mqtt callbacks run on the esp-mqtt task: they only copy data and post to the agent queue.
 *
 * NOT COMPILED HERE (ESP-IDF v5.3 mqtt component, CONFIG_MQTT_PROTOCOL_5=y).
 * Known esp-mqtt limitations: PUBACK reason codes are not surfaced by MQTT_EVENT_PUBLISHED
 * (reported as 0; EMQX additionally disconnects on ACL violations, which is surfaced), and the
 * host shim's own C MQTT session (im_mqtt.c) is what the host tests exercise.
 */
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "im_esp.h"
#include "mqtt_client.h"

static const char *TAG = "im_mqtt";
static esp_mqtt_client_handle_t s_client;
static uint8_t s_pins[4][32];
static size_t s_n_pins;
static char *s_frag;      /* reassembly of fragmented MQTT_EVENT_DATA */
static size_t s_frag_len;
static char *s_frag_topic;
static size_t s_frag_topic_len;

static void post(im_ev_type_t type, int code, bool flag)
{
    im_ev_t ev = {.type = type, .code = code, .flag = flag};
    (void)im_esp_post(&ev, 100);
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    esp_mqtt_event_handle_t e = data;
    (void)arg;
    (void)base;
    switch ((esp_mqtt_event_id_t)id) {
    case MQTT_EVENT_CONNECTED:
        post(IM_EV_MQTT_CONNECTED, 0, e->session_present != 0);
        break;
    case MQTT_EVENT_DISCONNECTED:
        post(IM_EV_MQTT_DISCONNECTED, 0, false);
        break;
    case MQTT_EVENT_ERROR:
        if (e->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
            post(IM_EV_MQTT_CONNECT_FAILED, 1, false); /* not_authorized */
        } else if (e->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
            post(IM_EV_MQTT_CONNECT_FAILED, 0, false); /* im_tls_last_failure() has the reason */
        }
        break;
    case MQTT_EVENT_PUBLISHED:
        post(IM_EV_MQTT_PUBACK, e->msg_id, false);
        break;
    case MQTT_EVENT_SUBSCRIBED: {
        im_ev_t ev = {.type = IM_EV_MQTT_SUBACK, .code = e->msg_id};
        /* first SUBACK reason code (granted QoS or 0x80+) */
        ev.flag = e->data_len > 0 && (uint8_t)e->data[0] >= 0x80;
        (void)im_esp_post(&ev, 100);
        break;
    }
    case MQTT_EVENT_DATA: {
        /* esp-mqtt splits messages larger than buffer.size; reassemble (bounded) */
        if (e->current_data_offset == 0) {
            free(s_frag);
            free(s_frag_topic);
            s_frag = NULL;
            s_frag_topic = NULL;
            if (e->total_data_len <= 0 || e->total_data_len > IM_AGENT_RX || e->topic_len <= 0 ||
                e->topic_len > 128) {
                break; /* oversize: dropped, never partially processed */
            }
            s_frag = malloc((size_t)e->total_data_len);
            s_frag_topic = malloc((size_t)e->topic_len);
            if (s_frag == NULL || s_frag_topic == NULL) {
                break;
            }
            memcpy(s_frag_topic, e->topic, (size_t)e->topic_len);
            s_frag_topic_len = (size_t)e->topic_len;
            s_frag_len = (size_t)e->total_data_len;
        }
        if (s_frag == NULL || e->current_data_offset + e->data_len > (int)s_frag_len) {
            break;
        }
        memcpy(s_frag + e->current_data_offset, e->data, (size_t)e->data_len);
        if (e->current_data_offset + e->data_len == (int)s_frag_len) {
            im_ev_t ev = {.type = IM_EV_MQTT_DATA,
                          .topic = s_frag_topic,
                          .topic_len = s_frag_topic_len,
                          .data = (uint8_t *)s_frag,
                          .len = s_frag_len};
            s_frag = NULL; /* ownership moves to the agent task */
            s_frag_topic = NULL;
            (void)im_esp_post(&ev, 1000);
        }
        break;
    }
    default:
        break;
    }
}

esp_err_t im_esp_mqtt_init(im_agent_t *agent)
{
    (void)agent;
    return ESP_OK;
}

im_err_t im_esp_mqtt_connect(void *ctx, const char *host, uint16_t port, const char *client_id)
{
    im_agent_t *a = ctx;
    im_tls_opts_t o;
    esp_transport_handle_t tls;
    esp_mqtt5_connection_property_config_t props = {
        .session_expiry_interval = 7 * 24 * 3600,
        .receive_maximum = 32,
        .maximum_packet_size = 16384,
        .request_problem_info = true,
    };
    if (s_client != NULL) {
        (void)im_esp_mqtt_disconnect(ctx);
    }
    s_n_pins = a->n_pins < 4 ? a->n_pins : 4;
    memcpy(s_pins, a->pins, s_n_pins * 32);
    o.alpn = "mqtt";
    o.pin_required = true;
    o.pins = (const uint8_t(*)[32])s_pins;
    o.n_pins = s_n_pins;
    tls = im_tls_transport_new(&o);
    if (tls == NULL) {
        return IM_ERR_IO;
    }
    esp_mqtt_client_config_t cfg = {
        .broker.address.hostname = host,
        .broker.address.port = port,
        .broker.address.transport = MQTT_TRANSPORT_OVER_SSL,
        .network.transport = tls,
        .network.disable_auto_reconnect = true,
        .network.timeout_ms = 10000,
        .session.protocol_ver = MQTT_PROTOCOL_V_5,
        .session.keepalive = 60,
        .session.disable_clean_session = true, /* clean_start = false */
        .credentials.client_id = client_id,    /* MUST equal the certificate CN */
        .buffer.size = 4096,
        .buffer.out_size = 4096,
        .task.stack_size = 6144,
        .task.priority = 5,
        .outbox.limit = 32 * 1024,
    };
    s_client = esp_mqtt_client_init(&cfg);
    if (s_client == NULL) {
        esp_transport_destroy(tls);
        return IM_ERR_IO;
    }
    (void)esp_mqtt5_client_set_connect_property(s_client, &props);
    (void)esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID, on_event, NULL);
    if (esp_mqtt_client_start(s_client) != ESP_OK) {
        esp_mqtt_client_destroy(s_client);
        s_client = NULL;
        return IM_ERR_IO;
    }
    ESP_LOGI(TAG, "connecting to %s:%u as %s", host, port, client_id);
    return IM_OK;
}

im_err_t im_esp_mqtt_disconnect(void *ctx)
{
    (void)ctx;
    if (s_client != NULL) {
        (void)esp_mqtt_client_disconnect(s_client);
        (void)esp_mqtt_client_stop(s_client);
        (void)esp_mqtt_client_destroy(s_client); /* also destroys the TLS transport */
        s_client = NULL;
    }
    return IM_OK;
}

im_err_t im_esp_mqtt_publish(void *ctx, const char *topic, const uint8_t *payload, size_t len,
                             int qos, bool retain, uint16_t *msg_id)
{
    int id;
    (void)ctx;
    if (s_client == NULL) {
        return IM_ERR_STATE;
    }
    id = esp_mqtt_client_publish(s_client, topic, (const char *)payload, (int)len, qos, retain);
    if (id < 0) {
        return IM_ERR_IO;
    }
    if (msg_id != NULL) {
        *msg_id = (uint16_t)id;
    }
    return IM_OK;
}

im_err_t im_esp_mqtt_subscribe(void *ctx, const char *topic, uint16_t *msg_id)
{
    int id;
    (void)ctx;
    if (s_client == NULL) {
        return IM_ERR_STATE;
    }
    id = esp_mqtt_client_subscribe_single(s_client, topic, 1);
    if (id < 0) {
        return IM_ERR_IO;
    }
    if (msg_id != NULL) {
        *msg_id = (uint16_t)id;
    }
    return IM_OK;
}
