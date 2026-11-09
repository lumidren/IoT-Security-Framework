/*
 * IronMesh ESP32 firmware entry point (ESP-IDF v5.3).
 *
 * Tasks (least privilege: only the agent task touches protocol state):
 *   agent  prio 6, 12 KiB  - owns im_agent_t; drains a bounded queue (16 events) fed by
 *   esp-mqtt prio 5, 6 KiB - network/MQTT events (copies only)
 *   ota_dl prio 3, 6 KiB   - firmware download, 4 KiB chunks with queue backpressure
 *   dut    prio 2, 4 KiB   - hil only: USB-Serial/JTAG line reader
 *   tick   (queue timeout) - 100 ms agent tick: backoff, renewal, telemetry, OTA health check
 *
 * NOT COMPILED HERE - ESP-IDF is not installed on the authoring host. The agent itself
 * (components/im_core/im_agent.c) is compiled and tested on the host by host/core-tests and
 * host/dut-shim.
 */
#include <string.h>
#include <time.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "im_agent.h"
#include "im_esp.h"
#include "esp_secure_cert_read.h"
#include "esp_secure_cert_tlv_read.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "ironmesh";

/* PKI bundle verification key (Ed25519): written by the factory station into the
 * esp_secure_cert partition (TLV USER_DATA_1, HARDWARE_SETUP.md section 3) - never compiled in. */
static esp_err_t bundle_pubkey(uint8_t out[32])
{
    esp_secure_cert_tlv_config_t tlv = {.type = ESP_SECURE_CERT_USER_DATA_1_TLV,
                                        .subtype = ESP_SECURE_CERT_SUBTYPE_0};
    esp_secure_cert_tlv_info_t info = {0};
    esp_err_t e = esp_secure_cert_get_tlv_info(&tlv, &info);
    if (e == ESP_OK && info.length == 32) {
        memcpy(out, info.data, 32);
    } else if (e == ESP_OK) {
        e = ESP_ERR_INVALID_SIZE;
    }
    esp_secure_cert_free_tlv_info(&info);
    return e;
}

static QueueHandle_t s_q;
static im_agent_t s_agent; /* ~40 KiB, static: no heap fragmentation */
static uint8_t s_bootstrap_kid[20];

bool im_esp_post(const im_ev_t *ev, uint32_t timeout_ms)
{
    if (s_q != NULL && xQueueSend(s_q, ev, pdMS_TO_TICKS(timeout_ms)) == pdTRUE) {
        return true;
    }
    free(ev->topic);
    free(ev->data);
    return false;
}

/* ---- platform callbacks executed on the agent task ------------------------------------------ */

static uint64_t now_unix(void *ctx)
{
    (void)ctx;
    return (uint64_t)time(NULL);
}

static uint64_t mono_ms(void *ctx)
{
    (void)ctx;
    return (uint64_t)(esp_timer_get_time() / 1000);
}

static im_err_t est_enroll(void *ctx, bool renew)
{
    im_ev_t ev = {.type = IM_EV_ENROLL, .code = renew ? 1 : 0};
    (void)ctx;
    return im_esp_post(&ev, 0) ? IM_OK : IM_ERR_BUSY; /* runs after the current event */
}

static void emit(void *ctx, const char *line, size_t len)
{
    (void)ctx;
#if CONFIG_IRONMESH_DUT_CONTROL
    im_esp_dut_emit(line, len);
#else
    (void)line;
    (void)len;
#endif
}

static void reboot(void *ctx, int reason)
{
    (void)ctx;
    ESP_LOGW(TAG, "reboot (%d)", reason);
    vTaskDelay(pdMS_TO_TICKS(200)); /* let esp-mqtt flush the last PUBACKs */
    esp_restart();
}

/* ---- agent task ------------------------------------------------------------------------------ */

static void handle(const im_ev_t *ev)
{
    im_agent_t *a = &s_agent;
    switch (ev->type) {
    case IM_EV_MQTT_CONNECTED:
        im_agent_on_connected(a, "TLSv1.3", "mqtt", ev->flag, im_tls_last_resumed());
        break;
    case IM_EV_MQTT_CONNECT_FAILED:
        im_agent_on_connect_failed(a, ev->code == 1 ? "not_authorized" : im_tls_last_failure());
        break;
    case IM_EV_MQTT_DISCONNECTED:
        im_agent_on_disconnected(a, "network", 0);
        break;
    case IM_EV_MQTT_DATA:
        im_agent_on_message(a, ev->topic, ev->topic_len, ev->data, ev->len);
        break;
    case IM_EV_MQTT_PUBACK:
        im_agent_on_puback(a, (uint16_t)ev->code, 0);
        break;
    case IM_EV_MQTT_SUBACK:
        im_agent_on_suback(a, (uint16_t)ev->code, ev->flag ? 0x87 : 0x01);
        break;
    case IM_EV_OTA_DATA:
        im_agent_on_ota_data(a, ev->data, ev->len);
        break;
    case IM_EV_OTA_DONE:
        im_agent_on_ota_done(a, (im_err_t)ev->code);
        break;
    case IM_EV_ENROLL:
        (void)im_esp_est_enroll(a, ev->code != 0);
        if (a->provisioned && a->state != IM_ST_CONNECTED) {
            (void)im_agent_connect(a); /* zero-touch: connect right after enrollment */
        }
        break;
    case IM_EV_DUT_LINE:
#if CONFIG_IRONMESH_DUT_CONTROL
        im_esp_dut_handle_line(a, (const char *)ev->data, ev->len);
#endif
        break;
    default:
        break;
    }
}

static void agent_task(void *arg)
{
    (void)arg;
    ESP_ERROR_CHECK(esp_task_wdt_add(NULL));
    for (;;) {
        im_ev_t ev;
        if (xQueueReceive(s_q, &ev, pdMS_TO_TICKS(100)) == pdTRUE) {
            handle(&ev);
            /* plaintext config / payloads are not retained */
            if (ev.data != NULL) {
                im_secure_zero(ev.data, ev.len);
            }
            free(ev.data);
            free(ev.topic);
        }
        im_agent_tick(&s_agent);
        esp_task_wdt_reset();
    }
}

/* ---- Wi-Fi + SNTP ---------------------------------------------------------------------------- */

static void wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)data;
    if (base == WIFI_EVENT && (id == WIFI_EVENT_STA_START || id == WIFI_EVENT_STA_DISCONNECTED)) {
        (void)esp_wifi_connect();
    }
}

static void wifi_start(void)
{
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    wifi_config_t wc = {0};
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event, NULL));
    strncpy((char *)wc.sta.ssid, CONFIG_IRONMESH_WIFI_SSID, sizeof wc.sta.ssid - 1);
    strncpy((char *)wc.sta.password, CONFIG_IRONMESH_WIFI_PSK, sizeof wc.sta.password - 1);
    wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wc.sta.pmf_cfg.required = true;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());
    /* timestamps are checked to +/-300 s: wait for SNTP before talking to the cloud */
    esp_sntp_config_t sntp = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    (void)esp_netif_sntp_init(&sntp);
    (void)esp_netif_sntp_sync_wait(pdMS_TO_TICKS(30000));
}

void app_main(void)
{
    static im_agent_config_t cfg;
    static im_agent_platform_t pf;
    esp_err_t e;
    const char *slot = "ota_0";
    uint64_t fw_size = 0;
    size_t kid_len = 0;

    im_esp_hardening_init();
    e = nvs_flash_init(); /* encrypted per CONFIG_NVS_ENCRYPTION + key protection scheme */
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        e = nvs_flash_init();
    }
    ESP_ERROR_CHECK(e);
    ESP_ERROR_CHECK(im_esp_crypto_init());
    /* key store: ATECC608B or encrypted NVS (Kconfig); slots 0 / 2 / 3 per im_keyslot.h */
    ESP_ERROR_CHECK(im_esp_keystore_init());
    pf.identity = im_esp_keystore_identity();
    /* loads the identity record (active slot + operational cert) before any key is used */
    ESP_ERROR_CHECK(im_esp_kv_init(&pf.kv));
    ESP_ERROR_CHECK(im_esp_storage_init(&pf.storage));
    ESP_ERROR_CHECK(im_esp_bootstrap_serial(s_bootstrap_kid, sizeof s_bootstrap_kid, &kid_len));

    /* device and tenant ids come from the bootstrap certificate subject (CN / OU); the
     * factory station also writes them to NVS for convenience */
    static char device_id[24];
    static char tenant_id[40];
    {
        size_t n1 = sizeof device_id;
        size_t n2 = sizeof tenant_id;
        nvs_handle_t h;
        ESP_ERROR_CHECK(nvs_open("ironmesh", NVS_READONLY, &h));
        ESP_ERROR_CHECK(nvs_get_str(h, "device_id", device_id, &n1));
        ESP_ERROR_CHECK(nvs_get_str(h, "tenant_id", tenant_id, &n2));
        nvs_close(h);
    }

    cfg.device_id = device_id;
    cfg.tenant_id = tenant_id;
    cfg.product = CONFIG_IRONMESH_PRODUCT;
    cfg.fw_version = IM_FW_VERSION;
    cfg.fw_version_code = IM_FW_VERSION_CODE;
    ESP_ERROR_CHECK(im_esp_running_image(&fw_size, cfg.fw_hash, &slot));
    cfg.fw_size = fw_size;
    cfg.slot_size = 0x2E0000;
    ESP_ERROR_CHECK(bundle_pubkey(cfg.bundle_pubkey));
    cfg.require_pq = IS_ENABLED(CONFIG_IRONMESH_REQUIRE_PQ);
    cfg.telemetry_interval_s = CONFIG_IRONMESH_TELEMETRY_INTERVAL_S;
    cfg.ringbuf_slot_size = 512;
    cfg.bootstrap_kid = s_bootstrap_kid;
    cfg.bootstrap_kid_len = kid_len;
    cfg.target = "esp32-hil";
    cfg.boot_reason = im_esp_boot_reason();
    cfg.active_slot = slot;
    cfg.ota_host = CONFIG_IRONMESH_OTA_HOST; /* T-60 artifact host allowlist */

    pf.ctx = &s_agent;
    pf.now_unix = now_unix;
    pf.mono_ms = mono_ms;
    pf.mqtt_connect = im_esp_mqtt_connect;
    pf.mqtt_disconnect = im_esp_mqtt_disconnect;
    pf.mqtt_publish = im_esp_mqtt_publish;
    pf.mqtt_subscribe = im_esp_mqtt_subscribe;
    pf.est_enroll = est_enroll;
    im_esp_ota_platform(&pf.ota);
    pf.ota_download = im_esp_ota_download;
    pf.sample = im_esp_telemetry_sample;
    pf.emit = emit;
    pf.reboot = reboot;

    s_q = xQueueCreate(16, sizeof(im_ev_t));
    configASSERT(s_q != NULL);
#if CONFIG_IRONMESH_DUT_CONTROL
    im_esp_dut_start();
#endif
    wifi_start();
    ESP_ERROR_CHECK(im_agent_init(&s_agent, &cfg, &pf) == IM_OK ? ESP_OK : ESP_FAIL);
    ESP_ERROR_CHECK(im_esp_mqtt_init(&s_agent));
    ESP_ERROR_CHECK(im_agent_start(&s_agent) == IM_OK ? ESP_OK : ESP_FAIL);
    /* zero-touch: enroll when unprovisioned, otherwise connect (the agent retries with backoff) */
    if (s_agent.provisioned) {
        (void)im_agent_connect(&s_agent);
    } else {
        (void)im_agent_enroll(&s_agent, false);
    }
    xTaskCreate(agent_task, "im_agent", 12288, NULL, 6, NULL);
}
