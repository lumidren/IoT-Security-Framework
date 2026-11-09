/*
 * Telemetry sampler (contract section 5 Telemetry body, ESP32 fields): heap, RSSI, on-die
 * temperature, uptime; auth failures and firmware fields are filled in by im_core.
 * CPU load uses FreeRTOS run-time stats when CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS is set.
 *
 * NOT COMPILED HERE (ESP-IDF v5.3 esp_wifi, temperature_sensor, heap_caps, esp_netif).
 */
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "im_esp.h"
#include "soc/soc_caps.h"
#if SOC_TEMP_SENSOR_SUPPORTED
#include "driver/temperature_sensor.h"
static temperature_sensor_handle_t s_temp;
#endif

static double cpu_load_pct(void)
{
#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS
    static uint32_t last_total;
    static uint32_t last_idle;
    uint32_t total = 0;
    uint32_t idle = 0;
    TaskStatus_t st[24];
    UBaseType_t n = uxTaskGetSystemState(st, 24, &total);
    for (UBaseType_t i = 0; i < n; i++) {
        if (strncmp(st[i].pcTaskName, "IDLE", 4) == 0) {
            idle += st[i].ulRunTimeCounter;
        }
    }
    uint32_t dt = total - last_total;
    uint32_t di = idle - last_idle;
    last_total = total;
    last_idle = idle;
    if (dt == 0) {
        return 0.0;
    }
    /* idle counters accumulate per core */
    double busy = 100.0 - (100.0 * (double)di) / ((double)dt * portNUM_PROCESSORS);
    return busy < 0.0 ? 0.0 : busy > 100.0 ? 100.0 : busy;
#else
    return 0.0;
#endif
}

void im_esp_telemetry_sample(void *ctx, im_telemetry_t *t)
{
    wifi_ap_record_t ap;
    size_t total = heap_caps_get_total_size(MALLOC_CAP_DEFAULT);
    size_t free_b = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
    (void)ctx;
    t->cpu_pct = cpu_load_pct();
    t->mem_pct = total ? 100.0 * (double)(total - free_b) / (double)total : 0.0;
    t->has_free_heap = true;
    t->free_heap = esp_get_free_heap_size();
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        t->has_rssi = true;
        t->rssi = ap.rssi;
    }
    t->temp_c = 0.0;
#if SOC_TEMP_SENSOR_SUPPORTED
    if (s_temp == NULL) {
        temperature_sensor_config_t cfg = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
        if (temperature_sensor_install(&cfg, &s_temp) == ESP_OK) {
            (void)temperature_sensor_enable(s_temp);
        }
    }
    float c;
    if (s_temp != NULL && temperature_sensor_get_celsius(s_temp, &c) == ESP_OK) {
        t->temp_c = (double)c;
    }
#endif
    /* lwIP has no cheap per-interface byte counters; reported as 0 on the ESP32 */
    t->net_rx_bytes = 0;
    t->net_tx_bytes = 0;
    t->uptime_s = (uint64_t)(esp_timer_get_time() / 1000000);
}
