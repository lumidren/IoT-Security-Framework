/*
 * Runtime hardening. Most controls are build/eFuse configuration (sdkconfig.defaults.prod:
 * Secure Boot v2, flash encryption release mode, ROM download mode disabled, JTAG disabled by
 * eFuse, no console, no logs, stack protector strong, memory protection, watchdogs); this file
 * verifies them at boot and refuses to run a production image on an unprotected chip, and
 * configures the task watchdog. Task priorities/stacks (least privilege) are set in app_main.c:
 *   agent 6/12 KiB (only task touching protocol state), esp-mqtt 5/6 KiB, OTA download 3/6 KiB,
 *   DUT reader 2/4 KiB (hil only).
 *
 * NOT COMPILED HERE (ESP-IDF v5.3 bootloader_support, efuse, esp_task_wdt).
 */
#include "esp_efuse.h"
#include "esp_flash_encrypt.h"
#include "esp_log.h"
#include "esp_secure_boot.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "im_esp.h"

static const char *TAG = "im_hard";

void im_esp_hardening_init(void)
{
    bool sb = esp_secure_boot_enabled();
    bool fe = esp_flash_encryption_enabled();
#if CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE
    bool release = esp_flash_encryption_mode() == ESP_FLASH_ENC_MODE_RELEASE;
#else
    bool release = false;
#endif
    ESP_LOGI(TAG, "secure boot %d, flash encryption %d (release %d)", sb, fe, release);
#if CONFIG_SECURE_BOOT && CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE
    /* production image: never run with the protections switched off */
    if (!sb || !fe || !release) {
        esp_restart(); /* silent reboot loop rather than leaking keys */
    }
#endif
#if !CONFIG_IRONMESH_DUT_CONTROL && CONFIG_ESP_CONSOLE_NONE
    esp_log_level_set("*", ESP_LOG_NONE);
#endif
    /* task watchdog: the agent task subscribes itself and feeds every loop iteration */
    esp_task_wdt_config_t wdt = {
        .timeout_ms = 10000,
        .idle_core_mask = (1u << portNUM_PROCESSORS) - 1u,
        .trigger_panic = true,
    };
    if (esp_task_wdt_reconfigure(&wdt) != ESP_OK) {
        (void)esp_task_wdt_init(&wdt);
    }
}
