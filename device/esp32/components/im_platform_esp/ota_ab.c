/*
 * A/B OTA slots for the im_core OTA state machine (esp_ota_ops, ESP-IDF v5.3):
 *   slot_begin   esp_ota_begin(next update partition, sequential writes)
 *   slot_write   esp_ota_write (full image, or the IMDELTA1 applier's output)
 *   slot_finish  esp_ota_end -> image + Secure Boot v2 signature validation; secure_version of
 *                the new image must not be below the eFuse value (anti-rollback)
 *   set_boot     esp_ota_set_boot_partition (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE: the image
 *                boots in ESP_OTA_IMG_PENDING_VERIFY)
 *   mark_valid   esp_ota_mark_app_valid_cancel_rollback (after MQTT connected + telemetry
 *                acked; with CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK this also burns the eFuse
 *                secure version)
 *   rollback     esp_ota_mark_app_invalid_rollback_and_reboot (health timeout, 120 s)
 * The download runs in its own task and streams chunks to the agent task through the queue.
 *
 * NOT COMPILED HERE (ESP-IDF v5.3 app_update, esp_http_client, efuse, bootloader_support).
 */
#include <string.h>

#include "esp_app_desc.h"
#include "esp_efuse.h"
#include "esp_http_client.h"
#include "esp_image_format.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "im_esp.h"
#include "mbedtls/sha256.h"
#include "nvs.h"

static const char *TAG = "im_ota";
static const esp_partition_t *s_part;
static esp_ota_handle_t s_handle;
static uint64_t s_written;
static char s_url[2049];

static im_err_t slot_begin(void *ctx, uint64_t size)
{
    (void)ctx;
    s_part = esp_ota_get_next_update_partition(NULL);
    if (s_part == NULL || size > s_part->size) {
        return IM_ERR_STORAGE;
    }
    s_written = 0;
    return esp_ota_begin(s_part, OTA_WITH_SEQUENTIAL_WRITES, &s_handle) == ESP_OK ? IM_OK
                                                                                 : IM_ERR_STORAGE;
}

static im_err_t slot_write(void *ctx, uint64_t off, const uint8_t *d, size_t n)
{
    (void)ctx;
    if (off != s_written) {
        return IM_ERR_IO; /* the core writes strictly sequentially */
    }
    if (esp_ota_write(s_handle, d, n) != ESP_OK) {
        return IM_ERR_IO;
    }
    s_written += n;
    return IM_OK;
}

static im_err_t slot_finish(void *ctx)
{
    esp_app_desc_t desc;
    (void)ctx;
    if (esp_ota_end(s_handle) != ESP_OK) {
        return IM_ERR_CRYPTO; /* image or Secure Boot signature invalid */
    }
    if (esp_ota_get_partition_description(s_part, &desc) != ESP_OK) {
        return IM_ERR_CRYPTO;
    }
#if CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK
    if (!esp_efuse_check_secure_version(desc.secure_version)) {
        ESP_LOGW(TAG, "secure_version %u below eFuse", (unsigned)desc.secure_version);
        return IM_ERR_MF_ROLLBACK;
    }
#endif
    return IM_OK;
}

static void slot_abort(void *ctx)
{
    (void)ctx;
    (void)esp_ota_abort(s_handle);
}

static im_err_t set_boot(void *ctx, uint64_t version_code)
{
    (void)ctx;
    (void)version_code; /* recorded by im_core in the campaign record (NVS) */
    return esp_ota_set_boot_partition(s_part) == ESP_OK ? IM_OK : IM_ERR_STORAGE;
}

static im_err_t read_running(void *ctx, uint64_t off, uint8_t *buf, size_t n)
{
    (void)ctx;
    /* flash-encrypted app partitions are transparently decrypted by esp_partition_read */
    return esp_partition_read(esp_ota_get_running_partition(), (size_t)off, buf, n) == ESP_OK
               ? IM_OK
               : IM_ERR_IO;
}

static im_err_t mark_valid(void *ctx)
{
    (void)ctx;
    return esp_ota_mark_app_valid_cancel_rollback() == ESP_OK ? IM_OK : IM_ERR_STORAGE;
}

static im_err_t rollback(void *ctx)
{
    (void)ctx;
    esp_ota_mark_app_invalid_rollback_and_reboot(); /* does not return on success */
    return IM_ERR_STORAGE;
}

void im_esp_ota_platform(im_ota_platform_t *pf)
{
    memset(pf, 0, sizeof *pf);
    pf->slot_begin = slot_begin;
    pf->slot_write = slot_write;
    pf->slot_finish = slot_finish;
    pf->slot_abort = slot_abort;
    pf->set_boot = set_boot;
    pf->read_running = read_running;
    pf->mark_valid = mark_valid;
    pf->rollback = rollback;
    pf->report = NULL; /* the agent publishes OtaStatus itself */
}

/* ---- download task ------------------------------------------------------------------------- */

static void download_task(void *arg)
{
    static uint8_t ca[2048];
    size_t ca_len = sizeof ca;
    nvs_handle_t h;
    im_ev_t done = {.type = IM_EV_OTA_DONE, .code = IM_OK};
    esp_http_client_config_t cfg = {
        .url = s_url,
        .timeout_ms = 15000,
        .buffer_size = 4096,
        .keep_alive_enable = false,
    };
    esp_http_client_handle_t c;
    (void)arg;
    /* server authentication with the Services CA from EST /cacerts (first stored certificate) */
    if (nvs_open("ironmesh", NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_blob(h, "cacerts", ca, &ca_len) == ESP_OK) {
            cfg.cert_pem = (const char *)ca;
            cfg.cert_len = ca_len; /* DER accepted when cert_len is set */
        }
        nvs_close(h);
    }
    if (strncmp(s_url, "https://", 8) != 0 || cfg.cert_pem == NULL) {
        done.code = IM_ERR_IO;
        goto out;
    }
    c = esp_http_client_init(&cfg);
    if (c == NULL || esp_http_client_open(c, 0) != ESP_OK || esp_http_client_fetch_headers(c) < 0 ||
        esp_http_client_get_status_code(c) != 200) {
        done.code = IM_ERR_IO;
    } else {
        for (;;) {
            uint8_t *buf = malloc(4096);
            int n;
            if (buf == NULL) {
                done.code = IM_ERR_IO;
                break;
            }
            n = esp_http_client_read(c, (char *)buf, 4096);
            if (n <= 0) {
                free(buf);
                if (n < 0) {
                    done.code = IM_ERR_IO;
                }
                break;
            }
            im_ev_t ev = {.type = IM_EV_OTA_DATA, .data = buf, .len = (size_t)n};
            if (!im_esp_post(&ev, 30000)) { /* backpressure: the agent writes flash */
                done.code = IM_ERR_IO;
                break;
            }
        }
    }
    if (c != NULL) {
        esp_http_client_close(c);
        esp_http_client_cleanup(c);
    }
out:
    (void)im_esp_post(&done, portMAX_DELAY);
    vTaskDelete(NULL);
}

im_err_t im_esp_ota_download(void *ctx, const char *url, size_t url_len)
{
    (void)ctx;
    if (url_len >= sizeof s_url) {
        return IM_ERR_ARG;
    }
    memcpy(s_url, url, url_len);
    s_url[url_len] = '\0';
    /* least privilege: below the agent task, bounded stack */
    return xTaskCreate(download_task, "im_ota_dl", 6144, NULL, 3, NULL) == pdPASS ? IM_OK
                                                                                 : IM_ERR_IO;
}

esp_err_t im_esp_running_image(uint64_t *size, uint8_t sha256[32], const char **slot_name)
{
    const esp_partition_t *p = esp_ota_get_running_partition();
    esp_partition_pos_t pos = {.offset = p->address, .size = p->size};
    esp_image_metadata_t md;
    mbedtls_sha256_context ctx;
    static uint8_t buf[4096];
    size_t len;
    if (esp_image_get_metadata(&pos, &md) != ESP_OK) {
        return ESP_FAIL;
    }
    /* The manifest's image_sha256 covers the exact .bin that was downloaded: image + appended
     * SHA-256 and, with Secure Boot v2, the 4 KiB signature sector after 4 KiB alignment. */
    len = md.image_len;
#if CONFIG_SECURE_BOOT_V2_ENABLED
    len = ((len + 4095u) & ~4095u) + 4096u;
#endif
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    for (size_t off = 0; off < len; off += sizeof buf) {
        size_t n = len - off < sizeof buf ? len - off : sizeof buf;
        if (esp_partition_read(p, off, buf, n) != ESP_OK) {
            mbedtls_sha256_free(&ctx);
            return ESP_FAIL;
        }
        mbedtls_sha256_update(&ctx, buf, n);
    }
    mbedtls_sha256_finish(&ctx, sha256);
    mbedtls_sha256_free(&ctx);
    *size = len;
    *slot_name = p->label;
    return ESP_OK;
}

int im_esp_boot_reason(void)
{
    switch (esp_reset_reason()) {
    case ESP_RST_TASK_WDT:
    case ESP_RST_INT_WDT:
    case ESP_RST_WDT:
        return IM_REBOOT_WATCHDOG;
    case ESP_RST_SW:
    case ESP_RST_PANIC:
        return IM_REBOOT_REQUESTED;
    default:
        return IM_REBOOT_POWER_ON;
    }
}
