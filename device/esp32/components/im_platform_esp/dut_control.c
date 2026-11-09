/*
 * DUT control channel (conformance/DUT_PROTOCOL.md) over USB-Serial/JTAG for the HIL runner.
 * TEST HOOK: compiled only with CONFIG_IRONMESH_DUT_CONTROL (hil profile); the prod profile
 * forces it off and tools/check_prod_config.py enforces that in CI.
 *
 * Framing: protocol lines in both directions start with "@@IM " so they can be separated from
 * log output on the same port. The request dispatcher is im_core's im_dut_handle(), executed on
 * the agent task (the reader task only splits lines and posts them).
 *
 * NOT COMPILED HERE (ESP-IDF v5.3 driver/usb_serial_jtag.h).
 */
#include <stdlib.h>
#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "esp_ota_ops.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "im_esp.h"

#define PREFIX "@@IM "
#define PREFIX_LEN 5u
#define LINE_MAX (64u * 1024u)

static char s_resp[16384];

static void reader_task(void *arg)
{
    static char line[LINE_MAX + 1];
    size_t n = 0;
    bool overflow = false;
    (void)arg;
    for (;;) {
        uint8_t buf[128];
        int r = usb_serial_jtag_read_bytes(buf, sizeof buf, pdMS_TO_TICKS(50));
        for (int i = 0; i < r; i++) {
            char c = (char)buf[i];
            if (c == '\n') {
                if (!overflow && n > PREFIX_LEN && memcmp(line, PREFIX, PREFIX_LEN) == 0) {
                    size_t len = n - PREFIX_LEN;
                    if (len > 0 && line[n - 1] == '\r') {
                        len--;
                    }
                    char *copy = malloc(len + 1);
                    if (copy != NULL) {
                        memcpy(copy, line + PREFIX_LEN, len);
                        copy[len] = 0;
                        im_ev_t ev = {.type = IM_EV_DUT_LINE, .data = (uint8_t *)copy, .len = len};
                        (void)im_esp_post(&ev, 1000);
                    }
                }
                n = 0;
                overflow = false;
            } else if (n < LINE_MAX) {
                line[n++] = c;
            } else {
                overflow = true; /* > 64 KiB: dropped as a whole */
            }
        }
    }
}

void im_esp_dut_start(void)
{
    usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    cfg.rx_buffer_size = 4096;
    cfg.tx_buffer_size = 4096;
    if (usb_serial_jtag_driver_install(&cfg) == ESP_OK) {
        (void)xTaskCreate(reader_task, "im_dut", 4096, NULL, 2, NULL);
    }
}

void im_esp_dut_emit(const char *line, size_t len)
{
    (void)usb_serial_jtag_write_bytes(PREFIX, PREFIX_LEN, pdMS_TO_TICKS(100));
    (void)usb_serial_jtag_write_bytes(line, len, pdMS_TO_TICKS(500));
    (void)usb_serial_jtag_write_bytes("\n", 1, pdMS_TO_TICKS(100));
}

static void slots_hook(void *ctx, im_json_w_t *w, const char **active, const char **pending)
{
    const esp_partition_t *run = esp_ota_get_running_partition();
    const esp_partition_t *boot = esp_ota_get_boot_partition();
    (void)ctx;
    *active = run->label;
    *pending = boot != NULL && boot != run ? boot->label : NULL;
    if (w == NULL) {
        return;
    }
    for (int i = 0; i < 2; i++) {
        const esp_partition_t *p =
            esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_0 + i, NULL);
        esp_app_desc_t d;
        esp_ota_img_states_t st;
        const char *state = "empty";
        if (p == NULL) {
            continue;
        }
        im_jw_obj(w);
        im_jw_key(w, "name");
        im_jw_cstr(w, p->label);
        if (esp_ota_get_partition_description(p, &d) == ESP_OK) {
            im_jw_key(w, "version");
            im_jw_cstr(w, d.version);
            im_jw_key(w, "version_code");
            im_jw_u64(w, d.secure_version);
            im_jw_key(w, "sha256_hex");
            im_jw_hex(w, d.app_elf_sha256, 32);
        } else {
            im_jw_key(w, "version");
            im_jw_null(w);
        }
        if (esp_ota_get_state_partition(p, &st) == ESP_OK) {
            state = st == ESP_OTA_IMG_VALID            ? "valid"
                    : st == ESP_OTA_IMG_PENDING_VERIFY ? "pending_verify"
                    : st == ESP_OTA_IMG_NEW            ? "new"
                    : st == ESP_OTA_IMG_INVALID        ? "invalid"
                    : st == ESP_OTA_IMG_ABORTED        ? "aborted"
                                                       : "undefined";
        }
        im_jw_key(w, "state");
        im_jw_cstr(w, state);
        im_jw_obj_end(w);
    }
}

void im_esp_dut_handle_line(im_agent_t *agent, const char *line, size_t len)
{
    /* set_clock is a host-target op: unsupported on hardware (SNTP owns the clock) */
    im_dut_hooks_t hooks = {.set_clock = NULL, .slots = slots_hook, .ctx = NULL};
    size_t n = 0;
    if (im_dut_handle(agent, &hooks, line, len, s_resp, sizeof s_resp, &n) == IM_OK) {
        im_esp_dut_emit(s_resp, n);
    }
}
