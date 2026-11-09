/*
 * Persistent state for im_core: the im_kv_t over encrypted NVS (sequence high-water mark,
 * replay windows, provisioning record, trust bundle, OTA campaign record) and the im_storage_t
 * over the "storage" partition (offline telemetry ring buffer; flash-encrypted in hil/prod).
 * Also the certificate store (bootstrap cert from esp_secure_cert, operational cert in NVS).
 *
 * NOT COMPILED HERE (ESP-IDF v5.3: nvs, esp_partition, esp_secure_cert_mgr).
 */
#include <string.h>

#include "esp_partition.h"
#include "esp_secure_cert_read.h"
#include "im_esp.h"
#include "mbedtls/x509_crt.h"
#include "nvs.h"

#define NS "ironmesh"
#define OP_CERT_KEY "op_cert"
#define OP_CERT_MAX 2048u

static nvs_handle_t s_nvs;
static const esp_partition_t *s_part;
static uint8_t s_cert[OP_CERT_MAX];
static size_t s_cert_len;

static im_err_t kv_get(void *ctx, const char *key, uint8_t *buf, size_t cap, size_t *len)
{
    size_t n = cap;
    esp_err_t e;
    (void)ctx;
    e = nvs_get_blob(s_nvs, key, buf, &n);
    if (e == ESP_ERR_NVS_NOT_FOUND) {
        return IM_ERR_NOT_FOUND;
    }
    if (e == ESP_ERR_NVS_INVALID_LENGTH) {
        return IM_ERR_BUFFER;
    }
    if (e != ESP_OK) {
        return IM_ERR_STORAGE;
    }
    *len = n;
    return IM_OK;
}

static im_err_t kv_set(void *ctx, const char *key, const uint8_t *data, size_t len)
{
    (void)ctx;
    /* nvs_commit makes the write durable before im_core uses the value (seq, replay) */
    if (nvs_set_blob(s_nvs, key, data, len) != ESP_OK || nvs_commit(s_nvs) != ESP_OK) {
        return IM_ERR_STORAGE;
    }
    return IM_OK;
}

static im_err_t kv_erase(void *ctx, const char *key)
{
    (void)ctx;
    esp_err_t e = nvs_erase_key(s_nvs, key);
    if (e != ESP_OK && e != ESP_ERR_NVS_NOT_FOUND) {
        return IM_ERR_STORAGE;
    }
    return nvs_commit(s_nvs) == ESP_OK ? IM_OK : IM_ERR_STORAGE;
}

esp_err_t im_esp_kv_init(im_kv_t *kv)
{
    esp_err_t e = nvs_open(NS, NVS_READWRITE, &s_nvs);
    if (e != ESP_OK) {
        return e;
    }
    kv->get = kv_get;
    kv->set = kv_set;
    kv->erase = kv_erase;
    kv->ctx = NULL;
    s_cert_len = sizeof s_cert;
    if (nvs_get_blob(s_nvs, OP_CERT_KEY, s_cert, &s_cert_len) != ESP_OK) {
        s_cert_len = 0;
    }
    return ESP_OK;
}

static im_err_t st_read(void *ctx, uint32_t off, uint8_t *buf, size_t len)
{
    (void)ctx;
    return esp_partition_read(s_part, off, buf, len) == ESP_OK ? IM_OK : IM_ERR_IO;
}

static im_err_t st_write(void *ctx, uint32_t off, const uint8_t *data, size_t len)
{
    (void)ctx;
    /* plaintext partition (see partitions.csv): the ring buffer's 1-byte ack write only clears
     * bits, which NOR flash allows without an erase; records are signed, not secret */
    return esp_partition_write(s_part, off, data, len) == ESP_OK ? IM_OK : IM_ERR_IO;
}

static im_err_t st_erase(void *ctx, uint32_t off, size_t len)
{
    (void)ctx;
    return esp_partition_erase_range(s_part, off, len) == ESP_OK ? IM_OK : IM_ERR_IO;
}

esp_err_t im_esp_storage_init(im_storage_t *st)
{
    s_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x40, "storage");
    if (s_part == NULL) {
        return ESP_ERR_NOT_FOUND;
    }
    st->read = st_read;
    st->write = st_write;
    st->erase = st_erase;
    st->ctx = NULL;
    st->size = (uint32_t)s_part->size;
    st->sector_size = (uint32_t)s_part->erase_size;
    return ESP_OK;
}

esp_err_t im_esp_client_cert(const uint8_t **der, size_t *len)
{
    static char *boot;
    static uint32_t boot_len;
    if (s_cert_len > 0) {
        *der = s_cert;
        *len = s_cert_len;
        return ESP_OK;
    }
    /* bootstrap certificate written by the factory station into esp_secure_cert */
    if (boot == NULL && esp_secure_cert_get_device_cert(&boot, &boot_len) != ESP_OK) {
        return ESP_ERR_NOT_FOUND;
    }
    *der = (const uint8_t *)boot;
    *len = boot_len;
    return ESP_OK;
}

esp_err_t im_esp_store_operational_cert(const uint8_t *der, size_t len)
{
    if (len > sizeof s_cert) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (nvs_set_blob(s_nvs, OP_CERT_KEY, der, len) != ESP_OK || nvs_commit(s_nvs) != ESP_OK) {
        return ESP_FAIL;
    }
    memcpy(s_cert, der, len);
    s_cert_len = len;
    return ESP_OK;
}

esp_err_t im_esp_bootstrap_serial(uint8_t *serial, size_t cap, size_t *len)
{
    char *boot = NULL;
    uint32_t boot_len = 0;
    mbedtls_x509_crt crt;
    esp_err_t e = ESP_FAIL;
    if (esp_secure_cert_get_device_cert(&boot, &boot_len) != ESP_OK) {
        return ESP_ERR_NOT_FOUND;
    }
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_der(&crt, (const uint8_t *)boot, boot_len) == 0 &&
        crt.serial.len <= cap) {
        /* minimal big-endian form (WIRE_FORMAT.md section 3.3) */
        size_t s = 0;
        while (s + 1 < crt.serial.len && crt.serial.p[s] == 0) {
            s++;
        }
        memcpy(serial, crt.serial.p + s, crt.serial.len - s);
        *len = crt.serial.len - s;
        e = ESP_OK;
    }
    mbedtls_x509_crt_free(&crt);
    return e;
}
