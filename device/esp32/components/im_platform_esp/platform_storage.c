/*
 * Persistent state for im_core: the im_kv_t over encrypted NVS (sequence high-water mark,
 * replay windows, provisioning record, trust bundle, OTA campaign record) and the im_storage_t
 * over the "storage" partition (offline telemetry ring buffer; flash-encrypted in hil/prod).
 * Also the identity record: (active operational key slot, operational certificate) as ONE NVS
 * blob "id_rec" (im_keyslot_record_*), so the slot index and the certificate always change
 * together - nvs_set_blob + nvs_commit either leaves the old blob or the complete new one, and a
 * power loss mid-renewal keeps the old slot/cert pair. The bootstrap cert is in esp_secure_cert.
 *
 * NOT COMPILED HERE (ESP-IDF v5.3: nvs, esp_partition, esp_secure_cert_mgr).
 */
#include <string.h>
#include <time.h>

#include "esp_partition.h"
#include "esp_secure_cert_read.h"
#include "im_esp.h"
#include "mbedtls/x509_crt.h"
#include "nvs.h"

#define NS "ironmesh"
#define ID_REC_KEY "id_rec"

static nvs_handle_t s_nvs;
static const esp_partition_t *s_part;
static uint8_t s_rec[IM_KEYSLOT_RECORD_MAX];
static const uint8_t *s_cert; /* points into s_rec */
static size_t s_cert_len;
static uint8_t s_active;      /* 0 = never enrolled */
static uint64_t s_not_after;

static uint64_t x509_unix(const mbedtls_x509_time *t)
{
    int64_t y = t->year - (t->mon <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t mp = (t->mon + 9) % 12;
    int64_t doy = (153 * mp + 2) / 5 + t->day - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (uint64_t)((era * 146097 + doe - 719468) * 86400 + t->hour * 3600 + t->min * 60 + t->sec);
}

/* Adopt a decoded record (slot + cert) as the current identity. */
static esp_err_t adopt(const uint8_t *rec, size_t len)
{
    uint8_t slot;
    const uint8_t *cert;
    size_t cert_len;
    mbedtls_x509_crt crt;
    uint64_t na = 0;
    if (im_keyslot_record_decode(rec, len, &slot, &cert, &cert_len) != IM_OK) {
        return ESP_ERR_INVALID_STATE;
    }
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_der(&crt, cert, cert_len) == 0) {
        na = x509_unix(&crt.valid_to);
    }
    mbedtls_x509_crt_free(&crt);
    if (na == 0) {
        return ESP_ERR_INVALID_STATE;
    }
    if (rec != s_rec) {
        memcpy(s_rec, rec, len);
    }
    s_cert = s_rec + (cert - rec);
    s_cert_len = cert_len;
    s_not_after = na;
    s_active = slot;
    return ESP_OK;
}

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
    {
        size_t n = sizeof s_rec;
        if (nvs_get_blob(s_nvs, ID_REC_KEY, s_rec, &n) != ESP_OK || adopt(s_rec, n) != ESP_OK) {
            s_active = IM_SLOT_BOOTSTRAP; /* never enrolled (or unusable record): bootstrap */
            s_cert_len = 0;
        }
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

uint8_t im_esp_active_slot(void)
{
    return s_active;
}

uint64_t im_esp_op_not_after(void)
{
    return s_cert_len ? s_not_after : 0;
}

uint8_t im_esp_signing_slot(void)
{
    im_keyslot_plan_t p;
    /* same rule as the enrollment plan: operational key while its certificate is valid */
    if (im_keyslot_plan(s_active, s_cert_len > 0, (uint64_t)time(NULL), s_not_after, &p) != IM_OK) {
        return IM_SLOT_BOOTSTRAP;
    }
    return p.tls_slot;
}

esp_err_t im_esp_client_cert(const uint8_t **der, size_t *len)
{
    static char *boot;
    static uint32_t boot_len;
    if (im_esp_signing_slot() != IM_SLOT_BOOTSTRAP) {
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

esp_err_t im_esp_commit_identity(uint8_t new_slot, const uint8_t *der, size_t len)
{
    static uint8_t rec[IM_KEYSLOT_RECORD_MAX];
    size_t n;
    if (im_keyslot_record_encode(new_slot, der, len, rec, sizeof rec, &n) != IM_OK) {
        return ESP_ERR_INVALID_ARG;
    }
    /* the single commit point of a (re-)enrollment */
    if (nvs_set_blob(s_nvs, ID_REC_KEY, rec, n) != ESP_OK || nvs_commit(s_nvs) != ESP_OK) {
        return ESP_FAIL; /* old record (slot + cert) still in force */
    }
    return adopt(rec, n);
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
