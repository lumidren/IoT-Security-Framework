/*
 * EST client (RFC 7030) with the IronMesh attestation (contract section 3):
 *   GET  /.well-known/est/cacerts                 -> CA certificates (pin candidates, NVS)
 *   GET  /.well-known/est/ironmesh/nonce          -> 32-byte single-use nonce
 *   new P-256 key in the INACTIVE operational slot, PKCS#10 CSR (CN, OU, O, SAN URI)
 *   attestation = COSE_Sign1 type 10 built by im_core, signed by the TLS client key
 *   POST /.well-known/est/simple(re)enroll + X-IronMesh-Attestation -> PKCS#7 certs-only and
 *        X-IronMesh-Bundle (verified by im_core with the factory bundle key)
 *   commit: (new slot, new cert) written as one NVS blob, then the active slot flips
 *
 * Slot plan (im_keyslot_plan, pure and host-tested): while the operational certificate is valid,
 * TLS + attestation use the active operational slot (2 or 3) and simplereenroll; first
 * enrollment and after expiry they use the bootstrap slot 0 + bootstrap cert and simpleenroll.
 * The new key always goes to the slot that is not active, so a failure or power loss at any
 * point before the commit leaves the old slot/cert pair valid.
 *
 * HTTP/1.1 is spoken over the IronMesh TLS transport (im_tls.c) rather than esp_http_client so
 * that the TLS client key can be an ATECC slot key; esp-tls only supports slot 0.
 *
 * Pinning (threat model T-29), exactly like MQTT: the EST server chain must contain a CA whose
 * SPKI SHA-256 is pinned (im_tls.c pin_required). The pins come from im_agent_est_pins() - the
 * pure rule in im_core (im_est_pins_select, host-tested): the signed trust bundle's ca_pins once
 * enrolled, before that the factory-provisioned PKI CA pin(s): NVS "est_pins" (n * 32 bytes,
 * tools/factory_provision.py --est-pin), falling back to the SPKI of the CA certificate in
 * esp_secure_cert. With no pin at all the enrollment fails closed. The /cacerts response is still
 * stored, but it can only ever add anchors that are already pinned.
 *
 * NOT COMPILED HERE (ESP-IDF v5.3 + mbedTLS 3.6 x509write_csr / base64).
 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_secure_cert_read.h"
#include "esp_transport.h"
#include "im_esp.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "nvs.h"

static const char *TAG = "im_est";

#define RESP_MAX 8192
#define HDR_MAX 1536

typedef struct {
    int status;
    char headers[HDR_MAX];
    uint8_t *body;
    size_t body_len;
} http_resp_t;

static uint8_t s_resp[RESP_MAX];
static uint8_t s_est_pins[IM_AGENT_PINS * IM_PIN_LEN];
static size_t s_n_est_pins;

static int rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}

/* Factory PKI CA pin(s): NVS "est_pins" written at the factory, else the SPKI SHA-256 of the CA
 * certificate in esp_secure_cert (the factory-provisioned PKI CA). Returns the number of pins. */
static size_t factory_pins(uint8_t *out, size_t cap)
{
    nvs_handle_t h;
    size_t n = cap * IM_PIN_LEN;
    char *ca = NULL;
    uint32_t ca_len = 0;
    mbedtls_x509_crt crt;
    size_t got = 0;
    if (nvs_open("ironmesh", NVS_READONLY, &h) == ESP_OK) {
        esp_err_t e = nvs_get_blob(h, "est_pins", out, &n);
        nvs_close(h);
        if (e == ESP_OK && n > 0 && n % IM_PIN_LEN == 0) {
            return n / IM_PIN_LEN;
        }
    }
    mbedtls_x509_crt_init(&crt);
    if (cap > 0 && esp_secure_cert_get_ca_cert(&ca, &ca_len) == ESP_OK &&
        mbedtls_x509_crt_parse(&crt, (const uint8_t *)ca, ca_len) == 0 &&
        mbedtls_sha256(crt.pk_raw.p, crt.pk_raw.len, out, 0) == 0) {
        ESP_LOGW(TAG, "no factory est_pins in NVS: pinning the esp_secure_cert CA");
        got = 1;
    }
    mbedtls_x509_crt_free(&crt);
    return got;
}

/* T-29: the pins every EST request of this enrollment must satisfy (bundle pins once enrolled,
 * the factory pin before; decided by im_core). */
static esp_err_t select_pins(im_agent_t *a)
{
    static uint8_t factory[IM_AGENT_PINS * IM_PIN_LEN];
    size_t nf = factory_pins(factory, IM_AGENT_PINS);
    s_n_est_pins = 0;
    return im_agent_est_pins(a, factory, nf, s_est_pins, IM_AGENT_PINS, &s_n_est_pins) == IM_OK &&
                   s_n_est_pins > 0
               ? ESP_OK
               : ESP_FAIL;
}

static esp_err_t http(const char *req, size_t req_len, http_resp_t *out)
{
    im_tls_opts_t o = {.alpn = NULL,
                       .pin_required = true,
                       .pins = (const uint8_t(*)[32])s_est_pins,
                       .n_pins = s_n_est_pins};
    esp_transport_handle_t t = im_tls_transport_new(&o);
    size_t n = 0;
    char *sep;
    esp_err_t e = ESP_FAIL;
    if (t == NULL) {
        return ESP_ERR_NO_MEM;
    }
    if (esp_transport_connect(t, CONFIG_IRONMESH_EST_HOST, CONFIG_IRONMESH_EST_PORT, 10000) != 0 ||
        esp_transport_write(t, req, (int)req_len, 10000) != (int)req_len) {
        goto done;
    }
    for (;;) {
        int r = esp_transport_read(t, (char *)s_resp + n, (int)(sizeof s_resp - 1 - n), 10000);
        if (r <= 0) {
            break; /* Connection: close */
        }
        n += (size_t)r;
        if (n >= sizeof s_resp - 1) {
            goto done; /* response too large: refuse rather than truncate */
        }
    }
    s_resp[n] = 0;
    sep = strstr((char *)s_resp, "\r\n\r\n");
    if (sep == NULL || sscanf((char *)s_resp, "HTTP/1.%*d %d", &out->status) != 1) {
        goto done;
    }
    size_t hl = (size_t)(sep - (char *)s_resp);
    if (hl >= sizeof out->headers) {
        goto done;
    }
    memcpy(out->headers, s_resp, hl);
    out->headers[hl] = 0;
    out->body = (uint8_t *)sep + 4;
    out->body_len = n - hl - 4;
    if (strcasestr(out->headers, "transfer-encoding: chunked") != NULL) {
        /* de-chunk in place */
        uint8_t *src = out->body;
        uint8_t *end = out->body + out->body_len;
        uint8_t *dst = out->body;
        for (;;) {
            unsigned long sz = strtoul((char *)src, NULL, 16);
            uint8_t *data = (uint8_t *)strstr((char *)src, "\r\n");
            if (data == NULL || sz == 0) {
                break;
            }
            data += 2;
            if (data + sz > end) {
                goto done;
            }
            memmove(dst, data, sz);
            dst += sz;
            src = data + sz + 2;
        }
        out->body_len = (size_t)(dst - out->body);
    }
    e = ESP_OK;
done:
    esp_transport_close(t);
    esp_transport_destroy(t);
    return e;
}

static const char *header(const http_resp_t *r, const char *name, size_t *len)
{
    const char *p = strcasestr(r->headers, name);
    const char *v;
    const char *eol;
    if (p == NULL) {
        return NULL;
    }
    v = p + strlen(name);
    while (*v == ' ' || *v == ':') {
        v++;
    }
    eol = strstr(v, "\r\n");
    *len = eol ? (size_t)(eol - v) : strlen(v);
    return v;
}

/* base64 (optionally url-safe / unpadded / line-wrapped) -> bytes */
static int b64(const char *in, size_t n, uint8_t *out, size_t cap, size_t *olen)
{
    static char tmp[6144];
    size_t k = 0;
    for (size_t i = 0; i < n && k < sizeof tmp - 4; i++) {
        char c = in[i];
        if (c == '\r' || c == '\n' || c == ' ') {
            continue;
        }
        tmp[k++] = c == '-' ? '+' : c == '_' ? '/' : c;
    }
    while (k % 4) {
        tmp[k++] = '=';
    }
    return mbedtls_base64_decode(out, cap, olen, (const unsigned char *)tmp, k);
}

static uint64_t x509_unix(const mbedtls_x509_time *t)
{
    int64_t y = t->year - (t->mon <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t mp = (t->mon + 9) % 12;
    int64_t doy = (153 * mp + 2) / 5 + t->day - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    int64_t days = era * 146097 + doe - 719468;
    return (uint64_t)(days * 86400 + t->hour * 3600 + t->min * 60 + t->sec);
}

/* DER walk of ContentInfo{signedData, [0]{SignedData{..., [0] certificates}}} */
static size_t der_len(const uint8_t *p, size_t avail, size_t *hdr)
{
    if (avail < 2) {
        return 0;
    }
    if (p[1] < 0x80) {
        *hdr = 2;
        return p[1];
    }
    size_t nb = p[1] & 0x7f;
    size_t l = 0;
    if (nb == 0 || nb > 3 || avail < 2 + nb) {
        return 0;
    }
    for (size_t i = 0; i < nb; i++) {
        l = (l << 8) | p[2 + i];
    }
    *hdr = 2 + nb;
    return l;
}

static int pkcs7_certs(const uint8_t *p, size_t n, mbedtls_x509_crt *chain)
{
    size_t h;
    size_t l = der_len(p, n, &h); /* ContentInfo SEQ */
    if (l == 0 || h + l > n) {
        return -1;
    }
    p += h;
    l = der_len(p, n - h, &h); /* OID */
    p += h + l;
    l = der_len(p, 8, &h); /* [0] */
    p += h;
    l = der_len(p, 8, &h); /* SignedData SEQ */
    const uint8_t *sd = p + h;
    const uint8_t *sd_end = sd + l;
    while (sd < sd_end) {
        size_t eh;
        size_t el = der_len(sd, (size_t)(sd_end - sd), &eh);
        if (sd[0] == 0xA0) { /* certificates */
            const uint8_t *c = sd + eh;
            const uint8_t *c_end = c + el;
            while (c < c_end) {
                size_t ch;
                size_t cl = der_len(c, (size_t)(c_end - c), &ch);
                if (cl == 0 || mbedtls_x509_crt_parse_der(chain, c, ch + cl) != 0) {
                    return -1;
                }
                c += ch + cl;
            }
            return 0;
        }
        if (eh + el == 0) {
            return -1;
        }
        sd += eh + el;
    }
    return -1;
}

static esp_err_t build_csr(im_agent_t *a, uint8_t slot, uint8_t *der, size_t cap, size_t *len)
{
    mbedtls_x509write_csr w;
    mbedtls_pk_context pk;
    char subject[160];
    char uri[128];
    mbedtls_x509_san_list san;
    int r;
    if (im_esp_keystore_pk(slot, &pk) != ESP_OK) {
        return ESP_FAIL;
    }
    snprintf(subject, sizeof subject, "CN=%s,OU=%s,O=IronMesh", a->cfg.device_id, a->cfg.tenant_id);
    snprintf(uri, sizeof uri, "urn:ironmesh:tenant:%s:device:%s", a->cfg.tenant_id,
             a->cfg.device_id);
    memset(&san, 0, sizeof san);
    san.node.type = MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER;
    san.node.san.unstructured_name.p = (unsigned char *)uri;
    san.node.san.unstructured_name.len = strlen(uri);
    mbedtls_x509write_csr_init(&w);
    mbedtls_x509write_csr_set_md_alg(&w, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&w, &pk);
    r = mbedtls_x509write_csr_set_subject_name(&w, subject);
    if (r == 0) {
        r = mbedtls_x509write_csr_set_subject_alternative_name(&w, &san);
    }
    if (r == 0) {
        r = mbedtls_x509write_csr_der(&w, der, cap, rng, NULL); /* written at the END of der */
    }
    if (r > 0) {
        memmove(der, der + cap - (size_t)r, (size_t)r);
        *len = (size_t)r;
    }
    mbedtls_x509write_csr_free(&w);
    mbedtls_pk_free(&pk);
    return r > 0 ? ESP_OK : ESP_FAIL;
}

static void fail(im_agent_t *a, int status, const char *reason)
{
    /* nothing to undo: the active slot and its certificate were never touched */
    ESP_LOGW(TAG, "enrollment failed: %d %s", status, reason);
    im_agent_on_enroll_failed(a, status, reason);
}

static void store_cacerts(const uint8_t *p7, size_t n)
{
    static uint8_t der_buf[4096];
    mbedtls_x509_crt chain;
    nvs_handle_t h;
    size_t off = 0;
    mbedtls_x509_crt_init(&chain);
    if (pkcs7_certs(p7, n, &chain) == 0 && nvs_open("ironmesh", NVS_READWRITE, &h) == ESP_OK) {
        for (mbedtls_x509_crt *c = &chain; c && c->raw.len && off + c->raw.len < sizeof der_buf;
             c = c->next) {
            memcpy(der_buf + off, c->raw.p, c->raw.len); /* DER concatenation */
            off += c->raw.len;
        }
        (void)nvs_set_blob(h, "cacerts", der_buf, off);
        (void)nvs_commit(h);
        nvs_close(h);
    }
    mbedtls_x509_crt_free(&chain);
}

static int get(char *req, size_t cap, const char *path, http_resp_t *r)
{
    int len = snprintf(req, cap, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path,
                       CONFIG_IRONMESH_EST_HOST);
    if (len <= 0 || (size_t)len >= cap) {
        return -1;
    }
    return http(req, (size_t)len, r) == ESP_OK ? 0 : -1;
}

esp_err_t im_esp_est_enroll(im_agent_t *a, bool renew)
{
    static char req[4096];
    static uint8_t csr[768];
    static uint8_t att[1024];
    static char att_b64[1500];
    static char csr_b64[1100];
    static uint8_t p7[4096];
    static uint8_t bundle[IM_AGENT_BUNDLE_MAX];
    http_resp_t r;
    uint8_t nonce[32];
    uint8_t pub[65];
    size_t n;
    size_t csr_len;
    size_t att_len;
    size_t blen = 0;
    const char *v;
    im_keyslot_plan_t plan;
    mbedtls_x509_crt chain;
    int len;

    (void)renew; /* the plan decides: renewal is only possible while the cert is still valid */
    if (im_keyslot_plan(im_esp_active_slot(), im_esp_op_not_after() != 0, (uint64_t)time(NULL),
                        im_esp_op_not_after(), &plan) != IM_OK) {
        fail(a, 0, "slot plan");
        return ESP_FAIL;
    }
    /* invariant the contract relies on: the TLS client key (im_esp_signing_slot, used by
     * im_tls.c and by the identity that signs the attestation) is the plan's key */
    if (im_esp_signing_slot() != plan.tls_slot) {
        fail(a, 0, "slot mismatch");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "%s: tls/attestation slot %u, new key slot %u",
             plan.reenroll ? "simplereenroll" : "simpleenroll", plan.tls_slot, plan.new_slot);
    if (select_pins(a) != ESP_OK) {
        fail(a, 0, "tls_pin_mismatch"); /* no bundle and no factory pin: never connect unpinned */
        return ESP_FAIL;
    }

    /* CA certificates (anchors / pin candidates for the broker) */
    if (get(req, sizeof req, "/.well-known/est/cacerts", &r) == 0 && r.status == 200 &&
        b64((const char *)r.body, r.body_len, p7, sizeof p7, &n) == 0) {
        store_cacerts(p7, n);
    }
    /* nonce */
    if (get(req, sizeof req, "/.well-known/est/ironmesh/nonce", &r) != 0) {
        fail(a, 0, im_tls_last_failure()); /* network, tls_pin_mismatch, ... */
        return ESP_FAIL;
    }
    if (r.status != 200) {
        fail(a, r.status, "nonce refused");
        return ESP_FAIL;
    }
    v = strstr((const char *)r.body, "\"nonce\"");
    v = v ? strchr(v + 7, '"') : NULL;
    if (v == NULL || b64(v + 1, strcspn(v + 1, "\""), nonce, sizeof nonce, &n) != 0 || n != 32) {
        fail(a, r.status, "bad nonce");
        return ESP_FAIL;
    }
    /* fresh key in the inactive slot, CSR for it, attestation by the TLS client key */
    if (im_esp_keystore_genkey(plan.new_slot, pub) != ESP_OK) {
        fail(a, 0, "key generation");
        return ESP_FAIL;
    }
    if (build_csr(a, plan.new_slot, csr, sizeof csr, &csr_len) != ESP_OK ||
        im_agent_attestation(a, nonce, csr, csr_len, att, sizeof att, &att_len) != IM_OK) {
        fail(a, 0, "csr/attestation");
        return ESP_FAIL;
    }
    (void)mbedtls_base64_encode((unsigned char *)att_b64, sizeof att_b64, &n, att, att_len);
    (void)mbedtls_base64_encode((unsigned char *)csr_b64, sizeof csr_b64, &n, csr, csr_len);
    len = snprintf(req, sizeof req,
                   "POST /.well-known/est/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
                   "Content-Type: application/pkcs10\r\nContent-Transfer-Encoding: base64\r\n"
                   "X-IronMesh-Attestation: %s\r\nContent-Length: %u\r\n\r\n%s",
                   plan.reenroll ? "simplereenroll" : "simpleenroll", CONFIG_IRONMESH_EST_HOST,
                   att_b64, (unsigned)strlen(csr_b64), csr_b64);
    if (len <= 0 || (size_t)len >= sizeof req || http(req, (size_t)len, &r) != ESP_OK) {
        fail(a, 0, "network");
        return ESP_FAIL;
    }
    if (r.status != 200) {
        fail(a, r.status, r.status == 403 ? "forbidden" : "enroll refused");
        return ESP_FAIL;
    }
    if (b64((const char *)r.body, r.body_len, p7, sizeof p7, &n) != 0) {
        fail(a, r.status, "pkcs7 encoding");
        return ESP_FAIL;
    }
    mbedtls_x509_crt_init(&chain);
    if (pkcs7_certs(p7, n, &chain) != 0) {
        mbedtls_x509_crt_free(&chain);
        fail(a, r.status, "pkcs7");
        return ESP_FAIL;
    }
    v = header(&r, "X-IronMesh-Bundle", &n);
    if (v != NULL && b64(v, n, bundle, sizeof bundle, &blen) != 0) {
        blen = 0;
    }
    /* leaf = the non-CA certificate; it must certify the key that was just generated */
    for (mbedtls_x509_crt *c = &chain; c != NULL && c->raw.len > 0; c = c->next) {
        uint8_t cert_pub[65];
        size_t pl = 0;
        if (c->MBEDTLS_PRIVATE(ca_istrue)) {
            continue;
        }
        if (mbedtls_ecp_point_write_binary(&mbedtls_pk_ec(c->pk)->MBEDTLS_PRIVATE(grp),
                                           &mbedtls_pk_ec(c->pk)->MBEDTLS_PRIVATE(Q),
                                           MBEDTLS_ECP_PF_UNCOMPRESSED, &pl, cert_pub,
                                           sizeof cert_pub) != 0 ||
            pl != 65 || memcmp(cert_pub, pub, 65) != 0) {
            break;
        }
        /* THE commit point: slot index + certificate in one NVS write, then the flip */
        if (im_esp_commit_identity(plan.new_slot, c->raw.p, c->raw.len) != ESP_OK) {
            break;
        }
        if (im_agent_on_enrolled(a, c->serial.p, c->serial.len, x509_unix(&c->valid_from),
                                 x509_unix(&c->valid_to), blen ? bundle : NULL, blen) != IM_OK) {
            ESP_LOGE(TAG, "agent refused the enrollment result (bundle signature?)");
        }
        mbedtls_x509_crt_free(&chain);
        return ESP_OK;
    }
    mbedtls_x509_crt_free(&chain);
    fail(a, r.status, "no usable leaf certificate");
    return ESP_FAIL;
}
