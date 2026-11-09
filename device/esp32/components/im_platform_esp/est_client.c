/*
 * EST client (RFC 7030) with the IronMesh attestation (contract section 3):
 *   GET  /.well-known/est/cacerts                 -> CA certificates (pin candidates, NVS)
 *   GET  /.well-known/est/ironmesh/nonce          -> 32-byte single-use nonce
 *   new P-256 key in the secure element / encrypted NVS, PKCS#10 CSR (CN, OU, O, SAN URI)
 *   attestation = COSE_Sign1 type 10 built by im_core with the CURRENT identity key
 *   POST /.well-known/est/simple(re)enroll + X-IronMesh-Attestation -> PKCS#7 certs-only and
 *        X-IronMesh-Bundle (verified by im_core with the factory bundle key)
 *
 * HTTP/1.1 is spoken over the IronMesh TLS transport (im_tls.c) rather than esp_http_client so
 * that the TLS client key can be the ATECC slot key; esp-tls only supports slot 0.
 * ATECC608B: one operational slot (HARDWARE_SETUP.md), so re-enrollment authenticates with the
 * bootstrap certificate + slot 0 (simpleenroll; accepted by the PKI for the same device) and the
 * attestation is signed by slot 0 with the bootstrap serial as kid. Software keys keep current
 * and new key side by side and use simplereenroll with the operational certificate.
 *
 * NOT COMPILED HERE (ESP-IDF v5.3 + mbedTLS 3.6 x509write_csr / base64).
 */
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_transport.h"
#include "im_esp.h"
#include "mbedtls/base64.h"
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

static int rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}

static esp_err_t http(const char *req, size_t req_len, http_resp_t *out)
{
    im_tls_opts_t o = {.alpn = NULL, .pin_required = false, .pins = NULL, .n_pins = 0};
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

static esp_err_t build_csr(im_agent_t *a, uint8_t *der, size_t cap, size_t *len)
{
    mbedtls_x509write_csr w;
    mbedtls_pk_context pk;
    char subject[160];
    char uri[128];
    mbedtls_x509_san_list san;
    int r;
    if (im_esp_identity_pending_pk(&pk) != ESP_OK) {
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

static void commit(bool ok)
{
#if CONFIG_IRONMESH_SE_ATECC608
    im_esp_atecc_commit(ok);
#else
    im_esp_nvs_commit(ok);
#endif
}

static void fail(im_agent_t *a, int status, const char *reason)
{
    ESP_LOGW(TAG, "enrollment failed: %d %s", status, reason);
    commit(false);
    im_agent_on_enroll_failed(a, status, reason);
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
    const char *op;
    uint8_t kid[20];
    size_t kid_len;
    mbedtls_x509_crt chain;
    int len;

#if CONFIG_IRONMESH_SE_ATECC608
    /* authenticate with the bootstrap cert + slot 0 (see header comment) */
    im_esp_atecc_commit(false);
    op = "simpleenroll";
    if (im_esp_bootstrap_serial(kid, sizeof kid, &kid_len) != ESP_OK) {
        fail(a, 0, "no bootstrap certificate");
        return ESP_FAIL;
    }
#else
    op = renew ? "simplereenroll" : "simpleenroll";
    if (renew) {
        memcpy(kid, a->kid, a->kid_len);
        kid_len = a->kid_len;
    } else if (im_esp_bootstrap_serial(kid, sizeof kid, &kid_len) != ESP_OK) {
        fail(a, 0, "no bootstrap certificate");
        return ESP_FAIL;
    }
#endif
    /* CA certificates (anchors / pin candidates for the broker) */
    len = snprintf(req, sizeof req,
                   "GET /.well-known/est/cacerts HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                   CONFIG_IRONMESH_EST_HOST);
    if (http(req, (size_t)len, &r) == ESP_OK && r.status == 200 &&
        b64((const char *)r.body, r.body_len, p7, sizeof p7, &n) == 0) {
        nvs_handle_t h;
        mbedtls_x509_crt_init(&chain);
        if (pkcs7_certs(p7, n, &chain) == 0 && nvs_open("ironmesh", NVS_READWRITE, &h) == ESP_OK) {
            static uint8_t pem_buf[4096];
            size_t off = 0;
            for (mbedtls_x509_crt *c = &chain; c && c->raw.len && off + c->raw.len < sizeof pem_buf;
                 c = c->next) {
                memcpy(pem_buf + off, c->raw.p, c->raw.len); /* DER concatenation */
                off += c->raw.len;
            }
            (void)nvs_set_blob(h, "cacerts", pem_buf, off);
            (void)nvs_commit(h);
            nvs_close(h);
        }
        mbedtls_x509_crt_free(&chain);
    }
    /* nonce */
    len = snprintf(req, sizeof req,
                   "GET /.well-known/est/ironmesh/nonce HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                   CONFIG_IRONMESH_EST_HOST);
    if (http(req, (size_t)len, &r) != ESP_OK) {
        fail(a, 0, "network");
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
    /* fresh key + CSR + attestation by the current identity */
#if CONFIG_IRONMESH_SE_ATECC608
    if (im_esp_atecc_new_operational(pub) != ESP_OK) {
#else
    if (im_esp_nvs_new_operational(pub) != ESP_OK) {
#endif
        fail(a, 0, "key generation");
        return ESP_FAIL;
    }
    if (build_csr(a, csr, sizeof csr, &csr_len) != ESP_OK ||
        im_agent_attestation_kid(a, kid, kid_len, nonce, csr, csr_len, att, sizeof att, &att_len) !=
            IM_OK) {
        fail(a, 0, "csr/attestation");
        return ESP_FAIL;
    }
    (void)mbedtls_base64_encode((unsigned char *)att_b64, sizeof att_b64, &n, att, att_len);
    (void)mbedtls_base64_encode((unsigned char *)csr_b64, sizeof csr_b64, &n, csr, csr_len);
    len = snprintf(req, sizeof req,
                   "POST /.well-known/est/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
                   "Content-Type: application/pkcs10\r\nContent-Transfer-Encoding: base64\r\n"
                   "X-IronMesh-Attestation: %s\r\nContent-Length: %u\r\n\r\n%s",
                   op, CONFIG_IRONMESH_EST_HOST, att_b64, (unsigned)strlen(csr_b64), csr_b64);
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
    /* leaf = the non-CA certificate */
    for (mbedtls_x509_crt *c = &chain; c != NULL && c->raw.len > 0; c = c->next) {
        if (!c->MBEDTLS_PRIVATE(ca_istrue)) {
            if (im_esp_store_operational_cert(c->raw.p, c->raw.len) != ESP_OK) {
                break;
            }
            commit(true);
            if (im_agent_on_enrolled(a, c->serial.p, c->serial.len, x509_unix(&c->valid_from),
                                     x509_unix(&c->valid_to), blen ? bundle : NULL, blen) != IM_OK) {
                ESP_LOGE(TAG, "agent refused the enrollment result (bundle signature?)");
            }
            mbedtls_x509_crt_free(&chain);
            return ESP_OK;
        }
    }
    mbedtls_x509_crt_free(&chain);
    fail(a, r.status, "no leaf certificate");
    return ESP_FAIL;
}
