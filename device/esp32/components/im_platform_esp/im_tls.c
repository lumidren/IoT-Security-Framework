/*
 * IronMesh TLS transport: an esp_transport for esp-mqtt (and the EST client) built directly on
 * mbedTLS 3.6 so that
 *   - only TLS 1.3 is offered (contract section 4; TLS 1.2 brokers fail with tls_handshake),
 *   - ALPN "mqtt" is required,
 *   - the trust anchors are exactly the CA certificates whose SPKI SHA-256 is pinned in the
 *     trust bundle (contract section 4) - a broker under any other CA fails with
 *     tls_pin_mismatch BEFORE a single MQTT byte is sent (C-TLS-2),
 *   - the server certificate SAN must match the broker host (mbedtls_ssl_set_hostname),
 *   - the client key is the current signing slot (ATECC608B operational slot 2/3, or bootstrap
 *     slot 0 before enrollment / after expiry; opaque pk from cryptoauthlib) - esp-tls'
 *     secure-element hook is hard-wired to slot 0, which is the bootstrap key,
 *   - TLS 1.3 session tickets are kept in RAM and offered on reconnect (C-TLS-4).
 *
 * NOT COMPILED HERE (ESP-IDF v5.3 tcp_transport + mbedTLS 3.6 + lwIP).
 */
#include <errno.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_secure_cert_read.h"
#include "esp_transport.h"
#include "im_esp.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "mbedtls/net_sockets.h" /* MBEDTLS_ERR_NET_* returned by the socket BIO */
#include "mbedtls/sha256.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "nvs.h"

static const char *TAG = "im_tls";

typedef struct {
    im_tls_opts_t opts;
    uint8_t pins[4][32];
    int fd;
    bool pin_hit;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt anchors;
    mbedtls_x509_crt own;
    mbedtls_pk_context key;
} im_tls_t;

static const char *s_last_failure = "network";
static bool s_last_resumed;
static mbedtls_ssl_session s_ticket;
static bool s_have_ticket;
static const char *k_alpn[2] = {"mqtt", NULL};

const char *im_tls_last_failure(void)
{
    return s_last_failure;
}

bool im_tls_last_resumed(void)
{
    return s_last_resumed;
}

static int rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    esp_fill_random(out, len);
    return 0;
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    im_tls_t *t = ctx;
    int n = send(t->fd, buf, len, 0);
    if (n < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? MBEDTLS_ERR_SSL_WANT_WRITE
                                                         : MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return n;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    im_tls_t *t = ctx;
    int n = recv(t->fd, buf, len, 0);
    if (n < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? MBEDTLS_ERR_SSL_WANT_READ
                                                         : MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return n == 0 ? MBEDTLS_ERR_NET_CONN_RESET : n;
}

static bool pinned(const im_tls_t *t, const mbedtls_x509_crt *c)
{
    uint8_t h[32];
    if (mbedtls_sha256(c->pk_raw.p, c->pk_raw.len, h, 0) != 0) {
        return false;
    }
    for (size_t i = 0; i < t->opts.n_pins; i++) {
        if (memcmp(h, t->pins[i], 32) == 0) {
            return true;
        }
    }
    return false;
}

/* Called for every certificate of the verified chain (depth 0 = server). */
static int verify_cb(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    im_tls_t *t = ctx;
    if (depth > 0 && pinned(t, crt)) {
        t->pin_hit = true;
    }
    (void)flags; /* chain/hostname failures stay in *flags and abort the handshake */
    return 0;
}

/* Anchor candidates: CA certificates from EST /cacerts (NVS) and the factory CA in
 * esp_secure_cert. With pins (MQTT, and EST since T-29), every candidate is considered and only
 * pinned ones are kept, so a stored /cacerts blob can never add an unpinned anchor and the
 * factory PKI CA stays usable after /cacerts was stored. Without pins: NVS, else the factory CA. */
static esp_err_t load_anchors(im_tls_t *t)
{
    static uint8_t buf[4096];
    size_t n = sizeof buf;
    nvs_handle_t h;
    bool from_nvs = false;
    mbedtls_x509_crt all;
    mbedtls_x509_crt_init(&all);
    if (nvs_open("ironmesh", NVS_READONLY, &h) == ESP_OK) {
        from_nvs = nvs_get_blob(h, "cacerts", buf, &n) == ESP_OK;
        nvs_close(h);
    }
    if (from_nvs) {
        (void)mbedtls_x509_crt_parse(&all, buf, n);
    }
    if (!from_nvs || t->opts.pin_required) {
        char *ca = NULL;
        uint32_t ca_len = 0;
        if (esp_secure_cert_get_ca_cert(&ca, &ca_len) == ESP_OK) {
            (void)mbedtls_x509_crt_parse(&all, (const uint8_t *)ca, ca_len);
        }
    }
    for (mbedtls_x509_crt *c = &all; c != NULL && c->raw.len > 0; c = c->next) {
        if (!t->opts.pin_required || pinned(t, c)) {
            (void)mbedtls_x509_crt_parse_der(&t->anchors, c->raw.p, c->raw.len);
        }
    }
    mbedtls_x509_crt_free(&all);
    return t->anchors.raw.len > 0 ? ESP_OK : ESP_ERR_NOT_FOUND;
}

static int tcp_open(const char *host, int port, int timeout_ms)
{
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *res = NULL;
    char p[8];
    int fd = -1;
    snprintf(p, sizeof p, "%d", port);
    if (getaddrinfo(host, p, &hints, &res) != 0 || res == NULL) {
        return -1;
    }
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd >= 0) {
        struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(res);
    return fd;
}

static void tls_free(im_tls_t *t)
{
    mbedtls_ssl_free(&t->ssl);
    mbedtls_ssl_config_free(&t->conf);
    mbedtls_x509_crt_free(&t->anchors);
    mbedtls_x509_crt_free(&t->own);
    mbedtls_pk_free(&t->key);
    if (t->fd >= 0) {
        close(t->fd);
        t->fd = -1;
    }
}

static int tls_connect(esp_transport_handle_t tr, const char *host, int port, int timeout_ms)
{
    im_tls_t *t = esp_transport_get_context_data(tr);
    const uint8_t *cert;
    size_t cert_len;
    int r;

    s_last_failure = "network";
    s_last_resumed = false;
    t->pin_hit = false;
    mbedtls_ssl_init(&t->ssl);
    mbedtls_ssl_config_init(&t->conf);
    mbedtls_x509_crt_init(&t->anchors);
    mbedtls_x509_crt_init(&t->own);
    mbedtls_pk_init(&t->key);
    if (load_anchors(t) != ESP_OK) {
        s_last_failure = "tls_pin_mismatch"; /* no configured CA matches the bundle pins */
        tls_free(t);
        return -1;
    }
    if (im_esp_client_cert(&cert, &cert_len) != ESP_OK ||
        mbedtls_x509_crt_parse_der(&t->own, cert, cert_len) != 0 ||
        im_esp_keystore_pk(im_esp_signing_slot(), &t->key) != ESP_OK) {
        s_last_failure = "cert_rejected";
        tls_free(t);
        return -1;
    }
    mbedtls_ssl_config_defaults(&t->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_min_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&t->conf, &t->anchors, NULL);
    mbedtls_ssl_conf_verify(&t->conf, verify_cb, t);
    mbedtls_ssl_conf_own_cert(&t->conf, &t->own, &t->key);
    mbedtls_ssl_conf_rng(&t->conf, rng, NULL);
    mbedtls_ssl_conf_session_tickets(&t->conf, MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
    if (t->opts.alpn != NULL) {
        mbedtls_ssl_conf_alpn_protocols(&t->conf, k_alpn);
    }
    if (mbedtls_ssl_setup(&t->ssl, &t->conf) != 0 || mbedtls_ssl_set_hostname(&t->ssl, host) != 0) {
        tls_free(t);
        return -1;
    }
    if (s_have_ticket && t->opts.alpn != NULL) {
        (void)mbedtls_ssl_set_session(&t->ssl, &s_ticket);
        s_last_resumed = true; /* offered; mbedTLS exposes no public "was resumed" flag */
    }
    t->fd = tcp_open(host, port, timeout_ms);
    if (t->fd < 0) {
        s_last_failure = "network";
        tls_free(t);
        return -1;
    }
    mbedtls_ssl_set_bio(&t->ssl, t, bio_send, bio_recv, NULL);
    while ((r = mbedtls_ssl_handshake(&t->ssl)) != 0) {
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        uint32_t flags = mbedtls_ssl_get_verify_result(&t->ssl);
        if (r == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED && (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED)) {
            s_last_failure = "tls_pin_mismatch";
        } else if (r == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE ||
                   r == MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION) {
            s_last_failure = "tls_handshake";
        } else if (r == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
            s_last_failure = "cert_rejected";
        } else if (r == MBEDTLS_ERR_SSL_TIMEOUT || r == MBEDTLS_ERR_NET_RECV_FAILED) {
            s_last_failure = "timeout";
        } else {
            s_last_failure = "tls_handshake";
        }
        ESP_LOGW(TAG, "handshake failed: -0x%04x (%s)", (unsigned)-r, s_last_failure);
        tls_free(t);
        return -1;
    }
    if (t->opts.pin_required && !t->pin_hit) {
        s_last_failure = "tls_pin_mismatch";
        tls_free(t);
        return -1;
    }
    if (t->opts.alpn != NULL) {
        const char *a = mbedtls_ssl_get_alpn_protocol(&t->ssl);
        if (a == NULL || strcmp(a, "mqtt") != 0) {
            s_last_failure = "tls_handshake";
            tls_free(t);
            return -1;
        }
    }
    return 0;
}

static int tls_read(esp_transport_handle_t tr, char *buf, int len, int timeout_ms)
{
    im_tls_t *t = esp_transport_get_context_data(tr);
    (void)timeout_ms; /* socket SO_RCVTIMEO set at connect */
    for (;;) {
        int r = mbedtls_ssl_read(&t->ssl, (unsigned char *)buf, (size_t)len);
        if (r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            mbedtls_ssl_session_free(&s_ticket);
            mbedtls_ssl_session_init(&s_ticket);
            s_have_ticket = mbedtls_ssl_get_session(&t->ssl, &s_ticket) == 0;
            continue;
        }
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_TIMEOUT) {
            return ERR_TCP_TRANSPORT_CONNECTION_TIMEOUT;
        }
        if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == 0) {
            return ERR_TCP_TRANSPORT_CONNECTION_CLOSED_BY_FIN;
        }
        return r < 0 ? -1 : r;
    }
}

static int tls_write(esp_transport_handle_t tr, const char *buf, int len, int timeout_ms)
{
    im_tls_t *t = esp_transport_get_context_data(tr);
    int done = 0;
    (void)timeout_ms;
    while (done < len) {
        int r = mbedtls_ssl_write(&t->ssl, (const unsigned char *)buf + done, (size_t)(len - done));
        if (r == MBEDTLS_ERR_SSL_WANT_WRITE || r == MBEDTLS_ERR_SSL_WANT_READ) {
            continue;
        }
        if (r < 0) {
            return -1;
        }
        done += r;
    }
    return done;
}

static int tls_poll(esp_transport_handle_t tr, int timeout_ms, bool for_read)
{
    im_tls_t *t = esp_transport_get_context_data(tr);
    fd_set set;
    struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
    if (for_read && mbedtls_ssl_get_bytes_avail(&t->ssl) > 0) {
        return 1;
    }
    FD_ZERO(&set);
    FD_SET(t->fd, &set);
    return select(t->fd + 1, for_read ? &set : NULL, for_read ? NULL : &set, NULL, &tv);
}

static int tls_poll_read(esp_transport_handle_t tr, int timeout_ms)
{
    return tls_poll(tr, timeout_ms, true);
}

static int tls_poll_write(esp_transport_handle_t tr, int timeout_ms)
{
    return tls_poll(tr, timeout_ms, false);
}

static int tls_close(esp_transport_handle_t tr)
{
    im_tls_t *t = esp_transport_get_context_data(tr);
    if (t->fd >= 0) {
        (void)mbedtls_ssl_close_notify(&t->ssl);
    }
    tls_free(t);
    return 0;
}

static int tls_destroy(esp_transport_handle_t tr)
{
    im_tls_t *t = esp_transport_get_context_data(tr);
    tls_close(tr);
    free(t);
    return 0;
}

esp_transport_handle_t im_tls_transport_new(const im_tls_opts_t *opts)
{
    esp_transport_handle_t tr = esp_transport_init();
    im_tls_t *t = calloc(1, sizeof *t);
    if (tr == NULL || t == NULL) {
        free(t);
        if (tr) {
            esp_transport_destroy(tr);
        }
        return NULL;
    }
    t->opts = *opts;
    t->fd = -1;
    if (t->opts.n_pins > 4) {
        t->opts.n_pins = 4;
    }
    for (size_t i = 0; i < t->opts.n_pins; i++) {
        memcpy(t->pins[i], opts->pins[i], 32);
    }
    t->opts.pins = (const uint8_t(*)[32])t->pins;
    esp_transport_set_context_data(tr, t);
    esp_transport_set_func(tr, tls_connect, tls_read, tls_write, tls_close, tls_poll_read,
                           tls_poll_write, tls_destroy);
    return tr;
}
