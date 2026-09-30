// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "transport/tls.h"
#include "platform/platform.h"
#include "common/util.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <psa/crypto.h>

struct tls_conn {
    mbedtls_ssl_context ssl;
    tls_io_t io;
    sock_t s;
    char err[160];
};

static mbedtls_x509_crt g_roots;
static mbedtls_ssl_config g_conf;
static int g_ready;   // 0 not tried, 1 ready, -1 failed
static char g_setup_err[160];

static int rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    randombytes_buf(out, len);
    return 0;
}

static void add_der(void *ctx, const uint8_t *der, size_t len) {
    // A certificate mbedTLS can't read (an odd algorithm, say) is only skipped.
    mbedtls_x509_crt_parse_der((mbedtls_x509_crt *)ctx, der, len);
}

static int add_file(void *ctx, const char *path) {
    FILE *f = platform_fopen(path, "rb");
    if (!f) return -1;
    fclose(f);
    int rc = mbedtls_x509_crt_parse_file((mbedtls_x509_crt *)ctx, path);
    return rc >= 0 && ((mbedtls_x509_crt *)ctx)->version != 0 ? 0 : -1;
}

int tls_setup(char *err, size_t cap) {
    if (g_ready == 0) {
        g_ready = -1;
        if (psa_crypto_init() != PSA_SUCCESS) {
            copy_str(g_setup_err, "the TLS library's crypto failed to start", sizeof g_setup_err);
        } else {
            mbedtls_x509_crt_init(&g_roots);
            platform_ca_roots(add_der, add_file, &g_roots);
            if (g_roots.version == 0) {
                copy_str(g_setup_err, "no trusted root certificates found on this system", sizeof g_setup_err);
            } else {
                mbedtls_ssl_config_init(&g_conf);
                if (mbedtls_ssl_config_defaults(&g_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                                MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
                    copy_str(g_setup_err, "TLS configuration failed", sizeof g_setup_err);
                } else {
                    mbedtls_ssl_conf_authmode(&g_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
                    mbedtls_ssl_conf_ca_chain(&g_conf, &g_roots, NULL);
                    mbedtls_ssl_conf_rng(&g_conf, rng, NULL);
                    mbedtls_ssl_conf_min_tls_version(&g_conf, MBEDTLS_SSL_VERSION_TLS1_2);
                    g_ready = 1;
                }
            }
        }
    }
    if (g_ready != 1 && err) copy_str(err, g_setup_err, cap);
    return g_ready == 1 ? 0 : -1;
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
    tls_conn_t *t = ctx;
    int n = t->io.send(t->io.ctx, buf, len);
    if (n > 0) return n;
    return n == 0 ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_NET_SEND_FAILED;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
    tls_conn_t *t = ctx;
    int n = t->io.recv(t->io.ctx, buf, len);
    if (n > 0) return n;
    return n == 0 ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_CONN_RESET;
}

static int sock_send(void *ctx, const void *data, size_t len) { return net_tcp_send(((tls_conn_t *)ctx)->s, data, len); }
static int sock_recv(void *ctx, void *buf, size_t cap) { return net_tcp_recv(((tls_conn_t *)ctx)->s, buf, cap); }

tls_conn_t *tls_new(sock_t s, const char *host) {
    tls_io_t io = { sock_send, sock_recv, NULL };
    tls_conn_t *t = tls_new_io(&io, host);
    if (t) { t->s = s; t->io.ctx = t; }
    return t;
}

tls_conn_t *tls_new_io(const tls_io_t *io, const char *host) {
    if (tls_setup(NULL, 0) != 0) return NULL;
    tls_conn_t *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->io = *io;
    t->s = SOCK_INVALID;
    mbedtls_ssl_init(&t->ssl);
    if (mbedtls_ssl_setup(&t->ssl, &g_conf) != 0 || mbedtls_ssl_set_hostname(&t->ssl, host) != 0) {
        mbedtls_ssl_free(&t->ssl);
        free(t);
        return NULL;
    }
    mbedtls_ssl_set_bio(&t->ssl, t, bio_send, bio_recv, NULL);
    return t;
}

static void note_error(tls_conn_t *t, int rc) {
    if (rc == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
        char info[256];
        uint32_t flags = mbedtls_ssl_get_verify_result(&t->ssl);
        mbedtls_x509_crt_verify_info(info, sizeof info, "", flags);
        info[strcspn(info, "\n")] = '\0';
        snprintf(t->err, sizeof t->err, "certificate rejected: %.130s", info);
        return;
    }
    char msg[128];
    mbedtls_strerror(rc, msg, sizeof msg);
    snprintf(t->err, sizeof t->err, "%s", msg);
}

int tls_handshake(tls_conn_t *t) {
    int rc = mbedtls_ssl_handshake(&t->ssl);
    if (rc == 0) return 1;
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
    note_error(t, rc);
    return -1;
}

int tls_write(tls_conn_t *t, const void *data, size_t len) {
    int rc = mbedtls_ssl_write(&t->ssl, data, len);
    if (rc >= 0) return rc;
    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
    note_error(t, rc);
    return -1;
}

int tls_read(tls_conn_t *t, void *buf, size_t cap) {
    for (int tries = 0; tries < 4; tries++) {
        int rc = mbedtls_ssl_read(&t->ssl, buf, cap);
        if (rc > 0) return rc;
        if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) { copy_str(t->err, "closed by the server", sizeof t->err); return -1; }
        if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
        // TLS 1.3 servers send session tickets after the handshake; there's nothing to do but read on.
        if (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
        note_error(t, rc);
        return -1;
    }
    return 0;
}

const char *tls_error(const tls_conn_t *t) { return t->err[0] ? t->err : "failed"; }

void tls_free(tls_conn_t *t) {
    if (!t) return;
    mbedtls_ssl_free(&t->ssl);
    sodium_memzero(t, sizeof *t);
    free(t);
}
