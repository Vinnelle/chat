// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// net.h over an in-memory queue, for the engine tests and fuzz targets. Every socket is
// 127.0.0.1:PORT; a datagram sent to that address waits in the queue until the socket's owner
// reads it. The LAN beacon port can't be opened, so sessions only find each other through the
// peers they're given.
#define _POSIX_C_SOURCE 200809L
#include "net.h"
#include "fake_net.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

// net_common.h also carries helpers for real sockets, which have no use here.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "net_common.h"
#pragma GCC diagnostic pop

#define FAKE_LAN_PORT 47474
#define FAKE_SOCKS 16
#define FAKE_QUEUE 2048
#define FAKE_DGRAM_MAX 4096

typedef struct { int used; uint16_t port; } fake_sock_t;
typedef struct { addr_t from, to; size_t len; uint8_t data[FAKE_DGRAM_MAX]; } fake_dgram_t;

static fake_sock_t g_socks[FAKE_SOCKS];
static fake_dgram_t g_queue[FAKE_QUEUE];
static int g_queued;
static uint16_t g_next_port = 40000;

fake_net_filter_fn fake_net_filter;
void *fake_net_filter_ctx;

void net_startup(void) {}
void net_shutdown(void) {}

static fake_sock_t *sock_of(sock_t s) {
    return s >= 1 && s <= FAKE_SOCKS && g_socks[s - 1].used ? &g_socks[s - 1] : NULL;
}

sock_t net_udp_open(uint16_t port, unsigned flags, uint16_t *bound_port) {
    (void)flags;
    if (port == FAKE_LAN_PORT) return SOCK_INVALID;
    if (port == 0) port = g_next_port++;
    for (int i = 0; i < FAKE_SOCKS; i++)
        if (g_socks[i].used && g_socks[i].port == port) return SOCK_INVALID;
    for (int i = 0; i < FAKE_SOCKS; i++) {
        if (g_socks[i].used) continue;
        g_socks[i].used = 1;
        g_socks[i].port = port;
        if (bound_port) *bound_port = port;
        return i + 1;
    }
    return SOCK_INVALID;
}

void net_close(sock_t s) {
    fake_sock_t *fs = sock_of(s);
    if (fs) fs->used = 0;
}

addr_t fake_net_addr(uint16_t port) { return addr_loopback(port); }

void fake_net_inject(addr_t from, addr_t to, const void *data, size_t len) {
    if (g_queued >= FAKE_QUEUE || len > FAKE_DGRAM_MAX) return;
    fake_dgram_t *d = &g_queue[g_queued++];
    d->from = from;
    d->to = to;
    d->len = len;
    memcpy(d->data, data, len);
}

int net_send(sock_t s, const void *data, size_t len, addr_t to) {
    fake_sock_t *fs = sock_of(s);
    if (!fs) return -1;
    addr_t from = fake_net_addr(fs->port);
    if (fake_net_filter && fake_net_filter(fake_net_filter_ctx, from, to, data, len)) return (int)len;
    fake_net_inject(from, to, data, len);
    return (int)len;
}

int net_recv(sock_t s, void *buf, size_t buflen, addr_t *from) {
    fake_sock_t *fs = sock_of(s);
    if (!fs) return -1;
    addr_t me = fake_net_addr(fs->port);
    for (int i = 0; i < g_queued; i++) {
        fake_dgram_t *d = &g_queue[i];
        if (!addr_equal(d->to, me)) continue;
        // Like recvfrom: a datagram longer than the buffer comes back cut short.
        size_t n = d->len < buflen ? d->len : buflen;
        memcpy(buf, d->data, n);
        if (from) *from = d->from;
        memmove(d, d + 1, (size_t)(g_queued - i - 1) * sizeof *d);
        g_queued--;
        return (int)n;
    }
    return -1;
}

int fake_net_pending(void) { return g_queued; }
void fake_net_clear(void) { g_queued = 0; }

void net_wait(sock_t *socks, int *ready, int n, int timeout_ms) {
    (void)timeout_ms;
    for (int i = 0; i < n; i++) {
        ready[i] = 0;
        fake_sock_t *fs = sock_of(socks[i]);
        if (!fs) continue;
        addr_t me = fake_net_addr(fs->port);
        for (int k = 0; k < g_queued; k++) if (addr_equal(g_queue[k].to, me)) { ready[i] = 1; break; }
    }
}

int addr_resolve_all(const char *host, uint16_t port, addr_t *out, int max) {
    (void)host; (void)port; (void)out; (void)max;
    return 0;
}

int addr_resolve_numeric(const char *host, uint16_t port, addr_t *out) {
    uint8_t ip6[16];
    struct in_addr ip4;
    if (inet_pton(AF_INET, host, &ip4) == 1) { addr_set_v4(out, &ip4.s_addr, port); return 0; }
    if (inet_pton(AF_INET6, host, ip6) == 1) { addr_set_v6(out, ip6, port); return 0; }
    return -1;
}

void addr_to_string(addr_t a, char out[ADDR_STR_LEN]) {
    char ipbuf[INET6_ADDRSTRLEN];
    if (a.is_v6) {
        inet_ntop(AF_INET6, a.ip, ipbuf, sizeof ipbuf);
        snprintf(out, ADDR_STR_LEN, "[%s]:%u", ipbuf, (unsigned)a.port);
    } else {
        inet_ntop(AF_INET, a.ip, ipbuf, sizeof ipbuf);
        snprintf(out, ADDR_STR_LEN, "%s:%u", ipbuf, (unsigned)a.port);
    }
}
