// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ws2tcpip.h>
#include <mswsock.h>
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif
typedef WSAPOLLFD pollfd_t;
#define poll_fn WSAPoll
#define CLOSESOCK closesocket

#include "net_common.h"

void net_startup(void) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
}

void net_shutdown(void) {
    WSACleanup();
}

static void set_nonblock(sock_t s) {
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
}

static void tame_connreset(sock_t s) {
    DWORD b;
    BOOL enable = FALSE;
    WSAIoctl(s, SIO_UDP_CONNRESET, &enable, sizeof enable, NULL, 0, &b, NULL, NULL);
}

static sock_t open_v4(uint16_t port, unsigned flags, uint16_t *bound_port) {
    sock_t s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == SOCK_INVALID) return SOCK_INVALID;
    int one = 1;
    if (flags & NET_REUSE) {
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
#ifdef SO_REUSEPORT
        setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char *)&one, sizeof one);
#endif
    }
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const char *)&one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(port);
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) != 0) { CLOSESOCK(s); return SOCK_INVALID; }
    tame_connreset(s);
    set_nonblock(s);
    if (bound_port) {
        struct sockaddr_in got;
        socklen_t len = sizeof got;
        if (getsockname(s, (struct sockaddr *)&got, &len) == 0) *bound_port = ntohs(got.sin_port);
    }
    return s;
}

static sock_t open_v6(uint16_t port, unsigned flags, uint16_t *bound_port) {
    sock_t s = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s == SOCK_INVALID) return SOCK_INVALID;
    int one = 1, zero = 0;
    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&zero, sizeof zero) != 0) {
        CLOSESOCK(s);
        return SOCK_INVALID;
    }
    if (flags & NET_REUSE) {
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
#ifdef SO_REUSEPORT
        setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char *)&one, sizeof one);
#endif
    }
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const char *)&one, sizeof one);
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = in6addr_any;
    sa.sin6_port = htons(port);
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) != 0) { CLOSESOCK(s); return SOCK_INVALID; }
    tame_connreset(s);
    set_nonblock(s);
    if (bound_port) {
        struct sockaddr_in6 got;
        socklen_t len = sizeof got;
        if (getsockname(s, (struct sockaddr *)&got, &len) == 0) *bound_port = ntohs(got.sin6_port);
    }
    return s;
}

sock_t net_udp_open(uint16_t port, unsigned flags, uint16_t *bound_port) {
    if (flags & NET_DUAL) {
        sock_t s = open_v6(port, flags, bound_port);
        if (s != SOCK_INVALID) { fam_set(s, 1); return s; }
    }
    sock_t s = open_v4(port, flags, bound_port);
    if (s != SOCK_INVALID) fam_set(s, 0);
    return s;
}

void net_close(sock_t s) {
    if (s == SOCK_INVALID) return;
    fam_clear(s);
    CLOSESOCK(s);
}

int net_send(sock_t s, const void *data, size_t len, addr_t to) {
    if (fam_is_v6(s)) {
        struct sockaddr_in6 sa;
        to_sockaddr6(to, &sa);
        return (int)sendto(s, (const char *)data, (int)len, 0, (struct sockaddr *)&sa, sizeof sa);
    }
    if (!addr_is_v4(to)) return -1;
    struct sockaddr_in sa;
    to_sockaddr4(to, &sa);
    return (int)sendto(s, (const char *)data, (int)len, 0, (struct sockaddr *)&sa, sizeof sa);
}

int net_recv(sock_t s, void *buf, size_t buflen, addr_t *from) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof ss;
    int n = (int)recvfrom(s, (char *)buf, (int)buflen, 0, (struct sockaddr *)&ss, &slen);
    if (n < 0) return -1;
    if (from) from_sockaddr(&ss, from);
    return n;
}

void net_wait(sock_t *socks, int *ready, int n, int timeout_ms) {
    pollfd_t pfds[NET_WAIT_MAX];
    int m = n < NET_WAIT_MAX ? n : NET_WAIT_MAX;
    for (int i = 0; i < m; i++) { pfds[i].fd = socks[i]; pfds[i].events = POLLIN; pfds[i].revents = 0; }
    poll_fn(pfds, (unsigned int)m, timeout_ms);
    for (int i = 0; i < m; i++) ready[i] = (pfds[i].revents & POLLIN) ? 1 : 0;
}

int addr_resolve_all(const char *host, uint16_t port, addr_t *out, int max) {
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return 0;
    int n = 0;
    for (ai = res; ai && n < max; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ai->ai_addr;
            addr_set_v4(&out[n], &sa->sin_addr.s_addr, port);
            n++;
        } else if (ai->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ai->ai_addr;
            addr_set_v6(&out[n], (const uint8_t *)&sa->sin6_addr, port);
            n++;
        }
    }
    freeaddrinfo(res);
    return n;
}

void addr_to_string(addr_t a, char out[ADDR_STR_LEN]) {
    char ipbuf[INET6_ADDRSTRLEN];
    if (a.is_v6) {
        struct in6_addr ia;
        memcpy(&ia, a.ip, 16);
        InetNtopA(AF_INET6, &ia, ipbuf, sizeof ipbuf);
        if (a.scope) snprintf(out, ADDR_STR_LEN, "[%s%%%u]:%u", ipbuf, (unsigned)a.scope, (unsigned)a.port);
        else snprintf(out, ADDR_STR_LEN, "[%s]:%u", ipbuf, (unsigned)a.port);
    } else {
        struct in_addr ia;
        memcpy(&ia.s_addr, a.ip, 4);
        InetNtopA(AF_INET, &ia, ipbuf, sizeof ipbuf);
        snprintf(out, ADDR_STR_LEN, "%s:%u", ipbuf, (unsigned)a.port);
    }
}
