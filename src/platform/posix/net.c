// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#define _POSIX_C_SOURCE 200809L
#include "platform/net.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
typedef struct pollfd pollfd_t;
#define poll_fn poll
#define CLOSESOCK close

#include "platform/net_common.h"

void net_startup(void) {
}

void net_shutdown(void) {
}

static void set_nonblock(sock_t s) {
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
}

// Close-on-exec, so curl and tor don't inherit the session's sockets. SOCK_CLOEXEC closes the
// gap between socket() and fcntl() where another thread could spawn one of them.
static sock_t open_socket(int family) {
    sock_t s;
#ifdef SOCK_CLOEXEC
    s = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s != SOCK_INVALID || errno != EINVAL) return s;
#endif
    s = socket(family, SOCK_DGRAM, 0);
    if (s != SOCK_INVALID) fcntl(s, F_SETFD, FD_CLOEXEC);
    return s;
}

static sock_t open_v4(uint16_t port, unsigned flags, uint16_t *bound_port) {
    sock_t s = open_socket(AF_INET);
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
    set_nonblock(s);
    if (bound_port) {
        struct sockaddr_in got;
        socklen_t len = sizeof got;
        if (getsockname(s, (struct sockaddr *)&got, &len) == 0) *bound_port = ntohs(got.sin_port);
    }
    return s;
}

static sock_t open_v6(uint16_t port, unsigned flags, uint16_t *bound_port) {
    sock_t s = open_socket(AF_INET6);
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
    if (to.kind != ADDR_UDP) return -1;
    if (fam_is_v6(s)) {
        struct sockaddr_in6 sa;
        to_sockaddr6(to, &sa);
        return (int)sendto(s, (const char *)data, len, 0, (struct sockaddr *)&sa, sizeof sa);
    }
    if (!addr_is_v4(to)) return -1;
    struct sockaddr_in sa;
    to_sockaddr4(to, &sa);
    return (int)sendto(s, (const char *)data, len, 0, (struct sockaddr *)&sa, sizeof sa);
}

int net_recv(sock_t s, void *buf, size_t buflen, addr_t *from) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof ss;
    ssize_t n;
    do {
        slen = sizeof ss;
        n = recvfrom(s, (char *)buf, buflen, 0, (struct sockaddr *)&ss, &slen);
    } while (n < 0 && errno == EINTR);
    if (n < 0) return -1;
    if (from) from_sockaddr(&ss, from);
    return (int)n;
}

void net_wait(sock_t *socks, int *ready, int n, int timeout_ms) {
    pollfd_t pfds[NET_WAIT_MAX];
    int m = n < NET_WAIT_MAX ? n : NET_WAIT_MAX;
    for (int i = 0; i < m; i++) { pfds[i].fd = socks[i]; pfds[i].events = POLLIN; pfds[i].revents = 0; }
    poll_fn(pfds, (unsigned int)m, timeout_ms);
    for (int i = 0; i < m; i++) ready[i] = (pfds[i].revents & POLLIN) ? 1 : 0;
}

static sock_t open_stream(int family) {
    sock_t s;
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    s = socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s != SOCK_INVALID || errno != EINVAL) return s;
#endif
    s = socket(family, SOCK_STREAM, 0);
    if (s != SOCK_INVALID) { fcntl(s, F_SETFD, FD_CLOEXEC); set_nonblock(s); }
    return s;
}

static void no_delay(sock_t s) {
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
}

sock_t net_tcp_connect(addr_t to) {
    if (to.kind != ADDR_UDP) return SOCK_INVALID;
    sock_t s = open_stream(to.is_v6 ? AF_INET6 : AF_INET);
    if (s == SOCK_INVALID) return SOCK_INVALID;
    no_delay(s);
    int rc;
    if (to.is_v6) { struct sockaddr_in6 sa; to_sockaddr6(to, &sa); rc = connect(s, (struct sockaddr *)&sa, sizeof sa); }
    else { struct sockaddr_in sa; to_sockaddr4(to, &sa); rc = connect(s, (struct sockaddr *)&sa, sizeof sa); }
    if (rc != 0 && errno != EINPROGRESS) { CLOSESOCK(s); return SOCK_INVALID; }
    return s;
}

int net_tcp_connect_done(sock_t s) {
    struct pollfd p = { s, POLLOUT, 0 };
    if (poll(&p, 1, 0) <= 0) return 0;
    int err = 0;
    socklen_t len = sizeof err;
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &len) != 0 || err != 0) return -1;
    return (p.revents & POLLOUT) ? 1 : -1;
}

sock_t net_tcp_listen_loopback(uint16_t *port) {
    sock_t s = open_stream(AF_INET);
    if (s == SOCK_INVALID) return SOCK_INVALID;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(s, 16) != 0) { CLOSESOCK(s); return SOCK_INVALID; }
    socklen_t len = sizeof sa;
    if (getsockname(s, (struct sockaddr *)&sa, &len) != 0) { CLOSESOCK(s); return SOCK_INVALID; }
    *port = ntohs(sa.sin_port);
    return s;
}

sock_t net_tcp_accept(sock_t listener) {
    sock_t s;
    do { s = accept(listener, NULL, NULL); } while (s == SOCK_INVALID && errno == EINTR);
    if (s == SOCK_INVALID) return SOCK_INVALID;
    fcntl(s, F_SETFD, FD_CLOEXEC);
    set_nonblock(s);
    no_delay(s);
    return s;
}

int net_tcp_send(sock_t s, const void *data, size_t len) {
    ssize_t n;
    do { n = send(s, data, len, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
    if (n >= 0) return (int)n;
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
}

int net_tcp_recv(sock_t s, void *buf, size_t cap) {
    ssize_t n;
    do { n = recv(s, buf, cap, 0); } while (n < 0 && errno == EINTR);
    if (n > 0) return (int)n;
    if (n == 0) return -1;
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
}

int net_local_addr_toward(addr_t dest, addr_t *out) {
    if (dest.kind != ADDR_UDP) return -1;
    sock_t s = open_socket(dest.is_v6 ? AF_INET6 : AF_INET);
    if (s == SOCK_INVALID) return -1;
    struct sockaddr_storage ss;
    socklen_t len;
    int rc;
    if (dest.is_v6) { struct sockaddr_in6 sa; to_sockaddr6(dest, &sa); rc = connect(s, (struct sockaddr *)&sa, sizeof sa); }
    else { struct sockaddr_in sa; to_sockaddr4(dest, &sa); rc = connect(s, (struct sockaddr *)&sa, sizeof sa); }
    len = sizeof ss;
    if (rc == 0) rc = getsockname(s, (struct sockaddr *)&ss, &len);
    CLOSESOCK(s);
    if (rc != 0) return -1;
    from_sockaddr(&ss, out);
    return 0;
}

int net_set_multicast_if(sock_t s, const uint8_t local_ip[IP4_LEN]) {
    struct in_addr a;
    memcpy(&a.s_addr, local_ip, IP4_LEN);
    return setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&a, sizeof a) == 0 ? 0 : -1;
}

static int resolve(const char *host, uint16_t port, addr_t *out, int max, int flags) {
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = flags;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return 0;
    int n = 0;
    for (ai = res; ai && n < max; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ai->ai_addr;
            addr_set_v4(&out[n], &sa->sin_addr.s_addr, port);
            n++;
        } else if (ai->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ai->ai_addr;
            addr_set_v6(&out[n], sa->sin6_addr.s6_addr, port);
            n++;
        }
    }
    freeaddrinfo(res);
    return n;
}

int addr_resolve_all(const char *host, uint16_t port, addr_t *out, int max) {
    if (host_is_onion(host)) return 0;
    return resolve(host, port, out, max, 0);
}

int addr_resolve_numeric(const char *host, uint16_t port, addr_t *out) {
    return resolve(host, port, out, 1, AI_NUMERICHOST) == 1 ? 0 : -1;
}

void addr_to_string(addr_t a, char out[ADDR_STR_LEN]) {
    if (virtual_to_string(a, out)) return;
    char ipbuf[INET6_ADDRSTRLEN];
    if (a.is_v6) {
        inet_ntop(AF_INET6, a.ip, ipbuf, sizeof ipbuf);
        if (a.scope) snprintf(out, ADDR_STR_LEN, "[%s%%%u]:%u", ipbuf, (unsigned)a.scope, (unsigned)a.port);
        else snprintf(out, ADDR_STR_LEN, "[%s]:%u", ipbuf, (unsigned)a.port);
    } else {
        struct in_addr ia;
        memcpy(&ia.s_addr, a.ip, IP4_LEN);
        inet_ntop(AF_INET, &ia, ipbuf, sizeof ipbuf);
        snprintf(out, ADDR_STR_LEN, "%s:%u", ipbuf, (unsigned)a.port);
    }
}
