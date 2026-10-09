// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_NET_COMMON_H
#define CHAT_NET_COMMON_H

#include "common/util.h"

#define NET_WAIT_MAX 16
#define NET_FAM_SLOTS 64
#define NET_HOST_MAX 256

static struct { sock_t s; int v6; int used; } g_fam[NET_FAM_SLOTS];

static void fam_set(sock_t s, int v6) {
    for (int i = 0; i < NET_FAM_SLOTS; i++)
        if (g_fam[i].used && g_fam[i].s == s) { g_fam[i].v6 = v6; return; }
    for (int i = 0; i < NET_FAM_SLOTS; i++)
        if (!g_fam[i].used) { g_fam[i].used = 1; g_fam[i].s = s; g_fam[i].v6 = v6; return; }
}

static void fam_clear(sock_t s) {
    for (int i = 0; i < NET_FAM_SLOTS; i++)
        if (g_fam[i].used && g_fam[i].s == s) { g_fam[i].used = 0; return; }
}

static int fam_is_v6(sock_t s) {
    for (int i = 0; i < NET_FAM_SLOTS; i++)
        if (g_fam[i].used && g_fam[i].s == s) return g_fam[i].v6;
    return 0;
}

// An IPv4 address as IPv6 starts with these: ::ffff:a.b.c.d.
static const uint8_t V4MAP_PREFIX[IP6_LEN - IP4_LEN] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

void addr_set_v4(addr_t *a, const void *net_order_4, uint16_t port) {
    memset(a, 0, sizeof *a);
    memcpy(a->ip, net_order_4, IP4_LEN);
    a->port = port;
    a->is_v6 = 0;
}

static void addr_set_v6(addr_t *a, const uint8_t ip16[IP6_LEN], uint16_t port) {
    memset(a, 0, sizeof *a);
    if (memcmp(ip16, V4MAP_PREFIX, sizeof V4MAP_PREFIX) == 0) {
        memcpy(a->ip, ip16 + sizeof V4MAP_PREFIX, IP4_LEN);
        a->port = port;
        a->is_v6 = 0;
        return;
    }
    memcpy(a->ip, ip16, IP6_LEN);
    a->port = port;
    a->is_v6 = 1;
}

int addr_is_v4(addr_t a) { return !a.is_v6; }

int addr_equal(addr_t a, addr_t b) {
    if (a.kind != b.kind || a.port != b.port || a.is_v6 != b.is_v6) return 0;
    if (a.kind != ADDR_UDP) return memcmp(a.ip, b.ip, IP6_LEN) == 0;
    if (a.is_v6) return a.scope == b.scope && memcmp(a.ip, b.ip, IP6_LEN) == 0;
    return memcmp(a.ip, b.ip, IP4_LEN) == 0;
}

addr_t addr_virtual(addr_kind_t kind, const uint8_t id[IP6_LEN]) {
    addr_t a;
    memset(&a, 0, sizeof a);
    memcpy(a.ip, id, IP6_LEN);
    a.port = 1;
    a.kind = (uint8_t)kind;
    return a;
}

// "nostr:..." or "tor:..." for a relayed address; 0 for a real one, left to the caller.
static int virtual_to_string(addr_t a, char out[ADDR_STR_LEN]) {
    if (a.kind == ADDR_UDP) return 0;
    char hex[IP6_LEN * 2 + 1];
    hex_encode(a.ip, IP6_LEN, hex);
    snprintf(out, ADDR_STR_LEN, "%s:%s", a.kind == ADDR_NOSTR ? "nostr" : "tor", hex);
    return 1;
}

int host_is_onion(const char *host) {
    static const char ONION[] = ".onion";
    size_t n = strlen(host), sl = sizeof ONION - 1;
    while (n > 0 && host[n - 1] == '.') n--;
    return n >= sl && strncasecmp(host + n - sl, ONION, sl) == 0;
}

addr_t addr_broadcast_lan(uint16_t port) {
    addr_t a;
    uint32_t bcast = 0xFFFFFFFFu;
    addr_set_v4(&a, &bcast, port);
    return a;
}

addr_t addr_loopback(uint16_t port) {
    addr_t a;
    uint8_t lo[4] = { 127, 0, 0, 1 };
    addr_set_v4(&a, lo, port);
    return a;
}

static void to_sockaddr4(addr_t a, struct sockaddr_in *sa) {
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    memcpy(&sa->sin_addr.s_addr, a.ip, IP4_LEN);
    sa->sin_port = htons(a.port);
}

static void to_sockaddr6(addr_t a, struct sockaddr_in6 *sa) {
    memset(sa, 0, sizeof *sa);
    sa->sin6_family = AF_INET6;
    sa->sin6_port = htons(a.port);
    if (a.is_v6) {
        memcpy(&sa->sin6_addr, a.ip, IP6_LEN);
        sa->sin6_scope_id = a.scope;
    } else {
        uint8_t mapped[IP6_LEN];
        memcpy(mapped, V4MAP_PREFIX, sizeof V4MAP_PREFIX);
        memcpy(mapped + sizeof V4MAP_PREFIX, a.ip, IP4_LEN);
        memcpy(&sa->sin6_addr, mapped, IP6_LEN);
    }
}

static void from_sockaddr(const struct sockaddr_storage *ss, addr_t *out) {
    memset(out, 0, sizeof *out);
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)ss;
        addr_set_v6(out, (const uint8_t *)&sa->sin6_addr, ntohs(sa->sin6_port));
        if (out->is_v6) out->scope = sa->sin6_scope_id;
    } else {
        const struct sockaddr_in *sa = (const struct sockaddr_in *)ss;
        addr_set_v4(out, &sa->sin_addr.s_addr, ntohs(sa->sin_port));
    }
}

int addr_resolve(const char *host, uint16_t port, addr_t *out) {
    if (host_is_onion(host)) return -1;
    addr_t got[ADDR_RESOLVE_MAX];
    int n = addr_resolve_all(host, port, got, ADDR_RESOLVE_MAX);
    if (n <= 0) return -1;
    *out = got[0];
    return 0;
}

// Splits "HOST:PORT" or "[IPv6]:PORT", with an optional %scope on the host. Looks nothing up.
static int split_hostport(const char *hostport, char host[NET_HOST_MAX], uint16_t *port_out, uint32_t *scope_out) {
    const char *portstr;
    if (hostport[0] == '[') {
        const char *close = strchr(hostport, ']');
        if (!close || close[1] != ':') return -1;
        size_t hlen = (size_t)(close - hostport - 1);
        if (hlen == 0 || hlen >= NET_HOST_MAX) return -1;
        memcpy(host, hostport + 1, hlen);
        host[hlen] = '\0';
        portstr = close + 2;
    } else {
        const char *colon = strchr(hostport, ':');
        if (!colon || strchr(colon + 1, ':')) return -1;
        size_t hlen = (size_t)(colon - hostport);
        if (hlen == 0 || hlen >= NET_HOST_MAX) return -1;
        memcpy(host, hostport, hlen);
        host[hlen] = '\0';
        portstr = colon + 1;
    }
    if (!*portstr) return -1;
    for (const char *p = portstr; *p; p++) if (*p < '0' || *p > '9') return -1;
    long port = strtol(portstr, NULL, 10);
    if (port <= 0 || port > UINT16_MAX) return -1;

    uint32_t scope = 0;
    char *pct = strchr(host, '%');
    if (pct) {
        *pct = '\0';
        for (const char *p = pct + 1; *p; p++) {
            if (*p < '0' || *p > '9') { scope = 0; break; }
            scope = scope * 10 + (uint32_t)(*p - '0');
        }
    }
    *port_out = (uint16_t)port;
    *scope_out = scope;
    return 0;
}

static int parse_hostport(const char *hostport, addr_t *out, int numeric) {
    char host[NET_HOST_MAX];
    uint16_t port;
    uint32_t scope;
    if (split_hostport(hostport, host, &port, &scope) != 0) return -1;
    int rc = numeric ? addr_resolve_numeric(host, port, out) : addr_resolve(host, port, out);
    if (rc != 0) return -1;
    if (out->is_v6) out->scope = scope;
    return 0;
}

int addr_check_hostport(const char *hostport) {
    char host[NET_HOST_MAX];
    uint16_t port;
    uint32_t scope;
    return split_hostport(hostport, host, &port, &scope);
}

int addr_parse_hostport(const char *hostport, addr_t *out) { return parse_hostport(hostport, out, 0); }
int addr_parse_ip_port(const char *hostport, addr_t *out) { return parse_hostport(hostport, out, 1); }

#endif
