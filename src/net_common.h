// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_NET_COMMON_H
#define CHAT_NET_COMMON_H

#define NET_WAIT_MAX 16
#define NET_FAM_SLOTS 64

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

static const uint8_t V4MAP_PREFIX[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

void addr_set_v4(addr_t *a, const void *net_order_4, uint16_t port) {
    memset(a, 0, sizeof *a);
    memcpy(a->ip, net_order_4, 4);
    a->port = port;
    a->is_v6 = 0;
}

static void addr_set_v6(addr_t *a, const uint8_t ip16[16], uint16_t port) {
    memset(a, 0, sizeof *a);
    if (memcmp(ip16, V4MAP_PREFIX, 12) == 0) {
        memcpy(a->ip, ip16 + 12, 4);
        a->port = port;
        a->is_v6 = 0;
        return;
    }
    memcpy(a->ip, ip16, 16);
    a->port = port;
    a->is_v6 = 1;
}

int addr_is_v4(addr_t a) { return !a.is_v6; }

int addr_equal(addr_t a, addr_t b) {
    if (a.port != b.port || a.is_v6 != b.is_v6) return 0;
    if (a.is_v6) return a.scope == b.scope && memcmp(a.ip, b.ip, 16) == 0;
    return memcmp(a.ip, b.ip, 4) == 0;
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
    memcpy(&sa->sin_addr.s_addr, a.ip, 4);
    sa->sin_port = htons(a.port);
}

static void to_sockaddr6(addr_t a, struct sockaddr_in6 *sa) {
    memset(sa, 0, sizeof *sa);
    sa->sin6_family = AF_INET6;
    sa->sin6_port = htons(a.port);
    if (a.is_v6) {
        memcpy(&sa->sin6_addr, a.ip, 16);
        sa->sin6_scope_id = a.scope;
    } else {
        uint8_t mapped[16];
        memcpy(mapped, V4MAP_PREFIX, 12);
        memcpy(mapped + 12, a.ip, 4);
        memcpy(&sa->sin6_addr, mapped, 16);
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
    addr_t got[ADDR_RESOLVE_MAX];
    int n = addr_resolve_all(host, port, got, ADDR_RESOLVE_MAX);
    if (n <= 0) return -1;
    *out = got[0];
    return 0;
}

int addr_parse_hostport(const char *hostport, addr_t *out) {
    char host[256];
    const char *portstr;

    if (hostport[0] == '[') {
        const char *close = strchr(hostport, ']');
        if (!close || close[1] != ':') return -1;
        size_t hlen = (size_t)(close - hostport - 1);
        if (hlen == 0 || hlen >= sizeof host) return -1;
        memcpy(host, hostport + 1, hlen);
        host[hlen] = '\0';
        portstr = close + 2;
    } else {
        const char *colon = strchr(hostport, ':');
        if (!colon || strchr(colon + 1, ':')) return -1;
        size_t hlen = (size_t)(colon - hostport);
        if (hlen == 0 || hlen >= sizeof host) return -1;
        memcpy(host, hostport, hlen);
        host[hlen] = '\0';
        portstr = colon + 1;
    }

    if (!*portstr) return -1;
    for (const char *p = portstr; *p; p++) if (*p < '0' || *p > '9') return -1;
    long port = strtol(portstr, NULL, 10);
    if (port <= 0 || port > 65535) return -1;

    uint32_t scope = 0;
    char *pct = strchr(host, '%');
    if (pct) {
        *pct = '\0';
        for (const char *p = pct + 1; *p; p++) {
            if (*p < '0' || *p > '9') { scope = 0; break; }
            scope = scope * 10 + (uint32_t)(*p - '0');
        }
    }

    if (addr_resolve(host, (uint16_t)port, out) != 0) return -1;
    if (out->is_v6) out->scope = scope;
    return 0;
}

#endif
