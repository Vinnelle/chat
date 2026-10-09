// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "transport/portmap.h"
#include "crypto/crypto.h"
#include "platform/platform.h"
#include "common/util.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PCP_PORT 5351
#define SSDP_PORT 1900
#define LEASE 3600u
#define HTTP_CAP 65536
#define HTTP_TIMEOUT 5.0
#define SSDP_WAIT 3.0
#define RETRY_AFTER_FAIL 600.0
// A permanent UPnP mapping (no lease) is checked this often.
#define PERMANENT_RECHECK 3600.0
#define UPNP_RENEW_RETRY 60.0
// PCP and NAT-PMP requests go a few times, each wait twice the one before.
#define GW_TRIES 3
#define GW_RETRY_BASE 0.25
#define RENEW_TRIES 4
#define RENEW_RETRY_BASE 0.5
#define SSDP_SENDS 2
#define SSDP_RESEND 1.0
// A mapping is removed on exit with a request that waits this long at most.
#define DELETE_WAIT 1.0
#define DELETE_POLL_MS 20
#define RECV_BATCH 16
#define DGRAM_MAX 1500
#define HTTP_REQ_MAX 2048
#define HTTP_PORT 80
#define HTTP_OK 200
// Where a status line's code starts: "HTTP/1.1 200".
#define HTTP_STATUS_AT 9
#define CHUNK_DIGITS_MAX 7
#define IP4_STR_LEN 16
#define SSDP_HOST "239.255.255.250:1900"

// PCP (RFC 6887): a 24-byte header (version, opcode, result, lifetime, our address as IPv4-mapped
// IPv6), then MAP's nonce, protocol, internal port, external port and external address.
enum { PCP_VERSION = 2, PCP_OP_MAP = 1, PCP_RESPONSE = 0x80, PROTO_UDP = 17 };
enum { PCP_RESULT_AT = 3, PCP_LIFETIME_AT = 4, PCP_CLIENT_IP_AT = 8, PCP_NONCE_AT = 24, PCP_PROTO_AT = 36,
       PCP_INTERNAL_AT = 40, PCP_EXTERNAL_AT = 42, PCP_EXT_IP_AT = 44, PCP_MAP_LEN = 60, PCP_NONCE_LEN = 12 };
// NAT-PMP (RFC 6886): version 0, an opcode (plus 128 in a reply), then a request's ports and
// lifetime, or a reply's result, time since the router started, and the external address or ports.
enum { NATPMP_OP_EXTIP = 0, NATPMP_OP_MAP_UDP = 1, NATPMP_RESPONSE = 128 };
enum { NATPMP_INTERNAL_AT = 4, NATPMP_EXTERNAL_AT = 6, NATPMP_LIFETIME_AT = 8, NATPMP_MAP_LEN = 12 };
enum { NATPMP_RESULT_AT = 2, NATPMP_EXTIP_AT = 8, NATPMP_EXTIP_REPLY_LEN = 12, NATPMP_MAPPED_AT = 10,
       NATPMP_MAPPED_LIFETIME_AT = 12, NATPMP_MAP_REPLY_LEN = 16 };
// UPnP's errors: the router only takes permanent mappings, or the port is someone else's.
#define UPNP_ONLY_PERMANENT 725
#define UPNP_CONFLICT 718
#define CONFLICT_TRIES 3
// After a conflict, another port is picked from these.
#define RANDOM_PORT_MIN 20000
#define RANDOM_PORTS 40000

enum {
    P_START, P_PCP, P_NATPMP, P_SSDP, P_DESC, P_ADD, P_EXTIP, P_MAPPED, P_FAILED
};
enum { VIA_NONE, VIA_PCP, VIA_NATPMP, VIA_UPNP };
enum { HTTP_CONNECTING, HTTP_SENDING, HTTP_RECEIVING };

typedef struct {
    sock_t s;
    int stage;
    char req[HTTP_REQ_MAX];
    size_t req_len, sent;
    char *resp;
    size_t resp_len;
    double deadline;
} http_t;

struct portmap {
    int state, via;
    uint16_t internal_port, external_port, want_external;
    uint8_t gw[IP4_LEN];
    int have_gw;
    uint8_t local_ip[IP4_LEN];
    uint8_t ext_ip[IP4_LEN];
    int have_ext_ip;
    sock_t udp;
    uint8_t nonce[PCP_NONCE_LEN];
    int tries;
    double next_send, deadline, renew_at;
    int renewing;
    // UPnP
    uint8_t igd_ip[IP4_LEN];
    uint16_t igd_port;
    char desc_path[256];
    char ctl_path[256];
    char service[96];
    int permanent, conflicts;
    http_t http;
    portmap_log_fn log;
    void *ctx;
    char why[120];
};

static void logf_(portmap_t *p, int verbose_only, const char *fmt, ...) {
    char msg[300];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    if (p->log) p->log(p->ctx, verbose_only, msg);
}

static int is_private_v4(const uint8_t ip[IP4_LEN]) {
    return ip[0] == 10 || (ip[0] == 172 && (ip[1] & 0xf0) == 16) || (ip[0] == 192 && ip[1] == 168)
        || (ip[0] == 169 && ip[1] == 254) || (ip[0] == 100 && (ip[1] & 0xc0) == 64);
}

static void ip_str(const uint8_t ip[IP4_LEN], char out[IP4_STR_LEN]) {
    snprintf(out, IP4_STR_LEN, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static const char *via_name(int via) { return via == VIA_PCP ? "PCP" : via == VIA_NATPMP ? "NAT-PMP" : "UPnP"; }

// An IPv4 address in the IPv6 form PCP carries: ::ffff:a.b.c.d.
static void v4_mapped(uint8_t out[IP6_LEN], const uint8_t ip[IP4_LEN]) {
    memset(out, 0, IP6_LEN - IP4_LEN - 2);
    out[IP6_LEN - IP4_LEN - 2] = out[IP6_LEN - IP4_LEN - 1] = 0xff;
    memcpy(out + IP6_LEN - IP4_LEN, ip, IP4_LEN);
}

portmap_t *portmap_new(uint16_t internal_port, portmap_log_fn log, void *ctx) {
    portmap_t *p = calloc(1, sizeof *p);
    if (!p) return NULL;
    p->internal_port = internal_port;
    p->want_external = internal_port;
    p->udp = SOCK_INVALID;
    p->http.s = SOCK_INVALID;
    p->log = log;
    p->ctx = ctx;
    p->state = P_START;
    gen_random(p->nonce, sizeof p->nonce);
    return p;
}

static void http_close(http_t *h) {
    if (h->s != SOCK_INVALID) net_close(h->s);
    h->s = SOCK_INVALID;
    free(h->resp);
    h->resp = NULL;
    h->resp_len = 0;
}

static void fail(portmap_t *p, double now, const char *why) {
    http_close(&p->http);
    copy_str(p->why, why, sizeof p->why);
    int was_mapped = p->via != VIA_NONE;
    p->state = P_FAILED;
    p->via = VIA_NONE;
    p->renewing = 0;
    p->deadline = now + RETRY_AFTER_FAIL;
    logf_(p, !was_mapped, "* port mapping: %s", why);
}

static void mapped(portmap_t *p, double now, int via, uint16_t ext, uint32_t lifetime) {
    int fresh = p->via == VIA_NONE || p->external_port != ext;
    p->via = via;
    p->external_port = ext;
    p->want_external = ext;
    p->state = P_MAPPED;
    p->renewing = 0;
    // Renew at half the lease. A permanent UPnP mapping (lifetime 0) is only checked every hour.
    p->renew_at = now + (lifetime ? (double)lifetime / 2.0 : PERMANENT_RECHECK);
    if (fresh) {
        char ext_ip[IP4_STR_LEN] = "?";
        if (p->have_ext_ip) ip_str(p->ext_ip, ext_ip);
        logf_(p, 0, "* port mapping: the router forwards %s:%u to this session (%s)", ext_ip, (unsigned)ext, via_name(via));
    }
}

static void send_gw(portmap_t *p, const uint8_t *msg, size_t len) {
    addr_t to;
    addr_set_v4(&to, p->gw, PCP_PORT);
    net_send(p->udp, msg, len, to);
}

static void send_pcp(portmap_t *p, uint32_t lifetime) {
    static const uint8_t ANY_IP[IP4_LEN];
    uint8_t m[PCP_MAP_LEN];
    memset(m, 0, sizeof m);
    m[0] = PCP_VERSION;
    m[1] = PCP_OP_MAP;
    store_be32(m + PCP_LIFETIME_AT, lifetime);
    v4_mapped(m + PCP_CLIENT_IP_AT, p->local_ip);
    memcpy(m + PCP_NONCE_AT, p->nonce, PCP_NONCE_LEN);
    m[PCP_PROTO_AT] = PROTO_UDP;
    store_be16(m + PCP_INTERNAL_AT, p->internal_port);
    store_be16(m + PCP_EXTERNAL_AT, p->want_external);
    v4_mapped(m + PCP_EXT_IP_AT, ANY_IP);
    send_gw(p, m, sizeof m);
}

static void send_natpmp(portmap_t *p, uint32_t lifetime) {
    uint8_t ext_req[2] = { 0, NATPMP_OP_EXTIP };
    send_gw(p, ext_req, sizeof ext_req);
    uint8_t m[NATPMP_MAP_LEN];
    memset(m, 0, sizeof m);
    m[1] = NATPMP_OP_MAP_UDP;
    store_be16(m + NATPMP_INTERNAL_AT, p->internal_port);
    store_be16(m + NATPMP_EXTERNAL_AT, p->want_external);
    store_be32(m + NATPMP_LIFETIME_AT, lifetime);
    send_gw(p, m, sizeof m);
}

static void send_ssdp(portmap_t *p) {
    static const char *const TARGETS[] = {
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
    };
    addr_t to;
    uint8_t mc[4] = { 239, 255, 255, 250 };
    addr_set_v4(&to, mc, SSDP_PORT);
    for (size_t i = 0; i < COUNT_OF(TARGETS); i++) {
        char msg[256];
        int n = snprintf(msg, sizeof msg, "M-SEARCH * HTTP/1.1\r\nHOST: " SSDP_HOST "\r\nMAN: \"ssdp:discover\"\r\n"
                                          "MX: 2\r\nST: %s\r\n\r\n", TARGETS[i]);
        net_send(p->udp, msg, (size_t)n, to);
    }
}

static int start_http(portmap_t *p, double now, const char *req, size_t len) {
    http_close(&p->http);
    if (len >= sizeof p->http.req) return -1;
    addr_t to;
    addr_set_v4(&to, p->igd_ip, p->igd_port);
    p->http.s = net_tcp_connect(to);
    if (p->http.s == SOCK_INVALID) return -1;
    p->http.resp = malloc(HTTP_CAP + 1);
    if (!p->http.resp) { http_close(&p->http); return -1; }
    memcpy(p->http.req, req, len);
    p->http.req_len = len;
    p->http.sent = 0;
    p->http.stage = HTTP_CONNECTING;
    p->http.deadline = now + HTTP_TIMEOUT;
    return 0;
}

// Moves the request forward. Returns 1 when the response is complete, 0 while waiting, -1 on failure.
static int http_step(http_t *h, double now) {
    if (h->s == SOCK_INVALID) return -1;
    if (now > h->deadline) return -1;
    if (h->stage == HTTP_CONNECTING) {
        int rc = net_tcp_connect_done(h->s);
        if (rc < 0) return -1;
        if (rc == 0) return 0;
        h->stage = HTTP_SENDING;
    }
    if (h->stage == HTTP_SENDING) {
        while (h->sent < h->req_len) {
            int n = net_tcp_send(h->s, h->req + h->sent, h->req_len - h->sent);
            if (n < 0) return -1;
            if (n == 0) return 0;
            h->sent += (size_t)n;
        }
        h->stage = HTTP_RECEIVING;
    }
    for (;;) {
        if (h->resp_len >= HTTP_CAP) return -1;
        int n = net_tcp_recv(h->s, h->resp + h->resp_len, HTTP_CAP - h->resp_len);
        if (n == 0) return 0;
        if (n < 0) break;   // Connection: close - the end of the response
        h->resp_len += (size_t)n;
    }
    h->resp[h->resp_len] = '\0';
    return 1;
}

static int find_ci(const char *hay, size_t len, const char *needle) {
    size_t n = strlen(needle);
    for (size_t i = 0; i + n <= len; i++)
        if (strncasecmp(hay + i, needle, n) == 0) return (int)i;
    return -1;
}

int portmap_http_body(const char *resp, size_t len, int *status, char *body, size_t cap) {
    if (len < 12 || !starts_with(resp, "HTTP/1.")) return -1;
    *status = atoi(resp + HTTP_STATUS_AT);
    int head_end = -1;
    for (size_t i = 0; i + 3 < len; i++) if (memcmp(resp + i, "\r\n\r\n", 4) == 0) { head_end = (int)i; break; }
    if (head_end < 0) return -1;
    const char *b = resp + head_end + 4;
    size_t blen = len - (size_t)head_end - 4;
    int te = find_ci(resp, (size_t)head_end, "\r\ntransfer-encoding:");
    int chunked = te >= 0 && find_ci(resp + te, (size_t)head_end - (size_t)te, "chunked") >= 0;
    size_t o = 0;
    if (!chunked) {
        if (blen >= cap) blen = cap - 1;
        memcpy(body, b, blen);
        o = blen;
    } else {
        size_t i = 0;
        for (;;) {
            size_t sz = 0, digits = 0;
            for (int h; i < blen && (h = hex_value(b[i])) >= 0; i++) {
                sz = sz * 16 + (size_t)h;
                if (++digits > CHUNK_DIGITS_MAX) return -1;
            }
            if (digits == 0) return -1;
            while (i < blen && b[i] != '\n') i++;
            i++;
            if (sz == 0) break;
            if (i > blen || sz > blen - i || o + sz >= cap) return -1;
            memcpy(body + o, b + i, sz);
            o += sz;
            i += sz;
            if (i + 2 <= blen && b[i] == '\r' && b[i + 1] == '\n') i += 2;
            else return -1;
        }
    }
    body[o] = '\0';
    return 0;
}

// The text of the first <name>...</name> in [s, s+len), or -1.
static int xml_text(const char *s, size_t len, const char *name, char *out, size_t cap) {
    char open[64], close[64];
    snprintf(open, sizeof open, "<%s>", name);
    snprintf(close, sizeof close, "</%s>", name);
    int a = find_ci(s, len, open);
    if (a < 0) return -1;
    size_t start = (size_t)a + strlen(open);
    int b = find_ci(s + start, len - start, close);
    if (b < 0) return -1;
    size_t n = (size_t)b;
    while (n > 0 && isspace((unsigned char)s[start])) { start++; n--; }
    while (n > 0 && isspace((unsigned char)s[start + n - 1])) n--;
    if (n >= cap) return -1;
    memcpy(out, s + start, n);
    out[n] = '\0';
    return 0;
}

int portmap_parse_control_url(const char *xml, size_t len, char *service, size_t scap, char *url, size_t ucap) {
    static const char *const WANTED[] = {
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    };
    for (size_t w = 0; w < COUNT_OF(WANTED); w++) {
        size_t pos = 0;
        while (pos < len) {
            int a = find_ci(xml + pos, len - pos, "<service>");
            if (a < 0) break;
            size_t start = pos + (size_t)a;
            int b = find_ci(xml + start, len - start, "</service>");
            if (b < 0) break;
            size_t blen = (size_t)b;
            char type[128];
            if (xml_text(xml + start, blen, "serviceType", type, sizeof type) == 0 && strcmp(type, WANTED[w]) == 0
                && xml_text(xml + start, blen, "controlURL", url, ucap) == 0 && strlen(type) < scap) {
                copy_str(service, type, scap);
                return 0;
            }
            pos = start + blen + sizeof "</service>" - 1;
        }
    }
    return -1;
}

// "http://IP[:PORT]/path" for a gateway at ip, or a path alone. Hosts other than the gateway are
// refused, so a device on the LAN can't point chat's requests anywhere else.
static int url_path(const char *url, const uint8_t ip[IP4_LEN], uint16_t *port, char *path, size_t cap) {
    static const char HTTP[] = "http://";
    if (strncasecmp(url, HTTP, sizeof HTTP - 1) == 0) {
        const char *h = url + sizeof HTTP - 1;
        size_t hl = strcspn(h, ":/");
        char host[32];
        if (hl == 0 || hl >= sizeof host) return -1;
        memcpy(host, h, hl);
        host[hl] = '\0';
        char want[IP4_STR_LEN];
        ip_str(ip, want);
        if (strcmp(host, want) != 0) return -1;
        h += hl;
        long pt = HTTP_PORT;
        if (*h == ':') { pt = strtol(h + 1, NULL, 10); h += 1 + strspn(h + 1, "0123456789"); }
        if (pt <= 0 || pt > UINT16_MAX) return -1;
        *port = (uint16_t)pt;
        url = *h ? h : "/";
    }
    if (url[0] != '/') {
        if (strlen(url) + 2 > cap) return -1;
        snprintf(path, cap, "/%s", url);
    } else {
        if (strlen(url) >= cap) return -1;
        copy_str(path, url, cap);
    }
    for (const char *c = path; *c; c++) if ((unsigned char)*c <= 0x20 || (unsigned char)*c >= 0x7f) return -1;
    return 0;
}

static size_t soap(portmap_t *p, char *out, size_t cap, const char *action, const char *args) {
    char body[1400];
    int bl = snprintf(body, sizeof body,
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:%s xmlns:u=\"%s\">%s</u:%s>"
        "</s:Body></s:Envelope>\r\n", action, p->service, args, action);
    if (bl <= 0 || (size_t)bl >= sizeof body) return 0;
    char ip[IP4_STR_LEN];
    ip_str(p->igd_ip, ip);
    int n = snprintf(out, cap, "POST %s HTTP/1.1\r\nHost: %s:%u\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n"
                               "SOAPAction: \"%s#%s\"\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
                     p->ctl_path, ip, (unsigned)p->igd_port, p->service, action, bl, body);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

static int send_add(portmap_t *p, double now) {
    char args[700], lan[IP4_STR_LEN], req[HTTP_REQ_MAX];
    ip_str(p->local_ip, lan);
    snprintf(args, sizeof args,
             "<NewRemoteHost></NewRemoteHost><NewExternalPort>%u</NewExternalPort><NewProtocol>UDP</NewProtocol>"
             "<NewInternalPort>%u</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled>"
             "<NewPortMappingDescription>udp</NewPortMappingDescription><NewLeaseDuration>%u</NewLeaseDuration>",
             (unsigned)p->want_external, (unsigned)p->internal_port, lan, p->permanent ? 0u : LEASE);
    size_t n = soap(p, req, sizeof req, "AddPortMapping", args);
    return n ? start_http(p, now, req, n) : -1;
}

static int send_extip(portmap_t *p, double now) {
    char req[HTTP_REQ_MAX];
    size_t n = soap(p, req, sizeof req, "GetExternalIPAddress", "");
    return n ? start_http(p, now, req, n) : -1;
}

static void begin_ssdp(portmap_t *p, double now) {
    p->state = P_SSDP;
    p->tries = 0;
    p->next_send = now;
    p->deadline = now + SSDP_WAIT;
}

static void on_udp(portmap_t *p, const uint8_t *d, size_t len, addr_t from, double now) {
    if (p->state == P_PCP || p->state == P_NATPMP || (p->state == P_MAPPED && p->renewing)) {
        if (from.is_v6 || from.port != PCP_PORT || memcmp(from.ip, p->gw, IP4_LEN) != 0) return;
        if (len >= PCP_MAP_LEN && d[0] == PCP_VERSION && d[1] == (PCP_RESPONSE | PCP_OP_MAP)
            && memcmp(d + PCP_NONCE_AT, p->nonce, PCP_NONCE_LEN) == 0) {
            if (d[PCP_RESULT_AT] != 0) {
                if (p->state == P_PCP) { p->state = P_NATPMP; p->tries = 0; p->next_send = now; }
                else fail(p, now, "the router refused to renew the mapping");
                return;
            }
            // The external address, unless the router left it all zeros.
            static const uint8_t UNKNOWN[IP4_LEN];
            const uint8_t *ext = d + PCP_EXT_IP_AT, *ext4 = ext + IP6_LEN - IP4_LEN;
            if (memcmp(ext4, UNKNOWN, IP4_LEN) != 0 && ext[IP6_LEN - IP4_LEN - 2] == 0xff && ext[IP6_LEN - IP4_LEN - 1] == 0xff) {
                memcpy(p->ext_ip, ext4, IP4_LEN);
                p->have_ext_ip = 1;
            }
            mapped(p, now, VIA_PCP, load_be16(d + PCP_EXTERNAL_AT), load_be32(d + PCP_LIFETIME_AT));
        } else if (len >= 2 && d[0] == 0) {
            if (d[1] == (NATPMP_RESPONSE | NATPMP_OP_EXTIP) && len >= NATPMP_EXTIP_REPLY_LEN && load_be16(d + NATPMP_RESULT_AT) == 0) {
                memcpy(p->ext_ip, d + NATPMP_EXTIP_AT, IP4_LEN);
                p->have_ext_ip = 1;
            } else if (d[1] == (NATPMP_RESPONSE | NATPMP_OP_MAP_UDP) && len >= NATPMP_MAP_REPLY_LEN) {
                if (load_be16(d + NATPMP_RESULT_AT) != 0) {
                    if (p->state == P_NATPMP) begin_ssdp(p, now);
                    else fail(p, now, "the router refused to renew the mapping");
                    return;
                }
                mapped(p, now, VIA_NATPMP, load_be16(d + NATPMP_MAPPED_AT), load_be32(d + NATPMP_MAPPED_LIFETIME_AT));
            } else if (p->state == P_PCP) {
                // A NAT-PMP router answering the PCP request with "unsupported version".
                p->state = P_NATPMP; p->tries = 0; p->next_send = now;
            }
        }
    } else if (p->state == P_SSDP) {
        if (from.is_v6 || from.port != SSDP_PORT || !is_private_v4(from.ip)) return;
        char msg[DGRAM_MAX];
        size_t n = len < sizeof msg - 1 ? len : sizeof msg - 1;
        memcpy(msg, d, n);
        msg[n] = '\0';
        if (!starts_with(msg, "HTTP/1.1 200")) return;
        static const char LOCATION[] = "\r\nlocation:";
        int at = find_ci(msg, n, LOCATION);
        if (at < 0) return;
        const char *v = msg + at + sizeof LOCATION - 1;
        while (*v == ' ') v++;
        char loc[300];
        size_t vl = strcspn(v, "\r\n");
        if (vl == 0 || vl >= sizeof loc) return;
        memcpy(loc, v, vl);
        loc[vl] = '\0';
        uint16_t port = HTTP_PORT;
        if (url_path(loc, from.ip, &port, p->desc_path, sizeof p->desc_path) != 0 || loc[0] == '/') return;
        memcpy(p->igd_ip, from.ip, IP4_LEN);
        p->igd_port = port;
        if (!p->have_gw) {
            addr_t gw;
            addr_set_v4(&gw, from.ip, SSDP_PORT);
            addr_t me;
            if (net_local_addr_toward(gw, &me) != 0 || me.is_v6) return;
            memcpy(p->local_ip, me.ip, IP4_LEN);
        }
        char ip[IP4_STR_LEN], req[512];
        ip_str(p->igd_ip, ip);
        int rn = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: %s:%u\r\nConnection: close\r\n\r\n",
                          p->desc_path, ip, (unsigned)p->igd_port);
        if (start_http(p, now, req, (size_t)rn) != 0) { fail(p, now, "can't reach the UPnP gateway"); return; }
        p->state = P_DESC;
    }
}

static void on_http_done(portmap_t *p, double now) {
    int status = 0;
    char *body = malloc(HTTP_CAP + 1);
    if (!body) { fail(p, now, "out of memory"); return; }
    int ok = portmap_http_body(p->http.resp, p->http.resp_len, &status, body, HTTP_CAP + 1) == 0;
    http_close(&p->http);
    if (p->state == P_DESC) {
        char url[256];
        if (!ok || status != HTTP_OK || portmap_parse_control_url(body, strlen(body), p->service, sizeof p->service, url, sizeof url) != 0
            || url_path(url, p->igd_ip, &p->igd_port, p->ctl_path, sizeof p->ctl_path) != 0) {
            fail(p, now, "the UPnP gateway offers no usable WAN connection service");
        } else if (send_add(p, now) != 0) {
            fail(p, now, "can't reach the UPnP gateway");
        } else {
            p->state = P_ADD;
        }
    } else if (p->state == P_ADD) {
        char code[16] = "";
        if (ok && status == HTTP_OK) {
            if (send_extip(p, now) == 0) p->state = P_EXTIP;
            else mapped(p, now, VIA_UPNP, p->want_external, p->permanent ? 0 : LEASE);
        } else if (ok && xml_text(body, strlen(body), "errorCode", code, sizeof code) == 0 && atoi(code) == UPNP_ONLY_PERMANENT
                   && !p->permanent) {
            // OnlyPermanentLeasesSupported: map without a lease. It's still removed on exit.
            p->permanent = 1;
            if (send_add(p, now) != 0) fail(p, now, "can't reach the UPnP gateway");
        } else if (ok && atoi(code) == UPNP_CONFLICT && p->conflicts < CONFLICT_TRIES) {
            // ConflictInMappingEntry: something else has this port, so try another.
            p->want_external = (uint16_t)(RANDOM_PORT_MIN + gen_uniform(RANDOM_PORTS));
            p->conflicts++;
            if (send_add(p, now) != 0) fail(p, now, "can't reach the UPnP gateway");
        } else {
            char why[80];
            snprintf(why, sizeof why, "the UPnP gateway refused the mapping (HTTP %d%s%s)", status, code[0] ? ", error " : "", code);
            fail(p, now, why);
        }
    } else if (p->state == P_EXTIP) {
        char ip[32];
        if (ok && status == HTTP_OK && xml_text(body, strlen(body), "NewExternalIPAddress", ip, sizeof ip) == 0) {
            addr_t a;
            if (addr_resolve_numeric(ip, 0, &a) == 0 && !a.is_v6) { memcpy(p->ext_ip, a.ip, IP4_LEN); p->have_ext_ip = 1; }
        }
        mapped(p, now, VIA_UPNP, p->want_external, p->permanent ? 0 : LEASE);
    }
    free(body);
}

void portmap_step(portmap_t *p, double now) {
    if (p->udp != SOCK_INVALID) {
        uint8_t buf[DGRAM_MAX];
        addr_t from;
        for (int i = 0; i < RECV_BATCH; i++) {
            int n = net_recv(p->udp, buf, sizeof buf, &from);
            if (n < 0) break;
            on_udp(p, buf, (size_t)n, from, now);
        }
    }
    switch (p->state) {
        case P_START: {
            p->udp = net_udp_open(0, 0, NULL);
            if (p->udp == SOCK_INVALID) { fail(p, now, "can't open a socket to talk to the router"); return; }
            p->have_gw = platform_default_gateway(p->gw) == 0 && is_private_v4(p->gw);
            if (p->have_gw) {
                addr_t gw, me;
                addr_set_v4(&gw, p->gw, PCP_PORT);
                if (net_local_addr_toward(gw, &me) == 0 && !me.is_v6) memcpy(p->local_ip, me.ip, IP4_LEN);
                else p->have_gw = 0;
            }
            // Discovery goes out on the router's side, even when a VPN holds the multicast route.
            if (p->have_gw) net_set_multicast_if(p->udp, p->local_ip);
            if (p->have_gw) { p->state = P_PCP; p->tries = 0; p->next_send = now; }
            else begin_ssdp(p, now);
            return;
        }
        case P_PCP:
        case P_NATPMP:
            if (now < p->next_send) return;
            if (p->tries >= GW_TRIES) {
                if (p->state == P_PCP) { p->state = P_NATPMP; p->tries = 0; p->next_send = now; }
                else begin_ssdp(p, now);
                return;
            }
            if (p->state == P_PCP) send_pcp(p, LEASE); else send_natpmp(p, LEASE);
            p->next_send = now + GW_RETRY_BASE * (double)(1u << p->tries);
            p->tries++;
            return;
        case P_SSDP:
            if (p->tries < SSDP_SENDS && now >= p->next_send) { send_ssdp(p); p->tries++; p->next_send = now + SSDP_RESEND; }
            if (now > p->deadline) fail(p, now, "no UPnP, NAT-PMP or PCP router answered");
            return;
        case P_DESC:
        case P_ADD:
        case P_EXTIP: {
            int rc = http_step(&p->http, now);
            if (rc < 0) fail(p, now, "the UPnP gateway stopped answering");
            else if (rc > 0) on_http_done(p, now);
            return;
        }
        case P_MAPPED:
            if (p->renewing) {
                if (now < p->next_send) return;
                if (p->tries >= RENEW_TRIES) { fail(p, now, "the router stopped renewing the mapping"); return; }
                if (p->via == VIA_PCP) send_pcp(p, LEASE); else send_natpmp(p, LEASE);
                p->next_send = now + RENEW_RETRY_BASE * (double)(1u << p->tries);
                p->tries++;
                return;
            }
            if (now < p->renew_at) return;
            if (p->via == VIA_UPNP) {
                if (send_add(p, now) == 0) p->state = P_ADD;
                else p->renew_at = now + UPNP_RENEW_RETRY;
            } else {
                p->renewing = 1;
                p->tries = 0;
                p->next_send = now;
            }
            return;
        case P_FAILED:
            // The network may have changed (another Wi-Fi, a router reboot), so look again later.
            if (now < p->deadline) return;
            if (p->udp != SOCK_INVALID) { net_close(p->udp); p->udp = SOCK_INVALID; }
            p->state = P_START;
            p->permanent = 0;
            p->conflicts = 0;
            p->want_external = p->internal_port;
            return;
        default:
            return;
    }
}

// Blocking: runs one SOAP request for up to a second.
static void upnp_delete(portmap_t *p) {
    char args[300], req[HTTP_REQ_MAX];
    snprintf(args, sizeof args, "<NewRemoteHost></NewRemoteHost><NewExternalPort>%u</NewExternalPort><NewProtocol>UDP</NewProtocol>",
             (unsigned)p->external_port);
    size_t n = soap(p, req, sizeof req, "DeletePortMapping", args);
    double start = now_seconds();
    if (!n || start_http(p, start, req, n) != 0) return;
    p->http.deadline = start + DELETE_WAIT;
    for (;;) {
        double now = now_seconds();
        int rc = http_step(&p->http, now);
        if (rc != 0) break;
        int ready = 0;
        net_wait(&p->http.s, &ready, 1, DELETE_POLL_MS);
    }
    http_close(&p->http);
}

void portmap_free(portmap_t *p) {
    if (!p) return;
    if (p->via == VIA_PCP) { send_pcp(p, 0); send_pcp(p, 0); }
    else if (p->via == VIA_NATPMP) { send_natpmp(p, 0); send_natpmp(p, 0); }
    else if (p->via == VIA_UPNP || p->state == P_ADD) upnp_delete(p);
    http_close(&p->http);
    if (p->udp != SOCK_INVALID) net_close(p->udp);
    free(p);
}

int portmap_mapped(const portmap_t *p, uint16_t *external_port) {
    if (p->via == VIA_NONE) return 0;
    if (external_port) *external_port = p->external_port;
    return 1;
}

void portmap_status(const portmap_t *p, char *out, size_t cap) {
    if (p->via != VIA_NONE) {
        char ip[IP4_STR_LEN] = "?";
        if (p->have_ext_ip) ip_str(p->ext_ip, ip);
        snprintf(out, cap, "%s:%u forwarded here by %s", ip, (unsigned)p->external_port, via_name(p->via));
    } else if (p->state == P_FAILED) {
        snprintf(out, cap, "none - %s", p->why);
    } else {
        snprintf(out, cap, "asking the router...");
    }
}
