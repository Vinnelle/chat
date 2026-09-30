// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "transport/ss.h"
#include "common/util.h"
#include <blake3.h>
#include <sodium.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TAG_LEN 16
#define MAX_SKEW 30
#define MAX_PADDING 900
#define TYPE_CLIENT 0
#define TYPE_SERVER 1

static const char SUBKEY_CONTEXT[] = "shadowsocks 2022 session subkey";

const char *ss_method_name(ss_method_t m) {
    switch (m) {
        case SS_AES_128_GCM: return "2022-blake3-aes-128-gcm";
        case SS_AES_256_GCM: return "2022-blake3-aes-256-gcm";
        default:             return "2022-blake3-chacha20-poly1305";
    }
}

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static unsigned get16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i)); }
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static int fresh_time(uint64_t ts) {
    long long d = (long long)ts - (long long)time(NULL);
    return d >= -MAX_SKEW && d <= MAX_SKEW;
}

// ---- the link ----

static int b64val(int ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+' || ch == '-') return 62;
    if (ch == '/' || ch == '_') return 63;
    return -1;
}

// Base64 in either alphabet, padded or not, as links carry it. Returns the length, or -1.
static long b64_decode_any(const char *in, size_t n, uint8_t *out, size_t cap) {
    while (n > 0 && in[n - 1] == '=') n--;
    if (n % 4 == 1) return -1;
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        int v = b64val((unsigned char)in[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return (long)o;
}

static int hexdigit(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int pct_decode(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; in[i]; i++) {
        int ch = (unsigned char)in[i];
        if (ch == '%') {
            int hi = hexdigit((unsigned char)in[i + 1]), lo = hi < 0 ? -1 : hexdigit((unsigned char)in[i + 2]);
            if (hi < 0 || lo < 0) return -1;
            ch = hi << 4 | lo;
            i += 2;
        }
        if (ch == 0 || o + 1 >= cap) return -1;
        out[o++] = (char)ch;
    }
    out[o] = '\0';
    return 0;
}

static int host_char_ok(int ch, int bracketed) {
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) return 1;
    return ch == '.' || ch == '-' || (!bracketed && ch == '_') || (bracketed && ch == ':');
}

static int fail_why(char *why, size_t cap, const char *msg) {
    if (why && cap) copy_str(why, msg, cap);
    return -1;
}

int ss_parse_url(const char *url, ss_config_t *out, char *why, size_t why_cap) {
    memset(out, 0, sizeof *out);
    if (strncmp(url, "ss://", 5) != 0) return fail_why(why, why_cap, "a Shadowsocks link starts with ss://");
    char link[SS_URL_MAX], info[256];
    size_t n = strcspn(url + 5, "#");
    if (n >= sizeof link) return fail_why(why, why_cap, "that link is too long");
    memcpy(link, url + 5, n);
    link[n] = '\0';
    char *query = strchr(link, '?');
    if (query) {
        if (strstr(query, "plugin=")) return fail_why(why, why_cap, "links with a plugin (SIP003) aren't supported");
        *query = '\0';
    }
    size_t len = strlen(link);
    if (len > 0 && link[len - 1] == '/') link[--len] = '\0';
    char *at = strrchr(link, '@');
    if (!at) return fail_why(why, why_cap, "no @ in it: want ss://METHOD:KEY@HOST:PORT");
    *at = '\0';
    char *hostport = at + 1;

    int rc = -1;
    if (pct_decode(link, info, sizeof info) != 0) { fail_why(why, why_cap, "the method and key don't decode"); goto done; }
    if (!strchr(info, ':')) {
        // SIP002's older form: base64url of "method:key".
        uint8_t dec[sizeof info];
        long d = b64_decode_any(info, strlen(info), dec, sizeof dec - 1);
        if (d <= 0 || memchr(dec, 0, (size_t)d)) { sodium_memzero(dec, sizeof dec); fail_why(why, why_cap, "the method and key don't decode"); goto done; }
        memcpy(info, dec, (size_t)d);
        info[d] = '\0';
        sodium_memzero(dec, sizeof dec);
    }
    char *colon = strchr(info, ':');
    if (!colon) { fail_why(why, why_cap, "no method: want METHOD:KEY before the @"); goto done; }
    *colon = '\0';
    const char *method = info, *key = colon + 1;
    if (strcmp(method, "2022-blake3-aes-128-gcm") == 0) { out->method = SS_AES_128_GCM; out->key_len = 16; }
    else if (strcmp(method, "2022-blake3-aes-256-gcm") == 0) { out->method = SS_AES_256_GCM; out->key_len = 32; }
    else if (strcmp(method, "2022-blake3-chacha20-poly1305") == 0) { out->method = SS_CHACHA20_POLY1305; out->key_len = 32; }
    else {
        fail_why(why, why_cap, "chat speaks Shadowsocks 2022 only: 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm or "
                               "2022-blake3-chacha20-poly1305");
        goto done;
    }
    if (strchr(key, ':')) { fail_why(why, why_cap, "a multi-user key (iPSK:uPSK) isn't supported"); goto done; }
    if (b64_decode_any(key, strlen(key), out->psk, sizeof out->psk) != (long)out->key_len) {
        fail_why(why, why_cap, out->key_len == 16 ? "the key isn't 16 bytes of base64" : "the key isn't 32 bytes of base64");
        goto done;
    }

    char *host = hostport, *port_s;
    int bracketed = 0;
    if (host[0] == '[') {
        char *close = strchr(host, ']');
        if (!close || close[1] != ':') { fail_why(why, why_cap, "want [IPv6]:PORT after the @"); goto done; }
        *close = '\0';
        host++;
        port_s = close + 2;
        bracketed = 1;
    } else {
        char *c = strrchr(host, ':');
        if (!c) { fail_why(why, why_cap, "no port after the host"); goto done; }
        *c = '\0';
        port_s = c + 1;
    }
    size_t hl = strlen(host);
    if (hl == 0 || hl >= sizeof out->host) { fail_why(why, why_cap, "no server host in it"); goto done; }
    for (size_t i = 0; i < hl; i++)
        if (!host_char_ok((unsigned char)host[i], bracketed)) { fail_why(why, why_cap, "the server host isn't a name or an address"); goto done; }
    char *end;
    long port = strtol(port_s, &end, 10);
    if (!port_s[0] || *end || port <= 0 || port > 65535) { fail_why(why, why_cap, "the port isn't 1-65535"); goto done; }
    copy_str(out->host, host, sizeof out->host);
    out->port = (uint16_t)port;
    rc = 0;
done:
    sodium_memzero(info, sizeof info);
    sodium_memzero(link, sizeof link);
    if (rc != 0) sodium_memzero(out, sizeof *out);
    return rc;
}

// ---- crypto ----

static void subkey(const ss_config_t *c, const uint8_t *salt, size_t salt_len, uint8_t *out) {
    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, SUBKEY_CONTEXT);
    blake3_hasher_update(&h, c->psk, c->key_len);
    blake3_hasher_update(&h, salt, salt_len);
    blake3_hasher_finalize(&h, out, c->key_len);
    sodium_memzero(&h, sizeof h);
}

// AEAD with a 12-byte nonce: ChaCha20-Poly1305, or AES-GCM. out may be in; the tag follows the text.
static int aead_seal(const ss_config_t *c, const uint8_t *key, const uint8_t nonce[12], const uint8_t *in,
                     size_t len, uint8_t *out) {
    if (c->method == SS_CHACHA20_POLY1305)
        return crypto_aead_chacha20poly1305_ietf_encrypt(out, NULL, in, len, NULL, 0, NULL, nonce, key) == 0 ? 0 : -1;
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, (unsigned)(c->key_len * 8));
    if (rc == 0) rc = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, len, nonce, 12, NULL, 0, in, out, TAG_LEN, out + len);
    mbedtls_gcm_free(&g);
    return rc == 0 ? 0 : -1;
}

// clen includes the tag; the text (clen - 16 bytes) goes to out, which may be in.
static int aead_open(const ss_config_t *c, const uint8_t *key, const uint8_t nonce[12], const uint8_t *in,
                     size_t clen, uint8_t *out) {
    if (clen < TAG_LEN) return -1;
    if (c->method == SS_CHACHA20_POLY1305)
        return crypto_aead_chacha20poly1305_ietf_decrypt(out, NULL, NULL, in, clen, NULL, 0, nonce, key) == 0 ? 0 : -1;
    size_t len = clen - TAG_LEN;
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, (unsigned)(c->key_len * 8));
    if (rc == 0) rc = mbedtls_gcm_auth_decrypt(&g, len, nonce, 12, NULL, 0, in + len, TAG_LEN, in, out);
    mbedtls_gcm_free(&g);
    return rc == 0 ? 0 : -1;
}

static int aes_block(const ss_config_t *c, int encrypt, const uint8_t in[16], uint8_t out[16]) {
    mbedtls_aes_context a;
    mbedtls_aes_init(&a);
    unsigned bits = (unsigned)(c->key_len * 8);
    int rc = encrypt ? mbedtls_aes_setkey_enc(&a, c->psk, bits) : mbedtls_aes_setkey_dec(&a, c->psk, bits);
    if (rc == 0) rc = mbedtls_aes_crypt_ecb(&a, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, in, out);
    mbedtls_aes_free(&a);
    return rc == 0 ? 0 : -1;
}

static void crypto_ready(void) {
    // AES-GCM may go through PSA; starting it again is free.
    psa_crypto_init();
}

// SOCKS5's form of an address: type, address, port. A name when host isn't NULL.
static size_t put_addr(uint8_t *p, const addr_t *to, const char *host, uint16_t port) {
    size_t o = 0;
    addr_t numeric;
    if (host && addr_resolve_numeric(host, port, &numeric) == 0) { to = &numeric; host = NULL; }
    if (host) {
        size_t hl = strlen(host);
        p[o++] = 3;
        p[o++] = (uint8_t)hl;
        memcpy(p + o, host, hl);
        o += hl;
    } else if (to->is_v6) {
        p[o++] = 4;
        memcpy(p + o, to->ip, 16);
        o += 16;
        port = to->port;
    } else {
        p[o++] = 1;
        memcpy(p + o, to->ip, 4);
        o += 4;
        port = to->port;
    }
    put16(p + o, port);
    return o + 2;
}

// Reads one. A name leaves *a zeroed and goes to host (if given). Returns its length, or -1.
static long get_addr(const uint8_t *p, size_t n, addr_t *a, char *host, size_t host_cap) {
    static const uint8_t v4map[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    memset(a, 0, sizeof *a);
    if (host && host_cap) host[0] = '\0';
    if (n < 1) return -1;
    switch (p[0]) {
        case 1:
            if (n < 7) return -1;
            addr_set_v4(a, p + 1, (uint16_t)get16(p + 5));
            return 7;
        case 4:
            if (n < 19) return -1;
            if (memcmp(p + 1, v4map, 12) == 0) {
                addr_set_v4(a, p + 13, (uint16_t)get16(p + 17));
            } else {
                memcpy(a->ip, p + 1, 16);
                a->is_v6 = 1;
                a->port = (uint16_t)get16(p + 17);
            }
            return 19;
        case 3: {
            if (n < 2) return -1;
            size_t hl = p[1];
            if (hl == 0 || n < 4 + hl) return -1;
            if (host && host_cap > hl) { memcpy(host, p + 2, hl); host[hl] = '\0'; }
            a->port = (uint16_t)get16(p + 2 + hl);
            return (long)(4 + hl);
        }
        default:
            return -1;
    }
}

// ---- UDP ----

// The other end's session: a server that restarted has a new one, so two are kept. Packet ids
// pass a 128-wide sliding window, as WireGuard's do.
typedef struct {
    int used, any;
    uint8_t sid[8];
    uint8_t key[32];
    uint64_t top, win[2];
    double seen;
} udp_peer_t;

struct ss_udp {
    ss_config_t c;
    int server;
    uint8_t sid[8];
    uint64_t pid;
    uint8_t key[32];        // AES: this end's session subkey
    uint8_t reply_to[8];    // a server end: the client session it answers
    udp_peer_t peers[2];
};

ss_udp_t *ss_udp_new(const ss_config_t *c, int server) {
    crypto_ready();
    ss_udp_t *u = calloc(1, sizeof *u);
    if (!u) return NULL;
    u->c = *c;
    u->server = server;
    randombytes_buf(u->sid, sizeof u->sid);
    if (c->method != SS_CHACHA20_POLY1305) subkey(c, u->sid, sizeof u->sid, u->key);
    return u;
}

void ss_udp_free(ss_udp_t *u) {
    if (!u) return;
    sodium_memzero(u, sizeof *u);
    free(u);
}

long ss_udp_seal(ss_udp_t *u, const addr_t *to, const char *host, uint16_t port, const uint8_t *data,
                 size_t len, uint8_t *out, size_t cap) {
    if (host && (strlen(host) == 0 || strlen(host) > 255)) return -1;
    int chacha = u->c.method == SS_CHACHA20_POLY1305;
    size_t head = chacha ? 24 : 16;
    uint8_t addr[2 + 255 + 2];
    size_t alen = put_addr(addr, to, host, port);
    size_t fixed = (chacha ? 16 : 0) + 1 + 8 + (u->server ? 8 : 0) + 2;
    size_t base = head + fixed + alen + len + TAG_LEN;
    size_t pad = !u->server && base < SS_UDP_TARGET ? SS_UDP_TARGET - base : 0;
    if (pad > MAX_PADDING) pad = MAX_PADDING;
    if (base + pad > cap) pad = 0;
    if (base > cap) return -1;

    uint64_t pid = u->pid++;
    uint8_t *body = out + head;
    size_t o = 0;
    if (chacha) {
        memcpy(body, u->sid, 8);
        put64(body + 8, pid);
        o = 16;
    }
    body[o++] = u->server ? TYPE_SERVER : TYPE_CLIENT;
    put64(body + o, (uint64_t)time(NULL));
    o += 8;
    if (u->server) { memcpy(body + o, u->reply_to, 8); o += 8; }
    put16(body + o, (unsigned)pad);
    o += 2;
    memset(body + o, 0, pad);
    o += pad;
    memcpy(body + o, addr, alen);
    o += alen;
    memmove(body + o, data, len);
    o += len;
    if (chacha) {
        randombytes_buf(out, 24);
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(body, NULL, body, o, NULL, 0, NULL, out, u->c.psk) != 0) return -1;
    } else {
        uint8_t sep[16];
        memcpy(sep, u->sid, 8);
        put64(sep + 8, pid);
        if (aead_seal(&u->c, u->key, sep + 4, body, o, body) != 0 || aes_block(&u->c, 1, sep, out) != 0) return -1;
    }
    return (long)(head + o + TAG_LEN);
}

static udp_peer_t *peer_session(ss_udp_t *u, const uint8_t sid[8]) {
    for (int i = 0; i < 2; i++) if (u->peers[i].used && memcmp(u->peers[i].sid, sid, 8) == 0) return &u->peers[i];
    return NULL;
}

static int window_fresh(const udp_peer_t *s, uint64_t pid) {
    if (!s || !s->any || pid > s->top) return 1;
    uint64_t back = s->top - pid;
    return back < 128 && !((s->win[back / 64] >> (back % 64)) & 1);
}

static void window_mark(udp_peer_t *s, uint64_t pid) {
    if (!s->any) {
        s->any = 1;
        s->top = pid;
        s->win[0] = 1;
        s->win[1] = 0;
    } else if (pid > s->top) {
        uint64_t shift = pid - s->top;
        if (shift >= 128) {
            s->win[0] = s->win[1] = 0;
        } else if (shift >= 64) {
            s->win[1] = s->win[0] << (shift - 64);
            s->win[0] = 0;
        } else {
            s->win[1] = (s->win[1] << shift) | (s->win[0] >> (64 - shift));
            s->win[0] <<= shift;
        }
        s->win[0] |= 1;
        s->top = pid;
    } else {
        uint64_t back = s->top - pid;
        s->win[back / 64] |= 1ULL << (back % 64);
    }
}

long ss_udp_open(ss_udp_t *u, uint8_t *pkt, size_t len, addr_t *from, const uint8_t **data, double now) {
    int chacha = u->c.method == SS_CHACHA20_POLY1305;
    size_t head = chacha ? 24 : 16;
    if (len < head + TAG_LEN + (chacha ? 16 : 0) + 1 + 8 + 2) return -1;
    uint8_t *body = pkt + head;
    size_t blen = len - head - TAG_LEN;
    uint8_t sid[8], key[32];
    uint64_t pid;
    size_t o = 0;
    if (chacha) {
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(body, NULL, NULL, body, len - head, NULL, 0, pkt, u->c.psk) != 0)
            return -1;
        memcpy(sid, body, 8);
        pid = get64(body + 8);
        o = 16;
    } else {
        uint8_t sep[16];
        if (aes_block(&u->c, 0, pkt, sep) != 0) return -1;
        memcpy(sid, sep, 8);
        pid = get64(sep + 8);
        udp_peer_t *known = peer_session(u, sid);
        if (known) memcpy(key, known->key, u->c.key_len);
        else subkey(&u->c, sid, 8, key);
        int rc = aead_open(&u->c, key, sep + 4, body, blen + TAG_LEN, body);
        if (rc != 0) { sodium_memzero(key, sizeof key); return -1; }
    }
    udp_peer_t *s = peer_session(u, sid);
    if (!window_fresh(s, pid)) return -1;

    if (o + 1 + 8 + (u->server ? 0 : 8) + 2 > blen) return -1;
    if (body[o++] != (u->server ? TYPE_CLIENT : TYPE_SERVER)) return -1;
    if (!fresh_time(get64(body + o))) return -1;
    o += 8;
    if (!u->server) {
        if (memcmp(body + o, u->sid, 8) != 0) return -1;
        o += 8;
    }
    size_t pad = get16(body + o);
    o += 2;
    if (pad > blen - o) return -1;
    o += pad;
    long al = get_addr(body + o, blen - o, from, NULL, 0);
    // What a server sends back comes from an address; a name there means nothing.
    if (al < 0 || (from->port == 0) || (body[o] == 3)) return -1;
    o += (size_t)al;

    if (!s) {
        s = !u->peers[0].used ? &u->peers[0] : !u->peers[1].used ? &u->peers[1]
          : u->peers[0].seen <= u->peers[1].seen ? &u->peers[0] : &u->peers[1];
        memset(s, 0, sizeof *s);
        s->used = 1;
        memcpy(s->sid, sid, 8);
        if (!chacha) memcpy(s->key, key, u->c.key_len);
    }
    window_mark(s, pid);
    s->seen = now;
    if (u->server) memcpy(u->reply_to, sid, 8);
    sodium_memzero(key, sizeof key);
    *data = body + o;
    return (long)(blen - o);
}

// ---- TCP ----

#define OUT_CAP (96 * 1024)
#define IN_CAP (72 * 1024)
#define PLAIN_CAP (72 * 1024)
#define SEND_CHUNK 16384

enum { IN_HEAD, IN_VARHEAD, IN_LEN, IN_PAYLOAD };

struct ss_stream {
    ss_config_t c;
    int server;
    ss_io_t io;
    char host[SS_HOST_MAX];
    uint16_t port;
    int started;               // our salt and header have gone into out
    uint8_t salt[32];          // our stream's salt
    uint8_t peer_salt[32];     // the other stream's: a response names the request's
    uint8_t okey[32], ononce[12];
    uint8_t ikey[32], inonce[12];
    int istate;
    size_t ineed;              // the next chunk's length, tag included
    uint8_t *out, *in, *plain;
    size_t out_len, in_len, plain_len, plain_off;
    int eof, dead;
    char err[120];
};

ss_stream_t *ss_stream_new(const ss_config_t *c, const ss_io_t *io, const char *host, uint16_t port, int server) {
    crypto_ready();
    ss_stream_t *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->out = malloc(OUT_CAP);
    s->in = malloc(IN_CAP);
    s->plain = malloc(PLAIN_CAP);
    if (!s->out || !s->in || !s->plain || (!server && (!host || !host[0] || strlen(host) > 255))) {
        ss_stream_free(s);
        return NULL;
    }
    s->c = *c;
    s->server = server;
    s->io = *io;
    if (host) copy_str(s->host, host, sizeof s->host);
    s->port = port;
    s->istate = IN_HEAD;
    return s;
}

void ss_stream_free(ss_stream_t *s) {
    if (!s) return;
    if (s->plain) { sodium_memzero(s->plain, PLAIN_CAP); free(s->plain); }
    free(s->out);
    free(s->in);
    sodium_memzero(s, sizeof *s);
    free(s);
}

const char *ss_stream_error(const ss_stream_t *s) { return s->err[0] ? s->err : "the Shadowsocks connection failed"; }
int ss_stream_dead(const ss_stream_t *s) { return s->dead; }

int ss_stream_target(const ss_stream_t *s, char *host, size_t cap, uint16_t *port) {
    if (!s->server || s->istate == IN_HEAD || s->istate == IN_VARHEAD) return -1;
    copy_str(host, s->host, cap);
    *port = s->port;
    return 0;
}

static int stream_fail(ss_stream_t *s, const char *why) {
    if (!s->err[0]) copy_str(s->err, why, sizeof s->err);
    s->dead = 1;
    return -1;
}

static void nonce_next(uint8_t n[12]) {
    for (int i = 0; i < 12 && ++n[i] == 0; i++) {}
}

static int out_seal(ss_stream_t *s, const uint8_t *data, size_t len) {
    if (s->out_len + len + TAG_LEN > OUT_CAP) return stream_fail(s, "too much waiting for the Shadowsocks server");
    if (aead_seal(&s->c, s->okey, s->ononce, data, len, s->out + s->out_len) != 0) return stream_fail(s, "sealing failed");
    nonce_next(s->ononce);
    s->out_len += len + TAG_LEN;
    return 0;
}

// The salt and both header chunks, with the first data in the second: one write, so the sizes on
// the wire don't give the protocol away. A response has one header, and the data follows it.
static int stream_start(ss_stream_t *s, const uint8_t *data, size_t len) {
    size_t kl = s->c.key_len;
    randombytes_buf(s->salt, kl);
    subkey(&s->c, s->salt, kl, s->okey);
    memset(s->ononce, 0, sizeof s->ononce);
    if (s->out_len + kl > OUT_CAP) return stream_fail(s, "too much waiting for the Shadowsocks server");
    memcpy(s->out + s->out_len, s->salt, kl);
    s->out_len += kl;
    uint8_t fixed[1 + 8 + 32 + 2];
    size_t f = 0;
    fixed[f++] = s->server ? TYPE_SERVER : TYPE_CLIENT;
    put64(fixed + f, (uint64_t)time(NULL));
    f += 8;
    if (s->server) {
        memcpy(fixed + f, s->peer_salt, kl);
        f += kl;
        put16(fixed + f, (unsigned)len);
        f += 2;
        return out_seal(s, fixed, f) || out_seal(s, data, len) ? -1 : 0;
    }
    size_t pad = randombytes_uniform(MAX_PADDING) + 1;
    uint8_t addr[2 + 255 + 2];
    size_t alen = put_addr(addr, NULL, s->host, s->port);
    size_t vlen = alen + 2 + pad + len;
    uint8_t *var = malloc(vlen);
    if (!var) return stream_fail(s, "out of memory");
    memcpy(var, addr, alen);
    put16(var + alen, (unsigned)pad);
    randombytes_buf(var + alen + 2, pad);
    memcpy(var + alen + 2 + pad, data, len);
    put16(fixed + f, (unsigned)vlen);
    f += 2;
    int rc = out_seal(s, fixed, f) || out_seal(s, var, vlen) ? -1 : 0;
    sodium_memzero(var, vlen);
    free(var);
    return rc;
}

int ss_stream_flush(ss_stream_t *s) {
    if (s->dead) return -1;
    while (s->out_len > 0) {
        int n = s->io.send(s->io.ctx, s->out, s->out_len);
        if (n < 0) return stream_fail(s, "the connection to the Shadowsocks server closed");
        if (n == 0) return 1;
        memmove(s->out, s->out + n, s->out_len - (size_t)n);
        s->out_len -= (size_t)n;
    }
    return 0;
}

int ss_stream_send(ss_stream_t *s, const void *data, size_t len) {
    if (ss_stream_flush(s) < 0) return -1;
    if (len == 0) return 0;
    // The socket is behind: the caller comes back.
    if (s->out_len > OUT_CAP / 2) return 0;
    size_t take = len > SEND_CHUNK ? SEND_CHUNK : len;
    if (!s->started) {
        if (s->server && s->istate == IN_HEAD) return stream_fail(s, "a response before the request");
        if (stream_start(s, data, take) != 0) return -1;
        s->started = 1;
    } else {
        uint8_t lb[2];
        put16(lb, (unsigned)take);
        if (out_seal(s, lb, 2) != 0 || out_seal(s, data, take) != 0) return -1;
    }
    if (ss_stream_flush(s) < 0) return -1;
    return (int)take;
}

static void consume(ss_stream_t *s, size_t n) {
    memmove(s->in, s->in + n, s->in_len - n);
    s->in_len -= n;
}

// Opens whatever whole chunks have come, into plain while it has room.
static int open_chunks(ss_stream_t *s) {
    size_t kl = s->c.key_len;
    for (;;) {
        switch (s->istate) {
            case IN_HEAD: {
                size_t fixed = s->server ? 1 + 8 + 2 : 1 + 8 + kl + 2, need = kl + fixed + TAG_LEN;
                if (s->in_len < need) return 0;
                uint8_t h[1 + 8 + 32 + 2];
                memcpy(s->peer_salt, s->in, kl);
                subkey(&s->c, s->peer_salt, kl, s->ikey);
                memset(s->inonce, 0, sizeof s->inonce);
                if (aead_open(&s->c, s->ikey, s->inonce, s->in + kl, fixed + TAG_LEN, h) != 0)
                    return stream_fail(s, "the Shadowsocks server's reply didn't open - is the key right?");
                nonce_next(s->inonce);
                if (h[0] != (s->server ? TYPE_CLIENT : TYPE_SERVER)) return stream_fail(s, "a Shadowsocks header of the wrong type");
                if (!fresh_time(get64(h + 1)))
                    return stream_fail(s, "the Shadowsocks server's clock and this one differ by over 30 seconds");
                if (!s->server && memcmp(h + 9, s->salt, kl) != 0) return stream_fail(s, "a reply to some other request");
                size_t len = get16(h + fixed - 2);
                consume(s, need);
                s->ineed = len + TAG_LEN;
                s->istate = s->server ? IN_VARHEAD : IN_PAYLOAD;
                break;
            }
            case IN_VARHEAD: {
                if (s->in_len < s->ineed) return 0;
                size_t vlen = s->ineed - TAG_LEN;
                if (aead_open(&s->c, s->ikey, s->inonce, s->in, s->ineed, s->in) != 0) return stream_fail(s, "a request didn't open");
                nonce_next(s->inonce);
                addr_t a;
                char host[256];
                long al = get_addr(s->in, vlen, &a, host, sizeof host);
                if (al < 0 || (size_t)al + 2 > vlen) return stream_fail(s, "a request with no target");
                if (host[0]) copy_str(s->host, host, sizeof s->host);
                else addr_to_string(a, s->host);
                s->port = a.port;
                size_t pad = get16(s->in + al);
                if ((size_t)al + 2 + pad > vlen) return stream_fail(s, "a request padded past its end");
                size_t skip = (size_t)al + 2 + pad, data = vlen - skip;
                if (data == 0 && pad == 0) return stream_fail(s, "a request with neither data nor padding");
                memcpy(s->plain + s->plain_len, s->in + skip, data);
                s->plain_len += data;
                consume(s, s->ineed);
                s->istate = IN_LEN;
                break;
            }
            case IN_LEN: {
                if (s->in_len < 2 + TAG_LEN) return 0;
                uint8_t lb[2];
                if (aead_open(&s->c, s->ikey, s->inonce, s->in, 2 + TAG_LEN, lb) != 0) return stream_fail(s, "a chunk didn't open");
                nonce_next(s->inonce);
                size_t len = get16(lb);
                if (len == 0) return stream_fail(s, "an empty chunk");
                consume(s, 2 + TAG_LEN);
                s->ineed = len + TAG_LEN;
                s->istate = IN_PAYLOAD;
                break;
            }
            case IN_PAYLOAD: {
                size_t len = s->ineed - TAG_LEN;
                if (s->in_len < s->ineed || s->plain_len + len > PLAIN_CAP) return 0;
                if (aead_open(&s->c, s->ikey, s->inonce, s->in, s->ineed, s->plain + s->plain_len) != 0)
                    return stream_fail(s, "a chunk didn't open");
                nonce_next(s->inonce);
                s->plain_len += len;
                consume(s, s->ineed);
                s->istate = IN_LEN;
                break;
            }
            default:
                return -1;
        }
    }
}

int ss_stream_recv(ss_stream_t *s, void *buf, size_t cap) {
    if (ss_stream_flush(s) < 0) return -1;
    if (s->plain_off == s->plain_len) {
        s->plain_off = s->plain_len = 0;
        while (!s->eof && s->in_len < IN_CAP) {
            int n = s->io.recv(s->io.ctx, s->in + s->in_len, IN_CAP - s->in_len);
            if (n < 0) s->eof = 1;
            if (n <= 0) break;
            s->in_len += (size_t)n;
        }
        if (open_chunks(s) < 0) return -1;
        if (s->plain_len == 0) {
            if (s->eof) return stream_fail(s, "the Shadowsocks server closed the connection");
            return 0;
        }
    }
    size_t n = s->plain_len - s->plain_off;
    if (n > cap) n = cap;
    memcpy(buf, s->plain + s->plain_off, n);
    s->plain_off += n;
    return (int)n;
}
