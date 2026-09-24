// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

static const char HEXCH[] = "0123456789abcdef";

static const char B64CH[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_encode(const uint8_t *in, size_t n, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = B64CH[(v >> 18) & 0x3f];
        out[o++] = B64CH[(v >> 12) & 0x3f];
        out[o++] = (i + 1 < n) ? B64CH[(v >> 6) & 0x3f] : '=';
        out[o++] = (i + 2 < n) ? B64CH[v & 0x3f] : '=';
    }
    out[o] = '\0';
    return o;
}

void hex_encode(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = HEXCH[in[i] >> 4];
        out[i * 2 + 1] = HEXCH[in[i] & 0xf];
    }
    out[len * 2] = '\0';
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int hex_decode(const char *in, size_t hexlen, uint8_t *out) {
    if (strlen(in) != hexlen || hexlen % 2 != 0) return -1;
    for (size_t i = 0; i < hexlen / 2; i++) {
        int hi = hexval(in[i * 2]), lo = hexval(in[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static uint32_t utf8_next(const unsigned char *s, size_t n, size_t i, size_t *adv) {
    unsigned char c = s[i];
    size_t len = 1;
    uint32_t cp = c;
    if ((c & 0x80) == 0) { len = 1; cp = c; }
    else if ((c & 0xe0) == 0xc0 && i + 1 < n) { len = 2; cp = c & 0x1f; }
    else if ((c & 0xf0) == 0xe0 && i + 2 < n) { len = 3; cp = c & 0x0f; }
    else if ((c & 0xf8) == 0xf0 && i + 3 < n) { len = 4; cp = c & 0x07; }
    else { *adv = 1; return c; }
    for (size_t k = 1; k < len; k++) {
        unsigned char cc = s[i + k];
        if ((cc & 0xc0) != 0x80) { *adv = 1; return c; }
        cp = (cp << 6) | (cc & 0x3f);
    }
    *adv = len;
    return cp;
}

static int is_stripped(uint32_t cp) {
    if (cp < 0x20 || cp == 0x7f) return 1;
    if (cp >= 0x80 && cp <= 0x9f) return 1;
    if (cp == 0x200e || cp == 0x200f) return 1;
    if (cp >= 0x202a && cp <= 0x202e) return 1;
    if (cp >= 0x2066 && cp <= 0x2069) return 1;
    return 0;
}

size_t clean_text(const char *in, char *out, size_t max_len) {
    size_t n = strlen(in), i = 0, o = 0;
    const unsigned char *s = (const unsigned char *)in;
    while (i < n) {
        size_t adv;
        uint32_t cp = utf8_next(s, n, i, &adv);
        if (!is_stripped(cp)) {
            if (o + adv > max_len) break;
            memcpy(out + o, s + i, adv);
            o += adv;
        }
        i += adv;
    }

    while (o > 0 && (out[o - 1] == ' ' || out[o - 1] == '\t' || out[o - 1] == '\n' || out[o - 1] == '\r'))
        o--;
    size_t lead = 0;
    while (lead < o && (out[lead] == ' ' || out[lead] == '\t' || out[lead] == '\n' || out[lead] == '\r'))
        lead++;
    if (lead > 0) { memmove(out, out + lead, o - lead); o -= lead; }
    out[o] = '\0';
    return o;
}

static const char SID_ALPHABET[] = "23456789ABCDEFGHJKMNPQRSTVWXYZ";

void random_session_id(char *out, size_t len) {
    uint8_t b[64];
    if (len > sizeof(b)) len = sizeof(b);
    randombytes_buf(b, len);
    for (size_t i = 0; i < len; i++) out[i] = SID_ALPHABET[b[i] % (sizeof(SID_ALPHABET) - 1)];
    out[len] = '\0';
}

static const char *NICK_ADJ[] = {
    "swift", "quiet", "brave", "lucky", "quick", "calm", "bright", "bold",
    "gentle", "sharp", "steady", "sunny", "clever", "mellow", "sly", "eager",
    "plucky", "spry", "vivid", "wry", "keen", "amber", "cosmic", "rustic",
};
static const char *NICK_NOUN[] = {
    "otter", "falcon", "maple", "comet", "heron", "lynx", "willow", "badger",
    "raven", "cedar", "ember", "sparrow", "harbor", "meadow", "gecko", "juniper",
    "pixel", "quartz", "tundra", "wren", "yonder", "zephyr", "canyon", "delta",
};

void random_nickname(char *out, size_t out_cap) {
    uint8_t b[3];
    randombytes_buf(b, sizeof b);
    const char *adj = NICK_ADJ[b[0] % (sizeof(NICK_ADJ) / sizeof(NICK_ADJ[0]))];
    const char *noun = NICK_NOUN[b[1] % (sizeof(NICK_NOUN) / sizeof(NICK_NOUN[0]))];
    snprintf(out, out_cap, "%s-%s%u", adj, noun, (unsigned)(b[2] % 100));
}

void copy_str(char *dst, const char *src, size_t dstsize) {
    if (dstsize == 0) return;
    size_t n = strlen(src);
    if (n > dstsize - 1) n = dstsize - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}
