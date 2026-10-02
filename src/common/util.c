// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "common/util.h"
#include <limits.h>
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

long base64_decode_strict(const char *in, size_t inlen, uint8_t *out, size_t cap) {
    if (inlen % 4 != 0) return -1;
    size_t o = 0;
    for (size_t i = 0; i < inlen; i += 4) {
        uint32_t v = 0;
        int pad = 0;
        for (int k = 0; k < 4; k++) {
            char ch = in[i + k];
            const char *hit = ch ? strchr(B64CH, ch) : NULL;
            if (ch == '=' && i + 4 == inlen && k >= 2 && (k == 3 || in[i + 3] == '=')) { pad++; v <<= 6; continue; }
            if (!hit || pad) return -1;
            v = (v << 6) | (uint32_t)(hit - B64CH);
        }
        for (int k = 0; k < 3 - pad; k++) {
            if (o >= cap) return -1;
            out[o++] = (uint8_t)(v >> (16 - 8 * k));
        }
    }
    return (long)o;
}

void hex_encode(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = HEXCH[in[i] >> 4];
        out[i * 2 + 1] = HEXCH[in[i] & 0xf];
    }
    out[len * 2] = '\0';
}

void hex_groups(const uint8_t *in, size_t len, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        if (i > 0 && i % 2 == 0) out[o++] = ' ';
        out[o++] = HEXCH[in[i] >> 4];
        out[o++] = HEXCH[in[i] & 0xf];
    }
    out[o] = '\0';
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

// Strict: overlong forms, surrogates and anything past U+10FFFF are malformed. Decoding those
// leniently would let e.g. C1 9B through as '[' while an 8-bit terminal reads the 9B as CSI.
static uint32_t utf8_next(const unsigned char *s, size_t n, size_t i, size_t *adv) {
    static const uint32_t MIN_CP[5] = { 0, 0, 0x80, 0x800, 0x10000 };
    unsigned char c = s[i];
    size_t len;
    uint32_t cp;
    if ((c & 0x80) == 0) { *adv = 1; return c; }
    else if ((c & 0xe0) == 0xc0 && i + 1 < n) { len = 2; cp = c & 0x1f; }
    else if ((c & 0xf0) == 0xe0 && i + 2 < n) { len = 3; cp = c & 0x0f; }
    else if ((c & 0xf8) == 0xf0 && i + 3 < n) { len = 4; cp = c & 0x07; }
    else { *adv = 1; return c; }
    for (size_t k = 1; k < len; k++) {
        unsigned char cc = s[i + k];
        if ((cc & 0xc0) != 0x80) { *adv = 1; return c; }
        cp = (cp << 6) | (cc & 0x3f);
    }
    if (cp < MIN_CP[len] || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) { *adv = 1; return c; }
    *adv = len;
    return cp;
}

uint32_t utf8_decode(const char *s, size_t n, size_t i, size_t *adv) {
    return utf8_next((const unsigned char *)s, n, i, adv);
}

size_t utf8_put(uint32_t cp, char *out) {
    if (cp < 0x80) { out[0] = (char)cp; return 1; }
    if (cp < 0x800) { out[0] = (char)(0xc0 | (cp >> 6)); out[1] = (char)(0x80 | (cp & 0x3f)); return 2; }
    if (cp < 0x10000) {
        out[0] = (char)(0xe0 | (cp >> 12)); out[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
        out[2] = (char)(0x80 | (cp & 0x3f)); return 3;
    }
    out[0] = (char)(0xf0 | (cp >> 18)); out[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3f)); out[3] = (char)(0x80 | (cp & 0x3f));
    return 4;
}

typedef struct { uint32_t lo, hi; } cp_range_t;

static int in_ranges(uint32_t cp, const cp_range_t *r, size_t n) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (cp < r[mid].lo) hi = mid;
        else if (cp > r[mid].hi) lo = mid + 1;
        else return 1;
    }
    return 0;
}

// Sorted. Combining marks and characters that take no column.
static const cp_range_t ZERO_WIDTH[] = {
    { 0x0300, 0x036f }, { 0x0483, 0x0489 }, { 0x0591, 0x05bd }, { 0x05bf, 0x05bf }, { 0x05c1, 0x05c2 },
    { 0x05c4, 0x05c5 }, { 0x05c7, 0x05c7 }, { 0x0610, 0x061a }, { 0x064b, 0x065f }, { 0x0670, 0x0670 },
    { 0x06d6, 0x06dc }, { 0x06df, 0x06e4 }, { 0x06e7, 0x06e8 }, { 0x06ea, 0x06ed }, { 0x0e31, 0x0e31 },
    { 0x0e34, 0x0e3a }, { 0x0e47, 0x0e4e }, { 0x1ab0, 0x1aff }, { 0x1dc0, 0x1dff }, { 0x200b, 0x200f },
    { 0x202a, 0x202e }, { 0x2060, 0x2064 }, { 0x20d0, 0x20ff }, { 0xfe00, 0xfe0f }, { 0xfe20, 0xfe2f },
    { 0xfeff, 0xfeff }, { 0xe0000, 0xe007f }, { 0xe0100, 0xe01ef },
};

// Sorted. East Asian wide and fullwidth ranges, and emoji that terminals draw two columns wide.
static const cp_range_t WIDE[] = {
    { 0x1100, 0x115f }, { 0x231a, 0x231b }, { 0x2329, 0x232a }, { 0x23e9, 0x23ec }, { 0x23f0, 0x23f0 },
    { 0x23f3, 0x23f3 }, { 0x25fd, 0x25fe }, { 0x2614, 0x2615 }, { 0x2648, 0x2653 }, { 0x267f, 0x267f },
    { 0x2693, 0x2693 }, { 0x26a1, 0x26a1 }, { 0x26aa, 0x26ab }, { 0x26bd, 0x26be }, { 0x26c4, 0x26c5 },
    { 0x26ce, 0x26ce }, { 0x26d4, 0x26d4 }, { 0x26ea, 0x26ea }, { 0x26f2, 0x26f3 }, { 0x26f5, 0x26f5 },
    { 0x26fa, 0x26fa }, { 0x26fd, 0x26fd }, { 0x2705, 0x2705 }, { 0x270a, 0x270b }, { 0x2728, 0x2728 },
    { 0x274c, 0x274c }, { 0x274e, 0x274e }, { 0x2753, 0x2755 }, { 0x2757, 0x2757 }, { 0x2795, 0x2797 },
    { 0x27b0, 0x27b0 }, { 0x27bf, 0x27bf }, { 0x2b1b, 0x2b1c }, { 0x2b50, 0x2b50 }, { 0x2b55, 0x2b55 },
    { 0x2e80, 0x303e }, { 0x3041, 0x33ff }, { 0x3400, 0x4dbf }, { 0x4e00, 0x9fff }, { 0xa000, 0xa4cf },
    { 0xa960, 0xa97f }, { 0xac00, 0xd7a3 }, { 0xf900, 0xfaff }, { 0xfe10, 0xfe19 }, { 0xfe30, 0xfe6f },
    { 0xff00, 0xff60 }, { 0xffe0, 0xffe6 }, { 0x16fe0, 0x18cff }, { 0x1b000, 0x1b2ff }, { 0x1f004, 0x1f004 },
    { 0x1f0cf, 0x1f0cf }, { 0x1f18e, 0x1f18e }, { 0x1f191, 0x1f19a }, { 0x1f200, 0x1f251 }, { 0x1f300, 0x1f64f },
    { 0x1f680, 0x1f6ff }, { 0x1f7e0, 0x1f7eb }, { 0x1f90c, 0x1f9ff }, { 0x1fa70, 0x1faff }, { 0x20000, 0x3fffd },
};

int utf8_char_cols(const char *s, size_t n, size_t i, size_t *adv) {
    uint32_t cp = utf8_next((const unsigned char *)s, n, i, adv);
    if (cp < 0x80 || *adv == 1) return 1;
    if (in_ranges(cp, ZERO_WIDTH, sizeof ZERO_WIDTH / sizeof ZERO_WIDTH[0])) return 0;
    return in_ranges(cp, WIDE, sizeof WIDE / sizeof WIDE[0]) ? 2 : 1;
}

size_t utf8_fit_cols(const char *s, size_t len, int max_cols, int *cols) {
    size_t i = 0;
    int used = 0;
    while (i < len && s[i]) {
        size_t adv;
        int w = utf8_char_cols(s, len, i, &adv);
        if (used + w > max_cols) break;
        used += w;
        i += adv;
    }
    if (cols) *cols = used;
    return i;
}

int utf8_str_cols(const char *s) {
    int cols;
    utf8_fit_cols(s, strlen(s), INT_MAX, &cols);
    return cols;
}

static int is_stripped(uint32_t cp) {
    if (cp < 0x20 || cp == 0x7f) return 1;
    if (cp >= 0x80 && cp <= 0x9f) return 1;
    if (cp == 0x61c || cp == 0x200e || cp == 0x200f) return 1;
    if (cp >= 0x202a && cp <= 0x202e) return 1;
    if (cp >= 0x2066 && cp <= 0x2069) return 1;
    return 0;
}

int has_control_chars(const char *in) {
    size_t n = strlen(in), i = 0;
    const unsigned char *s = (const unsigned char *)in;
    while (i < n) {
        size_t adv;
        if (is_stripped(utf8_next(s, n, i, &adv))) return 1;
        i += adv;
    }
    return 0;
}

size_t clean_text(const char *in, char *out, size_t max_len) {
    size_t n = strlen(in), i = 0, o = 0;
    const unsigned char *s = (const unsigned char *)in;
    while (i < n) {
        size_t adv;
        uint32_t cp = utf8_next(s, n, i, &adv);
        // A lone byte of 0x80 or more is malformed and dropped, so the result is always valid UTF-8.
        if (!is_stripped(cp) && !(adv == 1 && cp >= 0x80)) {
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
    if (len > 64) len = 64;
    // randombytes_uniform has no modulo bias, so every character carries the full log2(30) bits.
    for (size_t i = 0; i < len; i++)
        out[i] = SID_ALPHABET[randombytes_uniform((uint32_t)(sizeof(SID_ALPHABET) - 1))];
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
