// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "common/qr.h"
#include <stdlib.h>
#include <string.h>

// Level M: each version's error correction bytes per block, and its blocks.
static const uint8_t ECC_PER_BLOCK[QR_MAX_VERSION + 1] = { 0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26 };
static const uint8_t BLOCKS[QR_MAX_VERSION + 1] = { 0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5 };
#define MAX_CODEWORDS 346
#define MAX_BLOCKS 5
#define MAX_ECC 26

typedef struct {
    int size;
    uint8_t *dark;
    uint8_t fn[QR_MAX_SIZE * QR_MAX_SIZE];   // finders, timing, alignment, format and version
} grid_t;

// The modules left for data and error correction once the function patterns are drawn.
static int raw_modules(int ver) {
    int n = (16 * ver + 128) * ver + 64;
    if (ver >= 2) {
        int align = ver / 7 + 2;
        n -= (25 * align - 10) * align - 55;
        if (ver >= 7) n -= 36;
    }
    return n;
}

// GF(256) with the polynomial 0x11d.
static uint8_t gf_mul(uint8_t x, uint8_t y) {
    int z = 0;
    for (int i = 7; i >= 0; i--) {
        z = (z << 1) ^ ((z >> 7) * 0x11d);
        z ^= ((y >> i) & 1) * x;
    }
    return (uint8_t)z;
}

// The Reed-Solomon generator of this degree, highest power first and without its leading 1.
static void rs_divisor(int degree, uint8_t *out) {
    memset(out, 0, (size_t)degree);
    out[degree - 1] = 1;
    uint8_t root = 1;
    for (int i = 0; i < degree; i++) {
        for (int j = 0; j < degree; j++) {
            out[j] = gf_mul(out[j], root);
            if (j + 1 < degree) out[j] ^= out[j + 1];
        }
        root = gf_mul(root, 2);
    }
}

static void rs_remainder(const uint8_t *data, int len, const uint8_t *div, int degree, uint8_t *out) {
    memset(out, 0, (size_t)degree);
    for (int i = 0; i < len; i++) {
        uint8_t factor = data[i] ^ out[0];
        memmove(out, out + 1, (size_t)degree - 1);
        out[degree - 1] = 0;
        for (int j = 0; j < degree; j++) out[j] ^= gf_mul(div[j], factor);
    }
}

static void append(uint8_t *buf, int *bit, unsigned v, int n) {
    for (int k = n - 1; k >= 0; k--, (*bit)++)
        buf[*bit >> 3] |= (uint8_t)(((v >> k) & 1) << (7 - (*bit & 7)));
}

static void put(grid_t *g, int x, int y, int dark) {
    g->dark[y * g->size + x] = (uint8_t)(dark != 0);
    g->fn[y * g->size + x] = 1;
}

static void draw_format(grid_t *g, int mask) {
    int data = mask;   // level M's two bits are 00
    int rem = data;
    for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    int bits = (data << 10 | rem) ^ 0x5412, s = g->size;
    for (int i = 0; i <= 5; i++) put(g, 8, i, (bits >> i) & 1);
    put(g, 8, 7, (bits >> 6) & 1);
    put(g, 8, 8, (bits >> 7) & 1);
    put(g, 7, 8, (bits >> 8) & 1);
    for (int i = 9; i < 15; i++) put(g, 14 - i, 8, (bits >> i) & 1);
    for (int i = 0; i < 8; i++) put(g, s - 1 - i, 8, (bits >> i) & 1);
    for (int i = 8; i < 15; i++) put(g, 8, s - 15 + i, (bits >> i) & 1);
    put(g, 8, s - 8, 1);
}

static void draw_version(grid_t *g, int ver) {
    int rem = ver;
    for (int i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1f25);
    long bits = (long)ver << 12 | rem;
    for (int i = 0; i < 18; i++) {
        int bit = (int)((bits >> i) & 1), a = g->size - 11 + i % 3, b = i / 3;
        put(g, a, b, bit);
        put(g, b, a, bit);
    }
}

static int dist(int dx, int dy) { return abs(dx) > abs(dy) ? abs(dx) : abs(dy); }

static void draw_functions(grid_t *g, int ver) {
    int s = g->size;
    for (int i = 0; i < s; i++) {
        put(g, 6, i, i % 2 == 0);
        put(g, i, 6, i % 2 == 0);
    }
    // The finders, with the light separator around each.
    const int corner[3][2] = { { 3, 3 }, { s - 4, 3 }, { 3, s - 4 } };
    for (int f = 0; f < 3; f++)
        for (int dy = -4; dy <= 4; dy++)
            for (int dx = -4; dx <= 4; dx++) {
                int x = corner[f][0] + dx, y = corner[f][1] + dy, d = dist(dx, dy);
                if (x >= 0 && x < s && y >= 0 && y < s) put(g, x, y, d != 2 && d != 4);
            }
    int pos[7], n = 0;
    if (ver > 1) {
        n = ver / 7 + 2;
        int step = (ver * 4 + n * 2 + 1) / (n * 2 - 2) * 2;
        pos[0] = 6;
        for (int i = n - 1, p = s - 7; i >= 1; i--, p -= step) pos[i] = p;
    }
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            if ((i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0)) continue;
            for (int dy = -2; dy <= 2; dy++)
                for (int dx = -2; dx <= 2; dx++) put(g, pos[i] + dx, pos[j] + dy, dist(dx, dy) != 1);
        }
    // Reserved here, and drawn again once the mask is chosen.
    draw_format(g, 0);
    if (ver >= 7) draw_version(g, ver);
}

static void apply_mask(grid_t *g, int m) {
    int s = g->size;
    for (int y = 0; y < s; y++)
        for (int x = 0; x < s; x++) {
            if (g->fn[y * s + x]) continue;
            int inv;
            switch (m) {
                case 0:  inv = (x + y) % 2 == 0; break;
                case 1:  inv = y % 2 == 0; break;
                case 2:  inv = x % 3 == 0; break;
                case 3:  inv = (x + y) % 3 == 0; break;
                case 4:  inv = (x / 3 + y / 2) % 2 == 0; break;
                case 5:  inv = x * y % 2 + x * y % 3 == 0; break;
                case 6:  inv = (x * y % 2 + x * y % 3) % 2 == 0; break;
                default: inv = ((x + y) % 2 + x * y % 3) % 2 == 0; break;
            }
            g->dark[y * s + x] ^= (uint8_t)inv;
        }
}

// The standard's penalties: long runs, 2x2 blocks, shapes like a finder, and an uneven balance of
// dark and light. The mask with the least is the easiest to scan.
static long penalty(const grid_t *g) {
    static const uint8_t FINDER_A[11] = { 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0 };
    static const uint8_t FINDER_B[11] = { 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1 };
    int s = g->size;
    long score = 0, dark = 0;
    for (int pass = 0; pass < 2; pass++)
        for (int a = 0; a < s; a++) {
            uint8_t line[QR_MAX_SIZE];
            for (int b = 0; b < s; b++) line[b] = pass ? g->dark[b * s + a] : g->dark[a * s + b];
            int run = 1;
            for (int b = 1; b <= s; b++) {
                if (b < s && line[b] == line[b - 1]) { run++; continue; }
                if (run >= 5) score += 3 + run - 5;
                run = 1;
            }
            for (int b = 0; b + 11 <= s; b++)
                if (memcmp(line + b, FINDER_A, 11) == 0 || memcmp(line + b, FINDER_B, 11) == 0) score += 40;
        }
    for (int y = 0; y < s; y++)
        for (int x = 0; x < s; x++) {
            uint8_t c = g->dark[y * s + x];
            dark += c;
            if (x + 1 < s && y + 1 < s && c == g->dark[y * s + x + 1] && c == g->dark[(y + 1) * s + x]
                && c == g->dark[(y + 1) * s + x + 1])
                score += 3;
        }
    long total = (long)s * s;
    long k = (labs(dark * 20 - total * 10) + total - 1) / total - 1;
    return score + k * 10;
}

int qr_encode(const char *text, uint8_t out[QR_MAX_SIZE * QR_MAX_SIZE]) {
    size_t len = strlen(text);
    int ver = 1, cap = 0;
    for (; ver <= QR_MAX_VERSION; ver++) {
        cap = raw_modules(ver) / 8 - ECC_PER_BLOCK[ver] * BLOCKS[ver];
        if (len <= (size_t)cap && 4 + (ver < 10 ? 8 : 16) + 8 * (int)len <= cap * 8) break;
    }
    if (ver > QR_MAX_VERSION) return -1;

    // Byte mode, the length, the bytes, a terminator, then 0xec 0x11 ... to fill it.
    uint8_t data[MAX_CODEWORDS];
    memset(data, 0, sizeof data);
    int bit = 0;
    append(data, &bit, 4, 4);
    append(data, &bit, (unsigned)len, ver < 10 ? 8 : 16);
    for (size_t i = 0; i < len; i++) append(data, &bit, (uint8_t)text[i], 8);
    bit += cap * 8 - bit < 4 ? cap * 8 - bit : 4;
    bit = (bit + 7) & ~7;
    for (unsigned pad = 0xec; bit < cap * 8; pad ^= 0xec ^ 0x11) append(data, &bit, pad, 8);

    // Split into blocks, each with its error correction, then interleaved a byte at a time.
    int raw = raw_modules(ver) / 8, nb = BLOCKS[ver], ecc_len = ECC_PER_BLOCK[ver];
    int short_n = nb - raw % nb, short_len = raw / nb - ecc_len;
    uint8_t div[MAX_ECC], ecc[MAX_BLOCKS][MAX_ECC], all[MAX_CODEWORDS];
    const uint8_t *blk[MAX_BLOCKS];
    int blen[MAX_BLOCKS], off = 0, n = 0;
    rs_divisor(ecc_len, div);
    for (int b = 0; b < nb; b++) {
        blen[b] = short_len + (b >= short_n);
        blk[b] = data + off;
        rs_remainder(blk[b], blen[b], div, ecc_len, ecc[b]);
        off += blen[b];
    }
    for (int c = 0; c <= short_len; c++)
        for (int b = 0; b < nb; b++)
            if (c < blen[b]) all[n++] = blk[b][c];
    for (int c = 0; c < ecc_len; c++)
        for (int b = 0; b < nb; b++) all[n++] = ecc[b][c];

    static grid_t g;
    g.size = ver * 4 + 17;
    g.dark = out;
    int s = g.size;
    memset(out, 0, (size_t)s * (size_t)s);
    memset(g.fn, 0, sizeof g.fn);
    draw_functions(&g, ver);
    // Up and down two columns at a time from the right, skipping the vertical timing pattern.
    int i = 0;
    for (int right = s - 1; right >= 1; right -= 2) {
        if (right == 6) right = 5;
        for (int v = 0; v < s; v++)
            for (int j = 0; j < 2; j++) {
                int x = right - j, up = ((right + 1) & 2) == 0, y = up ? s - 1 - v : v;
                if (g.fn[y * s + x] || i >= raw * 8) continue;
                out[y * s + x] = (all[i >> 3] >> (7 - (i & 7))) & 1;
                i++;
            }
    }
    int best = 0;
    long best_score = -1;
    for (int m = 0; m < 8; m++) {
        apply_mask(&g, m);
        draw_format(&g, m);
        long sc = penalty(&g);
        if (best_score < 0 || sc < best_score) { best = m; best_score = sc; }
        apply_mask(&g, m);
    }
    apply_mask(&g, best);
    draw_format(&g, best);
    return s;
}
