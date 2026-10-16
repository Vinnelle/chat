// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// PNG: every colour type and bit depth, interlaced or not.
#include "common/image/decode.h"
#include <stdlib.h>
#include <string.h>

// A chunk is the length of its data, its type, the data, then a CRC of the type and data. The fields
// around the data are 4 bytes each.
#define CHUNK_FIELD 4
#define CHUNK_HEAD (2 * CHUNK_FIELD)
#define CHUNK_OVERHEAD (3 * CHUNK_FIELD)
#define CHUNK_MAX 0x7FFFFFFFu
// A decoder that doesn't know a chunk can skip it if this bit of its type's first letter is set.
#define CHUNK_ANCILLARY 0x20
#define PALETTE_MAX 256
#define ALPHA_OPAQUE 255

enum { IHDR_WIDTH = 0, IHDR_HEIGHT = 4, IHDR_DEPTH = 8, IHDR_CTYPE, IHDR_COMPRESSION, IHDR_FILTER, IHDR_INTERLACE, IHDR_LEN };
enum { PNG_GREY = 0, PNG_RGB = 2, PNG_PALETTE = 3, PNG_GREY_ALPHA = 4, PNG_RGBA = 6 };
enum { FILTER_NONE, FILTER_SUB, FILTER_UP, FILTER_AVERAGE, FILTER_PAETH };
enum { IDAT_NONE, IDAT_IN_RUN, IDAT_RUN_OVER };

static int is_chunk(const uint8_t *type, const char *name) { return memcmp(type, name, CHUNK_FIELD) == 0; }

#define CRC32_POLY 0xEDB88320u

static uint32_t crc32_of(const uint8_t *p, size_t n) {
    static uint32_t table[256];
    static int ready;
    if (!ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = c & 1 ? CRC32_POLY ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        ready = 1;
    }
    uint32_t c = UINT32_MAX;
    for (size_t i = 0; i < n; i++) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ UINT32_MAX;
}

#define ADAM7_PASSES 7
static const int A7_X0[ADAM7_PASSES] = { 0, 4, 0, 2, 0, 1, 0 }, A7_Y0[ADAM7_PASSES] = { 0, 0, 4, 0, 2, 0, 1 };
static const int A7_DX[ADAM7_PASSES] = { 8, 8, 4, 4, 2, 2, 1 }, A7_DY[ADAM7_PASSES] = { 8, 8, 8, 4, 4, 2, 2 };

typedef struct {
    uint32_t w, h;
    int depth, ctype, interlace;
    int channels;
    uint8_t pal[PALETTE_MAX][4];
    int npal;
    int has_key;
    uint16_t key[3];
} png_info_t;

// How many of a side of n an Adam7 pass has, starting at start and stepping by step.
static uint32_t pass_len(uint32_t n, int start, int step) {
    return n > (uint32_t)start ? (n - (uint32_t)start + (uint32_t)step - 1) / (uint32_t)step : 0;
}

// The size of pass ps: the whole image if it isn't interlaced.
static void pass_size(const png_info_t *pi, int ps, uint32_t *pw, uint32_t *ph) {
    *pw = pi->interlace ? pass_len(pi->w, A7_X0[ps], A7_DX[ps]) : pi->w;
    *ph = pi->interlace ? pass_len(pi->h, A7_Y0[ps], A7_DY[ps]) : pi->h;
}

static uint64_t row_bytes(uint32_t pw, size_t bits_px) { return ((uint64_t)pw * bits_px + 7) / 8; }

static int paeth(int a, int b, int c) {
    int p = a + b - c, pa = abs(p - a), pb = abs(p - b), pc = abs(p - c);
    return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

// The sample at index i of a row, at the row's bit depth (16-bit kept whole).
static unsigned sample(const uint8_t *row, size_t i, int depth) {
    if (depth == 8) return row[i];
    if (depth == 16) return load_be16(row + 2 * i);
    size_t bit = i * (size_t)depth;
    return (row[bit / 8] >> (8 - depth - (int)(bit % 8))) & ((1u << depth) - 1);
}

static int to8(unsigned v, int depth) {
    if (depth == 16) return (int)(v >> 8);
    if (depth == 8) return (int)v;
    return (int)(v * UINT8_MAX / ((1u << depth) - 1));
}

static int blend(int v, int bg, int alpha) {
    return (v * alpha + bg * (ALPHA_OPAQUE - alpha) + ALPHA_OPAQUE / 2) / ALPHA_OPAQUE;
}

static void put_pixel(thumb_acc_t *a, const png_info_t *pi, const uint8_t *row, size_t x, int ox, int oy, const uint8_t bg[3]) {
    int d = pi->depth, r, g, b, alpha = ALPHA_OPAQUE;
    size_t c = (size_t)pi->channels;
    switch (pi->ctype) {
        case PNG_GREY: {
            unsigned v = sample(row, x, d);
            r = g = b = to8(v, d);
            if (pi->has_key && v == pi->key[0]) alpha = 0;
            break;
        }
        case PNG_RGB: {
            unsigned vr = sample(row, x * 3, d), vg = sample(row, x * 3 + 1, d), vb = sample(row, x * 3 + 2, d);
            r = to8(vr, d); g = to8(vg, d); b = to8(vb, d);
            if (pi->has_key && vr == pi->key[0] && vg == pi->key[1] && vb == pi->key[2]) alpha = 0;
            break;
        }
        case PNG_PALETTE: {
            unsigned idx = sample(row, x, d);
            // An index past the end of the palette means damage. It's shown as black and never read past.
            if ((int)idx >= pi->npal) { r = g = b = 0; break; }
            r = pi->pal[idx][0]; g = pi->pal[idx][1]; b = pi->pal[idx][2]; alpha = pi->pal[idx][3];
            break;
        }
        case PNG_GREY_ALPHA:
            r = g = b = to8(sample(row, x * c, d), d);
            alpha = to8(sample(row, x * c + 1, d), d);
            break;
        default:
            r = to8(sample(row, x * c, d), d);
            g = to8(sample(row, x * c + 1, d), d);
            b = to8(sample(row, x * c + 2, d), d);
            alpha = to8(sample(row, x * c + 3, d), d);
            break;
    }
    if (alpha < ALPHA_OPAQUE) {
        r = blend(r, bg[0], alpha);
        g = blend(g, bg[1], alpha);
        b = blend(b, bg[2], alpha);
    }
    acc_add(a, ox, oy, r, g, b);
}

int png_thumb(const uint8_t *p, size_t len, int max_w, int max_h, const uint8_t bg[3], image_thumb_t *out,
                     char *why, size_t cap) {
    png_info_t pi;
    memset(&pi, 0, sizeof pi);
    for (int i = 0; i < PALETTE_MAX; i++) pi.pal[i][3] = ALPHA_OPAQUE;
    int have_ihdr = 0, have_plte = 0, idat_state = IDAT_NONE;
    uint64_t zlen = 0;
    size_t pos = PNG_SIGNATURE_LEN;
    int ended = 0;
    while (!ended) {
        if (len - pos < CHUNK_OVERHEAD) return fail(why, cap, "the PNG is cut short");
        uint32_t clen = load_be32(p + pos);
        if (clen > CHUNK_MAX || clen > len - pos - CHUNK_OVERHEAD) return fail(why, cap, "the PNG is cut short");
        const uint8_t *type = p + pos + CHUNK_FIELD, *d = p + pos + CHUNK_HEAD;
        if (CHECK_SUMS && crc32_of(type, (size_t)clen + CHUNK_FIELD) != load_be32(d + clen)) return fail(why, cap, "the PNG is damaged (a checksum is wrong)");
        if (!have_ihdr && !is_chunk(type, "IHDR")) return fail(why, cap, "the PNG doesn't start with its header");
        if (is_chunk(type, "IHDR")) {
            if (have_ihdr || clen != IHDR_LEN) return fail(why, cap, "the PNG's header is wrong");
            pi.w = load_be32(d + IHDR_WIDTH);
            pi.h = load_be32(d + IHDR_HEIGHT);
            pi.depth = d[IHDR_DEPTH];
            pi.ctype = d[IHDR_CTYPE];
            pi.interlace = d[IHDR_INTERLACE];
            int ok_depth;
            switch (pi.ctype) {
                case PNG_GREY: pi.channels = 1; ok_depth = pi.depth == 1 || pi.depth == 2 || pi.depth == 4 || pi.depth == 8 || pi.depth == 16; break;
                case PNG_RGB: pi.channels = 3; ok_depth = pi.depth == 8 || pi.depth == 16; break;
                case PNG_PALETTE: pi.channels = 1; ok_depth = pi.depth == 1 || pi.depth == 2 || pi.depth == 4 || pi.depth == 8; break;
                case PNG_GREY_ALPHA: pi.channels = 2; ok_depth = pi.depth == 8 || pi.depth == 16; break;
                case PNG_RGBA: pi.channels = 4; ok_depth = pi.depth == 8 || pi.depth == 16; break;
                default: ok_depth = 0; break;
            }
            if (!ok_depth || d[IHDR_COMPRESSION] != 0 || d[IHDR_FILTER] != 0 || pi.interlace > 1) return fail(why, cap, "the PNG's header is wrong");
            if (!sides_ok(pi.w, pi.h)) return fail(why, cap, "the image is too big to show");
            have_ihdr = 1;
        } else if (is_chunk(type, "PLTE")) {
            if (have_plte || idat_state != IDAT_NONE || clen % 3 != 0 || clen == 0 || clen > PALETTE_MAX * 3) return fail(why, cap, "the PNG's palette is wrong");
            pi.npal = (int)(clen / 3);
            for (int i = 0; i < pi.npal; i++) { pi.pal[i][0] = d[i * 3]; pi.pal[i][1] = d[i * 3 + 1]; pi.pal[i][2] = d[i * 3 + 2]; }
            have_plte = 1;
        } else if (is_chunk(type, "tRNS")) {
            if (idat_state != IDAT_NONE) return fail(why, cap, "the PNG's transparency comes too late");
            if (pi.ctype == PNG_PALETTE) {
                if (!have_plte || (int)clen > pi.npal) return fail(why, cap, "the PNG's transparency is wrong");
                for (uint32_t i = 0; i < clen; i++) pi.pal[i][3] = d[i];
            } else if (pi.ctype == PNG_GREY && clen == 2) {
                pi.has_key = 1;
                pi.key[0] = load_be16(d);
            } else if (pi.ctype == PNG_RGB && clen == 6) {
                pi.has_key = 1;
                for (int i = 0; i < 3; i++) pi.key[i] = load_be16(d + i * 2);
            } else {
                return fail(why, cap, "the PNG's transparency is wrong");
            }
        } else if (is_chunk(type, "IDAT")) {
            if (idat_state == IDAT_RUN_OVER) return fail(why, cap, "the PNG's image data is split up");
            if (pi.ctype == PNG_PALETTE && !have_plte) return fail(why, cap, "the PNG has no palette");
            idat_state = IDAT_IN_RUN;
            zlen += clen;
        } else if (is_chunk(type, "IEND")) {
            ended = 1;
        } else {
            if (!(type[0] & CHUNK_ANCILLARY)) return fail(why, cap, "the PNG has a part chat doesn't know how to read");
        }
        if (idat_state == IDAT_IN_RUN && !is_chunk(type, "IDAT")) idat_state = IDAT_RUN_OVER;
        pos += (size_t)clen + CHUNK_OVERHEAD;
    }
    if (idat_state == IDAT_NONE || zlen == 0) return fail(why, cap, "the PNG has no image data");

    // How much the image inflates to: each row of each pass, with its filter byte.
    size_t bits_px = (size_t)pi.depth * (size_t)pi.channels;
    uint64_t raw_len = 0;
    int passes = pi.interlace ? ADAM7_PASSES : 1;
    for (int ps = 0; ps < passes; ps++) {
        uint32_t pw, ph;
        pass_size(&pi, ps, &pw, &ph);
        if (pw && ph) raw_len += ph * (1 + row_bytes(pw, bits_px));
    }
    if (raw_len > IMAGE_MAX_RAW) return fail(why, cap, "the image is too big to show");

    uint8_t *z = malloc((size_t)zlen), *raw = malloc((size_t)raw_len);
    thumb_acc_t acc;
    if (!z || !raw || acc_init(&acc, (int)pi.w, (int)pi.h, max_w, max_h) != 0) {
        free(z); free(raw);
        return fail(why, cap, "out of memory");
    }
    size_t zo = 0;
    for (pos = PNG_SIGNATURE_LEN; pos + CHUNK_OVERHEAD <= len; ) {
        uint32_t clen = load_be32(p + pos);
        const uint8_t *type = p + pos + CHUNK_FIELD;
        if (is_chunk(type, "IDAT")) { memcpy(z + zo, p + pos + CHUNK_HEAD, clen); zo += clen; }
        if (is_chunk(type, "IEND")) break;
        pos += (size_t)clen + CHUNK_OVERHEAD;
    }
    int rc = zlib_inflate(z, (size_t)zlen, raw, (size_t)raw_len);
    free(z);
    if (rc != 0) { free(raw); acc_free(&acc); return fail(why, cap, "the PNG's image data is damaged"); }

    size_t bpp = bits_px >= 8 ? bits_px / 8 : 1;
    uint8_t *r = raw;
    for (int ps = 0; ps < passes; ps++) {
        uint32_t pw, ph;
        pass_size(&pi, ps, &pw, &ph);
        if (!pw || !ph) continue;
        size_t rowbytes = (size_t)row_bytes(pw, bits_px);
        uint8_t *prev = NULL;
        for (size_t y = 0; y < ph; y++) {
            int f = r[0];
            uint8_t *cur = r + 1;
            if (f > FILTER_PAETH) { free(raw); acc_free(&acc); return fail(why, cap, "the PNG's image data is damaged"); }
            for (size_t i = 0; i < rowbytes; i++) {
                int a = i >= bpp ? cur[i - bpp] : 0, b = prev ? prev[i] : 0, c = prev && i >= bpp ? prev[i - bpp] : 0;
                int v = cur[i];
                switch (f) {
                    case FILTER_SUB: v += a; break;
                    case FILTER_UP: v += b; break;
                    case FILTER_AVERAGE: v += (a + b) / 2; break;
                    case FILTER_PAETH: v += paeth(a, b, c); break;
                    default: break;
                }
                cur[i] = (uint8_t)v;
            }
            int oy = pi.interlace ? A7_Y0[ps] + (int)y * A7_DY[ps] : (int)y;
            for (size_t x = 0; x < pw; x++) {
                int ox = pi.interlace ? A7_X0[ps] + (int)x * A7_DX[ps] : (int)x;
                put_pixel(&acc, &pi, cur, x, ox, oy, bg);
            }
            prev = cur;
            r += 1 + rowbytes;
        }
    }
    free(raw);
    if (acc_finish(&acc, (int)pi.w, (int)pi.h, out) != 0) return fail(why, cap, "out of memory");
    return 0;
}
