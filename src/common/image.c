// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "common/image.h"
#include "common/util.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// A fuzzer's mutations would almost never get past the zlib and PNG checksums, so a fuzzing build
// doesn't check them.
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define CHECK_SUMS 0
#else
#define CHECK_SUMS 1
#endif

static int fail(char *why, size_t cap, const char *msg) {
    if (why && cap) copy_str(why, msg, cap);
    return -1;
}

#define PNG_SIGNATURE "\x89PNG\r\n\x1a\n"
#define PNG_SIGNATURE_LEN (sizeof PNG_SIGNATURE - 1)

static int le16(const uint8_t *p) { return p[0] | (p[1] << 8); }

const char *image_kind(const uint8_t *data, size_t len) {
    static const struct { const char *signature, *kind; } KINDS[] = {
        { PNG_SIGNATURE, "png" }, { "\xff\xd8\xff", "jpeg" }, { "GIF87a", "gif" }, { "GIF89a", "gif" },
    };
    for (size_t i = 0; i < COUNT_OF(KINDS); i++) {
        size_t n = strlen(KINDS[i].signature);
        if (len >= n && memcmp(data, KINDS[i].signature, n) == 0) return KINDS[i].kind;
    }
    return NULL;
}

void image_thumb_free(image_thumb_t *t) {
    if (!t) return;
    free(t->rgb);
    memset(t, 0, sizeof *t);
}

// ---- the thumbnail: each source pixel is added to the average for the pixel it falls in ----

enum { ACC_R, ACC_G, ACC_B, ACC_COUNT, ACC_FIELDS };

typedef struct {
    int sw, sh, tw, th;
    uint64_t *acc;   // tw * th * ACC_FIELDS: red, green, blue, and how many
    int *col, *row;  // the thumbnail column each source column falls in, and the row each row does
} thumb_acc_t;

// As wide as allowed (never wider than the source), then scaled down to fit if that's too tall.
static void fit(int sw, int sh, int max_w, int max_h, int *tw_out, int *th_out) {
    int tw = sw < max_w ? sw : max_w;
    int th = (int)(((int64_t)sh * tw + sw / 2) / sw);
    if (th < 1) th = 1;
    if (th > max_h) {
        th = sh < max_h ? sh : max_h;
        tw = (int)(((int64_t)sw * th + sh / 2) / sh);
        if (tw < 1) tw = 1;
        if (tw > max_w) tw = max_w;
    }
    *tw_out = tw;
    *th_out = th;
}

static void acc_free(thumb_acc_t *a) {
    free(a->acc);
    free(a->col);
    a->acc = NULL;
    a->col = a->row = NULL;
}

static int acc_init(thumb_acc_t *a, int sw, int sh, int max_w, int max_h) {
    memset(a, 0, sizeof *a);
    if (sw < 1 || sh < 1 || max_w < 1 || max_h < 1) return -1;
    a->sw = sw;
    a->sh = sh;
    fit(sw, sh, max_w, max_h, &a->tw, &a->th);
    a->acc = calloc((size_t)a->tw * (size_t)a->th * ACC_FIELDS, sizeof *a->acc);
    // Worked out once here, rather than with two divisions for every source pixel.
    a->col = malloc(((size_t)sw + (size_t)sh) * sizeof *a->col);
    if (!a->acc || !a->col) { acc_free(a); return -1; }
    a->row = a->col + sw;
    for (int x = 0; x < sw; x++) a->col[x] = (int)((int64_t)x * a->tw / sw);
    for (int y = 0; y < sh; y++) a->row[y] = (int)((int64_t)y * a->th / sh);
    return 0;
}

static uint64_t *acc_cell(const thumb_acc_t *a, int tx, int ty) {
    return a->acc + ((size_t)ty * (size_t)a->tw + (size_t)tx) * ACC_FIELDS;
}

static inline void acc_add(thumb_acc_t *a, int x, int y, int r, int g, int b) {
    if (x < 0 || y < 0 || x >= a->sw || y >= a->sh) return;
    uint64_t *c = acc_cell(a, a->col[x], a->row[y]);
    c[ACC_R] += (uint64_t)r;
    c[ACC_G] += (uint64_t)g;
    c[ACC_B] += (uint64_t)b;
    c[ACC_COUNT]++;
}

// A rectangle of one colour, x0 to x1 by y0 to y1 (not including x1 and y1), added a thumbnail pixel
// at a time rather than a source pixel at a time, so a GIF claiming a huge screen around a small
// frame costs no more than the thumbnail.
static void acc_fill(thumb_acc_t *a, int x0, int y0, int x1, int y1, const uint8_t rgb[3]) {
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > a->sw) x1 = a->sw;
    if (y1 > a->sh) y1 = a->sh;
    if (x0 >= x1 || y0 >= y1) return;
    for (int ty = 0; ty < a->th; ty++) {
        // The source rows that fall in thumbnail row ty are lo to hi, as acc_add maps them.
        int64_t lo = ((int64_t)ty * a->sh + a->th - 1) / a->th, hi = ((int64_t)(ty + 1) * a->sh + a->th - 1) / a->th;
        int64_t ny = (hi < y1 ? hi : y1) - (lo > y0 ? lo : y0);
        if (ny <= 0) continue;
        for (int tx = 0; tx < a->tw; tx++) {
            int64_t xl = ((int64_t)tx * a->sw + a->tw - 1) / a->tw, xh = ((int64_t)(tx + 1) * a->sw + a->tw - 1) / a->tw;
            int64_t nx = (xh < x1 ? xh : x1) - (xl > x0 ? xl : x0);
            if (nx <= 0) continue;
            uint64_t n = (uint64_t)nx * (uint64_t)ny, *c = acc_cell(a, tx, ty);
            c[ACC_R] += rgb[0] * n;
            c[ACC_G] += rgb[1] * n;
            c[ACC_B] += rgb[2] * n;
            c[ACC_COUNT] += n;
        }
    }
}

static int acc_finish(thumb_acc_t *a, int src_w, int src_h, image_thumb_t *out) {
    size_t n = (size_t)a->tw * (size_t)a->th;
    uint8_t *rgb = malloc(n * 3);
    if (!rgb) { acc_free(a); return -1; }
    for (size_t i = 0; i < n; i++) {
        const uint64_t *c = a->acc + i * ACC_FIELDS;
        for (int k = ACC_R; k <= ACC_B; k++) rgb[i * 3 + (size_t)k] = c[ACC_COUNT] ? (uint8_t)((c[k] + c[ACC_COUNT] / 2) / c[ACC_COUNT]) : 0;
    }
    acc_free(a);
    out->w = a->tw;
    out->h = a->th;
    out->src_w = src_w;
    out->src_h = src_h;
    out->rgb = rgb;
    return 0;
}

static int sides_ok(uint32_t w, uint32_t h) {
    return w >= 1 && h >= 1 && w <= IMAGE_MAX_SIDE && h <= IMAGE_MAX_SIDE && (uint64_t)w * h <= IMAGE_MAX_PIXELS;
}

// ---- inflate (RFC 1950 and 1951), into a buffer of exactly the size expected ----

#define MAXBITS 15
// The literal/length codes a dynamic block may have, the fixed code's (two of them never used), the
// distance codes, and the codes for code lengths.
enum { MAX_LCODES = 286, FIXED_LCODES = 288, MAX_DCODES = 30, CL_CODES = 19 };
enum { END_OF_BLOCK = 256, FIRST_LENGTH = 257 };
// The code length codes that repeat the last length, and that repeat a zero.
enum { CL_COPY = 16, CL_ZEROS = 17 };
enum { BLOCK_STORED, BLOCK_FIXED, BLOCK_DYNAMIC };

typedef struct {
    const uint8_t *in;
    size_t inlen, inpos;
    uint32_t bitbuf;
    int bitcnt;
    uint8_t *out;
    size_t outlen, outpos;
    int err;
} inflate_t;

typedef struct {
    short count[MAXBITS + 1];
    short symbol[FIXED_LCODES];
} huff_t;

static int bits(inflate_t *s, int need) {
    uint32_t val = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->inpos >= s->inlen) { s->err = 1; return 0; }
        val |= (uint32_t)s->in[s->inpos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = val >> need;
    s->bitcnt -= need;
    return (int)(val & ((1u << need) - 1));
}

// Canonical Huffman code from code lengths: 0 complete, above 0 incomplete, below 0 impossible.
static int construct(huff_t *h, const short *length, int n) {
    short offs[MAXBITS + 1];
    for (int len = 0; len <= MAXBITS; len++) h->count[len] = 0;
    for (int i = 0; i < n; i++) h->count[length[i]]++;
    if (h->count[0] == n) return 0;
    int left = 1;
    for (int len = 1; len <= MAXBITS; len++) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0) return left;
    }
    offs[1] = 0;
    for (int len = 1; len < MAXBITS; len++) offs[len + 1] = (short)(offs[len] + h->count[len]);
    for (int i = 0; i < n; i++) if (length[i] != 0) h->symbol[offs[length[i]]++] = (short)i;
    return left;
}

static int decode(inflate_t *s, const huff_t *h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= MAXBITS; len++) {
        code |= bits(s, 1);
        if (s->err) return -1;
        int count = h->count[len];
        if (code - count < first) return h->symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

static int stored(inflate_t *s) {
    s->bitbuf = 0;
    s->bitcnt = 0;
    if (s->inlen - s->inpos < 4) return -1;
    unsigned len = (unsigned)le16(s->in + s->inpos), nlen = (unsigned)le16(s->in + s->inpos + 2);
    s->inpos += 4;
    if (len != (~nlen & 0xffffu)) return -1;
    if (len > s->inlen - s->inpos || len > s->outlen - s->outpos) return -1;
    memcpy(s->out + s->outpos, s->in + s->inpos, len);
    s->inpos += len;
    s->outpos += len;
    return 0;
}

static int codes(inflate_t *s, const huff_t *lencode, const huff_t *distcode) {
    static const short lbase[MAX_LCODES - FIRST_LENGTH] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                                            35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
    static const short lext[MAX_LCODES - FIRST_LENGTH] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
                                                           4, 4, 4, 4, 5, 5, 5, 5, 0 };
    static const short dbase[MAX_DCODES] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
                                             1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
    static const short dext[MAX_DCODES] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
                                            11, 11, 12, 12, 13, 13 };
    for (;;) {
        int symbol = decode(s, lencode);
        if (symbol < 0) return -1;
        if (symbol < END_OF_BLOCK) {
            if (s->outpos >= s->outlen) return -1;
            s->out[s->outpos++] = (uint8_t)symbol;
        } else if (symbol == END_OF_BLOCK) {
            return 0;
        } else {
            symbol -= FIRST_LENGTH;
            if (symbol >= MAX_LCODES - FIRST_LENGTH) return -1;
            size_t len = (size_t)lbase[symbol] + (size_t)bits(s, lext[symbol]);
            int ds = decode(s, distcode);
            if (ds < 0 || ds >= MAX_DCODES) return -1;
            size_t dist = (size_t)dbase[ds] + (size_t)bits(s, dext[ds]);
            if (s->err || dist > s->outpos || len > s->outlen - s->outpos) return -1;
            for (size_t i = 0; i < len; i++, s->outpos++) s->out[s->outpos] = s->out[s->outpos - dist];
        }
    }
}

static int fixed(inflate_t *s) {
    static huff_t lencode, distcode;
    static int built;
    if (!built) {
        // As RFC 1951 3.2.6 gives them.
        short lengths[FIXED_LCODES];
        int i = 0;
        for (; i < 144; i++) lengths[i] = 8;
        for (; i < 256; i++) lengths[i] = 9;
        for (; i < 280; i++) lengths[i] = 7;
        for (; i < FIXED_LCODES; i++) lengths[i] = 8;
        construct(&lencode, lengths, FIXED_LCODES);
        for (i = 0; i < MAX_DCODES; i++) lengths[i] = 5;
        construct(&distcode, lengths, MAX_DCODES);
        built = 1;
    }
    return codes(s, &lencode, &distcode);
}

static int dynamic(inflate_t *s) {
    static const short order[CL_CODES] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    short lengths[MAX_LCODES + MAX_DCODES];
    huff_t lencode, distcode;
    int nlen = bits(s, 5) + FIRST_LENGTH, ndist = bits(s, 5) + 1, ncode = bits(s, 4) + 4;
    if (s->err || nlen > MAX_LCODES || ndist > MAX_DCODES) return -1;
    int index;
    for (index = 0; index < ncode; index++) lengths[order[index]] = (short)bits(s, 3);
    for (; index < CL_CODES; index++) lengths[order[index]] = 0;
    if (s->err || construct(&lencode, lengths, CL_CODES) != 0) return -1;
    index = 0;
    while (index < nlen + ndist) {
        int symbol = decode(s, &lencode);
        if (symbol < 0) return -1;
        if (symbol < CL_COPY) {
            lengths[index++] = (short)symbol;
            continue;
        }
        short len = 0;
        if (symbol == CL_COPY) {
            if (index == 0) return -1;
            len = lengths[index - 1];
            symbol = 3 + bits(s, 2);
        } else if (symbol == CL_ZEROS) {
            symbol = 3 + bits(s, 3);
        } else {
            symbol = 11 + bits(s, 7);
        }
        if (s->err || index + symbol > nlen + ndist) return -1;
        while (symbol--) lengths[index++] = len;
    }
    if (lengths[END_OF_BLOCK] == 0) return -1;
    int err = construct(&lencode, lengths, nlen);
    if (err < 0 || (err > 0 && nlen - lencode.count[0] != 1)) return -1;
    err = construct(&distcode, lengths + nlen, ndist);
    if (err < 0 || (err > 0 && ndist - distcode.count[0] != 1)) return -1;
    return codes(s, &lencode, &distcode);
}

// The most bytes added up before b could pass 32 bits, and the largest prime below 65536.
#define ADLER_NMAX 5552
#define ADLER_MOD 65521

static uint32_t adler32(const uint8_t *p, size_t n) {
    uint32_t a = 1, b = 0;
    while (n > 0) {
        size_t k = n < ADLER_NMAX ? n : ADLER_NMAX;
        n -= k;
        while (k--) { a += *p++; b += a; }
        a %= ADLER_MOD;
        b %= ADLER_MOD;
    }
    return (b << 16) | a;
}

// A zlib stream: a 2-byte header, the deflated data, then the Adler-32 of what it inflates to.
enum { ZLIB_HEAD = 2, ZLIB_TRAILER = 4, ZLIB_DEFLATE = 8, ZLIB_MAX_WINDOW = 7, ZLIB_CHECK = 31, ZLIB_FDICT = 0x20 };

// A zlib stream that inflates to exactly outlen bytes. Anything more or less means it's damaged.
static int zlib_inflate(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    if (inlen < ZLIB_HEAD + ZLIB_TRAILER) return -1;
    unsigned cmf = in[0], flg = in[1];
    if ((cmf & 15) != ZLIB_DEFLATE || (cmf >> 4) > ZLIB_MAX_WINDOW || load_be16(in) % ZLIB_CHECK != 0 || (flg & ZLIB_FDICT))
        return -1;
    inflate_t s = { in, inlen, ZLIB_HEAD, 0, 0, out, outlen, 0, 0 };
    int last;
    do {
        last = bits(&s, 1);
        int type = bits(&s, 2);
        if (s.err) return -1;
        int rc = type == BLOCK_STORED ? stored(&s) : type == BLOCK_FIXED ? fixed(&s) : type == BLOCK_DYNAMIC ? dynamic(&s) : -1;
        if (rc != 0 || s.err) return -1;
    } while (!last);
    if (s.outpos != outlen || s.inlen - s.inpos < ZLIB_TRAILER) return -1;
    return !CHECK_SUMS || adler32(out, outlen) == load_be32(in + s.inpos) ? 0 : -1;
}

// ---- PNG ----

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

static int png_thumb(const uint8_t *p, size_t len, int max_w, int max_h, const uint8_t bg[3], image_thumb_t *out,
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

// ---- baseline JPEG ----

// A marker is FF and then which one it is.
#define MARKER 0xFF
#define MARKER_LEN 2
enum {
    M_TEM = 0x01, M_SOF0 = 0xC0, M_SOF2 = 0xC2, M_SOF3 = 0xC3, M_DHT = 0xC4, M_JPG = 0xC8, M_DAC = 0xCC,
    M_SOF15 = 0xCF, M_RST0 = 0xD0, M_RST7 = 0xD7, M_SOI = 0xD8, M_EOI = 0xD9, M_SOS = 0xDA, M_DQT = 0xDB,
    M_DRI = 0xDD, M_APP14 = 0xEE,
};

#define BLOCK_SIDE 8
#define COEFS (BLOCK_SIDE * BLOCK_SIDE)
#define LAST_COEF (COEFS - 1)
#define MAX_COMPS 3
#define TABLE_IDS 4                   // of each kind of table
#define MAX_CODE_BITS 16
#define DHT_HEAD (1 + MAX_CODE_BITS)  // a table's class and id, then how many codes of each length
#define DC_MAX_BITS 11
#define ZRL 15                        // the run that, with a size of 0, skips sixteen zeros
#define MAX_SAMPLING 4
#define MAX_APPROX_BIT 13
#define SAMPLE_MID 128
#define SOF_HEAD 6                    // the precision, height, width and number of components
#define ADOBE_TRANSFORM 11            // where APP14 has the colour transform
#define MAX_OVERRUN 64
#define MAX_SCANS 500
#define MAX_MCU_BLOCKS 10
#define DC_ONLY_PIXELS 4000000
#define PI 3.14159265358979323846

typedef struct {
    uint8_t bits[MAX_CODE_BITS + 1];   // how many codes of each length
    uint8_t vals[256];
    int nvals;
    int32_t mincode[MAX_CODE_BITS + 1], maxcode[MAX_CODE_BITS + 1], valptr[MAX_CODE_BITS + 1];
    int set;
} jhuff_t;

typedef struct {
    int id, h, v, tq;
    int td, ta;             // this scan's tables
    int dc_pred;
    int bw, bh;             // its blocks across and down, padded to whole MCUs
    uint8_t *plane;         // bw * 8 by bh * 8 samples, or one per block with dc_only
    int stride;
    int16_t *coef;          // progressive: 64 a block (1 with dc_only), refined scan by scan
} jcomp_t;

typedef struct {
    const uint8_t *p;
    size_t len, pos;
    uint32_t bitbuf;
    int bitcnt;
    int marker_hit;         // a marker turned up where entropy-coded data was; zeros from here
    int overrun;            // bits read past that, in bytes: a little is normal, a lot means damage
    uint16_t qt[TABLE_IDS][COEFS];
    int qt_set[TABLE_IDS];
    jhuff_t dc[TABLE_IDS], ac[TABLE_IDS];
    int w, h, ncomp, hmax, vmax, mcux, mcuy;
    jcomp_t comp[MAX_COMPS];
    int restart;
    int dc_only;            // an eighth of the size: each block's DC alone
    int adobe_transform;    // -1 none seen
    int progressive;
    int ss, se, ah, al;     // the scan's band of coefficients, and which of their bits
    int eobrun;             // progressive: blocks left with nothing more in this band
} jpeg_t;

static const uint8_t ZIGZAG[COEFS] = {
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63
};

static int jhuff_build(jhuff_t *t) {
    int code = 0, k = 0;
    for (int l = 1; l <= MAX_CODE_BITS; l++) {
        t->valptr[l] = k;
        t->mincode[l] = code;
        code += t->bits[l];
        k += t->bits[l];
        t->maxcode[l] = t->bits[l] ? code - 1 : -1;
        // A code longer than the maximum length isn't valid.
        if (code > (1 << l)) return -1;
        code <<= 1;
    }
    t->set = 1;
    return 0;
}

static int jbit(jpeg_t *j) {
    if (j->bitcnt == 0) {
        int byte = 0;
        if (!j->marker_hit && j->pos < j->len) {
            byte = j->p[j->pos];
            if (byte == MARKER) {
                int next = j->pos + 1 < j->len ? j->p[j->pos + 1] : -1;
                if (next == 0x00) { j->pos += 2; }
                else { j->marker_hit = 1; byte = 0; j->overrun++; }
            } else {
                j->pos++;
            }
        } else {
            j->overrun++;
        }
        j->bitbuf = (uint32_t)byte;
        j->bitcnt = 8;
    }
    j->bitcnt--;
    return (int)((j->bitbuf >> j->bitcnt) & 1);
}

static int jbits(jpeg_t *j, int n) {
    int v = 0;
    for (int i = 0; i < n; i++) v = (v << 1) | jbit(j);
    return v;
}

static int jdecode(jpeg_t *j, const jhuff_t *t) {
    int code = 0;
    for (int l = 1; l <= MAX_CODE_BITS; l++) {
        code = (code << 1) | jbit(j);
        if (t->maxcode[l] >= 0 && code <= t->maxcode[l]) {
            int k = t->valptr[l] + code - t->mincode[l];
            return k >= 0 && k < t->nvals ? t->vals[k] : -1;
        }
    }
    return -1;
}

static int extend(int v, int s) { return s == 0 ? 0 : v < (1 << (s - 1)) ? v - (1 << s) + 1 : v; }

// A real image's DC never leaves 16 bits. Held there, it can't overflow once it's scaled by a 16-bit
// table or shifted for a progressive scan, however many differences a damaged one adds up.
static void dc_add(jcomp_t *c, int diff) {
    int v = c->dc_pred + diff;
    c->dc_pred = v < INT16_MIN ? INT16_MIN : v > INT16_MAX ? INT16_MAX : v;
}

// The next DC difference, added to comp's prediction.
static int read_dc(jpeg_t *j, jcomp_t *c) {
    int s = jdecode(j, &j->dc[c->td]);
    if (s < 0 || s > DC_MAX_BITS) return -1;
    dc_add(c, extend(jbits(j, s), s));
    return 0;
}

static uint8_t clamp8(int v) { return (uint8_t)(v < 0 ? 0 : v > UINT8_MAX ? UINT8_MAX : v); }

// A block's average sample, from its DC alone: the inverse DCT scales a DC by an eighth.
static uint8_t dc_sample(int dc) { return clamp8(dc / BLOCK_SIDE + SAMPLE_MID); }

// Where block (bx, by) of comp starts in its plane.
static uint8_t *block_at(const jpeg_t *j, const jcomp_t *c, int bx, int by) {
    size_t side = j->dc_only ? 1 : BLOCK_SIDE;
    return c->plane + (size_t)by * side * (size_t)c->stride + (size_t)bx * side;
}

static size_t block_coefs(const jpeg_t *j) { return j->dc_only ? 1 : COEFS; }

static int16_t *coefs_at(const jpeg_t *j, const jcomp_t *c, int bx, int by) {
    return c->coef + ((size_t)by * (size_t)c->bw + (size_t)bx) * block_coefs(j);
}

static void idct8x8(const int *in, uint8_t *out, int stride) {
    static float c[8][8];
    static int ready;
    if (!ready) {
        for (int u = 0; u < 8; u++)
            for (int x = 0; x < 8; x++)
                c[u][x] = (float)((u == 0 ? sqrt(0.5) : 1.0) * cos((2 * x + 1) * u * PI / 16.0) / 2.0);
        ready = 1;
    }
    float tmp[64];
    for (int y = 0; y < 8; y++)
        for (int x = 0; x < 8; x++) {
            float s = 0;
            for (int u = 0; u < 8; u++) s += c[u][x] * (float)in[y * 8 + u];
            tmp[y * 8 + x] = s;
        }
    for (int x = 0; x < 8; x++)
        for (int y = 0; y < 8; y++) {
            float s = 0;
            for (int v = 0; v < 8; v++) s += c[v][y] * tmp[v * 8 + x];
            out[y * stride + x] = clamp8((int)lrintf(s) + SAMPLE_MID);
        }
}

// One block of comp at block (bx, by) of its plane.
static int decode_block(jpeg_t *j, jcomp_t *c, int bx, int by) {
    int coef[COEFS] = { 0 };
    const jhuff_t *ac = &j->ac[c->ta];
    if (read_dc(j, c) != 0) return -1;
    const uint16_t *q = j->qt[c->tq];
    coef[0] = c->dc_pred * q[0];
    for (int k = 1; k < COEFS; ) {
        int rs = jdecode(j, ac);
        if (rs < 0) return -1;
        int r = rs >> 4, sz = rs & 15;
        if (sz == 0) { if (r != ZRL) break; k += ZRL + 1; continue; }
        k += r;
        if (k > LAST_COEF) return -1;
        // With dc_only the AC coefficients are only read to skip over them.
        int v = jbits(j, sz);
        if (!j->dc_only) coef[ZIGZAG[k]] = extend(v, sz) * q[k];
        k++;
    }
    if (bx >= c->bw || by >= c->bh) return 0;
    if (j->dc_only) *block_at(j, c, bx, by) = dc_sample(coef[0]);
    else idct8x8(coef, block_at(j, c, bx, by), c->stride);
    return 0;
}

// A coefficient that's already non-zero gets the scan's bit, away from zero.
static void refine(jpeg_t *j, int16_t *v) {
    int p1 = 1 << j->al;
    if (jbit(j) && (*v & p1) == 0) *v = (int16_t)(*v >= 0 ? *v + p1 : *v - p1);
}

// One block of a progressive scan: its DC or a band of its AC coefficients, the first bits of them or
// one more. They're kept as they come, to be scaled and turned into samples after the last scan.
static int decode_prog_block(jpeg_t *j, jcomp_t *c, int bx, int by) {
    if (bx >= c->bw || by >= c->bh) return -1;
    int16_t *b = coefs_at(j, c, bx, by);
    if (j->ss == 0) {
        if (j->ah == 0) {
            if (read_dc(j, c) != 0) return -1;
            b[0] = (int16_t)(c->dc_pred * (1 << j->al));
        } else if (jbit(j)) {
            b[0] = (int16_t)(b[0] | (1 << j->al));
        }
        return 0;
    }
    const jhuff_t *ac = &j->ac[c->ta];
    if (j->ah == 0) {
        if (j->eobrun > 0) { j->eobrun--; return 0; }
        for (int k = j->ss; k <= j->se; ) {
            int rs = jdecode(j, ac);
            if (rs < 0) return -1;
            int r = rs >> 4, s = rs & 15;
            if (s == 0) {
                if (r < ZRL) { j->eobrun = (1 << r) - 1 + (r ? jbits(j, r) : 0); break; }
                k += ZRL + 1;
                continue;
            }
            k += r;
            if (k > j->se) return -1;
            b[ZIGZAG[k]] = (int16_t)(extend(jbits(j, s), s) * (1 << j->al));
            k++;
        }
        return 0;
    }
    // A refining scan: each new coefficient is a single bit, and the ones skipped over on the way to
    // it that are already non-zero each get a bit too.
    int k = j->ss;
    if (j->eobrun == 0) {
        for (; k <= j->se; k++) {
            int rs = jdecode(j, ac);
            if (rs < 0) return -1;
            int r = rs >> 4, s = rs & 15, v = 0;
            if (s) {
                if (s != 1) return -1;
                v = jbit(j) ? 1 << j->al : -(1 << j->al);
            } else if (r < ZRL) {
                j->eobrun = (1 << r) + (r ? jbits(j, r) : 0);
                break;
            }
            for (; k <= j->se; k++) {
                int16_t *z = &b[ZIGZAG[k]];
                if (*z) refine(j, z);
                else if (r-- == 0) break;
            }
            if (v) {
                if (k > j->se) return -1;
                b[ZIGZAG[k]] = (int16_t)v;
            }
        }
    }
    if (j->eobrun > 0) {
        for (; k <= j->se; k++) if (b[ZIGZAG[k]]) refine(j, &b[ZIGZAG[k]]);
        j->eobrun--;
    }
    return 0;
}

static int scan_block(jpeg_t *j, jcomp_t *c, int bx, int by) {
    return j->progressive ? decode_prog_block(j, c, bx, by) : decode_block(j, c, bx, by);
}

static int is_rst(int m) { return m >= M_RST0 && m <= M_RST7; }

// Back to the start of a byte, past a restart marker if there is one, with the predictions reset.
static int restart_marker(jpeg_t *j) {
    j->bitcnt = 0;
    while (j->pos + 1 < j->len && !(j->p[j->pos] == MARKER && is_rst(j->p[j->pos + 1]))) {
        if (j->p[j->pos] == MARKER && j->p[j->pos + 1] != 0x00 && j->p[j->pos + 1] != MARKER) return -1;
        j->pos++;
    }
    if (j->pos + 1 >= j->len) return -1;
    j->pos += MARKER_LEN;
    j->marker_hit = 0;
    j->eobrun = 0;
    for (int i = 0; i < j->ncomp; i++) j->comp[i].dc_pred = 0;
    return 0;
}

static int decode_scan(jpeg_t *j, jcomp_t **sc, int ns) {
    j->bitcnt = 0;
    j->marker_hit = 0;
    j->eobrun = 0;
    for (int i = 0; i < ns; i++) sc[i]->dc_pred = 0;
    long count = 0;
    if (ns == 1) {
        // One component on its own: its blocks in order, as many as cover the image.
        jcomp_t *c = sc[0];
        int cw = (j->w * c->h + j->hmax - 1) / j->hmax, ch = (j->h * c->v + j->vmax - 1) / j->vmax;
        int bw = (cw + BLOCK_SIDE - 1) / BLOCK_SIDE, bh = (ch + BLOCK_SIDE - 1) / BLOCK_SIDE;
        for (int by = 0; by < bh; by++)
            for (int bx = 0; bx < bw; bx++) {
                if (j->restart && count && count % j->restart == 0 && restart_marker(j) != 0) return -1;
                if (scan_block(j, c, bx, by) != 0) return -1;
                count++;
                if (j->overrun > MAX_OVERRUN) return -1;
            }
        return 0;
    }
    for (int my = 0; my < j->mcuy; my++)
        for (int mx = 0; mx < j->mcux; mx++) {
            if (j->restart && count && count % j->restart == 0 && restart_marker(j) != 0) return -1;
            for (int i = 0; i < ns; i++) {
                jcomp_t *c = sc[i];
                for (int v = 0; v < c->v; v++)
                    for (int h = 0; h < c->h; h++)
                        if (scan_block(j, c, mx * c->h + h, my * c->v + v) != 0) return -1;
            }
            count++;
            if (j->overrun > MAX_OVERRUN) return -1;
        }
    return 0;
}

static void jpeg_free(jpeg_t *j) {
    for (int i = 0; i < MAX_COMPS; i++) {
        free(j->comp[i].plane);
        free(j->comp[i].coef);
        j->comp[i].plane = NULL;
        j->comp[i].coef = NULL;
    }
}

static int jpeg_thumb(const uint8_t *p, size_t len, int max_w, int max_h, image_thumb_t *out, char *why, size_t cap) {
    jpeg_t *j = calloc(1, sizeof *j);
    if (!j) return fail(why, cap, "out of memory");
    j->p = p;
    j->len = len;
    j->pos = MARKER_LEN;
    j->adobe_transform = -1;
    int have_frame = 0, scans = 0, rc = -1;
    const char *msg = "the JPEG is damaged";
    for (;;) {
        // The next marker, past any fill bytes.
        while (j->pos < len && p[j->pos] != MARKER) j->pos++;
        while (j->pos < len && p[j->pos] == MARKER) j->pos++;
        if (j->pos >= len) { msg = scans ? NULL : "the JPEG is cut short"; break; }
        int m = p[j->pos++];
        if (m == M_EOI) { msg = scans ? NULL : "the JPEG has no image data"; break; }
        // 00 after FF is a stuffed byte in a scan's data, not a marker; RSTn and TEM carry nothing.
        if (m == 0x00 || m == M_TEM || is_rst(m)) continue;
        if (len - j->pos < 2) { msg = "the JPEG is cut short"; break; }
        size_t seglen = load_be16(p + j->pos);
        if (seglen < 2 || seglen > len - j->pos) { msg = "the JPEG is cut short"; break; }
        const uint8_t *d = p + j->pos + 2;
        size_t dl = seglen - 2;
        j->pos += seglen;
        if (m == M_DQT) {
            for (size_t o = 0; o < dl; ) {
                int pq = d[o] >> 4, tq = d[o] & 15;
                size_t need = pq ? 2 * COEFS : COEFS;
                if (pq > 1 || tq >= TABLE_IDS || dl - o - 1 < need) { msg = "the JPEG's tables are wrong"; goto done; }
                for (int k = 0; k < COEFS; k++) j->qt[tq][k] = pq ? load_be16(d + o + 1 + 2 * k) : d[o + 1 + k];
                j->qt_set[tq] = 1;
                o += 1 + need;
            }
        } else if (m == M_DHT) {
            for (size_t o = 0; o < dl; ) {
                if (dl - o < DHT_HEAD) { msg = "the JPEG's tables are wrong"; goto done; }
                int tc = d[o] >> 4, th = d[o] & 15;
                if (tc > 1 || th >= TABLE_IDS) { msg = "the JPEG's tables are wrong"; goto done; }
                jhuff_t *t = tc ? &j->ac[th] : &j->dc[th];
                memset(t, 0, sizeof *t);
                int total = 0;
                for (int l = 1; l <= MAX_CODE_BITS; l++) { t->bits[l] = d[o + (size_t)l]; total += t->bits[l]; }
                if (total > (int)sizeof t->vals || dl - o - DHT_HEAD < (size_t)total) { msg = "the JPEG's tables are wrong"; goto done; }
                memcpy(t->vals, d + o + DHT_HEAD, (size_t)total);
                t->nvals = total;
                if (jhuff_build(t) != 0) { msg = "the JPEG's tables are wrong"; goto done; }
                o += DHT_HEAD + (size_t)total;
            }
        } else if (m == M_DRI) {
            if (dl < 2) { msg = "the JPEG is damaged"; goto done; }
            j->restart = load_be16(d);
        } else if (m == M_APP14) {
            if (dl > ADOBE_TRANSFORM && memcmp(d, "Adobe", 5) == 0) j->adobe_transform = d[ADOBE_TRANSFORM];
        } else if (m >= M_SOF0 && m <= M_SOF2) {
            if (have_frame || dl < SOF_HEAD) { msg = "the JPEG is damaged"; goto done; }
            j->progressive = m == M_SOF2;
            if (d[0] != 8) { msg = "chat only shows 8-bit JPEGs - download it instead"; goto done; }
            j->h = load_be16(d + 1);
            j->w = load_be16(d + 3);
            j->ncomp = d[5];
            if (j->ncomp != 1 && j->ncomp != 3) { msg = "chat only shows greyscale and colour JPEGs - download it instead"; goto done; }
            if (dl < SOF_HEAD + 3 * (size_t)j->ncomp || j->h == 0 || j->w == 0) { msg = "the JPEG is damaged"; goto done; }
            if (!sides_ok((uint32_t)j->w, (uint32_t)j->h)) { msg = "the image is too big to show"; goto done; }
            j->hmax = j->vmax = 1;
            for (int i = 0; i < j->ncomp; i++) {
                jcomp_t *c = &j->comp[i];
                const uint8_t *cd = d + SOF_HEAD + i * 3;
                c->id = cd[0];
                c->h = cd[1] >> 4;
                c->v = cd[1] & 15;
                c->tq = cd[2];
                if (c->h < 1 || c->h > MAX_SAMPLING || c->v < 1 || c->v > MAX_SAMPLING || c->tq >= TABLE_IDS) { msg = "the JPEG is damaged"; goto done; }
                for (int k = 0; k < i; k++) if (j->comp[k].id == c->id) { msg = "the JPEG is damaged"; goto done; }
                if (c->h > j->hmax) j->hmax = c->h;
                if (c->v > j->vmax) j->vmax = c->v;
            }
            j->mcux = (j->w + BLOCK_SIDE * j->hmax - 1) / (BLOCK_SIDE * j->hmax);
            j->mcuy = (j->h + BLOCK_SIDE * j->vmax - 1) / (BLOCK_SIDE * j->vmax);
            // Big images, and any where an eighth of the size is as big as the thumbnail, are read at an
            // eighth of their size. A thumbnail doesn't need more, and memory use stays small whatever
            // size the image claims.
            int tw, th;
            fit(j->w, j->h, max_w, max_h, &tw, &th);
            j->dc_only = (int64_t)j->w * j->h > DC_ONLY_PIXELS
                         || (tw <= (j->w + BLOCK_SIDE - 1) / BLOCK_SIDE && th <= (j->h + BLOCK_SIDE - 1) / BLOCK_SIDE);
            int px = j->dc_only ? 1 : BLOCK_SIDE;
            for (int i = 0; i < j->ncomp; i++) {
                jcomp_t *c = &j->comp[i];
                c->bw = j->mcux * c->h;
                c->bh = j->mcuy * c->v;
                c->stride = c->bw * px;
                c->plane = calloc((size_t)c->bw * (size_t)px * (size_t)c->bh * (size_t)px, 1);
                if (!c->plane) { msg = "out of memory"; goto done; }
                if (j->progressive) {
                    c->coef = calloc((size_t)c->bw * (size_t)c->bh * block_coefs(j), sizeof *c->coef);
                    if (!c->coef) { msg = "out of memory"; goto done; }
                }
            }
            have_frame = 1;
        } else if (m >= M_SOF3 && m <= M_SOF15 && m != M_DHT && m != M_JPG && m != M_DAC) {
            msg = "chat only shows baseline and progressive JPEGs - download it instead";
            goto done;
        } else if (m == M_SOS) {
            if (!have_frame || dl < 1) { msg = "the JPEG is damaged"; goto done; }
            // Real ones have a dozen or so. A progressive scan can pass over thousands of blocks in a few
            // bytes, so without a limit a small file could take minutes.
            if (scans >= MAX_SCANS) { msg = "the JPEG has too many scans"; goto done; }
            int ns = d[0];
            if (ns < 1 || ns > j->ncomp || dl < 1 + 2 * (size_t)ns + 3) { msg = "the JPEG is damaged"; goto done; }
            const uint8_t *tail = d + 1 + 2 * ns;
            j->ss = tail[0];
            j->se = tail[1];
            j->ah = tail[2] >> 4;
            j->al = tail[2] & 15;
            if (!j->progressive) {
                if (j->ss != 0 || j->se != LAST_COEF || tail[2] != 0) { msg = "chat only shows baseline JPEGs - download it instead"; goto done; }
            } else if (j->se > LAST_COEF || j->ss > j->se || (j->ss == 0) != (j->se == 0) || (j->ss > 0 && ns != 1)
                       || j->ah > MAX_APPROX_BIT || j->al > MAX_APPROX_BIT) {
                msg = "the JPEG is damaged";
                goto done;
            }
            // A progressive scan only uses the table for what it carries, and a refining DC scan none.
            int need_dc = j->ss == 0 && j->ah == 0, need_ac = !j->progressive || j->ss > 0;
            jcomp_t *sc[MAX_COMPS];
            for (int i = 0; i < ns; i++) {
                int id = d[1 + i * 2], tb = d[2 + i * 2];
                sc[i] = NULL;
                for (int k = 0; k < j->ncomp; k++) if (j->comp[k].id == id) sc[i] = &j->comp[k];
                if (!sc[i]) { msg = "the JPEG is damaged"; goto done; }
                for (int k = 0; k < i; k++) if (sc[k] == sc[i]) { msg = "the JPEG is damaged"; goto done; }
                sc[i]->td = tb >> 4;
                sc[i]->ta = tb & 15;
                if (sc[i]->td >= TABLE_IDS || sc[i]->ta >= TABLE_IDS || (need_dc && !j->dc[sc[i]->td].set)
                    || (need_ac && !j->ac[sc[i]->ta].set) || (!j->progressive && !j->qt_set[sc[i]->tq])) {
                    msg = "the JPEG's tables are missing"; goto done;
                }
            }
            if (ns > 1) {
                // An interleaved MCU is at most ten blocks.
                int blocks = 0;
                for (int i = 0; i < ns; i++) blocks += sc[i]->h * sc[i]->v;
                if (blocks > MAX_MCU_BLOCKS) { msg = "the JPEG is damaged"; goto done; }
            }
            // At an eighth of the size only the DC is used, so AC scans are skipped like any other segment.
            if (!(j->dc_only && j->ss > 0) && decode_scan(j, sc, ns) != 0) { msg = "the JPEG's image data is damaged"; goto done; }
            scans++;
            // Skip past the scan's data to the next marker.
            j->bitcnt = 0;
        } else if (m == M_SOI) {
            msg = "the JPEG is damaged";
            goto done;
        }
    }
    if (msg) goto done;

    for (int i = 0; j->progressive && i < j->ncomp; i++) {
        jcomp_t *c = &j->comp[i];
        if (!j->qt_set[c->tq]) { msg = "the JPEG's tables are missing"; goto done; }
        const uint16_t *q = j->qt[c->tq];
        for (int by = 0; by < c->bh; by++)
            for (int bx = 0; bx < c->bw; bx++) {
                const int16_t *b = coefs_at(j, c, bx, by);
                if (j->dc_only) {
                    *block_at(j, c, bx, by) = dc_sample(b[0] * q[0]);
                    continue;
                }
                int in[COEFS];
                for (int k = 0; k < COEFS; k++) in[ZIGZAG[k]] = b[ZIGZAG[k]] * q[k];
                idct8x8(in, block_at(j, c, bx, by), c->stride);
            }
        free(c->coef);
        c->coef = NULL;
    }

    {
        int scale = j->dc_only ? BLOCK_SIDE : 1;
        int ow = (j->w + scale - 1) / scale, oh = (j->h + scale - 1) / scale;
        thumb_acc_t acc;
        if (acc_init(&acc, ow, oh, max_w, max_h) != 0) { msg = "out of memory"; goto done; }
        int rgb_planes = j->ncomp == 3 && j->adobe_transform == 0;
        for (int y = 0; y < oh; y++)
            for (int x = 0; x < ow; x++) {
                int s[3];
                for (int i = 0; i < j->ncomp; i++) {
                    jcomp_t *c = &j->comp[i];
                    size_t sx = (size_t)x * (size_t)c->h / (size_t)j->hmax, sy = (size_t)y * (size_t)c->v / (size_t)j->vmax;
                    s[i] = c->plane[sy * (size_t)c->stride + sx];
                }
                int r, g, b;
                if (j->ncomp == 1) {
                    r = g = b = s[0];
                } else if (rgb_planes) {
                    r = s[0]; g = s[1]; b = s[2];
                } else {
                    float yy = (float)s[0], cb = (float)(s[1] - SAMPLE_MID), cr = (float)(s[2] - SAMPLE_MID);
                    r = clamp8((int)lrintf(yy + 1.402f * cr));
                    g = clamp8((int)lrintf(yy - 0.344136f * cb - 0.714136f * cr));
                    b = clamp8((int)lrintf(yy + 1.772f * cb));
                }
                acc_add(&acc, x, y, r, g, b);
            }
        if (acc_finish(&acc, j->w, j->h, out) != 0) { msg = "out of memory"; goto done; }
        rc = 0;
    }
done:
    if (rc != 0) fail(why, cap, msg ? msg : "the JPEG is damaged");
    jpeg_free(j);
    free(j);
    return rc;
}

// ---- GIF: the first frame ----

// The signature and the screen's width, height and flags (then two bytes not needed here), and an
// image's left, top, width, height and flags.
enum { GIF_HEADER = 13, GIF_DESCRIPTOR = 9 };
enum { GIF_EXTENSION = 0x21, GIF_IMAGE = 0x2C, GIF_TRAILER = 0x3B, GIF_GRAPHIC_CONTROL = 0xF9 };
#define GIF_HAS_COLOURS 0x80
#define GIF_INTERLACED 0x40
#define GIF_PASSES 4
#define GRAPHIC_CONTROL_LEN 4
#define LZW_MAX_BITS 12
#define LZW_CODES (1 << LZW_MAX_BITS)

// The colour table the flags say follows at *pos, if they do.
static int gif_colours(const uint8_t *p, size_t len, size_t *pos, int flags, const uint8_t **pal, int *npal) {
    if (!(flags & GIF_HAS_COLOURS)) return 0;
    *npal = 2 << (flags & 7);
    if ((size_t)*npal * 3 > len - *pos) return -1;
    *pal = p + *pos;
    *pos += (size_t)*npal * 3;
    return 0;
}

// Past a run of sub-blocks and the empty one that ends it.
static int gif_skip(const uint8_t *p, size_t len, size_t *pos) {
    for (;;) {
        if (*pos >= len) return -1;
        size_t n = p[(*pos)++];
        if (n == 0) return 0;
        if (n > len - *pos) return -1;
        *pos += n;
    }
}

typedef struct {
    const uint8_t *p;
    size_t len, pos;
    size_t left;            // bytes left in the sub-block being read
    uint32_t bitbuf;
    int bitcnt;
} gif_bits_t;

// The next code of n bits, read across sub-blocks, or -1 when they've run out.
static int gif_code(gif_bits_t *g, int n) {
    while (g->bitcnt < n) {
        if (g->left == 0) {
            if (g->pos >= g->len || g->p[g->pos] == 0) return -1;
            g->left = g->p[g->pos++];
        }
        if (g->pos >= g->len) return -1;
        g->bitbuf |= (uint32_t)g->p[g->pos++] << g->bitcnt;
        g->bitcnt += 8;
        g->left--;
    }
    int v = (int)(g->bitbuf & ((1u << n) - 1));
    g->bitbuf >>= n;
    g->bitcnt -= n;
    return v;
}

typedef struct {
    uint16_t prefix[LZW_CODES];
    uint8_t suffix[LZW_CODES], first[LZW_CODES];
    uint8_t stack[LZW_CODES];    // a code's string, last byte first
} gif_dict_t;

static const int GIF_Y0[GIF_PASSES] = { 0, 4, 2, 1 }, GIF_DY[GIF_PASSES] = { 8, 8, 4, 2 };

static int gif_thumb(const uint8_t *p, size_t len, int max_w, int max_h, const uint8_t bg[3], image_thumb_t *out,
                     char *why, size_t cap) {
    if (len < GIF_HEADER) return fail(why, cap, "the GIF is cut short");
    int sw = le16(p + 6), sh = le16(p + 8);
    const uint8_t *pal = NULL;
    int npal = 0;
    size_t pos = GIF_HEADER;
    if (gif_colours(p, len, &pos, p[10], &pal, &npal) != 0) return fail(why, cap, "the GIF is cut short");
    // Extensions up to the first frame are skipped, but for which colour is see-through.
    int trans = -1;
    for (;;) {
        if (pos >= len) return fail(why, cap, "the GIF is cut short");
        int b = p[pos++];
        if (b == GIF_IMAGE) break;
        if (b == GIF_TRAILER) return fail(why, cap, "the GIF has no image data");
        if (b != GIF_EXTENSION) return fail(why, cap, "the GIF is damaged");
        if (pos >= len) return fail(why, cap, "the GIF is cut short");
        if (p[pos++] == GIF_GRAPHIC_CONTROL && len - pos > GRAPHIC_CONTROL_LEN && p[pos] == GRAPHIC_CONTROL_LEN)
            trans = p[pos + 1] & 1 ? p[pos + 4] : -1;
        if (gif_skip(p, len, &pos) != 0) return fail(why, cap, "the GIF is cut short");
    }
    if (len - pos < GIF_DESCRIPTOR + 1) return fail(why, cap, "the GIF is cut short");
    int fx = le16(p + pos), fy = le16(p + pos + 2), fw = le16(p + pos + 4), fh = le16(p + pos + 6), flags = p[pos + 8];
    pos += GIF_DESCRIPTOR;
    if (gif_colours(p, len, &pos, flags, &pal, &npal) != 0) return fail(why, cap, "the GIF is cut short");
    if (!pal) return fail(why, cap, "the GIF has no colours");
    if (fw == 0 || fh == 0) return fail(why, cap, "the GIF is damaged");
    // A frame that goes past the screen it's on makes the picture bigger, as browsers do.
    int cw = fx + fw > sw ? fx + fw : sw, ch = fy + fh > sh ? fy + fh : sh;
    if (!sides_ok((uint32_t)cw, (uint32_t)ch)) return fail(why, cap, "the image is too big to show");
    if (pos >= len) return fail(why, cap, "the GIF is cut short");
    int minbits = p[pos++];
    if (minbits < 2 || minbits > 8) return fail(why, cap, "the GIF's image data is damaged");

    gif_dict_t *d = malloc(sizeof *d);
    thumb_acc_t acc;
    if (!d || acc_init(&acc, cw, ch, max_w, max_h) != 0) { free(d); return fail(why, cap, "out of memory"); }
    // Around the frame the screen shows through, drawn like any other transparency.
    acc_fill(&acc, 0, 0, cw, fy, bg);
    acc_fill(&acc, 0, fy + fh, cw, ch, bg);
    acc_fill(&acc, 0, fy, fx, fy + fh, bg);
    acc_fill(&acc, fx + fw, fy, cw, fy + fh, bg);

    gif_bits_t g = { p, len, pos, 0, 0, 0 };
    int clear = 1 << minbits, eoi = clear + 1, next = clear + 2, size = minbits + 1, prev = -1;
    for (int i = 0; i < clear; i++) { d->prefix[i] = 0; d->suffix[i] = d->first[i] = (uint8_t)i; }
    int interlaced = (flags & GIF_INTERLACED) != 0, pass = 0, x = 0, y = 0, bad = 0;
    uint64_t total = (uint64_t)fw * (uint64_t)fh, done = 0;
    while (done < total) {
        int code = gif_code(&g, size);
        if (code < 0 || code == eoi) break;
        if (code == clear) { size = minbits + 1; next = clear + 2; prev = -1; continue; }
        if (code > next || (prev < 0 && code > eoi)) { bad = 1; break; }
        // The string for code, last byte first. The code not in the table yet is prev's string and
        // its own first byte.
        int n = 0, c = code;
        if (code == next) {
            d->stack[n++] = d->first[prev];
            c = prev;
        }
        while (c >= clear) { d->stack[n++] = d->suffix[c]; c = d->prefix[c]; }
        d->stack[n++] = (uint8_t)c;
        if (prev >= 0 && next < LZW_CODES) {
            d->prefix[next] = (uint16_t)prev;
            d->suffix[next] = (uint8_t)c;
            d->first[next] = d->first[prev];
            if (++next == 1 << size && size < LZW_MAX_BITS) size++;
        }
        prev = code;
        while (n > 0 && done < total) {
            int idx = d->stack[--n];
            if (idx == trans) acc_add(&acc, fx + x, fy + y, bg[0], bg[1], bg[2]);
            // An index past the end of the palette means damage. It's shown as black and never read past.
            else if (idx >= npal) acc_add(&acc, fx + x, fy + y, 0, 0, 0);
            else acc_add(&acc, fx + x, fy + y, pal[idx * 3], pal[idx * 3 + 1], pal[idx * 3 + 2]);
            done++;
            if (++x < fw) continue;
            x = 0;
            if (!interlaced) { y++; continue; }
            y += GIF_DY[pass];
            while (y >= fh && pass < GIF_PASSES - 1) y = GIF_Y0[++pass];
        }
    }
    free(d);
    if (bad || done < total) {
        acc_free(&acc);
        return fail(why, cap, "the GIF's image data is damaged");
    }
    if (acc_finish(&acc, cw, ch, out) != 0) return fail(why, cap, "out of memory");
    return 0;
}

int image_thumbnail(const uint8_t *data, size_t len, int max_w, int max_h, const uint8_t bg[3],
                    image_thumb_t *out, char *why, size_t why_cap) {
    memset(out, 0, sizeof *out);
    static const uint8_t dark[3] = { 0, 0, 0 };
    if (!bg) bg = dark;
    if (max_w < 1 || max_h < 1) return fail(why, why_cap, "no room to show it");
    const char *kind = image_kind(data, len);
    if (!kind) return fail(why, why_cap, "not a PNG, JPEG or GIF image");
    if (strcmp(kind, "png") == 0) return png_thumb(data, len, max_w, max_h, bg, out, why, why_cap);
    if (strcmp(kind, "gif") == 0) return gif_thumb(data, len, max_w, max_h, bg, out, why, why_cap);
    return jpeg_thumb(data, len, max_w, max_h, out, why, why_cap);
}
