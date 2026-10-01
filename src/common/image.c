// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "common/image.h"
#include "common/util.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char *why, size_t cap, const char *msg) {
    if (why && cap) copy_str(why, msg, cap);
    return -1;
}

const char *image_kind(const uint8_t *data, size_t len) {
    if (len >= 8 && memcmp(data, "\x89PNG\r\n\x1a\n", 8) == 0) return "png";
    if (len >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) return "jpeg";
    return NULL;
}

void image_thumb_free(image_thumb_t *t) {
    if (!t) return;
    free(t->rgb);
    memset(t, 0, sizeof *t);
}

// ---- the thumbnail: each source pixel added into the average for its place ----

typedef struct {
    int sw, sh, tw, th;
    uint64_t *acc;   // tw * th * 4: red, green, blue, and how many
} thumb_acc_t;

static int acc_init(thumb_acc_t *a, int sw, int sh, int max_w, int max_h) {
    memset(a, 0, sizeof *a);
    if (sw < 1 || sh < 1 || max_w < 1 || max_h < 1) return -1;
    a->sw = sw;
    a->sh = sh;
    // As wide as allowed (never wider than the source), then shorter if it's too tall.
    int tw = sw < max_w ? sw : max_w;
    int th = (int)(((int64_t)sh * tw + sw / 2) / sw);
    if (th < 1) th = 1;
    if (th > max_h) {
        th = sh < max_h ? sh : max_h;
        tw = (int)(((int64_t)sw * th + sh / 2) / sh);
        if (tw < 1) tw = 1;
        if (tw > max_w) tw = max_w;
    }
    a->tw = tw;
    a->th = th;
    a->acc = calloc((size_t)tw * (size_t)th * 4, sizeof *a->acc);
    return a->acc ? 0 : -1;
}

static inline void acc_add(thumb_acc_t *a, int x, int y, int r, int g, int b) {
    if (x < 0 || y < 0 || x >= a->sw || y >= a->sh) return;
    int tx = (int)((int64_t)x * a->tw / a->sw), ty = (int)((int64_t)y * a->th / a->sh);
    uint64_t *c = a->acc + ((size_t)ty * (size_t)a->tw + (size_t)tx) * 4;
    c[0] += (uint64_t)r;
    c[1] += (uint64_t)g;
    c[2] += (uint64_t)b;
    c[3]++;
}

static int acc_finish(thumb_acc_t *a, int src_w, int src_h, image_thumb_t *out) {
    size_t n = (size_t)a->tw * (size_t)a->th;
    uint8_t *rgb = malloc(n * 3);
    if (!rgb) { free(a->acc); a->acc = NULL; return -1; }
    for (size_t i = 0; i < n; i++) {
        uint64_t *c = a->acc + i * 4;
        for (int k = 0; k < 3; k++) rgb[i * 3 + (size_t)k] = c[3] ? (uint8_t)((c[k] + c[3] / 2) / c[3]) : 0;
    }
    free(a->acc);
    a->acc = NULL;
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
    short symbol[288];
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
    unsigned len = s->in[s->inpos] | ((unsigned)s->in[s->inpos + 1] << 8);
    unsigned nlen = s->in[s->inpos + 2] | ((unsigned)s->in[s->inpos + 3] << 8);
    s->inpos += 4;
    if (len != (~nlen & 0xffffu)) return -1;
    if (len > s->inlen - s->inpos || len > s->outlen - s->outpos) return -1;
    memcpy(s->out + s->outpos, s->in + s->inpos, len);
    s->inpos += len;
    s->outpos += len;
    return 0;
}

static int codes(inflate_t *s, const huff_t *lencode, const huff_t *distcode) {
    static const short lbase[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                     35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
    static const short lext[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
    static const short dbase[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
                                     1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
    static const short dext[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
    for (;;) {
        int symbol = decode(s, lencode);
        if (symbol < 0) return -1;
        if (symbol < 256) {
            if (s->outpos >= s->outlen) return -1;
            s->out[s->outpos++] = (uint8_t)symbol;
        } else if (symbol == 256) {
            return 0;
        } else {
            symbol -= 257;
            if (symbol >= 29) return -1;
            size_t len = (size_t)lbase[symbol] + (size_t)bits(s, lext[symbol]);
            int ds = decode(s, distcode);
            if (ds < 0 || ds >= 30) return -1;
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
        short lengths[288];
        int i = 0;
        for (; i < 144; i++) lengths[i] = 8;
        for (; i < 256; i++) lengths[i] = 9;
        for (; i < 280; i++) lengths[i] = 7;
        for (; i < 288; i++) lengths[i] = 8;
        construct(&lencode, lengths, 288);
        for (i = 0; i < 30; i++) lengths[i] = 5;
        construct(&distcode, lengths, 30);
        built = 1;
    }
    return codes(s, &lencode, &distcode);
}

static int dynamic(inflate_t *s) {
    static const short order[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    short lengths[288 + 32];
    huff_t lencode, distcode;
    int nlen = bits(s, 5) + 257, ndist = bits(s, 5) + 1, ncode = bits(s, 4) + 4;
    if (s->err || nlen > 286 || ndist > 30) return -1;
    int index;
    for (index = 0; index < ncode; index++) lengths[order[index]] = (short)bits(s, 3);
    for (; index < 19; index++) lengths[order[index]] = 0;
    if (s->err || construct(&lencode, lengths, 19) != 0) return -1;
    index = 0;
    while (index < nlen + ndist) {
        int symbol = decode(s, &lencode);
        if (symbol < 0) return -1;
        if (symbol < 16) {
            lengths[index++] = (short)symbol;
            continue;
        }
        short len = 0;
        if (symbol == 16) {
            if (index == 0) return -1;
            len = lengths[index - 1];
            symbol = 3 + bits(s, 2);
        } else if (symbol == 17) {
            symbol = 3 + bits(s, 3);
        } else {
            symbol = 11 + bits(s, 7);
        }
        if (s->err || index + symbol > nlen + ndist) return -1;
        while (symbol--) lengths[index++] = len;
    }
    if (lengths[256] == 0) return -1;
    int err = construct(&lencode, lengths, nlen);
    if (err < 0 || (err > 0 && nlen - lencode.count[0] != 1)) return -1;
    err = construct(&distcode, lengths + nlen, ndist);
    if (err < 0 || (err > 0 && ndist - distcode.count[0] != 1)) return -1;
    return codes(s, &lencode, &distcode);
}

static uint32_t adler32(const uint8_t *p, size_t n) {
    uint32_t a = 1, b = 0;
    while (n > 0) {
        size_t k = n < 5552 ? n : 5552;
        n -= k;
        while (k--) { a += *p++; b += a; }
        a %= 65521;
        b %= 65521;
    }
    return (b << 16) | a;
}

// A zlib stream that inflates to exactly outlen bytes: anything more or less is damage.
static int zlib_inflate(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    if (inlen < 6) return -1;
    unsigned cmf = in[0], flg = in[1];
    if ((cmf & 15) != 8 || (cmf >> 4) > 7 || (cmf * 256 + flg) % 31 != 0 || (flg & 0x20)) return -1;
    inflate_t s = { in, inlen, 2, 0, 0, out, outlen, 0, 0 };
    int last;
    do {
        last = bits(&s, 1);
        int type = bits(&s, 2);
        if (s.err) return -1;
        int rc = type == 0 ? stored(&s) : type == 1 ? fixed(&s) : type == 2 ? dynamic(&s) : -1;
        if (rc != 0 || s.err) return -1;
    } while (!last);
    if (s.outpos != outlen || s.inlen - s.inpos < 4) return -1;
    const uint8_t *a = in + s.inpos;
    uint32_t want = ((uint32_t)a[0] << 24) | ((uint32_t)a[1] << 16) | ((uint32_t)a[2] << 8) | a[3];
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    (void)want;
    return 0;
#else
    return adler32(out, outlen) == want ? 0 : -1;
#endif
}

// ---- PNG ----

static uint32_t be32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

static uint32_t crc32_of(const uint8_t *p, size_t n) {
    static uint32_t table[256];
    static int ready;
    if (!ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        ready = 1;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

static const int A7_X0[7] = { 0, 4, 0, 2, 0, 1, 0 }, A7_Y0[7] = { 0, 0, 4, 0, 2, 0, 1 };
static const int A7_DX[7] = { 8, 8, 4, 4, 2, 2, 1 }, A7_DY[7] = { 8, 8, 8, 4, 4, 2, 2 };

typedef struct {
    uint32_t w, h;
    int depth, ctype, interlace;
    int channels;
    uint8_t pal[256][4];
    int npal;
    int has_key;
    uint16_t key[3];
} png_info_t;

static int paeth(int a, int b, int c) {
    int p = a + b - c, pa = abs(p - a), pb = abs(p - b), pc = abs(p - c);
    return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

// The sample at index i of a row, at the row's bit depth (16-bit kept whole).
static unsigned sample(const uint8_t *row, size_t i, int depth) {
    if (depth == 8) return row[i];
    if (depth == 16) return ((unsigned)row[2 * i] << 8) | row[2 * i + 1];
    size_t bit = i * (size_t)depth;
    return (row[bit / 8] >> (8 - depth - (int)(bit % 8))) & ((1u << depth) - 1);
}

static int to8(unsigned v, int depth) {
    if (depth == 16) return (int)(v >> 8);
    if (depth == 8) return (int)v;
    return (int)(v * 255 / ((1u << depth) - 1));
}

static void put_pixel(thumb_acc_t *a, const png_info_t *pi, const uint8_t *row, size_t x, int ox, int oy, const uint8_t bg[3]) {
    int d = pi->depth, r, g, b, alpha = 255;
    size_t c = (size_t)pi->channels;
    switch (pi->ctype) {
        case 0: {
            unsigned v = sample(row, x, d);
            r = g = b = to8(v, d);
            if (pi->has_key && v == pi->key[0]) alpha = 0;
            break;
        }
        case 2: {
            unsigned vr = sample(row, x * 3, d), vg = sample(row, x * 3 + 1, d), vb = sample(row, x * 3 + 2, d);
            r = to8(vr, d); g = to8(vg, d); b = to8(vb, d);
            if (pi->has_key && vr == pi->key[0] && vg == pi->key[1] && vb == pi->key[2]) alpha = 0;
            break;
        }
        case 3: {
            unsigned idx = sample(row, x, d);
            // An index past the palette is damage: shown as black, never read past it.
            if ((int)idx >= pi->npal) { r = g = b = 0; break; }
            r = pi->pal[idx][0]; g = pi->pal[idx][1]; b = pi->pal[idx][2]; alpha = pi->pal[idx][3];
            break;
        }
        case 4:
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
    if (alpha < 255) {
        r = (r * alpha + bg[0] * (255 - alpha) + 127) / 255;
        g = (g * alpha + bg[1] * (255 - alpha) + 127) / 255;
        b = (b * alpha + bg[2] * (255 - alpha) + 127) / 255;
    }
    acc_add(a, ox, oy, r, g, b);
}

static int png_thumb(const uint8_t *p, size_t len, int max_w, int max_h, const uint8_t bg[3], image_thumb_t *out,
                     char *why, size_t cap) {
    png_info_t pi;
    memset(&pi, 0, sizeof pi);
    for (int i = 0; i < 256; i++) pi.pal[i][3] = 255;
    int have_ihdr = 0, have_plte = 0, idat_state = 0;   // 0 none yet, 1 in the run, 2 run over
    uint64_t zlen = 0;
    size_t pos = 8;
    int ended = 0;
    while (!ended) {
        if (len - pos < 12) return fail(why, cap, "the PNG is cut short");
        uint32_t clen = be32(p + pos);
        if (clen > 0x7FFFFFFFu || clen > len - pos - 12) return fail(why, cap, "the PNG is cut short");
        const uint8_t *type = p + pos + 4, *d = p + pos + 8;
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        // (A fuzzer's mutations would almost never get past these, so a fuzzing build skips them.)
        if (crc32_of(type, (size_t)clen + 4) != be32(d + clen)) return fail(why, cap, "the PNG is damaged (a checksum is wrong)");
#endif
        if (!have_ihdr && memcmp(type, "IHDR", 4) != 0) return fail(why, cap, "the PNG doesn't start with its header");
        if (memcmp(type, "IHDR", 4) == 0) {
            if (have_ihdr || clen != 13) return fail(why, cap, "the PNG's header is wrong");
            pi.w = be32(d);
            pi.h = be32(d + 4);
            pi.depth = d[8];
            pi.ctype = d[9];
            pi.interlace = d[12];
            int ok_depth;
            switch (pi.ctype) {
                case 0: pi.channels = 1; ok_depth = pi.depth == 1 || pi.depth == 2 || pi.depth == 4 || pi.depth == 8 || pi.depth == 16; break;
                case 2: pi.channels = 3; ok_depth = pi.depth == 8 || pi.depth == 16; break;
                case 3: pi.channels = 1; ok_depth = pi.depth == 1 || pi.depth == 2 || pi.depth == 4 || pi.depth == 8; break;
                case 4: pi.channels = 2; ok_depth = pi.depth == 8 || pi.depth == 16; break;
                case 6: pi.channels = 4; ok_depth = pi.depth == 8 || pi.depth == 16; break;
                default: ok_depth = 0; break;
            }
            if (!ok_depth || d[10] != 0 || d[11] != 0 || pi.interlace > 1) return fail(why, cap, "the PNG's header is wrong");
            if (!sides_ok(pi.w, pi.h)) return fail(why, cap, "the image is too big to show");
            have_ihdr = 1;
        } else if (memcmp(type, "PLTE", 4) == 0) {
            if (have_plte || idat_state || clen % 3 != 0 || clen == 0 || clen > 768) return fail(why, cap, "the PNG's palette is wrong");
            pi.npal = (int)(clen / 3);
            for (int i = 0; i < pi.npal; i++) { pi.pal[i][0] = d[i * 3]; pi.pal[i][1] = d[i * 3 + 1]; pi.pal[i][2] = d[i * 3 + 2]; }
            have_plte = 1;
        } else if (memcmp(type, "tRNS", 4) == 0) {
            if (idat_state) return fail(why, cap, "the PNG's transparency comes too late");
            if (pi.ctype == 3) {
                if (!have_plte || (int)clen > pi.npal) return fail(why, cap, "the PNG's transparency is wrong");
                for (uint32_t i = 0; i < clen; i++) pi.pal[i][3] = d[i];
            } else if (pi.ctype == 0 && clen == 2) {
                pi.has_key = 1;
                pi.key[0] = (uint16_t)((d[0] << 8) | d[1]);
            } else if (pi.ctype == 2 && clen == 6) {
                pi.has_key = 1;
                for (int i = 0; i < 3; i++) pi.key[i] = (uint16_t)((d[i * 2] << 8) | d[i * 2 + 1]);
            } else {
                return fail(why, cap, "the PNG's transparency is wrong");
            }
        } else if (memcmp(type, "IDAT", 4) == 0) {
            if (idat_state == 2) return fail(why, cap, "the PNG's image data is split up");
            if (pi.ctype == 3 && !have_plte) return fail(why, cap, "the PNG has no palette");
            idat_state = 1;
            zlen += clen;
        } else if (memcmp(type, "IEND", 4) == 0) {
            ended = 1;
        } else {
            if (!(type[0] & 0x20)) return fail(why, cap, "the PNG has a part chat doesn't know how to read");
            if (idat_state == 1) idat_state = 2;
        }
        if (idat_state == 1 && memcmp(type, "IDAT", 4) != 0) idat_state = 2;
        pos += (size_t)clen + 12;
    }
    if (!idat_state || zlen == 0) return fail(why, cap, "the PNG has no image data");

    // How much the image inflates to: each row of each pass, with its filter byte.
    size_t bits_px = (size_t)pi.depth * (size_t)pi.channels;
    uint64_t raw_len = 0;
    int passes = pi.interlace ? 7 : 1;
    for (int ps = 0; ps < passes; ps++) {
        uint64_t pw = pi.interlace ? (pi.w > (uint32_t)A7_X0[ps] ? (pi.w - (uint32_t)A7_X0[ps] + (uint32_t)A7_DX[ps] - 1) / (uint32_t)A7_DX[ps] : 0) : pi.w;
        uint64_t ph = pi.interlace ? (pi.h > (uint32_t)A7_Y0[ps] ? (pi.h - (uint32_t)A7_Y0[ps] + (uint32_t)A7_DY[ps] - 1) / (uint32_t)A7_DY[ps] : 0) : pi.h;
        if (pw && ph) raw_len += ph * (1 + (pw * bits_px + 7) / 8);
    }
    if (raw_len > IMAGE_MAX_RAW) return fail(why, cap, "the image is too big to show");

    uint8_t *z = malloc((size_t)zlen), *raw = malloc((size_t)raw_len);
    thumb_acc_t acc;
    if (!z || !raw || acc_init(&acc, (int)pi.w, (int)pi.h, max_w, max_h) != 0) {
        free(z); free(raw);
        return fail(why, cap, "out of memory");
    }
    size_t zo = 0;
    for (pos = 8; pos + 12 <= len; ) {
        uint32_t clen = be32(p + pos);
        if (memcmp(p + pos + 4, "IDAT", 4) == 0) { memcpy(z + zo, p + pos + 8, clen); zo += clen; }
        if (memcmp(p + pos + 4, "IEND", 4) == 0) break;
        pos += (size_t)clen + 12;
    }
    int rc = zlib_inflate(z, (size_t)zlen, raw, (size_t)raw_len);
    free(z);
    if (rc != 0) { free(raw); free(acc.acc); return fail(why, cap, "the PNG's image data is damaged"); }

    size_t bpp = bits_px >= 8 ? bits_px / 8 : 1;
    uint8_t *r = raw;
    for (int ps = 0; ps < passes; ps++) {
        size_t pw = pi.interlace ? (pi.w > (uint32_t)A7_X0[ps] ? (pi.w - (uint32_t)A7_X0[ps] + (uint32_t)A7_DX[ps] - 1) / (uint32_t)A7_DX[ps] : 0) : pi.w;
        size_t ph = pi.interlace ? (pi.h > (uint32_t)A7_Y0[ps] ? (pi.h - (uint32_t)A7_Y0[ps] + (uint32_t)A7_DY[ps] - 1) / (uint32_t)A7_DY[ps] : 0) : pi.h;
        if (!pw || !ph) continue;
        size_t rowbytes = (pw * bits_px + 7) / 8;
        uint8_t *prev = NULL;
        for (size_t y = 0; y < ph; y++) {
            int f = r[0];
            uint8_t *cur = r + 1;
            if (f > 4) { free(raw); free(acc.acc); return fail(why, cap, "the PNG's image data is damaged"); }
            for (size_t i = 0; i < rowbytes; i++) {
                int a = i >= bpp ? cur[i - bpp] : 0, b = prev ? prev[i] : 0, c = prev && i >= bpp ? prev[i - bpp] : 0;
                int v = cur[i];
                switch (f) {
                    case 1: v += a; break;
                    case 2: v += b; break;
                    case 3: v += (a + b) / 2; break;
                    case 4: v += paeth(a, b, c); break;
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

typedef struct {
    uint8_t bits[17];       // how many codes of each length
    uint8_t vals[256];
    int nvals;
    int32_t mincode[17], maxcode[18], valptr[17];
    int set;
} jhuff_t;

typedef struct {
    int id, h, v, tq;
    int td, ta;             // this scan's tables
    int dc_pred;
    int bw, bh;             // its blocks across and down, padded to whole MCUs
    uint8_t *plane;         // bw * scale_px by bh * scale_px samples
    int stride;
} jcomp_t;

typedef struct {
    const uint8_t *p;
    size_t len, pos;
    uint32_t bitbuf;
    int bitcnt;
    int marker_hit;         // a marker turned up where entropy-coded data was; zeros from here
    int overrun;            // bits asked for past that, in bytes: a little is normal, a lot is damage
    uint16_t qt[4][64];
    int qt_set[4];
    jhuff_t dc[4], ac[4];
    int w, h, ncomp, hmax, vmax, mcux, mcuy;
    jcomp_t comp[3];
    int restart;
    int dc_only;            // an eighth of the size: each block's DC alone
    int adobe_transform;    // -1 none seen
} jpeg_t;

static const uint8_t ZIGZAG[64] = {
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63
};

static int jhuff_build(jhuff_t *t) {
    int code = 0, k = 0;
    for (int l = 1; l <= 16; l++) {
        t->valptr[l] = k;
        t->mincode[l] = code;
        code += t->bits[l];
        k += t->bits[l];
        t->maxcode[l] = t->bits[l] ? code - 1 : -1;
        // A code longer than its length allows is no code at all.
        if (code > (1 << l)) return -1;
        code <<= 1;
    }
    t->maxcode[17] = 0x7FFFFFFF;
    t->set = 1;
    return 0;
}

static int jbit(jpeg_t *j) {
    if (j->bitcnt == 0) {
        int byte = 0;
        if (!j->marker_hit && j->pos < j->len) {
            byte = j->p[j->pos];
            if (byte == 0xFF) {
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
    for (int l = 1; l <= 16; l++) {
        code = (code << 1) | jbit(j);
        if (t->maxcode[l] >= 0 && code <= t->maxcode[l]) {
            int k = t->valptr[l] + code - t->mincode[l];
            return k >= 0 && k < t->nvals ? t->vals[k] : -1;
        }
    }
    return -1;
}

static int extend(int v, int s) { return s == 0 ? 0 : v < (1 << (s - 1)) ? v - (1 << s) + 1 : v; }

static void idct8x8(const int *in, uint8_t *out, int stride) {
    static float c[8][8];
    static int ready;
    if (!ready) {
        for (int u = 0; u < 8; u++)
            for (int x = 0; x < 8; x++)
                c[u][x] = (float)((u == 0 ? sqrt(0.5) : 1.0) * cos((2 * x + 1) * u * 3.14159265358979323846 / 16.0) / 2.0);
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
            int px = (int)lrintf(s) + 128;
            out[y * stride + x] = (uint8_t)(px < 0 ? 0 : px > 255 ? 255 : px);
        }
}

// One block of comp at block (bx, by) of its plane.
static int decode_block(jpeg_t *j, jcomp_t *c, int bx, int by) {
    int coef[64] = { 0 };
    const jhuff_t *dc = &j->dc[c->td], *ac = &j->ac[c->ta];
    int s = jdecode(j, dc);
    if (s < 0 || s > 11) return -1;
    int diff = extend(jbits(j, s), s);
    c->dc_pred += diff;
    const uint16_t *q = j->qt[c->tq];
    coef[0] = c->dc_pred * q[0];
    if (j->dc_only) {
        // The AC coefficients are still read, to get past them.
        for (int k = 1; k < 64; ) {
            int rs = jdecode(j, ac);
            if (rs < 0) return -1;
            int r = rs >> 4, sz = rs & 15;
            if (sz == 0) { if (r != 15) break; k += 16; continue; }
            k += r;
            if (k > 63) return -1;
            jbits(j, sz);
            k++;
        }
        if (bx < c->bw && by < c->bh) {
            int v = coef[0] / 8 + 128;
            c->plane[(size_t)by * (size_t)c->stride + (size_t)bx] = (uint8_t)(v < 0 ? 0 : v > 255 ? 255 : v);
        }
        return 0;
    }
    for (int k = 1; k < 64; ) {
        int rs = jdecode(j, ac);
        if (rs < 0) return -1;
        int r = rs >> 4, sz = rs & 15;
        if (sz == 0) { if (r != 15) break; k += 16; continue; }
        k += r;
        if (k > 63) return -1;
        coef[ZIGZAG[k]] = extend(jbits(j, sz), sz) * q[k];
        k++;
    }
    if (bx < c->bw && by < c->bh) idct8x8(coef, c->plane + (size_t)by * 8 * (size_t)c->stride + (size_t)bx * 8, c->stride);
    return 0;
}

// Back to the start of a byte, past a restart marker if there is one, with the predictions reset.
static int restart_marker(jpeg_t *j) {
    j->bitcnt = 0;
    while (j->pos + 1 < j->len && !(j->p[j->pos] == 0xFF && j->p[j->pos + 1] >= 0xD0 && j->p[j->pos + 1] <= 0xD7)) {
        if (j->p[j->pos] == 0xFF && j->p[j->pos + 1] != 0x00 && j->p[j->pos + 1] != 0xFF) return -1;
        j->pos++;
    }
    if (j->pos + 1 >= j->len) return -1;
    j->pos += 2;
    j->marker_hit = 0;
    for (int i = 0; i < j->ncomp; i++) j->comp[i].dc_pred = 0;
    return 0;
}

static int decode_scan(jpeg_t *j, jcomp_t **sc, int ns) {
    j->bitcnt = 0;
    j->marker_hit = 0;
    for (int i = 0; i < ns; i++) sc[i]->dc_pred = 0;
    long count = 0;
    if (ns == 1) {
        // One component on its own: its blocks in order, as many as cover the image.
        jcomp_t *c = sc[0];
        int cw = (j->w * c->h + j->hmax - 1) / j->hmax, ch = (j->h * c->v + j->vmax - 1) / j->vmax;
        int bw = (cw + 7) / 8, bh = (ch + 7) / 8;
        for (int by = 0; by < bh; by++)
            for (int bx = 0; bx < bw; bx++) {
                if (j->restart && count && count % j->restart == 0 && restart_marker(j) != 0) return -1;
                if (decode_block(j, c, bx, by) != 0) return -1;
                count++;
                if (j->overrun > 64) return -1;
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
                        if (decode_block(j, c, mx * c->h + h, my * c->v + v) != 0) return -1;
            }
            count++;
            if (j->overrun > 64) return -1;
        }
    return 0;
}

static int u16(const uint8_t *p) { return (p[0] << 8) | p[1]; }

static void jpeg_free(jpeg_t *j) {
    for (int i = 0; i < 3; i++) { free(j->comp[i].plane); j->comp[i].plane = NULL; }
}

static int jpeg_thumb(const uint8_t *p, size_t len, int max_w, int max_h, image_thumb_t *out, char *why, size_t cap) {
    jpeg_t *j = calloc(1, sizeof *j);
    if (!j) return fail(why, cap, "out of memory");
    j->p = p;
    j->len = len;
    j->pos = 2;
    j->adobe_transform = -1;
    int have_frame = 0, scans = 0, rc = -1;
    const char *msg = "the JPEG is damaged";
    for (;;) {
        // The next marker, past any fill bytes.
        while (j->pos < len && p[j->pos] != 0xFF) j->pos++;
        while (j->pos < len && p[j->pos] == 0xFF) j->pos++;
        if (j->pos >= len) { msg = scans ? NULL : "the JPEG is cut short"; break; }
        int m = p[j->pos++];
        if (m == 0xD9) { msg = scans ? NULL : "the JPEG has no image data"; break; }
        // 00 after FF is a stuffed byte in a scan's data, not a marker; RSTn and TEM carry nothing.
        if (m == 0x00 || m == 0x01 || (m >= 0xD0 && m <= 0xD7)) continue;
        if (len - j->pos < 2) { msg = "the JPEG is cut short"; break; }
        size_t seglen = (size_t)u16(p + j->pos);
        if (seglen < 2 || seglen > len - j->pos) { msg = "the JPEG is cut short"; break; }
        const uint8_t *d = p + j->pos + 2;
        size_t dl = seglen - 2;
        j->pos += seglen;
        if (m == 0xDB) {
            for (size_t o = 0; o < dl; ) {
                int pq = d[o] >> 4, tq = d[o] & 15;
                size_t need = pq ? 128 : 64;
                if (pq > 1 || tq > 3 || dl - o - 1 < need) { msg = "the JPEG's tables are wrong"; goto done; }
                for (int k = 0; k < 64; k++) j->qt[tq][k] = pq ? (uint16_t)u16(d + o + 1 + 2 * k) : d[o + 1 + k];
                j->qt_set[tq] = 1;
                o += 1 + need;
            }
        } else if (m == 0xC4) {
            for (size_t o = 0; o < dl; ) {
                if (dl - o < 17) { msg = "the JPEG's tables are wrong"; goto done; }
                int tc = d[o] >> 4, th = d[o] & 15;
                if (tc > 1 || th > 3) { msg = "the JPEG's tables are wrong"; goto done; }
                jhuff_t *t = tc ? &j->ac[th] : &j->dc[th];
                memset(t, 0, sizeof *t);
                int total = 0;
                for (int l = 1; l <= 16; l++) { t->bits[l] = d[o + (size_t)l]; total += t->bits[l]; }
                if (total > 256 || dl - o - 17 < (size_t)total) { msg = "the JPEG's tables are wrong"; goto done; }
                memcpy(t->vals, d + o + 17, (size_t)total);
                t->nvals = total;
                if (jhuff_build(t) != 0) { msg = "the JPEG's tables are wrong"; goto done; }
                o += 17 + (size_t)total;
            }
        } else if (m == 0xDD) {
            if (dl < 2) { msg = "the JPEG is damaged"; goto done; }
            j->restart = u16(d);
        } else if (m == 0xEE) {
            if (dl >= 12 && memcmp(d, "Adobe", 5) == 0) j->adobe_transform = d[11];
        } else if (m == 0xC0 || m == 0xC1) {
            if (have_frame || dl < 6) { msg = "the JPEG is damaged"; goto done; }
            if (d[0] != 8) { msg = "chat only shows 8-bit JPEGs - download it instead"; goto done; }
            j->h = u16(d + 1);
            j->w = u16(d + 3);
            j->ncomp = d[5];
            if (j->ncomp != 1 && j->ncomp != 3) { msg = "chat only shows greyscale and colour JPEGs - download it instead"; goto done; }
            if (dl < 6 + 3 * (size_t)j->ncomp || j->h == 0 || j->w == 0) { msg = "the JPEG is damaged"; goto done; }
            if (!sides_ok((uint32_t)j->w, (uint32_t)j->h)) { msg = "the image is too big to show"; goto done; }
            j->hmax = j->vmax = 1;
            for (int i = 0; i < j->ncomp; i++) {
                jcomp_t *c = &j->comp[i];
                c->id = d[6 + i * 3];
                c->h = d[7 + i * 3] >> 4;
                c->v = d[7 + i * 3] & 15;
                c->tq = d[8 + i * 3];
                if (c->h < 1 || c->h > 4 || c->v < 1 || c->v > 4 || c->tq > 3) { msg = "the JPEG is damaged"; goto done; }
                for (int k = 0; k < i; k++) if (j->comp[k].id == c->id) { msg = "the JPEG is damaged"; goto done; }
                if (c->h > j->hmax) j->hmax = c->h;
                if (c->v > j->vmax) j->vmax = c->v;
            }
            j->mcux = (j->w + 8 * j->hmax - 1) / (8 * j->hmax);
            j->mcuy = (j->h + 8 * j->vmax - 1) / (8 * j->vmax);
            // Big images at an eighth of their size: a thumbnail needs no more, and the memory stays
            // small whatever the image claims.
            j->dc_only = (int64_t)j->w * j->h > 4000000;
            int px = j->dc_only ? 1 : 8;
            for (int i = 0; i < j->ncomp; i++) {
                jcomp_t *c = &j->comp[i];
                c->bw = j->mcux * c->h;
                c->bh = j->mcuy * c->v;
                c->stride = c->bw * px;
                c->plane = calloc((size_t)c->bw * (size_t)px * (size_t)c->bh * (size_t)px, 1);
                if (!c->plane) { msg = "out of memory"; goto done; }
            }
            have_frame = 1;
        } else if ((m >= 0xC2 && m <= 0xC3) || (m >= 0xC5 && m <= 0xC7) || (m >= 0xC9 && m <= 0xCB) || (m >= 0xCD && m <= 0xCF)) {
            msg = m == 0xC2 ? "chat doesn't show progressive JPEGs - download it instead"
                            : "chat only shows baseline JPEGs - download it instead";
            goto done;
        } else if (m == 0xDA) {
            if (!have_frame || dl < 1) { msg = "the JPEG is damaged"; goto done; }
            int ns = d[0];
            if (ns < 1 || ns > j->ncomp || dl < 1 + 2 * (size_t)ns + 3) { msg = "the JPEG is damaged"; goto done; }
            jcomp_t *sc[3];
            for (int i = 0; i < ns; i++) {
                int id = d[1 + i * 2], tb = d[2 + i * 2];
                sc[i] = NULL;
                for (int k = 0; k < j->ncomp; k++) if (j->comp[k].id == id) sc[i] = &j->comp[k];
                if (!sc[i]) { msg = "the JPEG is damaged"; goto done; }
                for (int k = 0; k < i; k++) if (sc[k] == sc[i]) { msg = "the JPEG is damaged"; goto done; }
                sc[i]->td = tb >> 4;
                sc[i]->ta = tb & 15;
                if (sc[i]->td > 3 || sc[i]->ta > 3 || !j->dc[sc[i]->td].set || !j->ac[sc[i]->ta].set || !j->qt_set[sc[i]->tq]) {
                    msg = "the JPEG's tables are missing"; goto done;
                }
            }
            const uint8_t *tail = d + 1 + 2 * ns;
            if (tail[0] != 0 || tail[1] != 63 || tail[2] != 0) { msg = "chat only shows baseline JPEGs - download it instead"; goto done; }
            if (ns > 1) {
                // An interleaved MCU is at most ten blocks.
                int blocks = 0;
                for (int i = 0; i < ns; i++) blocks += sc[i]->h * sc[i]->v;
                if (blocks > 10) { msg = "the JPEG is damaged"; goto done; }
            }
            if (decode_scan(j, sc, ns) != 0) { msg = "the JPEG's image data is damaged"; goto done; }
            scans++;
            // On past the scan's data to the marker after it.
            j->bitcnt = 0;
        } else if (m == 0xD8) {
            msg = "the JPEG is damaged";
            goto done;
        }
    }
    if (msg) goto done;

    {
        int scale = j->dc_only ? 8 : 1;
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
                    float yy = (float)s[0], cb = (float)s[1] - 128.0f, cr = (float)s[2] - 128.0f;
                    r = (int)lrintf(yy + 1.402f * cr);
                    g = (int)lrintf(yy - 0.344136f * cb - 0.714136f * cr);
                    b = (int)lrintf(yy + 1.772f * cb);
                    r = r < 0 ? 0 : r > 255 ? 255 : r;
                    g = g < 0 ? 0 : g > 255 ? 255 : g;
                    b = b < 0 ? 0 : b > 255 ? 255 : b;
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

int image_thumbnail(const uint8_t *data, size_t len, int max_w, int max_h, const uint8_t bg[3],
                    image_thumb_t *out, char *why, size_t why_cap) {
    memset(out, 0, sizeof *out);
    static const uint8_t dark[3] = { 0, 0, 0 };
    if (!bg) bg = dark;
    if (max_w < 1 || max_h < 1) return fail(why, why_cap, "no room to show it");
    const char *kind = image_kind(data, len);
    if (!kind) return fail(why, why_cap, "not a PNG or JPEG image");
    if (strcmp(kind, "png") == 0) return png_thumb(data, len, max_w, max_h, bg, out, why, why_cap);
    return jpeg_thumb(data, len, max_w, max_h, out, why, why_cap);
}
