// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Pictures cleaned before they're offered. Whatever is in them is the sender's own, but it's still
// read as untrusted: every length is checked before it's used, and anything that doesn't add up
// fails the clean rather than being copied through.
#include "common/clean.h"
#include "common/image.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *p;
    size_t n, cap;
    int bad;
} out_t;

static void put(out_t *o, const void *d, size_t n) {
    if (o->bad || n == 0) return;
    if (n > o->cap - o->n) {
        size_t cap = o->cap ? o->cap : 4096;
        while (cap - o->n < n) {
            if (cap > SIZE_MAX / 2) { o->bad = 1; return; }
            cap *= 2;
        }
        uint8_t *q = realloc(o->p, cap);
        if (!q) { o->bad = 1; return; }
        o->p = q;
        o->cap = cap;
    }
    memcpy(o->p + o->n, d, n);
    o->n += n;
}

static void put1(out_t *o, uint8_t b) { put(o, &b, 1); }

static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

// ---- JPEG ----

#define M_TEM 0x01
#define M_SOF0 0xC0
#define M_SOF1 0xC1
#define M_DHT 0xC4
#define M_DAC 0xCC
#define M_SOF15 0xCF
#define M_RST0 0xD0
#define M_RST7 0xD7
#define M_EOI 0xD9
#define M_SOS 0xDA
#define M_DQT 0xDB
#define M_DNL 0xDC
#define M_DRI 0xDD
#define M_DHP 0xDE
#define M_EXP 0xDF
#define M_APP0 0xE0
#define M_APP1 0xE1
#define M_APP2 0xE2
#define M_APP13 0xED
#define M_APP14 0xEE
#define M_COM 0xFE
#define COEFS 64
#define EXIF_HEAD 6
#define TIFF_HEAD 8
#define IFD_ENTRY 12
#define TAG_ORIENTATION 0x0112
#define TAG_GPS 0x8825
#define TIFF_SHORT 3
#define ORIENT_MAX 8
// One in this many coefficients that can move does.
#define NOISE_EVERY 8
// More blocks than the largest picture chat takes could have mean a damaged header.
#define BLOCKS_MAX (IMAGE_MAX_PIXELS / 16u)

// The next marker at *i, past any fill bytes, with *i after it. -1 if there isn't one there.
static int next_marker(const uint8_t *p, size_t len, size_t *i) {
    if (*i + 1 >= len || p[*i] != 0xFF) return -1;
    while (*i + 1 < len && p[*i + 1] == 0xFF) (*i)++;
    if (*i + 1 >= len) return -1;
    int m = p[*i + 1];
    *i += 2;
    return m;
}

// The length of the segment at at (its two length bytes included), if it's all there.
static int seg_len(const uint8_t *p, size_t len, size_t at, size_t *n) {
    if (len - at < 2) return -1;
    size_t l = (size_t)p[at] << 8 | p[at + 1];
    if (l < 2 || l > len - at) return -1;
    *n = l;
    return 0;
}

// Where the entropy-coded data starting at i ends: at the first marker that isn't a restart or a
// stuffed byte.
static size_t ecs_end(const uint8_t *p, size_t len, size_t i) {
    while (i < len) {
        if (p[i] != 0xFF || i + 1 >= len) { i++; continue; }
        uint8_t nx = p[i + 1];
        if (nx == 0x00 || (nx >= M_RST0 && nx <= M_RST7)) { i += 2; continue; }
        if (nx == 0xFF) { i++; continue; }
        return i;
    }
    return len;
}

static unsigned rd16(const uint8_t *q, int le) { return le ? (unsigned)(q[0] | q[1] << 8) : (unsigned)(q[0] << 8 | q[1]); }

static uint32_t rd32(const uint8_t *q, int le) {
    return le ? (uint32_t)q[0] | (uint32_t)q[1] << 8 | (uint32_t)q[2] << 16 | (uint32_t)q[3] << 24 : be32(q);
}

// The Orientation in the first IFD of an Exif segment (1 if it has none), and whether it has GPS.
static int exif_orientation(const uint8_t *d, size_t n, int *gps) {
    if (n < EXIF_HEAD + TIFF_HEAD || memcmp(d, "Exif\0\0", EXIF_HEAD) != 0) return 1;
    const uint8_t *t = d + EXIF_HEAD;
    size_t tn = n - EXIF_HEAD;
    int le = t[0] == 'I' && t[1] == 'I';
    if (!le && !(t[0] == 'M' && t[1] == 'M')) return 1;
    if (rd16(t + 2, le) != 42) return 1;
    uint32_t ifd = rd32(t + 4, le);
    if (ifd > tn - 2) return 1;
    unsigned count = rd16(t + ifd, le);
    int orient = 1;
    for (unsigned k = 0; k < count; k++) {
        size_t e = ifd + 2 + (size_t)k * IFD_ENTRY;
        if (e > tn - IFD_ENTRY) break;
        unsigned tag = rd16(t + e, le), type = rd16(t + e + 2, le);
        if (tag == TAG_GPS) *gps = 1;
        if (tag == TAG_ORIENTATION && type == TIFF_SHORT && rd32(t + e + 4, le) == 1) {
            unsigned v = rd16(t + e + 8, le);
            if (v >= 1 && v <= ORIENT_MAX) orient = (int)v;
        }
    }
    return orient;
}

// An Exif segment with nothing in it but the Orientation.
static void put_orientation(out_t *o, int orient) {
    static const uint8_t head[] = {
        0xFF, M_APP1, 0x00, 0x22, 'E', 'x', 'i', 'f', 0, 0,      // length 34
        'I', 'I', 42, 0, 8, 0, 0, 0,                             // little-endian, the IFD at 8
        1, 0,                                                    // one entry
        0x12, 0x01, TIFF_SHORT, 0, 1, 0, 0, 0,                   // Orientation, a SHORT, one of it
    };
    uint8_t tail[] = { (uint8_t)orient, 0, 0, 0, 0, 0, 0, 0 };  // its value, then no next IFD
    put(o, head, sizeof head);
    put(o, tail, sizeof tail);
}

// Whether a segment before the scans is kept, and if not, what it was.
static int jpeg_keep(int m, const uint8_t *d, size_t n, unsigned *took) {
    switch (m) {
        case M_DQT: case M_DHT: case M_DRI: case M_DAC: case M_DNL: case M_DHP: case M_EXP:
            return 1;
        case M_APP0:
            // JFXX holds a thumbnail.
            if (n >= 5 && memcmp(d, "JFIF\0", 5) == 0) return 1;
            *took |= CLEAN_EXTRA;
            return 0;
        case M_APP1:
            *took |= n >= EXIF_HEAD && memcmp(d, "Exif\0\0", EXIF_HEAD) == 0 ? CLEAN_CAMERA : CLEAN_XMP;
            return 0;
        case M_APP2:
            // MPF: more pictures in the file, each with Exif of its own.
            if (n >= 12 && memcmp(d, "ICC_PROFILE\0", 12) == 0) return 1;
            *took |= CLEAN_EXTRA;
            return 0;
        case M_APP13:
            *took |= CLEAN_IPTC;
            return 0;
        case M_APP14:
            // Adobe's, which says how CMYK and YCCK colours are stored.
            if (n >= 5 && memcmp(d, "Adobe", 5) == 0) return 1;
            *took |= CLEAN_OTHER;
            return 0;
        case M_COM:
            *took |= CLEAN_COMMENT;
            return 0;
        default:
            if (m >= M_SOF0 && m <= M_SOF15) return 1;
            *took |= CLEAN_OTHER;
            return 0;
    }
}

typedef struct {
    uint16_t code[256];
    uint8_t size[256];
    uint8_t vals[256];
    int mincode[17], maxcode[17], valptr[17];
    int ok;
} jhuff_t;

typedef struct {
    int sequential;   // SOF0 or SOF1: one pass, Huffman coded
    int width, height, ncomp, hmax, vmax, restart;
    struct { int id, h, v; } comp[4];
    jhuff_t dc[4], ac[4];
    uint64_t rng;
    unsigned changed;
} jnoise_t;

static uint32_t rnd(jnoise_t *s) {
    s->rng ^= s->rng >> 12;
    s->rng ^= s->rng << 25;
    s->rng ^= s->rng >> 27;
    return (uint32_t)((s->rng * 2685821657736338717ull) >> 32);
}

// Codes are given out shortest first, in the order the values are listed, so the same table
// decodes a value and encodes it again.
static void build_huff(jhuff_t *h, const uint8_t bits[16], const uint8_t *vals) {
    memset(h, 0, sizeof *h);
    int code = 0, k = 0;
    for (int len = 1; len <= 16; len++) {
        h->valptr[len] = k;
        h->mincode[len] = code;
        for (int j = 0; j < bits[len - 1]; j++, k++, code++) {
            h->vals[k] = vals[k];
            h->code[vals[k]] = (uint16_t)code;
            h->size[vals[k]] = (uint8_t)len;
        }
        h->maxcode[len] = bits[len - 1] ? code - 1 : -1;
        if (code > (1 << len)) return;
        code <<= 1;
    }
    h->ok = 1;
}

static void parse_dht(jnoise_t *s, const uint8_t *d, size_t n) {
    size_t i = 0;
    while (n - i >= 17) {
        int tc = d[i] >> 4, th = d[i] & 15;
        size_t total = 0;
        for (int k = 0; k < 16; k++) total += d[i + 1 + k];
        if (tc > 1 || th > 3 || total > 256 || total > n - i - 17) return;
        build_huff(tc ? &s->ac[th] : &s->dc[th], d + i + 1, d + i + 17);
        i += 17 + total;
    }
}

static void parse_sof(jnoise_t *s, int m, const uint8_t *d, size_t n) {
    s->sequential = 0;
    if ((m != M_SOF0 && m != M_SOF1) || n < 6) return;
    s->height = d[1] << 8 | d[2];
    s->width = d[3] << 8 | d[4];
    s->ncomp = d[5];
    if ((d[0] != 8 && d[0] != 12) || s->ncomp < 1 || s->ncomp > 4 || n < 6 + 3 * (size_t)s->ncomp) return;
    s->hmax = s->vmax = 1;
    for (int c = 0; c < s->ncomp; c++) {
        s->comp[c].id = d[6 + 3 * c];
        s->comp[c].h = d[7 + 3 * c] >> 4;
        s->comp[c].v = d[7 + 3 * c] & 15;
        if (s->comp[c].h < 1 || s->comp[c].h > 4 || s->comp[c].v < 1 || s->comp[c].v > 4) return;
        if (s->comp[c].h > s->hmax) s->hmax = s->comp[c].h;
        if (s->comp[c].v > s->vmax) s->vmax = s->comp[c].v;
    }
    s->sequential = 1;
}

typedef struct {
    const uint8_t *p;
    size_t n, i;
    uint32_t acc;
    int nbits;
} jbits_t;

// No bits are read past a marker.
static int read_bit(jbits_t *b) {
    if (b->nbits == 0) {
        if (b->i >= b->n) return -1;
        uint8_t byte = b->p[b->i];
        if (byte == 0xFF) {
            if (b->i + 1 >= b->n || b->p[b->i + 1] != 0x00) return -1;
            b->i += 2;
        } else {
            b->i++;
        }
        b->acc = byte;
        b->nbits = 8;
    }
    b->nbits--;
    return (int)(b->acc >> b->nbits) & 1;
}

static int read_bits(jbits_t *b, int n) {
    int v = 0;
    for (int k = 0; k < n; k++) {
        int bit = read_bit(b);
        if (bit < 0) return -1;
        v = v << 1 | bit;
    }
    return v;
}

static int read_sym(jbits_t *b, const jhuff_t *h) {
    int code = 0;
    for (int len = 1; len <= 16; len++) {
        int bit = read_bit(b);
        if (bit < 0) return -1;
        code = code << 1 | bit;
        if (h->maxcode[len] >= 0 && code >= h->mincode[len] && code <= h->maxcode[len])
            return h->vals[h->valptr[len] + code - h->mincode[len]];
    }
    return -1;
}

// The rest of the byte is padding, then restart marker number n.
static int read_restart(jbits_t *b, int n) {
    b->nbits = 0;
    while (b->i + 1 < b->n && b->p[b->i] == 0xFF && b->p[b->i + 1] == 0xFF) b->i++;
    if (b->i + 1 >= b->n || b->p[b->i] != 0xFF || b->p[b->i + 1] != M_RST0 + (n & 7)) return -1;
    b->i += 2;
    return 0;
}

typedef struct {
    out_t *o;
    uint32_t acc;
    int nbits;
} jput_t;

// A byte of 0xFF in the data is followed by a 0, so it can't be taken for a marker.
static void put_bits(jput_t *w, uint32_t v, int n) {
    for (int k = n - 1; k >= 0; k--) {
        w->acc = w->acc << 1 | ((v >> k) & 1);
        if (++w->nbits == 8) {
            uint8_t byte = (uint8_t)w->acc;
            put1(w->o, byte);
            if (byte == 0xFF) put1(w->o, 0x00);
            w->acc = 0;
            w->nbits = 0;
        }
    }
}

// The last byte is padded with 1s, before a restart marker or at the end of a scan.
static void put_flush(jput_t *w) {
    if (w->nbits) put_bits(w, (1u << (8 - w->nbits)) - 1, 8 - w->nbits);
}

// A step up or down within the coefficient's size class: the top bit of its amplitude bits stays,
// so its size, and with it the Huffman symbol before it, doesn't change.
static int nudge(jnoise_t *s, int bits, int size) {
    int top = 1 << (size - 1), low = bits & (top - 1);
    if (low == 0) low++;
    else if (low == top - 1) low--;
    else low += (rnd(s) & 1) ? 1 : -1;
    s->changed++;
    return (bits & top) | low;
}

// One block, copied symbol for symbol, but for the amplitudes that move. The DC coefficient never
// does, so a block's overall brightness stays.
static int noise_block(jnoise_t *s, jbits_t *b, jput_t *w, const jhuff_t *dc, const jhuff_t *ac) {
    int t = read_sym(b, dc);
    if (t < 0 || t > 15) return -1;
    put_bits(w, dc->code[t], dc->size[t]);
    if (t) {
        int bits = read_bits(b, t);
        if (bits < 0) return -1;
        put_bits(w, (uint32_t)bits, t);
    }
    for (int k = 1; k < COEFS; ) {
        int rs = read_sym(b, ac);
        if (rs < 0) return -1;
        put_bits(w, ac->code[rs], ac->size[rs]);
        int run = rs >> 4, size = rs & 15;
        if (size == 0) {
            if (run != 15) break;
            k += 16;
            continue;
        }
        k += run;
        if (k >= COEFS) return -1;
        int bits = read_bits(b, size);
        if (bits < 0) return -1;
        if (size >= 2 && rnd(s) % NOISE_EVERY == 0) bits = nudge(s, bits, size);
        put_bits(w, (uint32_t)bits, size);
        k++;
    }
    return 0;
}

// One scan of a sequential JPEG, written again with noise. 1 if it was, 0 if the scan is to be
// copied as it is: progressive, arithmetic coded, or anything this can't follow.
static int noise_scan(jnoise_t *s, const uint8_t *hdr, size_t hn, const uint8_t *ecs, size_t en, out_t *o) {
    if (!s->sequential || s->width == 0 || s->height == 0 || hn < 1) return 0;
    int ns = hdr[0];
    if (ns < 1 || ns > 4 || hn < 1 + 2 * (size_t)ns + 3) return 0;
    struct { int h, v; const jhuff_t *dc, *ac; } sc[4];
    for (int k = 0; k < ns; k++) {
        int id = hdr[1 + 2 * k], td = hdr[2 + 2 * k] >> 4, ta = hdr[2 + 2 * k] & 15, f = -1;
        for (int c = 0; c < s->ncomp; c++) if (s->comp[c].id == id) f = c;
        if (f < 0 || td > 3 || ta > 3 || !s->dc[td].ok || !s->ac[ta].ok) return 0;
        sc[k].h = s->comp[f].h;
        sc[k].v = s->comp[f].v;
        sc[k].dc = &s->dc[td];
        sc[k].ac = &s->ac[ta];
    }
    if (hdr[1 + 2 * ns] != 0 || hdr[2 + 2 * ns] != COEFS - 1 || hdr[3 + 2 * ns] != 0) return 0;
    uint64_t mcus;
    if (ns == 1) {
        // Not interleaved: a block at a time, over the component's own size.
        uint64_t cw = ((uint64_t)s->width * (uint64_t)sc[0].h + (uint64_t)s->hmax - 1) / (uint64_t)s->hmax;
        uint64_t ch = ((uint64_t)s->height * (uint64_t)sc[0].v + (uint64_t)s->vmax - 1) / (uint64_t)s->vmax;
        mcus = ((cw + 7) / 8) * ((ch + 7) / 8);
    } else {
        uint64_t mw = 8 * (uint64_t)s->hmax, mh = 8 * (uint64_t)s->vmax;
        mcus = (((uint64_t)s->width + mw - 1) / mw) * (((uint64_t)s->height + mh - 1) / mh);
    }
    if (mcus == 0 || mcus > BLOCKS_MAX) return 0;
    jbits_t b = { ecs, en, 0, 0, 0 };
    jput_t w = { o, 0, 0 };
    size_t start = o->n;
    unsigned changed = s->changed;
    int rst = 0;
    for (uint64_t m = 0; m < mcus; m++) {
        if (s->restart && m > 0 && m % (uint64_t)s->restart == 0) {
            if (read_restart(&b, rst) != 0) goto copy;
            put_flush(&w);
            uint8_t mk[2] = { 0xFF, (uint8_t)(M_RST0 + (rst & 7)) };
            put(o, mk, 2);
            rst++;
        }
        for (int k = 0; k < ns; k++) {
            int blocks = ns == 1 ? 1 : sc[k].h * sc[k].v;
            for (int j = 0; j < blocks; j++)
                if (noise_block(s, &b, &w, sc[k].dc, sc[k].ac) != 0) goto copy;
        }
    }
    put_flush(&w);
    return !o->bad;
copy:
    o->n = start;
    s->changed = changed;
    return 0;
}

static int clean_jpeg(const uint8_t *p, size_t len, int noise, const uint8_t seed[CLEAN_SEED_LEN], out_t *o) {
    unsigned took = 0;
    // The Orientation first, wherever its Exif is, so it goes right after the JFIF header.
    int orient = 1, gps = 0;
    size_t i = 2;
    for (;;) {
        int m = next_marker(p, len, &i);
        if (m < 0 || m == M_SOS || m == M_EOI) break;
        if (m == M_TEM || (m >= M_RST0 && m <= M_RST7)) continue;
        size_t n;
        if (seg_len(p, len, i, &n) != 0) return -1;
        if (m == M_APP1) {
            int x = exif_orientation(p + i + 2, n - 2, &gps);
            if (x != 1) orient = x;
        }
        i += n;
    }
    if (gps) took |= CLEAN_LOCATION;
    static jnoise_t s;
    memset(&s, 0, sizeof s);
    for (int k = 0; k < CLEAN_SEED_LEN; k++) s.rng = s.rng << 8 ^ s.rng >> 56 ^ seed[k];
    if (!s.rng) s.rng = 1;
    put(o, p, 2);
    int wrote_orient = orient == 1, scans = 0;
    i = 2;
    for (;;) {
        int m = next_marker(p, len, &i);
        if (m < 0) {
            // Cut off after its scans: it's finished as a whole file would be.
            if (!scans) return -1;
            put(o, "\xFF\xD9", 2);
            break;
        }
        if (m == M_EOI) {
            put(o, "\xFF\xD9", 2);
            // A motion photo's video, or another picture.
            if (i < len) took |= CLEAN_EXTRA;
            break;
        }
        if (m == M_TEM || (m >= M_RST0 && m <= M_RST7)) continue;
        size_t n;
        if (seg_len(p, len, i, &n) != 0) return -1;
        const uint8_t *d = p + i + 2;
        size_t dn = n - 2;
        uint8_t mk[2] = { 0xFF, (uint8_t)m };
        if (!wrote_orient && m != M_APP0) {
            put_orientation(o, orient);
            wrote_orient = 1;
        }
        if (m == M_SOS) {
            put(o, mk, 2);
            put(o, p + i, n);
            size_t ecs = i + n, end = ecs_end(p, len, ecs);
            if (!noise || !noise_scan(&s, d, dn, p + ecs, end - ecs, o)) put(o, p + ecs, end - ecs);
            scans++;
            i = end;
            continue;
        }
        if (jpeg_keep(m, d, dn, &took)) {
            put(o, mk, 2);
            put(o, p + i, n);
            if (m == M_DHT) parse_dht(&s, d, dn);
            else if (m == M_DRI && dn == 2) s.restart = d[0] << 8 | d[1];
            else if (m >= M_SOF0 && m <= M_SOF15 && m != M_DHT && m != M_DAC) parse_sof(&s, m, d, dn);
        }
        i += n;
    }
    if (s.changed) took |= CLEAN_NOISE;
    return o->bad ? -1 : (int)took;
}

// ---- PNG ----

#define PNG_SIG 8
#define CHUNK_HEAD 8
#define CHUNK_CRC 4

static int clean_png(const uint8_t *p, size_t len, out_t *o) {
    // What drawing it needs, including colour (iCCP, cICP and the rest) and animation.
    static const char *const KEEP[] = { "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "gAMA", "cHRM", "sRGB", "iCCP",
                                        "cICP", "sBIT", "bKGD", "pHYs", "acTL", "fcTL", "fdAT" };
    static const char XMP_KEY[] = "XML:com.adobe.xmp";
    unsigned took = 0;
    put(o, p, PNG_SIG);
    size_t i = PNG_SIG;
    while (len - i >= CHUNK_HEAD + CHUNK_CRC) {
        uint32_t n = be32(p + i);
        if (n > len - i - CHUNK_HEAD - CHUNK_CRC) return -1;
        const uint8_t *type = p + i + 4, *d = p + i + CHUNK_HEAD;
        size_t whole = CHUNK_HEAD + (size_t)n + CHUNK_CRC;
        int keep = 0;
        for (size_t k = 0; k < sizeof KEEP / sizeof KEEP[0]; k++) keep |= memcmp(type, KEEP[k], 4) == 0;
        if (keep) put(o, p + i, whole);
        else if (memcmp(type, "iTXt", 4) == 0 && n >= sizeof XMP_KEY && memcmp(d, XMP_KEY, sizeof XMP_KEY) == 0)
            took |= CLEAN_XMP;
        else if (memcmp(type, "tEXt", 4) == 0 || memcmp(type, "zTXt", 4) == 0 || memcmp(type, "iTXt", 4) == 0)
            took |= CLEAN_COMMENT;
        else if (memcmp(type, "eXIf", 4) == 0) took |= CLEAN_CAMERA;
        else if (memcmp(type, "tIME", 4) == 0) took |= CLEAN_TIME;
        else took |= CLEAN_OTHER;
        i += whole;
        if (memcmp(type, "IEND", 4) == 0) {
            if (i < len) took |= CLEAN_EXTRA;
            return o->bad ? -1 : (int)took;
        }
    }
    return -1;
}

// ---- GIF ----

#define GIF_HEAD 13
#define GIF_FLAGS_AT 10
#define GIF_TABLE 0x80
#define GIF_IMAGE 0x2C
#define GIF_EXT 0x21
#define GIF_END 0x3B
#define GIF_IMAGE_HEAD 10
#define GIF_APP_ID 11
#define EXT_GRAPHIC 0xF9
#define EXT_TEXT 0x01
#define EXT_COMMENT 0xFE
#define EXT_APP 0xFF

static int skip_blocks(const uint8_t *p, size_t len, size_t *i) {
    while (*i < len) {
        size_t n = p[(*i)++];
        if (n == 0) return 0;
        if (n > len - *i) return -1;
        *i += n;
    }
    return -1;
}

static size_t colour_table(int flags) { return flags & GIF_TABLE ? (size_t)3 << ((flags & 7) + 1) : 0; }

static int clean_gif(const uint8_t *p, size_t len, out_t *o) {
    if (len < GIF_HEAD) return -1;
    unsigned took = 0;
    size_t i = GIF_HEAD + colour_table(p[GIF_FLAGS_AT]);
    if (i > len) return -1;
    put(o, p, i);
    while (i < len) {
        size_t start = i;
        if (p[i] == GIF_END) {
            put1(o, GIF_END);
            if (i + 1 < len) took |= CLEAN_EXTRA;
            return o->bad ? -1 : (int)took;
        }
        if (p[i] == GIF_IMAGE) {
            if (len - i < GIF_IMAGE_HEAD + 1) return -1;
            i += GIF_IMAGE_HEAD + colour_table(p[i + GIF_IMAGE_HEAD - 1]);
            // The LZW code size, then the data.
            if (i >= len) return -1;
            i++;
            if (skip_blocks(p, len, &i) != 0) return -1;
            put(o, p + start, i - start);
            continue;
        }
        if (p[i] != GIF_EXT || len - i < 2) return -1;
        int label = p[i + 1], keep = label == EXT_GRAPHIC || label == EXT_TEXT;
        i += 2;
        if (label == EXT_APP) {
            // Only the ones that say how an animation loops.
            int app = len - i > GIF_APP_ID && p[i] == GIF_APP_ID;
            if (app && (memcmp(p + i + 1, "NETSCAPE2.0", GIF_APP_ID) == 0 || memcmp(p + i + 1, "ANIMEXTS1.0", GIF_APP_ID) == 0))
                keep = 1;
            else took |= app && memcmp(p + i + 1, "XMP DataXMP", GIF_APP_ID) == 0 ? CLEAN_XMP : CLEAN_OTHER;
        } else if (label == EXT_COMMENT) {
            took |= CLEAN_COMMENT;
        } else if (!keep) {
            took |= CLEAN_OTHER;
        }
        if (skip_blocks(p, len, &i) != 0) return -1;
        if (keep) put(o, p + start, i - start);
    }
    // No trailer: it gets one.
    put1(o, GIF_END);
    return o->bad ? -1 : (int)took;
}

int image_clean(const uint8_t *in, size_t len, int noise, const uint8_t seed[CLEAN_SEED_LEN], uint8_t **out,
                size_t *out_len) {
    *out = NULL;
    *out_len = 0;
    const char *kind = image_kind(in, len);
    if (!kind) return -1;
    out_t o = { NULL, 0, 0, 0 };
    o.cap = len + len / 8 + 64;
    if (!(o.p = malloc(o.cap))) return -1;
    int took = strcmp(kind, "jpeg") == 0 ? clean_jpeg(in, len, noise, seed, &o)
             : strcmp(kind, "png") == 0 ? clean_png(in, len, &o) : clean_gif(in, len, &o);
    if (took < 0 || o.bad) {
        free(o.p);
        return -1;
    }
    *out = o.p;
    *out_len = o.n;
    return took;
}

// ---- what chat can't clean, and names ----

static int lower(int ch) { return ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch; }

static int starts_nocase(const char *s, const char *prefix) {
    for (; *prefix; s++, prefix++) if (lower((unsigned char)*s) != lower((unsigned char)*prefix)) return 0;
    return 1;
}

static int ends_nocase(const char *s, const char *suffix) {
    size_t n = strlen(s), k = strlen(suffix);
    return n >= k && starts_nocase(s + n - k, suffix);
}

const char *clean_cannot(const uint8_t *h, size_t n, const char *name) {
    static const char *const OFFICE[] = { ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".doc", ".xls", ".ppt" };
    if (n >= 12 && memcmp(h + 4, "ftyp", 4) == 0) {
        const uint8_t *brand = h + 8;
        if (!memcmp(brand, "heic", 4) || !memcmp(brand, "heix", 4) || !memcmp(brand, "mif1", 4) || !memcmp(brand, "msf1", 4))
            return "HEIC picture";
        if (!memcmp(brand, "avif", 4) || !memcmp(brand, "avis", 4)) return "AVIF picture";
        if (!memcmp(brand, "qt  ", 4)) return "QuickTime video";
        return "MP4 file";
    }
    if (n >= 12 && memcmp(h, "RIFF", 4) == 0 && memcmp(h + 8, "WEBP", 4) == 0) return "WebP picture";
    if (n >= 4 && (memcmp(h, "II*\0", 4) == 0 || memcmp(h, "MM\0*", 4) == 0)) return "TIFF or raw photo";
    if (n >= 5 && memcmp(h, "%PDF-", 5) == 0) return "PDF";
    for (size_t k = 0; name && k < sizeof OFFICE / sizeof OFFICE[0]; k++)
        if (ends_nocase(name, OFFICE[k])) return "office document";
    return NULL;
}

static int digit(char ch) { return ch >= '0' && ch <= '9'; }

static int date_sep(char ch) { return ch == '-' || ch == '_' || ch == '.' || ch == ' '; }

int clean_name_tells(const char *name) {
    static const char *const PREFIX[] = { "IMG", "PXL_", "DSC", "MVIMG", "PANO_", "GOPR", "DJI_", "Screenshot",
                                          "Screen Shot", "Screen_Shot", "photo_", "signal-", "WhatsApp Image",
                                          "Snapchat-", "Camera_" };
    for (size_t k = 0; k < sizeof PREFIX / sizeof PREFIX[0]; k++) if (starts_nocase(name, PREFIX[k])) return 1;
    int run = 0;
    for (const char *p = name; *p; p++) {
        run = digit(*p) ? run + 1 : 0;
        if (run >= 6) return 1;
    }
    // A date like 2026-10-12.
    for (const char *p = name; strlen(p) >= 10; p++)
        if (digit(p[0]) && digit(p[1]) && digit(p[2]) && digit(p[3]) && date_sep(p[4]) && digit(p[5]) && digit(p[6])
            && date_sep(p[7]) && digit(p[8]) && digit(p[9]))
            return 1;
    return 0;
}
