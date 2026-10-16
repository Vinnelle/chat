// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// JPEG, baseline and progressive.
#include "common/image/decode.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

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

int jpeg_thumb(const uint8_t *p, size_t len, int max_w, int max_h, image_thumb_t *out, char *why, size_t cap) {
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
            thumb_fit(j->w, j->h, max_w, max_h, &tw, &th);
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
