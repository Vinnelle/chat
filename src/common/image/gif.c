// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// GIF: the first frame.
#include "common/image/decode.h"
#include <stdlib.h>

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

int gif_thumb(const uint8_t *p, size_t len, int max_w, int max_h, const uint8_t bg[3], image_thumb_t *out,
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
