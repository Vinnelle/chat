// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// image.h's functions, and the thumbnail the decoders add their pixels to.
#include "common/image/decode.h"
#include <stdlib.h>
#include <string.h>

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

// As wide as allowed (never wider than the source), then scaled down to fit if that's too tall.
void thumb_fit(int sw, int sh, int max_w, int max_h, int *tw_out, int *th_out) {
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

void acc_free(thumb_acc_t *a) {
    free(a->acc);
    free(a->col);
    a->acc = NULL;
    a->col = a->row = NULL;
}

int acc_init(thumb_acc_t *a, int sw, int sh, int max_w, int max_h) {
    memset(a, 0, sizeof *a);
    if (sw < 1 || sh < 1 || max_w < 1 || max_h < 1) return -1;
    a->sw = sw;
    a->sh = sh;
    thumb_fit(sw, sh, max_w, max_h, &a->tw, &a->th);
    a->acc = calloc((size_t)a->tw * (size_t)a->th * ACC_FIELDS, sizeof *a->acc);
    // Worked out once here, rather than with two divisions for every source pixel.
    a->col = malloc(((size_t)sw + (size_t)sh) * sizeof *a->col);
    if (!a->acc || !a->col) { acc_free(a); return -1; }
    a->row = a->col + sw;
    for (int x = 0; x < sw; x++) a->col[x] = (int)((int64_t)x * a->tw / sw);
    for (int y = 0; y < sh; y++) a->row[y] = (int)((int64_t)y * a->th / sh);
    return 0;
}

// A rectangle of one colour, x0 to x1 by y0 to y1 (not including x1 and y1), added a thumbnail pixel
// at a time rather than a source pixel at a time, so a GIF claiming a huge screen around a small
// frame costs no more than the thumbnail.
void acc_fill(thumb_acc_t *a, int x0, int y0, int x1, int y1, const uint8_t rgb[3]) {
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

int acc_finish(thumb_acc_t *a, int src_w, int src_h, image_thumb_t *out) {
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
