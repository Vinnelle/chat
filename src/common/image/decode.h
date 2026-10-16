// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What image.c and the decoders share: inflate.c, png.c, jpeg.c and gif.c. The rest of chat uses
// image.h.
#ifndef CHAT_IMAGE_DECODE_H
#define CHAT_IMAGE_DECODE_H

#include "common/image/image.h"
#include "common/util.h"
#include <stddef.h>
#include <stdint.h>

// A fuzzer's mutations would almost never get past the zlib and PNG checksums, so a fuzzing build
// doesn't check them.
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define CHECK_SUMS 0
#else
#define CHECK_SUMS 1
#endif

#define PNG_SIGNATURE "\x89PNG\r\n\x1a\n"
#define PNG_SIGNATURE_LEN (sizeof PNG_SIGNATURE - 1)

static inline int fail(char *why, size_t cap, const char *msg) {
    if (why && cap) copy_str(why, msg, cap);
    return -1;
}

static inline int le16(const uint8_t *p) { return p[0] | (p[1] << 8); }

static inline int sides_ok(uint32_t w, uint32_t h) {
    return w >= 1 && h >= 1 && w <= IMAGE_MAX_SIDE && h <= IMAGE_MAX_SIDE && (uint64_t)w * h <= IMAGE_MAX_PIXELS;
}

// ---- the thumbnail: each source pixel is added to the average for the pixel it falls in ----

enum { ACC_R, ACC_G, ACC_B, ACC_COUNT, ACC_FIELDS };

typedef struct {
    int sw, sh, tw, th;
    uint64_t *acc;   // tw * th * ACC_FIELDS: red, green, blue, and how many
    int *col, *row;  // the thumbnail column each source column falls in, and the row each row does
} thumb_acc_t;

static inline uint64_t *acc_cell(const thumb_acc_t *a, int tx, int ty) {
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

// image.c
void thumb_fit(int sw, int sh, int max_w, int max_h, int *tw_out, int *th_out);
int acc_init(thumb_acc_t *a, int sw, int sh, int max_w, int max_h);
void acc_free(thumb_acc_t *a);
void acc_fill(thumb_acc_t *a, int x0, int y0, int x1, int y1, const uint8_t rgb[3]);
int acc_finish(thumb_acc_t *a, int src_w, int src_h, image_thumb_t *out);

// inflate.c
int zlib_inflate(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

// png.c
int png_thumb(const uint8_t *p, size_t len, int max_w, int max_h, const uint8_t bg[3], image_thumb_t *out,
              char *why, size_t cap);

// jpeg.c
int jpeg_thumb(const uint8_t *p, size_t len, int max_w, int max_h, image_thumb_t *out, char *why, size_t cap);

// gif.c
int gif_thumb(const uint8_t *p, size_t len, int max_w, int max_h, const uint8_t bg[3], image_thumb_t *out,
              char *why, size_t cap);

#endif
