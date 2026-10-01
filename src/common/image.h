// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_IMAGE_H
#define CHAT_IMAGE_H

#include <stddef.h>
#include <stdint.h>

// PNG and baseline JPEG, decoded only as far as a thumbnail to show in the chat. Images come from
// other people, so nothing here trusts a byte of them: every length, table and dimension is
// checked before it's used, PNG's compressed data may inflate to exactly what its header says and
// no further, and the full-size image is never held at all. Each pixel goes straight into the
// thumbnail's average for its place; a large JPEG is read at an eighth of its size, a block at a
// time, so its memory stays small whatever it claims to be.

// What an image may claim to be. Past these it isn't shown.
#define IMAGE_MAX_SIDE 30000
#define IMAGE_MAX_PIXELS 120000000u
// A PNG's pixels inflated, the one thing held at full size.
#define IMAGE_MAX_RAW (128u * 1024 * 1024)

typedef struct {
    int w, h;          // the thumbnail's
    int src_w, src_h;  // the image's own
    uint8_t *rgb;      // w * h * 3, malloc'd
} image_thumb_t;

// "png", "jpeg", or NULL for neither (by the first bytes, which is all it goes by).
const char *image_kind(const uint8_t *data, size_t len);

// The image at most max_w by max_h, its shape kept; transparency is laid over bg. 0, or -1 with
// why: not an image chat can show, damaged, or bigger than it may be.
int image_thumbnail(const uint8_t *data, size_t len, int max_w, int max_h, const uint8_t bg[3],
                    image_thumb_t *out, char *why, size_t why_cap);
void image_thumb_free(image_thumb_t *t);

#endif
