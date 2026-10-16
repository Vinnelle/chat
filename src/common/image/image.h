// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_IMAGE_H
#define CHAT_IMAGE_H

#include <stddef.h>
#include <stdint.h>

// PNG, baseline and progressive JPEG, and the first frame of a GIF, decoded only as far as a
// thumbnail to show in the chat. Images come from other people, so none of their data is trusted.
// Every length, table and dimension is checked before it's used, PNG's compressed data can only
// inflate to the size its header gives, and the full size image is never held in memory. Each
// pixel is added straight into the thumbnail pixel it falls in. A JPEG that's large, or where an
// eighth of its size is as big as the thumbnail, is read at an eighth of its size, one block at a
// time, so memory use stays small whatever size it claims to be.

// The largest size an image can claim. Anything bigger isn't shown.
#define IMAGE_MAX_SIDE 30000
#define IMAGE_MAX_PIXELS 120000000u
// A PNG's inflated pixel data, the only thing held at full size.
#define IMAGE_MAX_RAW (128u * 1024 * 1024)

typedef struct {
    int w, h;          // the thumbnail's
    int src_w, src_h;  // the image's own
    uint8_t *rgb;      // w * h * 3, malloc'd
} image_thumb_t;

// "png", "jpeg", "gif", or NULL for none of them. Only looks at the first bytes.
const char *image_kind(const uint8_t *data, size_t len);

// Scales the image to fit in max_w by max_h, keeping its aspect ratio, with transparency drawn
// over bg. Returns 0, or -1 with the reason: not an image chat can show, damaged, or too big.
int image_thumbnail(const uint8_t *data, size_t len, int max_w, int max_h, const uint8_t bg[3],
                    image_thumb_t *out, char *why, size_t why_cap);
void image_thumb_free(image_thumb_t *t);

#endif
