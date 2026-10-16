// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Images as a peer could send them: whatever the bytes, a thumbnail of the size asked for, or a
// refusal with a reason. And the cleaner, which either refuses or gives back a picture of the same
// kind that it can clean again. Built with FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION, which lets damaged
// checksums through so mutations reach the inflater and the decoders behind them.
#include "common/image/image.h"
#include "common/image/clean.h"
#include <stdlib.h>
#include <string.h>

static void check(int ok) { if (!ok) abort(); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const uint8_t bg[3] = { 30, 30, 30 };
    int max_w = size > 0 ? 1 + data[0] % 80 : 64, max_h = size > 1 ? 1 + data[1] % 60 : 48;
    image_thumb_t t;
    char why[160] = "";
    if (image_thumbnail(data, size, max_w, max_h, bg, &t, why, sizeof why) == 0) {
        check(t.w >= 1 && t.h >= 1 && t.w <= max_w && t.h <= max_h && t.rgb != NULL);
        check(t.src_w >= t.w && t.src_h >= t.h);
        // Every byte of it is there to read.
        unsigned sum = 0;
        for (size_t i = 0; i < (size_t)t.w * (size_t)t.h * 3; i++) sum += t.rgb[i];
        (void)sum;
        image_thumb_free(&t);
    } else {
        check(why[0] != '\0');
    }
    uint8_t seed[CLEAN_SEED_LEN] = { 0 }, *out = NULL, *again = NULL;
    size_t out_len = 0, again_len = 0;
    if (size > 2) memcpy(seed, data + 2, size - 2 < sizeof seed ? size - 2 : sizeof seed);
    if (image_clean(data, size, 1, seed, &out, &out_len) >= 0) {
        check(out != NULL && image_kind(out, out_len) != NULL);
        check(strcmp(image_kind(out, out_len), image_kind(data, size)) == 0);
        check(image_clean(out, out_len, 0, seed, &again, &again_len) >= 0);
        free(again);
    } else {
        check(out == NULL);
    }
    free(out);
    return 0;
}
