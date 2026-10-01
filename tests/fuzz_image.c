// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Images as a peer could send them: whatever the bytes, a thumbnail of the size asked for, or a
// refusal with a reason. Built with FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION, which lets damaged
// checksums through so mutations reach the inflater and the decoders behind them.
#include "common/image.h"
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
    return 0;
}
