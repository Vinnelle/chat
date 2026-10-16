// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What a TPM answers, as anything at /dev/tpmrm0 could, and a sealed form as anyone who can write to
// a save's folder could leave its device file: tpm2_unseal of the sealed form the input starts with,
// or tpm2_seal, each answer the next piece of the input.
#include "tpm2.h"
#include "crypto/crypto.h"
#include <stdlib.h>
#include <string.h>

static void check(int ok) { if (!ok) abort(); }

typedef struct { const uint8_t *p; size_t left; } feed_t;

// Two bytes of length, then that many bytes, cut short where the input ends.
static const uint8_t *take(feed_t *f, size_t *n) {
    if (f->left < 2) return NULL;
    size_t want = (size_t)f->p[0] << 8 | f->p[1];
    f->p += 2;
    f->left -= 2;
    if (want > f->left) want = f->left;
    const uint8_t *p = f->p;
    f->p += want;
    f->left -= want;
    *n = want;
    return p;
}

// Each answer's size field is set to its length, and "busy, ask again" made an error, so the fuzzer's
// time goes past the framing, and not into retries' pauses.
static long answer(void *ctx, const uint8_t *cmd, size_t len, uint8_t *rsp, size_t cap) {
    (void)cmd; (void)len;
    size_t n;
    const uint8_t *p = take(ctx, &n);
    if (!p) return -1;
    if (n > cap) n = cap;
    memcpy(rsp, p, n);
    if (n >= 10) {
        for (int i = 0; i < 4; i++) rsp[2 + i] = (uint8_t)(n >> (24 - 8 * i));
        uint32_t rc = (uint32_t)rsp[6] << 24 | (uint32_t)rsp[7] << 16 | (uint32_t)rsp[8] << 8 | rsp[9];
        if (rc == 0x908 || rc == 0x90A || rc == 0x922) rsp[9] = 0x01;
    }
    return (long)n;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    crypto_setup();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const uint8_t secret[TPM2_SECRET_LEN] = { 7 };
    static uint8_t out[TPM2_SEALED_MAX];
    uint8_t got[TPM2_SECRET_LEN];
    char why[256] = "";
    if (size < 1) return 0;
    feed_t f = { data + 1, size - 1 };
    if (data[0] & 1) {
        long n = tpm2_seal(answer, &f, secret, out, sizeof out, why, sizeof why);
        check(n < 0 || (size_t)n <= sizeof out);
    } else {
        size_t n;
        const uint8_t *sealed = take(&f, &n);
        if (sealed) tpm2_unseal(answer, &f, sealed, n, got, why, sizeof why);
    }
    return 0;
}
