// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What a security key answers, as anything plugged in could: getInfo, then makeCredential, a probe
// or getAssertion with hmac-secret, each answer the next piece of the input.
#include "ctap2.h"
#include "crypto/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void check(int ok) { if (!ok) abort(); }

typedef struct { const uint8_t *p; size_t left; } feed_t;

// Each answer is two bytes of length, then that many bytes, cut short where the input ends.
static long answer(void *ctx, const uint8_t *msg, size_t len, uint8_t *rsp, size_t cap, char *why, size_t why_cap) {
    (void)msg; (void)len;
    feed_t *f = ctx;
    if (f->left < 2) {
        snprintf(why, why_cap, "unplugged");
        return CTAP2_IO;
    }
    size_t n = (size_t)f->p[0] << 8 | f->p[1];
    f->p += 2;
    f->left -= 2;
    if (n > f->left) n = f->left;
    if (n > cap) n = cap;
    memcpy(rsp, f->p, n);
    f->p += n;
    f->left -= n;
    return (long)n;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    crypto_setup();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const uint8_t c1[16] = { 1 }, c2[64] = { 2 }, salt[CTAP2_SALT_LEN] = { 3 };
    static const uint8_t *const creds[2] = { c1, c2 };
    static const size_t lens[2] = { sizeof c1, sizeof c2 };
    if (size < 1) return 0;
    uint8_t how = data[0];
    feed_t f = { data + 1, size - 1 };
    char why[256] = "";
    ctap2_info_t info;
    if (ctap2_get_info(answer, &f, &info, why, sizeof why) == 0) {
        check(info.protocols != 0);
    } else {
        // One that can't describe itself is asked the rest anyway, as one that described itself so.
        memset(&info, 0, sizeof info);
        info.hmac_secret = 1;
        info.protocols = how & 1 ? 1 << 2 : 1 << 1;
        info.token_perms = how >> 1 & 1;
    }
    const char *pin = how & 4 ? "1234" : NULL;
    uint8_t cred[CTAP2_CRED_MAX], secret[CTAP2_SECRET_LEN];
    size_t cred_len = 0;
    int which = -1, n = how & 8 ? 2 : 1;
    switch (how >> 4 & 3) {
        case 0:
            if (ctap2_make(answer, &f, &info, pin, cred, &cred_len, why, sizeof why) == 0)
                check(cred_len > 0 && cred_len <= CTAP2_CRED_MAX);
            break;
        case 1:
            if (ctap2_probe(answer, &f, creds, lens, n, &which, why, sizeof why) == 1) check(which >= 0 && which < n);
            break;
        default:
            if (ctap2_secret(answer, &f, &info, creds, lens, n, salt, pin != NULL, pin, secret, &which, why, sizeof why) == 0)
                check(which >= 0 && which < n);
            break;
    }
    return 0;
}
