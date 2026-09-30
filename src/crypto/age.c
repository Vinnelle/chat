// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "crypto/age.h"
#include "platform/platform.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t bech32_polymod(const uint8_t *values, size_t len) {
    static const uint32_t GEN[5] = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = (uint8_t)(chk >> 25);
        chk = ((chk & 0x1ffffff) << 5) ^ values[i];
        for (int j = 0; j < 5; j++)
            if ((b >> j) & 1) chk ^= GEN[j];
    }
    return chk;
}

static size_t convert_8_to_5(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint32_t acc = 0; int bits = 0; size_t n = 0;
    for (size_t i = 0; i < inlen; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 5) { bits -= 5; out[n++] = (uint8_t)((acc >> bits) & 0x1f); }
    }
    if (bits > 0) out[n++] = (uint8_t)((acc << (5 - bits)) & 0x1f);
    return n;
}

void age_export_recipient(const identity_keypair_t *idkp, char out[AGE_RECIPIENT_STRLEN + 1]) {
    uint8_t x25519_pub[32];
    if (crypto_sign_ed25519_pk_to_curve25519(x25519_pub, idkp->pub) != 0) {
        fprintf(stderr, "chat: identity key not convertible to AGE format\n");
        exit(1);
    }

    uint8_t data5[52 + 6];
    size_t n = convert_8_to_5(x25519_pub, 32, data5);

    static const char HRP[] = "age";

    uint8_t polymod_input[3 + 1 + 3 + 52 + 6 + 6];
    size_t p = 0;
    for (size_t i = 0; i < 3; i++) polymod_input[p++] = (uint8_t)(HRP[i] >> 5);
    polymod_input[p++] = 0;
    for (size_t i = 0; i < 3; i++) polymod_input[p++] = (uint8_t)(HRP[i] & 0x1f);
    for (size_t i = 0; i < n; i++) polymod_input[p++] = data5[i];
    size_t checksum_input_len = p;
    for (int i = 0; i < 6; i++) polymod_input[p++] = 0;

    uint32_t polymod = bech32_polymod(polymod_input, p) ^ 1u;
    uint8_t checksum[6];
    for (int i = 0; i < 6; i++) checksum[i] = (uint8_t)((polymod >> (5 * (5 - i))) & 0x1f);
    (void)checksum_input_len;

    size_t o = 0;
    memcpy(out, HRP, 3); o += 3;
    out[o++] = '1';
    for (size_t i = 0; i < n; i++) out[o++] = CHARSET[data5[i]];
    for (int i = 0; i < 6; i++) out[o++] = CHARSET[checksum[i]];
    out[o] = '\0';
}

// A character's 5-bit value, or -1. Upper case only: age-keygen writes the key that way, and
// bech32 never mixes cases.
static int bech32_upper_value(char c) {
    if (c == '\0' || (c >= 'a' && c <= 'z')) return -1;
    const char *hit = strchr(CHARSET, c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
    return hit ? (int)(hit - CHARSET) : -1;
}

int age_import_secret_key_text(const char *text, identity_keypair_t *idkp) {
    static const char PREFIX[] = "AGE-SECRET-KEY-1";
    static const char HRP[] = "age-secret-key-";
    enum { HRP_LEN = sizeof HRP - 1, DATA_LEN = AGE_SECRET_KEY_STRLEN - (sizeof PREFIX - 1) };
    const char *at = strstr(text, PREFIX);
    if (!at) return -1;
    at += sizeof PREFIX - 1;

    // The checksum runs over the HRP spread into high and low bits, then the data and checksum.
    uint8_t values[2 * HRP_LEN + 1 + DATA_LEN];
    size_t p = 0;
    for (size_t i = 0; i < HRP_LEN; i++) values[p++] = (uint8_t)(HRP[i] >> 5);
    values[p++] = 0;
    for (size_t i = 0; i < HRP_LEN; i++) values[p++] = (uint8_t)(HRP[i] & 0x1f);
    for (size_t i = 0; i < DATA_LEN; i++) {
        int v = bech32_upper_value(at[i]);
        if (v < 0) { sodium_memzero(values, sizeof values); return -1; }
        values[p++] = (uint8_t)v;
    }
    int rc = -1;
    if (bech32_polymod(values, p) == 1 && bech32_upper_value(at[DATA_LEN]) < 0) {
        // 52 five-bit groups: the 32-byte key, then four bits of padding that must be zero.
        const uint8_t *data5 = values + 2 * HRP_LEN + 1;
        uint8_t secret[32];
        uint32_t acc = 0;
        int bits = 0;
        size_t n = 0;
        for (size_t i = 0; i < DATA_LEN - 6; i++) {
            acc = (acc << 5) | data5[i];
            bits += 5;
            if (bits >= 8) { bits -= 8; secret[n++] = (uint8_t)(acc >> bits); }
        }
        if (n == 32 && (acc & ((1u << bits) - 1)) == 0) rc = identity_from_x25519(secret, idkp);
        sodium_memzero(secret, sizeof secret);
        sodium_memzero(&acc, sizeof acc);
    }
    sodium_memzero(values, sizeof values);
    return rc;
}

int age_import_secret_key(const char *path, identity_keypair_t *idkp) {
    char text[4096];
    long n = platform_read_file(path, text, sizeof(text) - 1);
    if (n < 0) return -1;
    text[n] = '\0';
    int rc = age_import_secret_key_text(text, idkp);
    sodium_memzero(text, sizeof text);
    return rc;
}
