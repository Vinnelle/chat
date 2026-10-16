// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// PGP and AGE secret-key import (a file the user picked, or text they pasted).
#include "crypto/pgp.h"
#include "crypto/age.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    if (sodium_init() < 0) abort();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Seed inputs often lack the armor lines, or the AGE key prefix; add them some of the time so
    // the decoders get exercised.
    static const char begin[] = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n";
    static const char end[] = "\n-----END PGP PRIVATE KEY BLOCK-----\n";
    static const char age_prefix[] = "AGE-SECRET-KEY-1";
    int wrap = size > 0 && (data[0] & 1);
    int age = size > 0 && (data[0] & 2);
    size_t cap = size + (wrap ? sizeof begin + sizeof end : 0) + (age ? sizeof age_prefix : 0) + 1;
    char *text = malloc(cap);
    if (!text) return 0;
    size_t n = 0;
    if (wrap) { memcpy(text, begin, sizeof begin - 1); n += sizeof begin - 1; }
    if (age) { memcpy(text + n, age_prefix, sizeof age_prefix - 1); n += sizeof age_prefix - 1; }
    memcpy(text + n, data, size); n += size;
    if (wrap) { memcpy(text + n, end, sizeof end - 1); n += sizeof end - 1; }
    text[n] = '\0';

    identity_keypair_t id, before;
    memset(&id, 0x5a, sizeof id);
    before = id;
    int rc = pgp_import_secret_key_text(text, &id);
    // A failed import must leave the identity it was given untouched.
    if (rc != 0 && memcmp(&id, &before, sizeof id) != 0) abort();
    if (rc == 0) {
        uint8_t pub[32];
        if (crypto_sign_ed25519_sk_to_pk(pub, id.priv) != 0 || memcmp(pub, id.pub, 32) != 0) abort();
    }

    memset(&id, 0x5a, sizeof id);
    rc = age_import_secret_key_text(text, &id);
    if (rc != 0 && memcmp(&id, &before, sizeof id) != 0) abort();
    if (rc == 0) {
        // A key that loaded has to sign in a way its public key verifies.
        static const uint8_t msg[] = "fuzz";
        uint8_t sig[ID_SIGN_LEN];
        identity_sign_bytes(&id, msg, sizeof msg, sig);
        if (!id.scalar || crypto_sign_verify_detached(sig, msg, sizeof msg, id.pub) != 0) abort();
    }
    free(text);
    return 0;
}
