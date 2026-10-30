// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Android gives apps a security key only through its USB and NFC APIs on the Java side, never as a
// device file a program can open, so a save can't need one here.
#include "platform/platform.h"
#include "common/util.h"

static const char WHY[] = "Android: chat can't talk to security keys itself";

int platform_seckey_usable(char *why, size_t why_cap) {
    copy_str(why, WHY, why_cap);
    return -1;
}

int platform_seckey_make(const uint8_t salt[SECKEY_SALT_LEN], const char *pin, uint8_t cred[SECKEY_CRED_MAX],
                         size_t *cred_len, int *uv, uint8_t secret[SECKEY_SECRET_LEN], seckey_wait_t *w, char *why,
                         size_t why_cap) {
    (void)salt; (void)pin; (void)cred; (void)cred_len; (void)uv; (void)secret; (void)w;
    copy_str(why, WHY, why_cap);
    return -1;
}

int platform_seckey_secret(const uint8_t *const *creds, const size_t *lens, const int *uv, int n,
                           const uint8_t salt[SECKEY_SALT_LEN], const char *pin, uint8_t secret[SECKEY_SECRET_LEN],
                           seckey_wait_t *w, char *why, size_t why_cap) {
    (void)creds; (void)lens; (void)uv; (void)n; (void)salt; (void)pin; (void)secret; (void)w;
    copy_str(why, WHY, why_cap);
    return -1;
}
