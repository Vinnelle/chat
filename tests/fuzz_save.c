// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// A save's files as anyone who can write to its folder could leave them: a securitykey file, which
// has to read back the same once written out again, and a sealed file's header, which says what
// Argon2id it takes, and what else it needs, before anything is opened.
#include "app/install.c"

static void check(int ok) { if (!ok) abort(); }

static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

// No device or security key here: what install.c asks of them fails.
device_kind_t platform_device_sealed_kind(const uint8_t *sealed, size_t len) { (void)sealed; (void)len; return DEVICE_NONE; }
long platform_device_seal(const uint8_t secret[DEVICE_SECRET_LEN], uint8_t *out, size_t cap, char *why, size_t why_cap) {
    (void)secret; (void)out; (void)cap; (void)why; (void)why_cap;
    return -1;
}
int platform_device_unseal(const uint8_t *sealed, size_t len, uint8_t secret[DEVICE_SECRET_LEN], char *why, size_t why_cap) {
    (void)sealed; (void)len; (void)secret; (void)why; (void)why_cap;
    return -1;
}
void platform_device_forget(const uint8_t *sealed, size_t len) { (void)sealed; (void)len; }
int platform_seckey_make(const uint8_t salt[SECKEY_SALT_LEN], const char *pin, uint8_t cred[SECKEY_CRED_MAX],
                         size_t *cred_len, int *uv, uint8_t secret[SECKEY_SECRET_LEN], seckey_wait_t *w, char *why,
                         size_t why_cap) {
    (void)salt; (void)pin; (void)cred; (void)cred_len; (void)uv; (void)secret; (void)w; (void)why; (void)why_cap;
    return -1;
}
int platform_seckey_secret(const uint8_t *const *creds, const size_t *lens, const int *uv, int n,
                           const uint8_t salt[SECKEY_SALT_LEN], const char *pin, uint8_t secret[SECKEY_SECRET_LEN],
                           seckey_wait_t *w, char *why, size_t why_cap) {
    (void)creds; (void)lens; (void)uv; (void)n; (void)salt; (void)pin; (void)secret; (void)w; (void)why; (void)why_cap;
    return -1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    crypto_setup();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static key_file_t f;
    static uint8_t out[SECKEY_FILE_MAX], plain[VERIFIED_FILE_MAX];
    if (size <= SECKEY_FILE_MAX && key_file_parse(data, size, &f) == 0) {
        check(f.n >= 1 && f.n <= KEYS_MAX);
        check(key_file_pack(&f, out) == size && memcmp(out, data, size) == 0);
    }
    check((pass_needs(data, size) & ~PASS_NEEDS_ALL) == 0);
    // Argon2id only runs for small limits, or the fuzzer would spend its time waiting on it: the
    // checks on the limits run first either way.
    if (size >= PASS_SEAL_OVERHEAD && be32(data + 8) <= 2 && be32(data + 12) <= 64) {
        static const uint8_t device[PASS_DEVICE_SECRET_LEN] = { 1 }, key[PASS_KEY_SECRET_LEN] = { 2 };
        held_t h = { 0 };
        size_t got = 0;
        if (pass_lock_of("passphrase", data, size, &h.lock) == 0) {
            pass_lock_set(&h.lock, pass_needs(data, size), device, key);
            memcpy(h.device, device, sizeof h.device);
            memcpy(h.key, key, sizeof h.key);
            h.have_device = h.have_key = 1;
            if (size - PASS_SEAL_OVERHEAD <= sizeof plain && unseal_with(&h, data, size, plain, sizeof plain, &got) == 0)
                check(got == size - PASS_SEAL_OVERHEAD);
        }
    }
    return 0;
}
