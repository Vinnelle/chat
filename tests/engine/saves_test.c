// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Saves, through app/saves/: sealing them, device locks, security keys and authenticator codes,
// the shadow passphrase, the lock screen, histories, tor's state and kept rooms.
#include "harness.h"

// ---- a device and a security key of the test's own, for app/saves/ ----

static uint8_t g_fake_key[32];

device_kind_t platform_device_kind(char *why, size_t why_cap) { (void)why; (void)why_cap; return DEVICE_TPM; }

device_kind_t platform_device_sealed_kind(const uint8_t *sealed, size_t len) {
    return len == 4 + DEVICE_SECRET_LEN && memcmp(sealed, "TEST", 4) == 0 ? DEVICE_TPM : DEVICE_NONE;
}

const char *platform_device_uses(device_kind_t kind) { (void)kind; return "the test's device"; }

int platform_device_losses(device_kind_t kind, const char **out, int max) { (void)kind; (void)out; (void)max; return 0; }

long platform_device_seal(const uint8_t secret[DEVICE_SECRET_LEN], uint8_t *out, size_t cap, char *why, size_t why_cap) {
    (void)why; (void)why_cap;
    if (cap < 4 + DEVICE_SECRET_LEN) return -1;
    memcpy(out, "TEST", 4);
    for (int i = 0; i < DEVICE_SECRET_LEN; i++) out[4 + i] = secret[i] ^ 0x5a;
    return 4 + DEVICE_SECRET_LEN;
}

int platform_device_unseal(const uint8_t *sealed, size_t len, uint8_t secret[DEVICE_SECRET_LEN], char *why, size_t why_cap) {
    (void)why; (void)why_cap;
    if (platform_device_sealed_kind(sealed, len) != DEVICE_TPM) return -1;
    for (int i = 0; i < DEVICE_SECRET_LEN; i++) secret[i] = sealed[4 + i] ^ 0x5a;
    return 0;
}

void platform_device_forget(const uint8_t *sealed, size_t len) { (void)sealed; (void)len; }

int platform_seckey_usable(char *why, size_t why_cap) { (void)why; (void)why_cap; return 0; }

// Like hmac-secret: a secret for the credential and salt that only this "key" can make.
static void fake_secret(const uint8_t *cred, size_t n, const uint8_t salt[SECKEY_SALT_LEN], uint8_t out[SECKEY_SECRET_LEN]) {
    uint8_t msg[SECKEY_CRED_MAX + SECKEY_SALT_LEN];
    memcpy(msg, cred, n);
    memcpy(msg + n, salt, SECKEY_SALT_LEN);
    hmac_sha256(g_fake_key, sizeof g_fake_key, msg, n + SECKEY_SALT_LEN, out);
}

int platform_seckey_make(const uint8_t salt[SECKEY_SALT_LEN], const char *pin, uint8_t cred[SECKEY_CRED_MAX],
                         size_t *cred_len, int *uv, uint8_t secret[SECKEY_SECRET_LEN], seckey_wait_t *w, char *why,
                         size_t why_cap) {
    (void)pin; (void)why; (void)why_cap;
    gen_random(cred, 16);
    *cred_len = 16;
    *uv = 0;
    fake_secret(cred, 16, salt, secret);
    __atomic_add_fetch(&w->touches, 2, __ATOMIC_RELEASE);
    return 0;
}

int platform_seckey_secret(const uint8_t *const *creds, const size_t *lens, const int *uv, int n,
                           const uint8_t salt[SECKEY_SALT_LEN], const char *pin, uint8_t secret[SECKEY_SECRET_LEN],
                           seckey_wait_t *w, char *why, size_t why_cap) {
    (void)uv; (void)pin; (void)why; (void)why_cap;
    if (n < 1) return SECKEY_NO_CRED;
    fake_secret(creds[0], lens[0], salt, secret);
    __atomic_add_fetch(&w->touches, 1, __ATOMIC_RELEASE);
    return 0;
}

void test_passphrase_seal(double *t) {
    (void)t;
    static const uint8_t secret[104] = "a signing key, as :install packs it";
    static const char settings[] = "[profile]\nnick = \"alice\"\n";
    uint8_t sealed[sizeof secret + PASS_SEAL_OVERHEAD], opened[sizeof secret];
    uint8_t sealed2[sizeof settings + PASS_SEAL_OVERHEAD], opened2[sizeof settings];
    size_t n = 0, n2 = 0, got = 0;
    pass_lock_t lk, again, wrong;
    CHECK(pass_lock_new("correct horse", &lk) == 0, "making a lock failed");
    CHECK(pass_seal(&lk, secret, sizeof secret, sealed, sizeof sealed - 1, &n) == PASS_FORMAT,
          "sealing into too small a buffer didn't refuse");
    CHECK(pass_seal(&lk, secret, sizeof secret, sealed, sizeof sealed, &n) == 0 && n == sizeof sealed,
          "sealing failed, or made %zu bytes, want %zu", n, sizeof sealed);
    CHECK(pass_seal(&lk, settings, sizeof settings, sealed2, sizeof sealed2, &n2) == 0
          && memcmp(sealed, sealed2, PASS_HEADER_LEN) == 0 && memcmp(sealed + PASS_HEADER_LEN, sealed2 + PASS_HEADER_LEN,
                                                                     AEAD_NONCE_LEN) != 0,
          "two secrets under one lock didn't share its header, or shared a nonce");
    // One Argon2id run, from either file, opens both.
    int rc = pass_lock_of("correct horse", sealed2, n2, &again);
    CHECK(rc == 0, "the right passphrase didn't make a lock (%d)", rc);
    rc = pass_unseal(&again, sealed, n, opened, sizeof opened, &got);
    CHECK(rc == 0 && got == sizeof secret && memcmp(opened, secret, sizeof secret) == 0,
          "the right passphrase didn't open the key (%d)", rc);
    rc = pass_unseal(&again, sealed2, n2, opened2, sizeof opened2, &got);
    CHECK(rc == 0 && got == sizeof settings && memcmp(opened2, settings, sizeof settings) == 0,
          "the right passphrase didn't open the settings (%d)", rc);
    CHECK(pass_lock_of("correct horsf", sealed, n, &wrong) == 0
          && pass_unseal(&wrong, sealed, n, opened, sizeof opened, &got) == PASS_WRONG,
          "a wrong passphrase didn't fail as one");
    pass_lock_t other;
    CHECK(pass_lock_new("correct horse", &other) == 0
          && pass_unseal(&other, sealed, n, opened, sizeof opened, &got) == PASS_WRONG,
          "the same passphrase with another salt opened it");
    sealed[16] ^= 1;   // the salt
    CHECK(pass_unseal(&lk, sealed, n, opened, sizeof opened, &got) == PASS_WRONG
          && pass_lock_of("correct horse", sealed, n, &wrong) == 0
          && pass_unseal(&wrong, sealed, n, opened, sizeof opened, &got) == PASS_WRONG,
          "a changed header still opened");
    sealed[16] ^= 1;
    sealed[PASS_SEAL_OVERHEAD] ^= 1;   // the sealed secret
    CHECK(pass_unseal(&lk, sealed, n, opened, sizeof opened, &got) == PASS_WRONG, "a changed secret still opened");
    sealed[PASS_SEAL_OVERHEAD] ^= 1;
    sealed[12] = 0xff;   // an Argon2id memory limit no one would ask for
    CHECK(pass_lock_of("correct horse", sealed, n, &wrong) == PASS_FORMAT,
          "a tampered memory limit wasn't refused before Argon2id ran");
    uint8_t junk[PASS_SEAL_OVERHEAD + 8];
    memset(junk, 'x', sizeof junk);
    CHECK(pass_lock_of("correct horse", junk, sizeof junk, &wrong) == PASS_FORMAT
          && pass_unseal(&lk, junk, sizeof junk, opened, sizeof opened, &got) == PASS_FORMAT,
          "bytes that were never sealed weren't refused");
}

// A lock that needs a device: the passphrase alone opens and seals nothing under it, and its header
// can't be changed to say it needs no device.
void test_device_lock(double *t) {
    (void)t;
    static const char settings[] = "[profile]\nnick = \"alice\"\n";
    uint8_t secret[PASS_DEVICE_SECRET_LEN], other[PASS_DEVICE_SECRET_LEN], opened[sizeof settings];
    uint8_t plain[sizeof settings + PASS_SEAL_OVERHEAD], locked[sizeof settings + PASS_SEAL_OVERHEAD];
    uint8_t scratch[sizeof settings + PASS_SEAL_OVERHEAD];
    size_t n = 0, ln = 0, sn = 0, got = 0;
    gen_random(secret, sizeof secret);
    memcpy(other, secret, sizeof other);
    other[0] ^= 1;
    pass_lock_t lk, dev, again, wrong;
    CHECK(pass_lock_new("correct horse", &lk) == 0
          && pass_seal(&lk, settings, sizeof settings, plain, sizeof plain, &n) == 0 && !pass_needs(plain, n),
          "a lock without a device said it needed one");
    dev = lk;
    pass_lock_set(&dev, PASS_NEEDS_DEVICE, secret, NULL);
    CHECK(pass_seal(&dev, settings, sizeof settings, locked, sizeof locked, &ln) == 0
          && pass_needs(locked, ln) == PASS_NEEDS_DEVICE && memcmp(locked, "chatdev1", 8) == 0
          && memcmp(locked + 8, plain + 8, PASS_HEADER_LEN - 8) == 0,
          "a device lock's header didn't say so, or didn't keep the limits and salt");
    CHECK(pass_unseal(&lk, locked, ln, opened, sizeof opened, &got) == PASS_WRONG
          && pass_unseal(&dev, plain, n, opened, sizeof opened, &got) == PASS_WRONG,
          "one lock opened what the other sealed");
    int rc = pass_lock_of("correct horse", locked, ln, &again);
    CHECK(rc == 0 && pass_unseal(&again, locked, ln, opened, sizeof opened, &got) == PASS_WRONG
          && pass_seal(&again, settings, sizeof settings, scratch, sizeof scratch, &sn) == PASS_FORMAT,
          "the passphrase alone opened or sealed something under a device lock (%d)", rc);
    wrong = again;
    pass_lock_set(&wrong, PASS_NEEDS_DEVICE, other, NULL);
    CHECK(pass_unseal(&wrong, locked, ln, opened, sizeof opened, &got) == PASS_WRONG, "another device's secret opened it");
    pass_lock_set(&again, PASS_NEEDS_DEVICE, secret, NULL);
    rc = pass_unseal(&again, locked, ln, opened, sizeof opened, &got);
    CHECK(rc == 0 && got == sizeof settings && memcmp(opened, settings, sizeof settings) == 0,
          "the passphrase and the device's secret didn't open it (%d)", rc);
    memcpy(scratch, locked, ln);
    memcpy(scratch, plain, 8);
    CHECK(pass_lock_of("correct horse", scratch, ln, &wrong) == 0
          && pass_unseal(&wrong, scratch, ln, opened, sizeof opened, &got) == PASS_WRONG
          && pass_unseal(&again, scratch, ln, opened, sizeof opened, &got) == PASS_WRONG,
          "a device-locked file opened once its header said it needed no device");
    pass_lock_set(&again, 0, NULL, NULL);
    rc = pass_unseal(&again, plain, n, opened, sizeof opened, &got);
    CHECK(rc == 0 && memcmp(again.header, plain, PASS_HEADER_LEN) == 0,
          "unlocked again, it wasn't the passphrase's own lock (%d)", rc);
}

// Every mix of a device, a security key and a code seals under a key of its own, the passphrase
// alone opens none of them, and a header can't be changed to need less.
void test_factor_locks(double *t) {
    (void)t;
    static const char settings[] = "[profile]\nnick = \"alice\"\n";
    uint8_t device[PASS_DEVICE_SECRET_LEN], key[PASS_KEY_SECRET_LEN], other[PASS_KEY_SECRET_LEN], opened[sizeof settings];
    uint8_t sealed[8][sizeof settings + PASS_SEAL_OVERHEAD], scratch[sizeof settings + PASS_SEAL_OVERHEAD];
    size_t len[8], got = 0;
    gen_random(device, sizeof device);
    gen_random(key, sizeof key);
    memcpy(other, key, sizeof other);
    other[5] ^= 1;
    pass_lock_t base, lk[8], again;
    CHECK(pass_lock_new("correct horse", &base) == 0, "making a lock failed");
    for (unsigned f = 0; f < 8; f++) {
        lk[f] = base;
        pass_lock_set(&lk[f], f, device, key);
        CHECK(pass_seal(&lk[f], settings, sizeof settings, sealed[f], sizeof sealed[f], &len[f]) == 0
              && pass_needs(sealed[f], len[f]) == f, "a lock needing %u didn't say so", f);
    }
    for (unsigned f = 0; f < 8; f++)
        for (unsigned g = 0; g < 8; g++)
            CHECK((pass_unseal(&lk[g], sealed[f], len[f], opened, sizeof opened, &got) == 0) == (f == g),
                  "the lock needing %u opened what the one needing %u sealed, or its own didn't", g, f);
    for (unsigned f = 1; f < 8; f++) {
        int rc = pass_lock_of("correct horse", sealed[f], len[f], &again);
        CHECK(rc == 0 && pass_unseal(&again, sealed[f], len[f], opened, sizeof opened, &got) == PASS_WRONG
              && pass_seal(&again, settings, sizeof settings, scratch, sizeof scratch, &got) == PASS_FORMAT,
              "the passphrase alone opened or sealed something needing %u (%d)", f, rc);
        pass_lock_set(&again, f, device, key);
        rc = pass_unseal(&again, sealed[f], len[f], opened, sizeof opened, &got);
        CHECK(rc == 0 && got == sizeof settings && memcmp(opened, settings, sizeof settings) == 0,
              "the passphrase and what it needs didn't open what needed %u (%d)", f, rc);
    }
    again = base;
    pass_lock_set(&again, PASS_NEEDS_KEY, device, other);
    CHECK(pass_unseal(&again, sealed[PASS_NEEDS_KEY], len[PASS_NEEDS_KEY], opened, sizeof opened, &got) == PASS_WRONG,
          "another security key's secret opened it");
    CHECK(memcmp(sealed[PASS_NEEDS_DEVICE], "chatdev1", 8) == 0 && memcmp(sealed[PASS_NEEDS_KEY], "chatmfa\x02", 8) == 0,
          "a device alone didn't keep the device lock's header, or a security key didn't get its own");
    unsigned both = PASS_NEEDS_KEY | PASS_NEEDS_CODE;
    memcpy(scratch, sealed[both], len[both]);
    scratch[7] = PASS_NEEDS_KEY;
    CHECK(pass_needs(scratch, len[both]) == PASS_NEEDS_KEY
          && pass_unseal(&lk[PASS_NEEDS_KEY], scratch, len[both], opened, sizeof opened, &got) == PASS_WRONG,
          "a header changed to leave the code out still opened");
    memcpy(scratch, sealed[PASS_NEEDS_CODE], len[PASS_NEEDS_CODE]);
    memcpy(scratch, "chatkey1", 8);
    CHECK(pass_unseal(&lk[0], scratch, len[PASS_NEEDS_CODE], opened, sizeof opened, &got) == PASS_WRONG,
          "a header changed to need nothing opened what needed a code");
    memcpy(scratch, sealed[PASS_NEEDS_DEVICE], len[PASS_NEEDS_DEVICE]);
    memcpy(scratch, "chatmfa\x01", 8);
    CHECK(pass_needs(scratch, len[PASS_NEEDS_DEVICE]) == 0
          && pass_unseal(&lk[PASS_NEEDS_DEVICE], scratch, len[PASS_NEEDS_DEVICE], opened, sizeof opened, &got) == PASS_FORMAT,
          "a second header for the device alone was taken");
}

// RFC 6238's SHA-1 values, cut to 6 digits, and RFC 4648's base32.
void test_totp(double *t) {
    (void)t;
    static const uint8_t secret[20] = { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                                        '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' };
    static const struct { uint64_t time; uint32_t code; } V[] = {
        { 59, 287082 }, { 1111111109, 81804 }, { 1111111111, 50471 }, { 1234567890, 5924 },
        { 2000000000, 279037 }, { 20000000000ull, 353130 },
    };
    for (size_t i = 0; i < sizeof V / sizeof V[0]; i++) {
        uint32_t got = totp_code(secret, sizeof secret, V[i].time / TOTP_PERIOD);
        CHECK(got == V[i].code, "the code at %llu was %06u, want %06u", (unsigned long long)V[i].time, (unsigned)got,
              (unsigned)V[i].code);
    }
    static const char *const B32[][2] = {
        { "", "" }, { "f", "MY" }, { "fo", "MZXQ" }, { "foo", "MZXW6" }, { "foob", "MZXW6YQ" }, { "fooba", "MZXW6YTB" },
        { "foobar", "MZXW6YTBOI" },
    };
    for (size_t i = 0; i < sizeof B32 / sizeof B32[0]; i++) {
        char out[16];
        base32_encode((const uint8_t *)B32[i][0], strlen(B32[i][0]), out);
        CHECK(strcmp(out, B32[i][1]) == 0, "base32 of \"%s\" was %s, want %s", B32[i][0], out, B32[i][1]);
    }
}

static int b32_value(char c) { return c >= 'A' && c <= 'Z' ? c - 'A' : c >= '2' && c <= '7' ? c - '2' + 26 : -1; }

// The code an app with this base32 secret shows now.
static void app_code(const char *b32, char out[8]) {
    uint8_t secret[TOTP_SECRET_LEN] = { 0 };
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (const char *p = b32; *p && n < sizeof secret; p++) {
        acc = acc << 5 | (uint32_t)b32_value(*p);
        bits += 5;
        if (bits >= 8) { secret[n++] = (uint8_t)(acc >> (bits - 8)); bits -= 8; }
    }
    snprintf(out, 8, "%06u", (unsigned)totp_code(secret, sizeof secret, (uint64_t)time(NULL) / TOTP_PERIOD));
}

static install_key_state_t wait_key(void) {
    install_key_state_t st;
    double until = now_seconds() + 10;
    while ((st = install_key_poll(NULL, NULL)) == INSTALL_KEY_RUNNING && now_seconds() < until) platform_sleep_ms(2);
    return st;
}

static int save_file_exists(const char *config, const char *file) {
    char path[600];
    struct stat st;
    snprintf(path, sizeof path, "%s/chat/saves/factors/%s", config, file);
    return stat(path, &st) == 0;
}

// A save end to end, through app/saves/: the security key before anything opens, the code
// before the save is used, factors taken away leaving no files behind, and a save left part way
// through a change finished with everything any of its files needs.
void test_save_factors(double *t) {
    (void)t;
    static char config[256];
    CHECK(test_temp_dir("saves", config, sizeof config) == 0, "no temporary folder");
    test_set_env(TEST_CONFIG_VAR, config);
    gen_random(g_fake_key, sizeof g_fake_key);
    static const char settings[] = "[profile]\nnick = \"alice\"\n";
    static char buf[INSTALL_SETTINGS_MAX];
    char b32[40], uri[160], code[8];
    const unsigned key = INSTALL_FACTOR_KEY, otp = INSTALL_FACTOR_CODE;

    install_use("factors");
    CHECK(install_lock_new("factors", "pw", key) == -1, "a save needing a security key was made without one");
    CHECK(install_key_make(NULL) == 0 && wait_key() == INSTALL_KEY_DONE, "registering the security key failed: %s",
          install_key_why());
    install_code_new("factors", b32, sizeof b32, uri, sizeof uri);
    CHECK(strlen(b32) == 32 && strncmp(uri, "otpauth://totp/chat:factors?secret=", 35) == 0,
          "the authenticator's secret or link is wrong: %s", uri);
    CHECK(install_lock_new("factors", "pw", key | otp) == -1, "a save asking for a code was made before one was checked");
    CHECK(install_code_try("12 34") == PASS_FORMAT, "a code that isn't 6 digits was taken");
    app_code(b32, code);
    CHECK(install_code_try(code) == 0, "the app's code wasn't taken");
    CHECK(install_lock_new("factors", "pw", key | otp) == 0 && install_write_settings(settings) == 0
          && install_write_verified("") == 0, "the save wasn't made: %s", install_why());
    CHECK(install_factors("factors") == (key | otp) && install_open_factors() == (key | otp)
          && save_file_exists(config, "securitykey") && save_file_exists(config, "authenticator"),
          "the new save doesn't need what it was made with (%u)", install_factors("factors"));
    install_forget();

    CHECK(install_unlock("factors", "pw") == INSTALL_KEY, "it opened without its security key");
    CHECK(install_key_open("factors", NULL) == 0 && wait_key() == INSTALL_KEY_DONE && install_key_ready("factors"),
          "its security key's secret wasn't read: %s", install_key_why());
    CHECK(install_unlock("factors", "wrong") == PASS_WRONG && install_key_ready("factors"),
          "a wrong passphrase opened it, or the security key's secret wasn't kept for another try");
    CHECK(install_unlock("factors", "pw") == 0 && install_code_pending() && !install_open_factors()
          && install_read_settings(buf, sizeof buf) < 0, "waiting for its code, the save was used");
    CHECK(install_check_code("1234567") == PASS_FORMAT, "7 digits were taken as a code");
    app_code(b32, code);
    CHECK(install_check_code(code) == 0 && !install_code_pending()
          && install_read_settings(buf, sizeof buf) == (long)strlen(settings), "the right code didn't open it");
    install_forget();

    uint8_t mine[sizeof g_fake_key];
    memcpy(mine, g_fake_key, sizeof mine);
    g_fake_key[0] ^= 1;
    CHECK(install_key_open("factors", NULL) == 0 && wait_key() == INSTALL_KEY_FAILED && !install_key_ready("factors"),
          "another security key's secret was taken");
    memcpy(g_fake_key, mine, sizeof g_fake_key);

    CHECK(install_key_open("factors", NULL) == 0 && wait_key() == INSTALL_KEY_DONE && install_unlock("factors", "pw") == 0,
          "it didn't open again");
    app_code(b32, code);
    CHECK(install_check_code(code) == 0, "the code didn't open it again");
    CHECK(install_set_factor(otp, 0) == 0 && install_factors("factors") == key && !save_file_exists(config, "authenticator"),
          "turning the code off left it needed, or its file behind: %s", install_why());
    CHECK(install_set_factor(key, 0) == 0 && install_factors("factors") == 0 && !save_file_exists(config, "securitykey"),
          "turning the security key off left it needed, or its file behind: %s", install_why());
    install_forget();
    CHECK(install_unlock("factors", "pw") == 0 && !install_code_pending()
          && install_read_settings(buf, sizeof buf) == (long)strlen(settings), "with neither, the passphrase didn't open it");

    // An old copy of the settings, from before the device lock, put back over the locked ones.
    static uint8_t old[INSTALL_SETTINGS_MAX + PASS_SEAL_OVERHEAD];
    char path[600];
    snprintf(path, sizeof path, "%s/chat/saves/factors/settings", config);
    long old_n = platform_read_file(path, old, sizeof old);
    CHECK(old_n > 0 && install_set_factor(INSTALL_FACTOR_DEVICE, 1) == 0
          && install_factors("factors") == INSTALL_FACTOR_DEVICE, "locking it to the device failed: %s", install_why());
    CHECK(platform_write_private(path, old, (size_t)old_n) == 0, "the old settings couldn't be put back");
    install_forget();
    CHECK(install_unlock("factors", "pw") == 0 && install_relocked() == 1 && install_factors("factors") == INSTALL_FACTOR_DEVICE
          && install_device_lock() != DEVICE_NONE, "a save part locked wasn't locked again when it opened");
    CHECK(install_remove("factors") == 0 && !save_file_exists(config, "device"), "it wasn't uninstalled");
}

static long save_size(const char *config, const char *save, const char *file) {
    char path[600];
    struct stat st;
    snprintf(path, sizeof path, "%s/chat/saves/%s/%s", config, save, file);
    return stat(path, &st) == 0 ? (long)st.st_size : -1;
}

static long read_save_file(const char *config, const char *save, const char *file, uint8_t *buf, size_t cap) {
    char path[600];
    snprintf(path, sizeof path, "%s/chat/saves/%s/%s", config, save, file);
    return platform_read_file(path, buf, cap);
}

// The shadow passphrase and self-destruct, through app/saves/: every save has a spare of one
// shape, decoy or chaff; every passphrase runs Argon2id for the save and its spare; the shadow
// passphrase puts the decoy in the save's place, needing the same factors, which it follows when
// they change; a passphrase tried on every save neither counts nor opens a decoy; too many wrong
// ones delete the save; and a decoy as the betas kept it still opens.
void test_duress(double *t) {
    (void)t;
    static char config[256];
    CHECK(test_temp_dir("duress", config, sizeof config) == 0, "no temporary folder");
    test_set_env(TEST_CONFIG_VAR, config);
    gen_random(g_fake_key, sizeof g_fake_key);
    static const char settings[] = "[profile]\nnick = \"alice\"\n";
    static const uint8_t key[] = "a signing key";
    static char buf[INSTALL_SETTINGS_MAX];
    uint8_t chaff[256], spare[256];

    install_use("d");
    CHECK(install_lock_new("d", "real", 0) == 0 && install_write_settings(settings) == 0 && install_write_verified("") == 0
          && install_write_key(key, sizeof key) == 0, "the save wasn't made: %s", install_why());
    long size = read_save_file(config, "d", "spare", chaff, sizeof chaff);
    CHECK(size > 0 && save_size(config, "d", "spare-lock") > 0 && !install_has_shadow(),
          "a new save has no spare, or says it has a decoy");
    CHECK(install_shadow_set("real") == -1 && !install_has_shadow(), "the save's own passphrase was taken as its shadow one");
    CHECK(install_shadow_set("decoy") == 0 && install_has_shadow(), "the shadow passphrase wasn't set: %s", install_why());
    CHECK(read_save_file(config, "d", "spare", spare, sizeof spare) == size && memcmp(spare, chaff, 16) == 0
          && memcmp(spare + 16, chaff + 16, 16) != 0, "the decoy's spare isn't the shape chaff is");
    install_forget();

    unsigned long runs = pass_derivations();
    CHECK(install_unlock("d", "wrong") == PASS_WRONG && pass_derivations() - runs == 2,
          "a wrong passphrase didn't run Argon2id twice");
    runs = pass_derivations();
    CHECK(install_unlock("d", "real") == 0 && pass_derivations() - runs == 2 && install_has_shadow()
          && install_read_settings(buf, sizeof buf) == (long)strlen(settings),
          "the real passphrase didn't open the save, or not with the same work");
    install_forget();

    install_arm_destroy("d", 3);
    CHECK(install_probe("d", "decoy") == PASS_WRONG && install_probe("d", "nope") == PASS_WRONG
          && install_tries_left("d") == 3 && save_size(config, "d", "key") > 0,
          "a passphrase tried on every save opened the decoy, or counted towards self-destruct");
    runs = pass_derivations();
    CHECK(install_unlock("d", "decoy") == 0 && pass_derivations() - runs == 2 && !install_has_shadow()
          && install_read_settings(buf, sizeof buf) == 0, "the shadow passphrase didn't open the decoy the same way");
    CHECK(save_size(config, "d", "key") < 0 && save_size(config, "d", "spare") == size && install_tries_left("d") == 3,
          "the decoy kept the real save's key, has no spare, or left self-destruct counting");
    install_forget();
    CHECK(install_unlock("d", "real") == PASS_WRONG && install_tries_left("d") == 2, "the real passphrase still opened it");
    CHECK(install_unlock("d", "x") == PASS_WRONG && install_unlock("d", "y") == INSTALL_DESTROYED
          && save_size(config, "d", "settings") < 0 && save_size(config, "d", "spare") < 0,
          "too many wrong passphrases didn't delete the save");

    // With a security key and a code, the decoy needs them too, and the device lock once it's on.
    const unsigned all = INSTALL_FACTOR_DEVICE | INSTALL_FACTOR_KEY | INSTALL_FACTOR_CODE;
    char b32[40], uri[160], code[8];
    install_use("f");
    CHECK(install_key_make(NULL) == 0 && wait_key() == INSTALL_KEY_DONE, "registering the security key failed");
    install_code_new("f", b32, sizeof b32, uri, sizeof uri);
    app_code(b32, code);
    CHECK(install_code_try(code) == 0 && install_lock_new("f", "real", INSTALL_FACTOR_KEY | INSTALL_FACTOR_CODE) == 0
          && install_write_settings(settings) == 0 && install_shadow_set("decoy") == 0,
          "the save or its decoy wasn't made: %s", install_why());
    long n = read_save_file(config, "f", "spare", spare, sizeof spare);
    CHECK(install_set_factor(INSTALL_FACTOR_DEVICE, 1) == 0 && install_has_shadow()
          && read_save_file(config, "f", "spare", spare, sizeof spare) == n && pass_needs(spare, (size_t)n) == all,
          "the decoy doesn't need the device lock turned on after it: %s", install_why());
    install_forget();
    CHECK(install_unlock("f", "decoy") == INSTALL_KEY, "the decoy was tried without the security key");
    CHECK(install_key_open("f", NULL) == 0 && wait_key() == INSTALL_KEY_DONE && install_unlock("f", "decoy") == 0
          && install_code_pending(), "the decoy didn't ask for the code");
    app_code(b32, code);
    CHECK(install_check_code(code) == 0 && install_open_factors() == all && install_read_settings(buf, sizeof buf) == 0
          && !install_has_shadow(), "the decoy didn't open needing everything the save needed");
    CHECK(install_remove("f") == 0, "it wasn't uninstalled");

    // A decoy as the betas kept it: in files of its own, sealed under the shadow passphrase alone.
    install_use("o");
    CHECK(install_lock_new("o", "real", 0) == 0 && install_write_settings(settings) == 0, "the save wasn't made");
    pass_lock_t old;
    uint8_t sealed[PASS_SEAL_OVERHEAD];
    size_t len = 0;
    char path[600];
    CHECK(pass_lock_new("decoy", &old) == 0 && pass_seal(&old, "", 0, sealed, sizeof sealed, &len) == 0, "no old decoy");
    snprintf(path, sizeof path, "%s/chat/saves/o/shadow-settings", config);
    platform_write_private(path, sealed, len);
    snprintf(path, sizeof path, "%s/chat/saves/o/spare", config);
    platform_remove(path);
    install_forget();
    CHECK(install_unlock("o", "real") == 0 && install_has_shadow() && install_shadow_news() == INSTALL_SHADOW_OLD
          && save_size(config, "o", "spare") < 0, "opening the save didn't keep the betas' decoy, or say so");
    install_forget();
    CHECK(install_unlock("o", "decoy") == 0 && install_read_settings(buf, sizeof buf) == 0
          && save_size(config, "o", "shadow-settings") < 0 && save_size(config, "o", "spare") == size,
          "the betas' decoy didn't open in the save's place");
    CHECK(install_remove("o") == 0, "it wasn't uninstalled");
}

// The lock screen's passphrase, through app/saves/: the open save's own unlocks it, checked against
// the lock held rather than its files; a wrong one counts toward self-destruct, which its own starts
// again; every try runs Argon2id for the save and its spare; the shadow passphrase closes the save
// with the decoy in its place; one wrong too many deletes it. And the PIN's check, without a save.
void test_lock_screen(double *t) {
    (void)t;
    static char config[256];
    CHECK(test_temp_dir("lock", config, sizeof config) == 0, "no temporary folder");
    test_set_env(TEST_CONFIG_VAR, config);
    static const char settings[] = "[profile]\nnick = \"alice\"\n";
    static const uint8_t key[] = "a signing key";
    static char buf[INSTALL_SETTINGS_MAX];

    install_use("l");
    CHECK(install_lock_new("l", "real", 0) == 0 && install_write_settings(settings) == 0
          && install_write_key(key, sizeof key) == 0 && install_shadow_set("decoy") == 0,
          "the save or its decoy wasn't made: %s", install_why());
    unsigned long runs = pass_derivations();
    CHECK(install_lock_try("real") == 0 && pass_derivations() - runs == 2
          && install_read_settings(buf, sizeof buf) == (long)strlen(settings),
          "its own passphrase didn't unlock it, or not with the same work");
    runs = pass_derivations();
    CHECK(install_lock_try("wrong") == PASS_WRONG && pass_derivations() - runs == 2
          && install_read_settings(buf, sizeof buf) == (long)strlen(settings),
          "a wrong passphrase didn't take the same work, or closed the save");

    char path[600];
    static const uint8_t junk[PASS_SEAL_OVERHEAD] = { 0 };
    snprintf(path, sizeof path, "%s/chat/saves/l/settings", config);
    CHECK(platform_write_private(path, junk, sizeof junk) == 0 && install_lock_try("real") == 0
          && install_write_settings(settings) == 0, "a changed settings file made its own passphrase fail");

    install_arm_destroy("l", 3);
    CHECK(install_lock_try("x") == PASS_WRONG && install_tries_left("l") == 2,
          "a wrong passphrase didn't count toward self-destruct");
    CHECK(install_lock_try("real") == 0 && install_tries_left("l") == 3, "its own passphrase didn't start the count again");
    CHECK(install_lock_try("x") == PASS_WRONG, "a wrong passphrase unlocked it");
    runs = pass_derivations();
    CHECK(install_lock_try("decoy") == INSTALL_DECOY && pass_derivations() - runs == 2
          && install_read_settings(buf, sizeof buf) < 0 && install_tries_left("l") == 3,
          "the shadow passphrase didn't close the save the same way, or left self-destruct counting");
    CHECK(save_size(config, "l", "key") < 0 && save_size(config, "l", "spare") > 0 && install_unlock("l", "real") == PASS_WRONG
          && install_unlock("l", "decoy") == 0 && install_read_settings(buf, sizeof buf) == 0,
          "the decoy didn't take the save's place");

    install_arm_destroy("l", 2);
    CHECK(install_lock_try("y") == PASS_WRONG && install_lock_try("z") == INSTALL_DESTROYED
          && save_size(config, "l", "settings") < 0 && save_size(config, "l", "spare") < 0
          && install_read_settings(buf, sizeof buf) < 0, "one wrong passphrase too many didn't delete the save");

    pass_lock_t pin, tried;
    CHECK(pass_lock_new("1234", &pin) == 0 && pass_lock_like("1234", &pin, &tried) == 0
          && crypto_equal(tried.base, pin.base, sizeof pin.base) == 0 && pass_lock_like("1235", &pin, &tried) == 0
          && crypto_equal(tried.base, pin.base, sizeof pin.base) != 0, "a PIN's check didn't tell it from another");
    crypto_wipe(&pin, sizeof pin);
    crypto_wipe(&tried, sizeof tried);
}

// A session's history: named the same by every member, sealed in the open save, read back as
// written, sealed again when the save's factors change, deleted by forget, by a decoy taking over
// and with the save. A peer is told when someone starts keeping one, and when they stop.
void test_history(double *t) {
    static char config[256];
    CHECK(test_temp_dir("history", config, sizeof config) == 0, "no temporary folder");
    test_set_env(TEST_CONFIG_VAR, config);
    static char buf[INSTALL_HISTORY_MAX];
    static const char lines[] = "2026-10-07 19:25\t-\t0\t0\tbob: hello\n";
    uint8_t id[CHAT_HISTORY_ID_LEN], theirs[CHAT_HISTORY_ID_LEN], other[CHAT_HISTORY_ID_LEN];
    chat_history_id(&A, id);
    chat_history_id(&B, theirs);
    memset(other, 7, sizeof other);
    CHECK(memcmp(id, theirs, sizeof id) == 0, "two members of one session name its history differently");

    install_use("h");
    CHECK(install_lock_new("h", "pw", 0) == 0 && install_write_settings("") == 0, "the save wasn't made: %s", install_why());
    CHECK(install_write_history(id, lines, strlen(lines)) == 0 && install_write_history(other, lines, 3) == 0
          && install_histories() == 2, "two histories weren't written");
    CHECK(install_set_factor(INSTALL_FACTOR_DEVICE, 1) == 0, "locking it to the device failed: %s", install_why());
    install_forget();
    CHECK(install_unlock("h", "pw") == 0 && install_read_history(id, buf, sizeof buf) == (long)strlen(lines)
          && memcmp(buf, lines, strlen(lines)) == 0, "a history didn't open once the save was locked to the device");
    CHECK(install_forget_history(other) == 0 && install_histories() == 1
          && install_read_history(other, buf, sizeof buf) == INSTALL_NO_FILE, "forgetting a history left it");
    CHECK(install_shadow_set("decoy") == 0, "the shadow passphrase wasn't set: %s", install_why());
    install_forget();
    CHECK(install_unlock("h", "decoy") == 0 && install_histories() == 0, "the decoy kept the real save's history");
    CHECK(install_write_history(id, lines, strlen(lines)) == 0 && install_remove("h") == 0
          && save_size(config, "h", "settings") < 0, "uninstalling left the save, or its history");

    peer_t *pa = peer_named(&B, "alice");
    int warned = log_b.histories;
    chat_set_history(&A, 1);
    RUN_UNTIL(t, 20, pa && pa->persists);
    CHECK(pa && pa->persists && log_b.histories == warned + 1, "bob wasn't told alice keeps a history");
    chat_set_history(&A, 0);
    RUN_UNTIL(t, 20, pa && !pa->persists);
    CHECK(pa && !pa->persists, "bob wasn't told alice stopped keeping one");
}

static void room_back(void *ctx, const char *table, const char *key, const toml_value *v) {
    (void)key;
    int *bad = ctx;
    if (strcmp(table, "rooms") == 0 && rooms_load(v) != 0) (*bad)++;
    if (strcmp(table, "open") == 0 && reopen_load(v) != 0) (*bad)++;
}

// Kept rooms through the settings file's [rooms] table and back, with odd labels and passwords, and
// the settings file padded so its size says little about how many there are.
void test_rooms(double *t) {
    (void)t;
    static char text[INSTALL_SETTINGS_MAX], buf[INSTALL_SETTINGS_MAX], config[256];
    static const char pw[] = "a \"quoted\"\\ pass\tword", nick[] = "[profile]\nnick = \"a\"\n";
    rooms_clear();
    CHECK(rooms_keep("home", "ABC234", pw) == 0 && rooms_keep("\x1b[2Jwork", "XYZ789", "") == 1
          && rooms_keep(" ", "QQQ222", "x") == 2 && rooms_keep("home again", "ABC234", pw) == 0 && rooms_count() == 3,
          "the rooms weren't kept, or one was kept twice");
    rooms_set_start(1, 1);
    CHECK(strcmp(room_at(0)->label, "home again") == 0 && strcmp(room_at(1)->label, "[2Jwork") == 0
          && strcmp(room_at(2)->label, "QQQ222") == 0, "a label wasn't cleaned, or a blank one isn't the id");
    size_t n = rooms_text(text, 0, sizeof text);
    CHECK(n > 0 && n < sizeof text, "the rooms didn't fit");
    rooms_clear();
    int bad = 0, bad_line = 0;
    CHECK(toml_parse(text, room_back, &bad, &bad_line) == 0 && bad == 0 && rooms_count() == 3
          && strcmp(room_at(0)->password, pw) == 0 && strcmp(room_at(1)->id, "XYZ789") == 0
          && room_at(1)->at_start && !room_at(0)->at_start && !room_at(1)->password[0],
          "the rooms didn't come back as they were kept:\n%s", text);
    rooms_forget(0);
    CHECK(rooms_count() == 2 && rooms_find("ABC234") < 0 && rooms_find("QQQ222") == 1, "forgetting a room didn't");

    // The sessions to reopen, in their own table beside the rooms: only a change counts as one, and one
    // that couldn't open is marked until it's listed again without.
    reopen_begin();
    reopen_add("XYZ789", pw, 0);
    reopen_add("QQQ222", "", 1);
    reopen_add("\x1b[2J", "x", 0);
    CHECK(reopen_end() == 1 && reopen_count() == 2 && !reopen_at(0)->unopened && reopen_at(1)->unopened,
          "the sessions to reopen weren't listed as they were added, or a bad id was");
    reopen_begin();
    reopen_add("XYZ789", pw, 0);
    reopen_add("QQQ222", "", 0);
    CHECK(reopen_end() == 0 && !reopen_at(1)->unopened, "the same list counted as a change, or kept its mark");
    n = rooms_text(text, 0, sizeof text);
    n = reopen_text(text, n, sizeof text);
    CHECK(n > 0 && n < sizeof text && strstr(text, "\n[open]\n"), "the sessions to reopen weren't written");
    rooms_clear();
    CHECK(reopen_count() == 0, "rooms_clear left the sessions to reopen");
    bad = 0;
    CHECK(toml_parse(text, room_back, &bad, &bad_line) == 0 && bad == 0 && rooms_count() == 2 && reopen_count() == 2
          && strcmp(reopen_at(0)->id, "XYZ789") == 0 && strcmp(reopen_at(0)->password, pw) == 0
          && strcmp(reopen_at(1)->id, "QQQ222") == 0 && !reopen_at(1)->password[0] && !reopen_at(1)->unopened,
          "the sessions to reopen didn't come back as they were:\n%s", text);

    // As many as can be kept, each as long as it can be with a password that's all quotes, leave room
    // for the settings beside them.
    rooms_clear();
    char id[MAX_SESSION_NAME + 1], label[ROOM_LABEL_MAX + 1], quotes[MAX_PASSWORD + 1];
    memset(quotes, '"', MAX_PASSWORD);
    quotes[MAX_PASSWORD] = '\0';
    memset(label, 'l', ROOM_LABEL_MAX);
    label[ROOM_LABEL_MAX] = '\0';
    for (int i = 0; i < ROOMS_MAX; i++) {
        snprintf(id, sizeof id, "%0*d", MAX_SESSION_NAME, i);
        CHECK(rooms_keep(label, id, quotes) == i, "room %d wasn't kept", i);
    }
    CHECK(rooms_keep("one more", "MORE22", "p") < 0, "more than %d rooms were kept", ROOMS_MAX);
    n = rooms_text(text, 0, sizeof text);
    CHECK(n + 6000 < INSTALL_SETTINGS_MAX, "the most rooms there can be take %zu bytes of the settings", n);
    // And beside those, as many sessions to reopen with the longest ids, and long plain passwords.
    char plain[65];
    memset(plain, 'p', 64);
    plain[64] = '\0';
    reopen_begin();
    for (int i = 0; i < ROOMS_MAX; i++) {
        snprintf(id, sizeof id, "%0*d", MAX_SESSION_NAME, i);
        reopen_add(id, plain, 0);
    }
    CHECK(reopen_end() == 1 && reopen_count() == ROOMS_MAX, "the sessions to reopen weren't all listed");
    n = reopen_text(text, n, sizeof text);
    CHECK(n + 6000 < INSTALL_SETTINGS_MAX, "the most rooms and sessions to reopen take %zu bytes of the settings", n);
    rooms_clear();

    CHECK(test_temp_dir("rooms", config, sizeof config) == 0, "no temporary folder");
    test_set_env(TEST_CONFIG_VAR, config);
    install_use("p");
    CHECK(install_lock_new("p", "pw", 0) == 0 && install_write_settings(nick) == 0
          && save_size(config, "p", "settings") == (long)(4096 + PASS_SEAL_OVERHEAD)
          && install_read_settings(buf, sizeof buf) == (long)strlen(nick) && strcmp(buf, nick) == 0,
          "the settings weren't padded to 4 KB, or didn't read back as they were");
    memset(text, 'x', 5000);
    text[5000] = '\0';
    CHECK(install_write_settings(text) == 0
          && save_size(config, "p", "settings") == (long)(8192 + PASS_SEAL_OVERHEAD)
          && install_read_settings(buf, sizeof buf) == 5000, "settings over 4 KB weren't padded to 8 KB");
    CHECK(install_remove("p") == 0, "it wasn't uninstalled");
}

// What chat's own tor keeps in the save: read back as it was written, sealed again when the save's
// lock changes, and gone when it's forgotten, with the decoy and with the save.
void test_tor_state(double *t) {
    (void)t;
    static char config[256];
    CHECK(test_temp_dir("torstate", config, sizeof config) == 0, "no temporary folder");
    test_set_env(TEST_CONFIG_VAR, config);
    enum { STATE_LEN = 3 * 1024 * 1024 };
    uint8_t *state = malloc(STATE_LEN), *back = NULL;
    size_t len = 0;
    CHECK(state != NULL, "out of memory");
    gen_random(state, STATE_LEN);

    install_use("g");
    CHECK(install_lock_new("g", "pw", 0) == 0 && install_write_settings("") == 0, "the save wasn't made: %s",
          install_why());
    CHECK(install_read_tor(&back, &len) == INSTALL_NO_FILE && !back, "a new save had tor's state");
    CHECK(install_write_tor(state, STATE_LEN) == 0
          && save_size(config, "g", "cache") == (long)(STATE_LEN + PASS_SEAL_OVERHEAD),
          "tor's state wasn't written, sealed");
    CHECK(install_set_factor(INSTALL_FACTOR_DEVICE, 1) == 0, "locking it to the device failed: %s", install_why());
    install_forget();
    CHECK(install_unlock("g", "pw") == 0 && install_read_tor(&back, &len) == 0 && len == (size_t)STATE_LEN
          && memcmp(back, state, STATE_LEN) == 0, "tor's state didn't open once the save was locked to the device");
    free(back);
    back = NULL;
    install_forget_tor();
    CHECK(save_size(config, "g", "cache") < 0 && install_read_tor(&back, &len) == INSTALL_NO_FILE,
          "forgetting tor's state left it");
    CHECK(install_write_tor(state, STATE_LEN) == 0 && install_shadow_set("decoy") == 0,
          "the shadow passphrase wasn't set: %s", install_why());
    install_forget();
    CHECK(install_unlock("g", "decoy") == 0 && save_size(config, "g", "cache") < 0
          && install_read_tor(&back, &len) == INSTALL_NO_FILE, "the decoy kept the real save's tor state");
    CHECK(install_write_tor(state, STATE_LEN) == 0 && install_remove("g") == 0 && save_size(config, "g", "cache") < 0,
          "uninstalling left tor's state");
    free(state);
}
