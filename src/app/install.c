// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/install.h"
#include "crypto/crypto.h"
#include "platform/platform.h"
#include "common/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SETTINGS_NAME "settings"
#define KEY_NAME "key"
#define VERIFIED_NAME "verified"
#define CODE_NAME "authenticator"
#define DEVICE_NAME "device"
#define SECKEY_NAME "securitykey"
#define TRIES_NAME "tries"
#define SPARE_NAME "spare"
#define SPARE_LOCK_NAME "spare-lock"
// A decoy as 0.5.0's betas made it, in files only a save with a decoy had: still opened, until the
// shadow passphrase is set again.
#define OLD_DECOY_SETTINGS "shadow-settings"
#define OLD_DECOY_KEY "shadow-key"
#define OLD_DECOY_VERIFIED "shadow-verified"
#define OLD_DECOY_CODE "shadow-authenticator"
#define TRIES_MAGIC "CT1"   // then one byte each: the limit, the count so far
// The spare: 1, whether the decoy asks for a code, and the code's secret, sealed under the decoy's
// lock. Without a decoy it's chaff: random bytes with the same size and header.
#define SPARE_PLAIN_LEN (2 + TOTP_SECRET_LEN)
#define SPARE_FILE_LEN (SPARE_PLAIN_LEN + PASS_SEAL_OVERHEAD)
// The spare's lock, sealed with the save's other files: 1, whether there's a decoy, then the decoy
// lock's header and the key its passphrase made (or random bytes), so the decoy can be sealed again
// when the save's factors change.
#define SPARE_LOCK_PLAIN_LEN (2 + PASS_HEADER_LEN + 32)
#define SPARE_LOCK_FILE_LEN (SPARE_LOCK_PLAIN_LEN + PASS_SEAL_OVERHEAD)
#define SETTINGS_FILE_MAX (INSTALL_SETTINGS_MAX + PASS_SEAL_OVERHEAD)
#define KEY_FILE_MAX (INSTALL_KEY_MAX + PASS_SEAL_OVERHEAD)
#define VERIFIED_FILE_MAX (INSTALL_VERIFIED_MAX + PASS_SEAL_OVERHEAD)
#define CODE_PLAIN_LEN (1 + TOTP_SECRET_LEN)
#define CODE_FILE_MAX (CODE_PLAIN_LEN + PASS_SEAL_OVERHEAD)
#define KEYS_MAX 4
#define KEY_FILE_MAGIC "CSK1"
#define KEY_FILE_HEAD (4 + SECKEY_SALT_LEN + 1)
#define KEY_ENTRY_MAX (3 + SECKEY_CRED_MAX + WRAP_LEN)
#define SECKEY_FILE_MAX (KEY_FILE_HEAD + KEYS_MAX * KEY_ENTRY_MAX)

#define F_DEVICE INSTALL_FACTOR_DEVICE
#define F_KEY    INSTALL_FACTOR_KEY
#define F_CODE   INSTALL_FACTOR_CODE

_Static_assert(DEVICE_SECRET_LEN == PASS_DEVICE_SECRET_LEN, "the device's secret is what a device lock mixes in");
_Static_assert(F_DEVICE == PASS_NEEDS_DEVICE && F_KEY == PASS_NEEDS_KEY && F_CODE == PASS_NEEDS_CODE,
               "a save's factors are its lock's");
_Static_assert(SECKEY_SECRET_LEN == 32 && PASS_KEY_SECRET_LEN == 32, "a security key's secret wraps the lock's");

// Also removes any .new files left by a crash while writing.
static const char *const FILES[] = { SETTINGS_NAME, KEY_NAME, VERIFIED_NAME, CODE_NAME, SECKEY_NAME,
                                     TRIES_NAME, SPARE_NAME, SPARE_LOCK_NAME, OLD_DECOY_SETTINGS, OLD_DECOY_KEY,
                                     OLD_DECOY_VERIFIED, OLD_DECOY_CODE,
                                     SETTINGS_NAME ".new", KEY_NAME ".new", VERIFIED_NAME ".new", CODE_NAME ".new",
                                     SECKEY_NAME ".new", TRIES_NAME ".new", SPARE_NAME ".new", SPARE_LOCK_NAME ".new",
                                     OLD_DECOY_SETTINGS ".new", OLD_DECOY_KEY ".new", OLD_DECOY_VERIFIED ".new",
                                     OLD_DECOY_CODE ".new", DEVICE_NAME ".new", DEVICE_NAME };
#define N_FILES (sizeof FILES / sizeof FILES[0])
static const char *const SEALED[] = { SETTINGS_NAME, KEY_NAME, VERIFIED_NAME, CODE_NAME, SPARE_LOCK_NAME };
#define N_SEALED (sizeof SEALED / sizeof SEALED[0])
static const char *const OLD_DECOY[] = { OLD_DECOY_SETTINGS, OLD_DECOY_KEY, OLD_DECOY_VERIFIED, OLD_DECOY_CODE };
#define N_OLD_DECOY (sizeof OLD_DECOY / sizeof OLD_DECOY[0])

#define SAVES_DIR "saves"

// A save's lock, and the secrets of its factors while they're known.
typedef struct {
    pass_lock_t lock;
    uint8_t device[DEVICE_SECRET_LEN];
    int have_device;
    device_kind_t device_kind;
    uint8_t key[PASS_KEY_SECRET_LEN];
    int have_key;
} held_t;

static held_t g_held;   // the open save's
static int g_open;
static char g_name[INSTALL_NAME_MAX + 1];
// The security key secret of a save being opened, from install_key_open, until install_unlock takes it.
static uint8_t g_try_key[PASS_KEY_SECRET_LEN];
static int g_have_try_key;
static char g_try_name[INSTALL_NAME_MAX + 1];
// A save opened that waits for its code: nothing of it is used, and the save that was open stays
// as it was, until install_check_code takes the code. Then it's finished with g_pend_all.
static held_t g_pend;
static held_t g_opening;   // what install_lock_new and install_unlock put together
static char g_pend_name[INSTALL_NAME_MAX + 1];
static int g_pending;
static uint8_t g_code[TOTP_SECRET_LEN];
static unsigned g_pend_all;
static char g_why[256];
static int g_relocked;
static pass_lock_t g_spare_lock;
static int g_decoy_state = -1;   // whether the open save has a decoy, -1 until it's read
static int g_decoy_lost;

// A save's securitykey file: one salt, then each security key's credential, whether it needs the
// key's PIN, and the save's security key secret wrapped under that key's hmac-secret. Any one of the
// keys gives the secret back.
typedef struct {
    int uv;
    size_t cred_len;
    uint8_t cred[SECKEY_CRED_MAX];
    uint8_t wrapped[WRAP_LEN];
} key_entry_t;

typedef struct {
    uint8_t salt[SECKEY_SALT_LEN];
    int n;
    key_entry_t e[KEYS_MAX];
} key_file_t;

// Set up and not used yet: a security key install_key_make registered, with the secret it wraps,
// and an authenticator secret from install_code_new.
static struct { int have; key_file_t file; uint8_t secret[PASS_KEY_SECRET_LEN]; } g_new_key;
static struct { int have, confirmed; uint8_t secret[TOTP_SECRET_LEN]; } g_new_code;

// The security key's thread reads and writes g_job, and nothing else, until g_job_state says it's done.
enum { JOB_IDLE, JOB_RUNNING, JOB_ENDED };
static struct {
    int make;
    char pin[64];
    uint8_t salt[SECKEY_SALT_LEN];
    int n;
    const uint8_t *creds[KEYS_MAX];
    size_t lens[KEYS_MAX];
    int uv[KEYS_MAX];
    uint8_t cred[SECKEY_CRED_MAX];
    size_t cred_len;
    int cred_uv;
    uint8_t secret[SECKEY_SECRET_LEN];
    int rc;
    char why[256];
    seckey_wait_t w;
} g_job;
static int g_job_state;
static key_file_t g_job_file;
static char g_job_name[INSTALL_NAME_MAX + 1];
static char g_key_why[256];

static void pin_secrets(void) {
    static int pinned;
    if (pinned) return;
    crypto_lock(&g_held, sizeof g_held);
    crypto_lock(&g_pend, sizeof g_pend);
    crypto_lock(&g_opening, sizeof g_opening);
    crypto_lock(g_try_key, sizeof g_try_key);
    crypto_lock(g_code, sizeof g_code);
    crypto_lock(&g_new_key, sizeof g_new_key);
    crypto_lock(&g_new_code, sizeof g_new_code);
    crypto_lock(&g_job, sizeof g_job);
    crypto_lock(&g_spare_lock, sizeof g_spare_lock);
    pinned = 1;
}

int install_name_ok(const char *name) {
    size_t n = strlen(name);
    if (n < 1 || n > INSTALL_NAME_MAX) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
            return -1;
    }
    return 0;
}

static const char *stored_name(const char *name) {
    return !name || strcmp(name, "default") == 0 ? "" : name;
}

const char *install_shown_name(const char *name) { return stored_name(name)[0] ? name : "default"; }

const char *install_current(void) { return g_name; }

void install_use(const char *name) {
    install_forget();
    copy_str(g_name, stored_name(name), sizeof g_name);
}

// The save's folder, created (with the folders above it) if create is set.
static int save_dir(const char *name, char *out, size_t cap, int create) {
    name = stored_name(name);
    if (name[0] && install_name_ok(name) != 0) return -1;
    char dir[900];
    if (platform_config_dir(dir, sizeof dir, create) != 0) return -1;
    if (!name[0]) { copy_str(out, dir, cap); return strlen(dir) < cap ? 0 : -1; }
    int n = snprintf(out, cap, "%s/" SAVES_DIR, dir);
    if (n <= 0 || (size_t)n >= cap || (create && platform_private_dir(out) != 0)) return -1;
    n = snprintf(out, cap, "%s/" SAVES_DIR "/%s", dir, name);
    if (n <= 0 || (size_t)n >= cap || (create && platform_private_dir(out) != 0)) return -1;
    return 0;
}

static int save_path(const char *name, const char *file, char *out, size_t cap, int create) {
    char dir[960];
    if (save_dir(name, dir, sizeof dir, create) != 0) return -1;
    int n = snprintf(out, cap, "%s/%s", dir, file);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

int install_where(const char *name, char *out, size_t cap) {
    char dir[960];
    if (save_dir(name, dir, sizeof dir, 0) != 0) return -1;
#ifndef _WIN32
    const char *home = platform_home_dir();
    size_t hl = home ? strlen(home) : 0;
    if (hl > 1 && strncmp(dir, home, hl) == 0 && dir[hl] == '/') {
        snprintf(out, cap, "~%s", dir + hl);
        return 0;
    }
#endif
    copy_str(out, dir, cap);
    return 0;
}

static int path_exists(const char *path) {
    char probe[1];
    return platform_read_file(path, probe, sizeof probe) >= 0;
}

static int has(const char *name, const char *file) {
    char path[1000];
    return save_path(name, file, path, sizeof path, 0) == 0 && path_exists(path);
}

static void remove_file(const char *name, const char *file) {
    char path[1000];
    if (save_path(name, file, path, sizeof path, 0) == 0) platform_remove(path);
}

int install_has_settings(const char *name) { return has(name, SETTINGS_NAME); }
int install_has_key(const char *name) { return has(name, KEY_NAME); }

static size_t file_max(const char *file) {
    return strcmp(file, SETTINGS_NAME) == 0 ? SETTINGS_FILE_MAX : strcmp(file, KEY_NAME) == 0 ? KEY_FILE_MAX
         : strcmp(file, CODE_NAME) == 0 ? CODE_FILE_MAX : VERIFIED_FILE_MAX;
}

static unsigned file_needs(const char *name, const char *file) {
    char path[1000];
    uint8_t head[8];
    if (save_path(name, file, path, sizeof path, 0) != 0 || platform_read_file(path, head, sizeof head) != (long)sizeof head)
        return 0;
    return pass_needs(head, sizeof head);
}

// What the save's files but one need.
static unsigned needs_but(const char *name, const char *skip) {
    unsigned all = 0;
    for (size_t i = 0; i < N_SEALED; i++)
        if (!skip || strcmp(SEALED[i], skip) != 0) all |= file_needs(name, SEALED[i]);
    return all;
}

unsigned install_factors(const char *name) { return needs_but(name, NULL); }

// The file that says how the save is locked: the settings, or the key if there are no settings.
// install_unlock opens it first.
static const char *lock_file(const char *name) {
    return install_has_settings(name) ? SETTINGS_NAME : KEY_NAME;
}

static int fill_save(install_save_t *s, const char *name) {
    memset(s, 0, sizeof *s);
    copy_str(s->name, name, sizeof s->name);
    s->settings = install_has_settings(name);
    s->key = install_has_key(name);
    if (!s->settings && !s->key) return -1;
    s->factors = install_factors(name);
    char path[1000];
    file_info_t fi;
    if (save_path(name, s->settings ? SETTINGS_NAME : KEY_NAME, path, sizeof path, 0) == 0
        && platform_file_info(path, &fi) == 0)
        copy_str(s->modified, fi.modified, sizeof s->modified);
    return 0;
}

typedef struct { char names[INSTALL_SAVES_MAX][INSTALL_NAME_MAX + 1]; int n; } name_list_t;

static void add_name(void *ctx, const char *name, int is_dir) {
    name_list_t *l = ctx;
    if (!is_dir || l->n >= INSTALL_SAVES_MAX || install_name_ok(name) != 0 || strcmp(name, "default") == 0) return;
    copy_str(l->names[l->n++], name, sizeof l->names[0]);
}

static int by_name(const void *a, const void *b) { return strcmp(a, b); }

int install_list(install_save_t *out, int max) {
    int n = 0;
    if (n < max && fill_save(&out[n], "") == 0) n++;
    char dir[900], saves[960];
    if (platform_config_dir(dir, sizeof dir, 0) != 0) return n;
    snprintf(saves, sizeof saves, "%s/" SAVES_DIR, dir);
    static name_list_t l;
    l.n = 0;
    if (platform_list_dir(saves, add_name, &l) != 0) return n;
    qsort(l.names, (size_t)l.n, sizeof l.names[0], by_name);
    for (int i = 0; i < l.n && n < max; i++)
        if (fill_save(&out[n], l.names[i]) == 0) n++;
    return n;
}

// buf holds max + 1, so a file too long to have been written by chat can be detected.
static int read_sealed(const char *save, const char *file, uint8_t *buf, size_t max, size_t *len) {
    char path[1000];
    if (save_path(save, file, path, sizeof path, 0) != 0) return INSTALL_NO_FILE;
    long n = platform_read_file(path, buf, max + 1);
    if (n < 0) return INSTALL_NO_FILE;
    if ((size_t)n > max) return PASS_FORMAT;
    *len = (size_t)n;
    return 0;
}

static void hold_device(const uint8_t *secret, device_kind_t kind) {
    pin_secrets();
    if (secret) memcpy(g_held.device, secret, sizeof g_held.device);
    else crypto_wipe(g_held.device, sizeof g_held.device);
    g_held.have_device = secret != NULL;
    g_held.device_kind = secret ? kind : DEVICE_NONE;
}

static void hold_key(const uint8_t *secret) {
    pin_secrets();
    if (secret) memcpy(g_held.key, secret, sizeof g_held.key);
    else crypto_wipe(g_held.key, sizeof g_held.key);
    g_held.have_key = secret != NULL;
}

static void forget_try_key(void) {
    crypto_wipe(g_try_key, sizeof g_try_key);
    g_have_try_key = 0;
    g_try_name[0] = '\0';
}

// The save that's open from now on.
static void hold(const char *name, const held_t *h) {
    pin_secrets();
    copy_str(g_name, stored_name(name), sizeof g_name);
    g_held = *h;
    g_open = 1;
    g_decoy_state = -1;
}

static long read_device(const char *name, uint8_t buf[DEVICE_SEALED_MAX + 1]) {
    char path[1000];
    if (save_path(name, DEVICE_NAME, path, sizeof path, 0) != 0) return -1;
    long n = platform_read_file(path, buf, DEVICE_SEALED_MAX + 1);
    return n > 0 && n <= DEVICE_SEALED_MAX ? n : -1;
}

// The device's secret for a save. 0, or -1 with g_why set.
static int device_unseal(const char *name, uint8_t secret[DEVICE_SECRET_LEN], device_kind_t *kind) {
    static uint8_t sealed[DEVICE_SEALED_MAX + 1];
    long n = read_device(name, sealed);
    if (n < 0) {
        copy_str(g_why, "its device file is missing or damaged", sizeof g_why);
        return -1;
    }
    *kind = platform_device_sealed_kind(sealed, (size_t)n);
    return platform_device_unseal(sealed, (size_t)n, secret, g_why, sizeof g_why);
}

// Destroys a save's device file, and what the device keeps for it.
static void forget_device(const char *name) {
    static uint8_t sealed[DEVICE_SEALED_MAX + 1];
    char path[1000];
    if (save_path(name, DEVICE_NAME, path, sizeof path, 0) != 0) return;
    long n = read_device(name, sealed);
    if (n > 0) platform_device_forget(sealed, (size_t)n);
    platform_remove(path);
}

// secret sealed to this device, in place of a save's device file, which is read back to be sure.
// What the device kept for the one it replaces is destroyed. 0, or -1 with g_why set.
static int device_seal(const char *name, const uint8_t secret[DEVICE_SECRET_LEN], device_kind_t *kind) {
    static uint8_t sealed[DEVICE_SEALED_MAX], old[DEVICE_SEALED_MAX + 1], back[DEVICE_SEALED_MAX + 1];
    char path[1000];
    if (save_path(name, DEVICE_NAME, path, sizeof path, 1) != 0) {
        copy_str(g_why, "there's nowhere to write its device file", sizeof g_why);
        return -1;
    }
    long n = platform_device_seal(secret, sealed, sizeof sealed, g_why, sizeof g_why);
    if (n < 0) return -1;
    long old_n = read_device(name, old);
    if (platform_write_private(path, sealed, (size_t)n) != 0 || read_device(name, back) != n
        || memcmp(back, sealed, (size_t)n) != 0) {
        platform_device_forget(sealed, (size_t)n);
        copy_str(g_why, "couldn't write its device file", sizeof g_why);
        return -1;
    }
    if (old_n > 0) platform_device_forget(old, (size_t)old_n);
    *kind = platform_device_sealed_kind(sealed, (size_t)n);
    return 0;
}

// ---- the securitykey file ----

static size_t entry_ad(const uint8_t salt[SECKEY_SALT_LEN], const key_entry_t *e, uint8_t *ad) {
    memcpy(ad, KEY_FILE_MAGIC, 4);
    memcpy(ad + 4, salt, SECKEY_SALT_LEN);
    ad[4 + SECKEY_SALT_LEN] = (uint8_t)e->uv;
    memcpy(ad + 5 + SECKEY_SALT_LEN, e->cred, e->cred_len);
    return 5 + SECKEY_SALT_LEN + e->cred_len;
}

static size_t key_file_pack(const key_file_t *f, uint8_t *out) {
    size_t n = 0;
    memcpy(out, KEY_FILE_MAGIC, 4);
    memcpy(out + 4, f->salt, SECKEY_SALT_LEN);
    out[4 + SECKEY_SALT_LEN] = (uint8_t)f->n;
    n = KEY_FILE_HEAD;
    for (int i = 0; i < f->n; i++) {
        const key_entry_t *e = &f->e[i];
        out[n++] = (uint8_t)e->uv;
        out[n++] = (uint8_t)(e->cred_len >> 8);
        out[n++] = (uint8_t)e->cred_len;
        memcpy(out + n, e->cred, e->cred_len);
        n += e->cred_len;
        memcpy(out + n, e->wrapped, WRAP_LEN);
        n += WRAP_LEN;
    }
    return n;
}

static int key_file_parse(const uint8_t *in, size_t len, key_file_t *f) {
    if (len < KEY_FILE_HEAD || memcmp(in, KEY_FILE_MAGIC, 4) != 0) return -1;
    memcpy(f->salt, in + 4, SECKEY_SALT_LEN);
    f->n = in[4 + SECKEY_SALT_LEN];
    if (f->n < 1 || f->n > KEYS_MAX) return -1;
    size_t p = KEY_FILE_HEAD;
    for (int i = 0; i < f->n; i++) {
        key_entry_t *e = &f->e[i];
        if (len - p < 3) return -1;
        e->uv = in[p];
        e->cred_len = (size_t)in[p + 1] << 8 | in[p + 2];
        p += 3;
        if (e->uv > 1 || e->cred_len == 0 || e->cred_len > SECKEY_CRED_MAX || len - p < e->cred_len + WRAP_LEN) return -1;
        memcpy(e->cred, in + p, e->cred_len);
        p += e->cred_len;
        memcpy(e->wrapped, in + p, WRAP_LEN);
        p += WRAP_LEN;
    }
    return p == len ? 0 : -1;
}

static int read_key_file(const char *name, key_file_t *f) {
    static uint8_t buf[SECKEY_FILE_MAX + 1];
    char path[1000];
    if (save_path(name, SECKEY_NAME, path, sizeof path, 0) != 0) return -1;
    long n = platform_read_file(path, buf, sizeof buf);
    return n > 0 && (size_t)n <= SECKEY_FILE_MAX ? key_file_parse(buf, (size_t)n, f) : -1;
}

// Read back to be sure, since the save can't be opened without it.
static int write_key_file(const char *name, const key_file_t *f) {
    static uint8_t buf[SECKEY_FILE_MAX], back[SECKEY_FILE_MAX + 1];
    char path[1000];
    if (save_path(name, SECKEY_NAME, path, sizeof path, 1) != 0) return -1;
    size_t n = key_file_pack(f, buf);
    if (platform_write_private(path, buf, n) != 0) return -1;
    long got = platform_read_file(path, back, sizeof back);
    return got == (long)n && memcmp(back, buf, n) == 0 ? 0 : -1;
}

// ---- opening ----

// A crash while the lock was being changed can leave a file sealed with other factors. One sealed
// with all of the save's and more is still read, if their secrets are held, but never one sealed with
// fewer.
static int unseal_with(const held_t *h, const uint8_t *sealed, size_t n, void *plain, size_t cap, size_t *len) {
    int rc = pass_unseal(&h->lock, sealed, n, plain, cap, len);
    if (rc != PASS_WRONG) return rc;
    unsigned needs = pass_needs(sealed, n);
    if (needs == h->lock.needs || (h->lock.needs & ~needs) || ((needs & F_DEVICE) && !h->have_device)
        || ((needs & F_KEY) && !h->have_key))
        return rc;
    pass_lock_t other = h->lock;
    pass_lock_set(&other, needs, h->device, h->key);
    rc = pass_unseal(&other, sealed, n, plain, cap, len);
    crypto_wipe(&other, sizeof other);
    return rc;
}

static int unseal(const uint8_t *sealed, size_t n, void *plain, size_t cap, size_t *len) {
    return g_open ? unseal_with(&g_held, sealed, n, plain, cap, len) : PASS_WRONG;
}

static int write_sealed_to(const char *name, const pass_lock_t *lk, const char *file, const void *plain, size_t len) {
    char path[1000];
    static uint8_t sealed[VERIFIED_FILE_MAX];
    size_t n;
    if (save_path(name, file, path, sizeof path, 1) != 0) return -1;
    if (pass_seal(lk, plain, len, sealed, sizeof sealed, &n) != 0) return -1;
    return platform_write_private(path, sealed, n);
}

static int write_sealed_with(const pass_lock_t *lk, const char *file, const void *plain, size_t len) {
    return g_open ? write_sealed_to(g_name, lk, file, plain, len) : -1;
}

static int write_code_to(const char *name, const pass_lock_t *lk, const uint8_t secret[TOTP_SECRET_LEN]) {
    uint8_t plain[CODE_PLAIN_LEN];
    plain[0] = 1;
    memcpy(plain + 1, secret, TOTP_SECRET_LEN);
    int rc = write_sealed_to(name, lk, CODE_NAME, plain, sizeof plain);
    crypto_wipe(plain, sizeof plain);
    return rc;
}

static int write_code(const pass_lock_t *lk, const uint8_t secret[TOTP_SECRET_LEN]) {
    return g_open ? write_code_to(g_name, lk, secret) : -1;
}

static int read_code(const char *name, const held_t *h, uint8_t secret[TOTP_SECRET_LEN]) {
    static uint8_t sealed[CODE_FILE_MAX + 1];
    uint8_t plain[CODE_FILE_MAX];
    size_t n = 0, len = 0;
    int rc = read_sealed(name, CODE_NAME, sealed, CODE_FILE_MAX, &n);
    if (rc == 0) rc = unseal_with(h, sealed, n, plain, sizeof plain, &len);
    if (rc == 0 && (len != CODE_PLAIN_LEN || plain[0] != 1)) rc = PASS_FORMAT;
    if (rc == 0) memcpy(secret, plain + 1, TOTP_SECRET_LEN);
    crypto_wipe(plain, sizeof plain);
    return rc;
}

static int set_lock(unsigned target);

// ---- the tries file, and the shadow passphrase ----

static int read_tries(const char *name, unsigned *limit, unsigned *count) {
    char path[1000];
    uint8_t b[5];
    if (save_path(name, TRIES_NAME, path, sizeof path, 0) != 0) return -1;
    if (platform_read_file(path, b, sizeof b) != (long)sizeof b || memcmp(b, TRIES_MAGIC, 3) != 0) return -1;
    *limit = b[3];
    *count = b[4];
    return 0;
}

static int write_tries(const char *name, unsigned limit, unsigned count) {
    char path[1000];
    uint8_t b[5];
    if (save_path(name, TRIES_NAME, path, sizeof path, 1) != 0) return -1;
    memcpy(b, TRIES_MAGIC, 3);
    b[3] = (uint8_t)limit;
    b[4] = (uint8_t)count;
    return platform_write_private(path, b, sizeof b);
}

int install_destroy_limit(const char *name) {
    unsigned l = 0, c = 0;
    return read_tries(name, &l, &c) == 0 ? (int)l : 0;
}

int install_tries_left(const char *name) {
    unsigned l = 0, c = 0;
    if (read_tries(name, &l, &c) != 0 || l == 0) return -1;
    return c >= l ? 0 : (int)(l - c);
}

int install_arm_destroy(const char *name, unsigned limit) {
    if (limit > 255) limit = 255;
    if (limit == 0) { remove_file(name, TRIES_NAME); return 0; }
    return write_tries(name, limit, 0);
}

// ---- the spare: a decoy, or chaff the same shape ----

static int old_decoy(const char *name) { return has(name, OLD_DECOY_SETTINGS); }

static void remove_old_decoy(const char *name) {
    for (size_t i = 0; i < N_OLD_DECOY; i++) remove_file(name, OLD_DECOY[i]);
}

static int write_spare_lock(const char *name, const pass_lock_t *lk, const pass_lock_t *decoy) {
    uint8_t plain[SPARE_LOCK_PLAIN_LEN];
    plain[0] = 1;
    plain[1] = decoy != NULL;
    if (decoy) {
        memcpy(plain + 2, decoy->header, PASS_HEADER_LEN);
        memcpy(plain + 2 + PASS_HEADER_LEN, decoy->base, sizeof decoy->base);
    } else {
        gen_random(plain + 2, sizeof plain - 2);
    }
    int rc = write_sealed_to(name, lk, SPARE_LOCK_NAME, plain, sizeof plain);
    crypto_wipe(plain, sizeof plain);
    return rc;
}

// 1, with the decoy's lock (its factors still to be set) in decoy, if the save has a decoy; 0 if it
// hasn't; -1 if its spare-lock file is missing or damaged.
static int read_spare_lock(const char *name, const held_t *h, pass_lock_t *decoy) {
    uint8_t sealed[SPARE_LOCK_FILE_LEN + 1], plain[SPARE_LOCK_PLAIN_LEN];
    size_t n = 0, len = 0;
    int out = -1, rc = read_sealed(name, SPARE_LOCK_NAME, sealed, SPARE_LOCK_FILE_LEN, &n);
    if (rc == 0) rc = unseal_with(h, sealed, n, plain, sizeof plain, &len);
    if (rc == 0 && len == sizeof plain && plain[0] == 1 && plain[1] <= 1) {
        out = plain[1];
        memset(decoy, 0, sizeof *decoy);
        if (out) {
            memcpy(decoy->header, plain + 2, PASS_HEADER_LEN);
            memcpy(decoy->base, plain + 2 + PASS_HEADER_LEN, sizeof decoy->base);
        }
    }
    crypto_wipe(plain, sizeof plain);
    return out;
}

static int write_chaff(const char *name, unsigned needs) {
    uint8_t buf[SPARE_FILE_LEN];
    char path[1000];
    pass_chaff(needs, SPARE_PLAIN_LEN, buf);
    return save_path(name, SPARE_NAME, path, sizeof path, 1) == 0 ? platform_write_private(path, buf, sizeof buf) : -1;
}

static int write_decoy(const char *name, const pass_lock_t *sl, const uint8_t *code) {
    uint8_t plain[SPARE_PLAIN_LEN] = { 1, code != NULL };
    if (code) memcpy(plain + 2, code, TOTP_SECRET_LEN);
    int rc = write_sealed_to(name, sl, SPARE_NAME, plain, sizeof plain);
    crypto_wipe(plain, sizeof plain);
    return rc;
}

// The spare made to need what the save needs: a decoy sealed again with the key its passphrase made,
// which the spare's lock keeps, and with the save's code if it asks for one; otherwise new chaff.
// 1 if the save has a decoy, 0 if not, -1 if it had one that couldn't be kept.
static int spare_fit(const char *name, const held_t *h, unsigned needs) {
    pass_lock_t *sl = &g_spare_lock;
    uint8_t code[TOTP_SECRET_LEN];
    int had = read_spare_lock(name, h, sl), out = 0;
    if (had == 1) {
        int with_code = (needs & F_CODE) && read_code(name, h, code) == 0;
        pass_lock_set(sl, needs, h->device, h->key);
        out = (with_code || !(needs & F_CODE)) && write_decoy(name, sl, with_code ? code : NULL) == 0 ? 1 : -1;
    }
    crypto_wipe(code, sizeof code);
    crypto_wipe(sl, sizeof *sl);
    if (out == 1) return 1;
    write_chaff(name, needs);
    if (had != 0) write_spare_lock(name, &h->lock, NULL);
    return out;
}

// Opened with its own passphrase, a save is written just as when its decoy takes its place: every
// sealed file and the spare, so the files' times don't say which passphrase opened it.
static void refresh(const char *name, const held_t *h) {
    static uint8_t buf[VERIFIED_FILE_MAX + 1];
    char path[1000];
    for (size_t i = 0; i < N_SEALED; i++) {
        if (save_path(name, SEALED[i], path, sizeof path, 0) != 0) continue;
        long n = platform_read_file(path, buf, sizeof buf);
        if (n > 0 && (size_t)n <= VERIFIED_FILE_MAX) platform_write_private(path, buf, (size_t)n);
    }
    // A decoy the betas made can't be sealed again without its passphrase, so it stays as it is.
    if (!old_decoy(name) && spare_fit(name, h, h->lock.needs) < 0) g_decoy_lost = 1;
}

// The decoy takes the save's place, settings first, so from then on the real passphrase opens
// nothing. The save's key goes. Its device and securitykey files stay, since the decoy needs them
// too. Then it gets a spare of chaff, as a save without a decoy has.
static void promote(const char *name, const pass_lock_t *sl, const uint8_t *spare_plain, int old) {
    if (old) {
        static const char *const to[] = { SETTINGS_NAME, KEY_NAME, VERIFIED_NAME, CODE_NAME };
        static uint8_t buf[VERIFIED_FILE_MAX + 1];
        char path[1000];
        for (size_t i = 0; i < N_OLD_DECOY; i++) {
            long n = save_path(name, OLD_DECOY[i], path, sizeof path, 0) == 0 ? platform_read_file(path, buf, sizeof buf) : -1;
            if (n > 0 && (size_t)n <= VERIFIED_FILE_MAX && save_path(name, to[i], path, sizeof path, 1) == 0)
                platform_write_private(path, buf, (size_t)n);
            else
                remove_file(name, to[i]);
        }
    } else {
        write_sealed_to(name, sl, SETTINGS_NAME, "", 0);
        remove_file(name, KEY_NAME);
        write_sealed_to(name, sl, VERIFIED_NAME, "", 0);
        if (spare_plain[1]) write_code_to(name, sl, spare_plain + 2);
        else remove_file(name, CODE_NAME);
    }
    write_spare_lock(name, sl, NULL);
    write_chaff(name, sl->needs);
    remove_old_decoy(name);
}

// A wrong passphrase: PASS_WRONG, or INSTALL_DESTROYED if it was one too many.
static int wrong_pass(const char *name) {
    unsigned limit = 0, count = 0;
    if (read_tries(name, &limit, &count) != 0 || limit == 0) return PASS_WRONG;
    count++;
    if (count >= limit) {
        install_remove(name);
        snprintf(g_why, sizeof g_why, "the wrong passphrase was entered %u times in a row", count);
        return INSTALL_DESTROYED;
    }
    write_tries(name, limit, count);
    return PASS_WRONG;
}

int install_lock_new(const char *name, const char *passphrase, unsigned factors) {
    held_t *h = &g_opening;
    g_why[0] = '\0';
    factors &= PASS_NEEDS_ALL;
    if ((factors & F_KEY) && !g_new_key.have) {
        copy_str(g_why, "no security key is registered for it", sizeof g_why);
        return -1;
    }
    if ((factors & F_CODE) && !(g_new_code.have && g_new_code.confirmed)) {
        copy_str(g_why, "no authenticator app is set up for it", sizeof g_why);
        return -1;
    }
    pin_secrets();
    memset(h, 0, sizeof *h);
    int rc = pass_lock_new(passphrase, &h->lock), wrote_device = 0, wrote_key = 0;
    if (rc == 0 && (factors & F_DEVICE)) {
        gen_random(h->device, sizeof h->device);
        if (device_seal(name, h->device, &h->device_kind) != 0) rc = INSTALL_DEVICE;
        else wrote_device = h->have_device = 1;
    }
    if (rc == 0 && (factors & F_KEY)) {
        if (write_key_file(name, &g_new_key.file) == 0) {
            memcpy(h->key, g_new_key.secret, sizeof h->key);
            wrote_key = h->have_key = 1;
        } else {
            copy_str(g_why, "couldn't write its securitykey file", sizeof g_why);
            rc = -1;
        }
    }
    if (rc == 0) {
        pass_lock_set(&h->lock, factors, h->device, h->key);
        hold(name, h);
        if ((factors & F_CODE) && write_code(&g_held.lock, g_new_code.secret) != 0) {
            copy_str(g_why, "couldn't write its authenticator file", sizeof g_why);
            install_forget();
            remove_file(name, CODE_NAME);
            rc = -1;
        }
    }
    // Every save has a spare from the start, so having one says nothing. One that can't be written
    // now is when the save is next opened.
    if (rc == 0) {
        g_decoy_lost = 0;
        write_spare_lock(name, &g_held.lock, NULL);
        write_chaff(name, factors);
    }
    // A save that can't be made with all its factors leaves nothing behind.
    if (rc != 0 && wrote_key) remove_file(name, SECKEY_NAME);
    if (rc != 0 && wrote_device) forget_device(name);
    crypto_wipe(h, sizeof *h);
    if (rc == 0) install_setup_forget();
    return rc;
}

// Part way through a change (chat stopped, or a file was swapped for one sealed with fewer
// factors), the save is finished the safer way: with every factor any of its files needs.
static void finish_open(unsigned all) {
    if (all != g_held.lock.needs) g_relocked = set_lock(all) == 0 ? 1 : -1;
}

// Tried on the settings file, which exists whenever the key file does, unless writing it failed.
// A save locked to the device needs it before anything else: elsewhere no passphrase can open it,
// so none is tried. A save may still have files a crash left locked to it. A security key that any
// file needs is needed first too, so nothing is ever sealed again without it. act: a wrong
// passphrase counts towards self-destruct, and the shadow passphrase opens the decoy.
static int unlock(const char *name, const char *passphrase, int act) {
    static uint8_t sealed[SETTINGS_FILE_MAX + 1], plain[SETTINGS_FILE_MAX], spare[SETTINGS_FILE_MAX + 1];
    held_t *h = &g_opening;
    pass_lock_t *sl = &g_spare_lock;
    size_t n = 0, sn = 0, got;
    g_relocked = 0;
    g_decoy_lost = 0;
    g_why[0] = '\0';
    int rc = read_sealed(name, SETTINGS_NAME, sealed, SETTINGS_FILE_MAX, &n);
    if (rc == INSTALL_NO_FILE) rc = read_sealed(name, KEY_NAME, sealed, KEY_FILE_MAX, &n);
    if (rc != 0) return rc;
    pin_secrets();
    memset(h, 0, sizeof *h);
    unsigned locked = pass_needs(sealed, n), all = locked | install_factors(name);
    if (all & F_DEVICE) {
        h->have_device = device_unseal(name, h->device, &h->device_kind) == 0;
        if (!h->have_device && (locked & F_DEVICE)) {
            crypto_wipe(h, sizeof *h);
            return INSTALL_DEVICE;
        }
    }
    if (all & F_KEY) {
        if (!install_key_ready(name)) {
            crypto_wipe(h, sizeof *h);
            return INSTALL_KEY;
        }
        memcpy(h->key, g_try_key, sizeof h->key);
        h->have_key = 1;
    }
    int old = 0, sr = read_sealed(name, SPARE_NAME, spare, SETTINGS_FILE_MAX, &sn);
    if (sr == INSTALL_NO_FILE) {
        sr = read_sealed(name, OLD_DECOY_SETTINGS, spare, SETTINGS_FILE_MAX, &sn);
        old = sr == 0;
    }
    rc = pass_lock_of(passphrase, sealed, n, &h->lock);
    // Argon2id runs for the spare on every try, decoy or chaff, or on a new salt for a save without
    // one, so how long a passphrase takes doesn't say what it opened.
    if (sr == 0) sr = pass_lock_of(passphrase, spare, sn, sl);
    if (sr != 0 && sr != PASS_NOMEM) sr = pass_lock_new(passphrase, sl) == PASS_NOMEM ? PASS_NOMEM : -1;
    if (rc == 0 && sr == PASS_NOMEM) rc = PASS_NOMEM;
    if (rc == 0) pass_lock_set(&h->lock, locked, h->device, h->key);
    if (rc == 0) rc = pass_unseal(&h->lock, sealed, n, plain, sizeof plain, &got);
    int decoy = 0;
    if (rc == PASS_WRONG && sr == 0) {
        unsigned sneeds = pass_needs(spare, sn);
        if ((!(sneeds & F_DEVICE) || h->have_device) && (!(sneeds & F_KEY) || h->have_key)) {
            pass_lock_set(sl, sneeds, h->device, h->key);
            decoy = pass_unseal(sl, spare, sn, plain, sizeof plain, &got) == 0
                 && (old || (got == SPARE_PLAIN_LEN && plain[0] == 1 && plain[1] <= 1));
        }
    }
    if (rc != 0 && !(decoy && act)) {
        crypto_wipe(plain, sizeof plain);
        crypto_wipe(sl, sizeof *sl);
        int w = rc == PASS_WRONG && act ? wrong_pass(name) : rc;
        crypto_wipe(h, sizeof *h);
        return w;
    }
    forget_try_key();
    if (decoy) {
        promote(name, sl, plain, old);
        h->lock = *sl;
        locked = sl->needs;
        all = locked | install_factors(name);
    } else {
        refresh(name, h);
    }
    crypto_wipe(plain, sizeof plain);
    crypto_wipe(sl, sizeof *sl);
    { unsigned l = 0, c = 0; if (read_tries(name, &l, &c) == 0 && l) write_tries(name, l, 0); }
    if (!h->have_device) h->device_kind = DEVICE_NONE;
    unsigned usable = all & ~(h->have_device ? 0u : F_DEVICE);
    if (all & F_CODE) {
        install_code_cancel();
        if (read_code(name, h, g_code) != 0) {
            crypto_wipe(h, sizeof *h);
            copy_str(g_why, "its authenticator file is missing or damaged, so the code it asks for can't be checked",
                     sizeof g_why);
            return INSTALL_LOST;
        }
        g_pend = *h;
        copy_str(g_pend_name, stored_name(name), sizeof g_pend_name);
        g_pend_all = usable;
        g_pending = 1;
        crypto_wipe(h, sizeof *h);
        return 0;
    }
    hold(name, h);
    crypto_wipe(h, sizeof *h);
    finish_open(usable);
    return 0;
}

int install_unlock(const char *name, const char *passphrase) { return unlock(name, passphrase, 1); }

int install_probe(const char *name, const char *passphrase) { return unlock(name, passphrase, 0); }

int install_code_pending(void) { return g_pending; }

void install_code_cancel(void) {
    crypto_wipe(&g_pend, sizeof g_pend);
    crypto_wipe(g_code, sizeof g_code);
    g_pend_name[0] = '\0';
    g_pending = 0;
}

// Spaces and dashes, as some apps show a code, are left out.
static int parse_code(const char *code, uint32_t *out) {
    uint32_t v = 0;
    int n = 0;
    for (const char *p = code; *p; p++) {
        if (*p == ' ' || *p == '-') continue;
        if (*p < '0' || *p > '9' || n >= TOTP_DIGITS) return PASS_FORMAT;
        v = v * 10 + (uint32_t)(*p - '0');
        n++;
    }
    if (n != TOTP_DIGITS) return PASS_FORMAT;
    *out = v;
    return 0;
}

// The step before and after too, for a phone's clock that's a little out.
static int code_matches(const uint8_t secret[TOTP_SECRET_LEN], uint32_t code) {
    uint64_t step = (uint64_t)time(NULL) / TOTP_PERIOD;
    int ok = 0;
    for (int d = -1; d <= 1; d++) ok |= totp_code(secret, TOTP_SECRET_LEN, step + (uint64_t)(int64_t)d) == code;
    return ok;
}

int install_check_code(const char *code) {
    uint32_t v;
    if (!g_pending) return PASS_WRONG;
    if (parse_code(code, &v) != 0) return PASS_FORMAT;
    if (!code_matches(g_code, v)) {
        // Without the pause, a script could try every code through chat in minutes.
        platform_sleep_ms(1500);
        return PASS_WRONG;
    }
    hold(g_pend_name, &g_pend);
    unsigned all = g_pend_all;
    install_code_cancel();
    finish_open(all);
    return 0;
}

int install_relocked(void) { return g_relocked; }

void install_forget(void) {
    crypto_wipe(&g_held, sizeof g_held);
    g_held.device_kind = DEVICE_NONE;
    forget_try_key();
    install_code_cancel();
    g_open = 0;
    g_decoy_state = -1;
    g_decoy_lost = 0;
}

unsigned install_open_factors(void) { return g_open ? g_held.lock.needs : 0; }

device_kind_t install_device_lock(void) {
    return g_open && (g_held.lock.needs & F_DEVICE) ? g_held.device_kind : DEVICE_NONE;
}

const char *install_why(void) { return g_why; }

static long read_text(const char *file, size_t max, char *buf, size_t cap) {
    static uint8_t sealed[VERIFIED_FILE_MAX + 1];
    size_t n = 0, len = 0;
    if (cap < 1) return PASS_FORMAT;
    int rc = read_sealed(g_name, file, sealed, max, &n);
    if (rc == 0) rc = unseal(sealed, n, buf, cap - 1, &len);
    if (rc != 0) return rc;
    buf[len] = '\0';
    return (long)len;
}

long install_read_settings(char *buf, size_t cap) { return read_text(SETTINGS_NAME, SETTINGS_FILE_MAX, buf, cap); }
long install_read_verified(char *buf, size_t cap) { return read_text(VERIFIED_NAME, VERIFIED_FILE_MAX, buf, cap); }

static int write_sealed(const char *file, const void *plain, size_t len) {
    return write_sealed_with(&g_held.lock, file, plain, len);
}

int install_write_settings(const char *text) { return write_sealed(SETTINGS_NAME, text, strlen(text)); }

int install_write_verified(const char *text) {
    size_t len = strlen(text);
    return len > INSTALL_VERIFIED_MAX ? -1 : write_sealed(VERIFIED_NAME, text, len);
}

int install_write_key(const void *secret, size_t len) {
    return len > INSTALL_KEY_MAX ? -1 : write_sealed(KEY_NAME, secret, len);
}

int install_read_key(void *secret, size_t cap, size_t *len) {
    uint8_t sealed[KEY_FILE_MAX + 1];
    size_t n = 0;
    int rc = read_sealed(g_name, KEY_NAME, sealed, KEY_FILE_MAX, &n);
    if (rc == 0) rc = unseal(sealed, n, secret, cap, len);
    return rc;
}

// ---- changing the factors ----

// One of the open save's files sealed again under lk. 0 once it is (or if there's no such file),
// 1 if it can't be read and stays as it was, -1 if it can't be written.
static int reseal(const char *file, const pass_lock_t *lk) {
    static uint8_t sealed[VERIFIED_FILE_MAX + 1], plain[VERIFIED_FILE_MAX];
    size_t n = 0, len = 0;
    int rc = read_sealed(g_name, file, sealed, file_max(file), &n);
    if (rc == INSTALL_NO_FILE || (rc == 0 && n >= PASS_HEADER_LEN && memcmp(sealed, lk->header, PASS_HEADER_LEN) == 0))
        return 0;
    int out = 1;
    if (rc == 0 && unseal(sealed, n, plain, sizeof plain, &len) == 0) {
        out = write_sealed_with(lk, file, plain, len) == 0 ? 0 : -1;
        if (out < 0) snprintf(g_why, sizeof g_why, "couldn't write its %s file", file);
    }
    crypto_wipe(plain, sizeof plain);
    return out;
}

static int reseal_lock_file(const char *file, const pass_lock_t *next) {
    int rc = reseal(file, next);
    if (rc > 0) snprintf(g_why, sizeof g_why, "its %s file can't be read", file);
    if (rc == 0) g_held.lock = *next;
    return rc == 0 ? 0 : -1;
}

// Every file sealed again under the lock for target, whose factors' secrets are held. The lock file
// says how the save is locked, so it's sealed again last when adding factors and first when taking
// them away, and the files a factor needs are written before anything depends on them and deleted
// after nothing does. A crash in between leaves files sealed both ways, and install_unlock opens
// that with all their factors.
static int set_lock(unsigned target) {
    pass_lock_t next = g_held.lock;
    pass_lock_set(&next, target, g_held.device, g_held.key);
    int fewer = (g_held.lock.needs & ~target) != 0, rc = 0, skipped = 0;
    const char *first = lock_file(g_name);
    if ((target & F_CODE) && !(g_held.lock.needs & F_CODE) && g_new_code.have && g_new_code.confirmed
        && write_code(&next, g_new_code.secret) != 0) {
        copy_str(g_why, "couldn't write its authenticator file", sizeof g_why);
        rc = -1;
    }
    if (rc == 0 && fewer) rc = reseal_lock_file(first, &next);
    for (size_t i = 0; i < N_SEALED && rc == 0; i++) {
        if (strcmp(SEALED[i], first) == 0 || (strcmp(SEALED[i], CODE_NAME) == 0 && !(target & F_CODE))) continue;
        int r = reseal(SEALED[i], &next);
        if (r > 0) skipped++;
        else rc = r;
    }
    if (rc == 0 && !fewer) rc = reseal_lock_file(first, &next);
    crypto_wipe(&next, sizeof next);
    if (rc != 0) return -1;
    // While the secrets of factors going away are still held. A decoy the betas made can't be
    // sealed again without its passphrase.
    if (!old_decoy(g_name) && spare_fit(g_name, &g_held, target) < 0) g_decoy_lost = 1;
    g_decoy_state = -1;
    if (target & F_CODE) crypto_wipe(&g_new_code, sizeof g_new_code);
    // A factor's own file only goes once no file that couldn't be sealed again still needs it.
    if (!(target & F_CODE) && !(needs_but(g_name, CODE_NAME) & F_CODE)) remove_file(g_name, CODE_NAME);
    unsigned still = install_factors(g_name);
    if (!(target & F_KEY) && !(still & F_KEY)) {
        remove_file(g_name, SECKEY_NAME);
        hold_key(NULL);
    }
    if (!(target & F_DEVICE) && !(still & F_DEVICE) && (g_held.have_device || has(g_name, DEVICE_NAME))) {
        forget_device(g_name);
        hold_device(NULL, DEVICE_NONE);
    }
    if (skipped)
        snprintf(g_why, sizeof g_why, "%d of its files can't be read (damaged, or sealed some other way), and %s left as %s",
                 skipped, skipped == 1 ? "is" : "are", skipped == 1 ? "it was" : "they were");
    return 0;
}

// The device's secret, in the save's device file. One this device unsealed already is kept: files
// a crash left locked to it need it. If the device file no longer gives it back, it's sealed again
// before anything depends on it.
static int device_ready(void) {
    uint8_t secret[DEVICE_SECRET_LEN];
    device_kind_t kind = g_held.device_kind;
    int sealed = 0;
    if (g_held.have_device) {
        uint8_t back[DEVICE_SECRET_LEN];
        device_kind_t was;
        memcpy(secret, g_held.device, sizeof secret);
        sealed = device_unseal(g_name, back, &was) == 0 && crypto_equal(back, secret, sizeof back) == 0;
        crypto_wipe(back, sizeof back);
    } else if (install_factors(g_name) & F_DEVICE) {
        copy_str(g_why, "some of its files are locked to a device secret this device can't unseal", sizeof g_why);
        return -1;
    } else {
        gen_random(secret, sizeof secret);
    }
    if (!sealed && device_seal(g_name, secret, &kind) != 0) {
        crypto_wipe(secret, sizeof secret);
        return -1;
    }
    hold_device(secret, kind);
    crypto_wipe(secret, sizeof secret);
    return 0;
}

// The security key registered by install_key_make, written to the save's securitykey file. A save
// with files a crash left needing a security key keeps the secret it has, and its file.
static int key_ready(void) {
    static key_file_t f;
    if (g_held.have_key) {
        if (read_key_file(g_name, &f) == 0) return 0;
        copy_str(g_why, "some of its files need a security key, and its securitykey file is missing or damaged", sizeof g_why);
        return -1;
    }
    if (install_factors(g_name) & F_KEY) {
        copy_str(g_why, "some of its files need a security key whose secret chat doesn't have", sizeof g_why);
        return -1;
    }
    if (!g_new_key.have) {
        copy_str(g_why, "no security key is registered for it", sizeof g_why);
        return -1;
    }
    if (write_key_file(g_name, &g_new_key.file) != 0) {
        copy_str(g_why, "couldn't write its securitykey file", sizeof g_why);
        return -1;
    }
    hold_key(g_new_key.secret);
    crypto_wipe(&g_new_key, sizeof g_new_key);
    return 0;
}

int install_set_factor(unsigned factor, int on) {
    g_why[0] = '\0';
    if (!g_open) {
        copy_str(g_why, "no save is open", sizeof g_why);
        return -1;
    }
    int is_on = (g_held.lock.needs & factor) != 0;
    // Off, with a secret for it still held, some files may be left needing it, and are finished.
    int held = factor == F_DEVICE ? g_held.have_device : factor == F_KEY ? g_held.have_key : 0;
    if (on ? is_on : !is_on && !held) return 0;
    if (on && factor == F_DEVICE && device_ready() != 0) return -1;
    if (on && factor == F_KEY && key_ready() != 0) return -1;
    if (on && factor == F_CODE && !(g_new_code.have && g_new_code.confirmed)) {
        copy_str(g_why, "no authenticator app is set up for it", sizeof g_why);
        return -1;
    }
    return set_lock(on ? g_held.lock.needs | factor : g_held.lock.needs & ~factor);
}

// ---- security keys ----

static void key_thread(void *arg) {
    (void)arg;
    const char *pin = g_job.pin[0] ? g_job.pin : NULL;
    if (g_job.make)
        g_job.rc = platform_seckey_make(g_job.salt, pin, g_job.cred, &g_job.cred_len, &g_job.cred_uv, g_job.secret, &g_job.w,
                                        g_job.why, sizeof g_job.why);
    else
        g_job.rc = platform_seckey_secret(g_job.creds, g_job.lens, g_job.uv, g_job.n, g_job.salt, pin, g_job.secret, &g_job.w,
                                          g_job.why, sizeof g_job.why);
    crypto_wipe(g_job.pin, sizeof g_job.pin);
    __atomic_store_n(&g_job_state, JOB_ENDED, __ATOMIC_RELEASE);
}

static int start_job(const char *pin) {
    g_job.rc = -1;
    g_job.why[0] = '\0';
    memset(&g_job.w, 0, sizeof g_job.w);
    copy_str(g_job.pin, pin ? pin : "", sizeof g_job.pin);
    __atomic_store_n(&g_job_state, JOB_RUNNING, __ATOMIC_RELEASE);
    if (platform_spawn_thread(key_thread, NULL) == 0) return 0;
    crypto_wipe(g_job.pin, sizeof g_job.pin);
    __atomic_store_n(&g_job_state, JOB_IDLE, __ATOMIC_RELEASE);
    copy_str(g_key_why, "couldn't start a thread to wait for the security key", sizeof g_key_why);
    return -1;
}

static int job_busy(void) {
    if (__atomic_load_n(&g_job_state, __ATOMIC_ACQUIRE) == JOB_IDLE) return 0;
    copy_str(g_key_why, "a security key is in use already", sizeof g_key_why);
    return 1;
}

int install_key_make(const char *pin) {
    if (job_busy()) return -1;
    pin_secrets();
    g_job.make = 1;
    g_job_name[0] = '\0';
    gen_random(g_job.salt, sizeof g_job.salt);
    return start_job(pin);
}

int install_key_open(const char *name, const char *pin) {
    if (job_busy()) return -1;
    pin_secrets();
    if (read_key_file(name, &g_job_file) != 0) {
        copy_str(g_key_why, "its securitykey file is missing or damaged", sizeof g_key_why);
        return -1;
    }
    g_job.make = 0;
    copy_str(g_job_name, stored_name(name), sizeof g_job_name);
    memcpy(g_job.salt, g_job_file.salt, sizeof g_job.salt);
    g_job.n = g_job_file.n;
    for (int i = 0; i < g_job_file.n; i++) {
        g_job.creds[i] = g_job_file.e[i].cred;
        g_job.lens[i] = g_job_file.e[i].cred_len;
        g_job.uv[i] = g_job_file.e[i].uv;
    }
    return start_job(pin);
}

// A newly registered security key, wrapping a new secret for the save.
static void stage_new_key(void) {
    key_file_t *f = &g_new_key.file;
    key_entry_t *e = &f->e[0];
    static uint8_t ad[5 + SECKEY_SALT_LEN + SECKEY_CRED_MAX];
    memset(f, 0, sizeof *f);
    memcpy(f->salt, g_job.salt, sizeof f->salt);
    f->n = 1;
    e->uv = g_job.cred_uv != 0;
    e->cred_len = g_job.cred_len;
    memcpy(e->cred, g_job.cred, g_job.cred_len);
    gen_random(g_new_key.secret, sizeof g_new_key.secret);
    secret_wrap(g_job.secret, ad, entry_ad(f->salt, e, ad), g_new_key.secret, e->wrapped);
    g_new_key.have = 1;
}

static int take_key(int i) {
    static uint8_t ad[5 + SECKEY_SALT_LEN + SECKEY_CRED_MAX];
    if (i >= g_job_file.n
        || secret_unwrap(g_job.secret, ad, entry_ad(g_job_file.salt, &g_job_file.e[i], ad), g_job_file.e[i].wrapped,
                         g_try_key) != 0) {
        copy_str(g_key_why, "the security key's secret doesn't open the save's securitykey file", sizeof g_key_why);
        return -1;
    }
    g_have_try_key = 1;
    copy_str(g_try_name, g_job_name, sizeof g_try_name);
    return 0;
}

install_key_state_t install_key_poll(int *stage, int *touches) {
    int st = __atomic_load_n(&g_job_state, __ATOMIC_ACQUIRE);
    if (stage) *stage = __atomic_load_n(&g_job.w.stage, __ATOMIC_ACQUIRE);
    if (touches) *touches = __atomic_load_n(&g_job.w.touches, __ATOMIC_ACQUIRE);
    if (st == JOB_IDLE) return INSTALL_KEY_IDLE;
    if (st == JOB_RUNNING) return INSTALL_KEY_RUNNING;
    copy_str(g_key_why, g_job.why, sizeof g_key_why);
    int rc = g_job.rc;
    install_key_state_t out = rc == SECKEY_PIN ? INSTALL_KEY_PIN : rc == SECKEY_CANCELLED ? INSTALL_KEY_CANCELLED
                            : INSTALL_KEY_FAILED;
    if (g_job.make && rc == 0) {
        stage_new_key();
        out = INSTALL_KEY_DONE;
    } else if (!g_job.make && rc >= 0) {
        out = take_key(rc) == 0 ? INSTALL_KEY_DONE : INSTALL_KEY_FAILED;
    }
    crypto_wipe(g_job.secret, sizeof g_job.secret);
    __atomic_store_n(&g_job_state, JOB_IDLE, __ATOMIC_RELEASE);
    return out;
}

void install_key_cancel(void) { __atomic_store_n(&g_job.w.cancel, 1, __ATOMIC_RELEASE); }

const char *install_key_why(void) { return g_key_why; }

int install_key_ready(const char *name) { return g_have_try_key && strcmp(g_try_name, stored_name(name)) == 0; }

// ---- authenticator codes ----

void install_code_new(const char *name, char *b32, size_t b32_cap, char *uri, size_t uri_cap) {
    char text[(TOTP_SECRET_LEN * 8 + 4) / 5 + 1];
    pin_secrets();
    gen_random(g_new_code.secret, sizeof g_new_code.secret);
    g_new_code.have = 1;
    g_new_code.confirmed = 0;
    base32_encode(g_new_code.secret, sizeof g_new_code.secret, text);
    copy_str(b32, text, b32_cap);
    snprintf(uri, uri_cap, "otpauth://totp/chat:%s?secret=%s&issuer=chat", install_shown_name(name), text);
    crypto_wipe(text, sizeof text);
}

int install_code_try(const char *code) {
    uint32_t v;
    if (!g_new_code.have) return PASS_WRONG;
    if (parse_code(code, &v) != 0) return PASS_FORMAT;
    if (!code_matches(g_new_code.secret, v)) return PASS_WRONG;
    g_new_code.confirmed = 1;
    return 0;
}

void install_setup_forget(void) {
    crypto_wipe(&g_new_key, sizeof g_new_key);
    crypto_wipe(&g_new_code, sizeof g_new_code);
}

// ---- the shadow passphrase ----

int install_has_shadow(void) {
    if (!g_open) return 0;
    if (g_decoy_state < 0) {
        g_decoy_state = old_decoy(g_name) || read_spare_lock(g_name, &g_held, &g_spare_lock) == 1;
        crypto_wipe(&g_spare_lock, sizeof g_spare_lock);
    }
    return g_decoy_state;
}

int install_shadow_news(void) {
    if (!g_open) return INSTALL_SHADOW_OK;
    if (g_decoy_lost) {
        g_decoy_lost = 0;
        return INSTALL_SHADOW_LOST;
    }
    return old_decoy(g_name) ? INSTALL_SHADOW_OLD : INSTALL_SHADOW_OK;
}

// The decoy is sealed under its own passphrase and the save's own factor secrets, so it needs the
// same device, security key and code. Its spare is written first: until the spare's lock says so,
// the save doesn't count as having a decoy. The save's own passphrase would only ever open the save.
int install_shadow_set(const char *passphrase) {
    static uint8_t sealed[SETTINGS_FILE_MAX + 1];
    g_why[0] = '\0';
    if (!g_open) { copy_str(g_why, "no save is open", sizeof g_why); return -1; }
    unsigned needs = g_held.lock.needs;
    if (((needs & F_DEVICE) && !g_held.have_device) || ((needs & F_KEY) && !g_held.have_key)) {
        copy_str(g_why, "the save's own factors aren't all available", sizeof g_why);
        return -1;
    }
    pin_secrets();
    pass_lock_t *sl = &g_spare_lock;
    uint8_t code[TOTP_SECRET_LEN];
    const char *lf = lock_file(g_name);
    size_t n = 0;
    int with_code = 0, rc = read_sealed(g_name, lf, sealed, file_max(lf), &n);
    if (rc == 0) rc = pass_lock_of(passphrase, sealed, n, sl);
    if (rc == 0 && crypto_equal(sl->base, g_held.lock.base, sizeof sl->base) == 0) {
        copy_str(g_why, "that's the save's own passphrase", sizeof g_why);
        rc = -1;
    }
    if (rc == 0) rc = pass_lock_new(passphrase, sl);
    if (rc == 0) {
        pass_lock_set(sl, needs, g_held.device, g_held.key);
        with_code = (needs & F_CODE) && read_code(g_name, &g_held, code) == 0;
        if ((needs & F_CODE) && !with_code) {
            copy_str(g_why, "its authenticator file can't be read", sizeof g_why);
            rc = -1;
        }
    }
    if (rc == 0 && (write_decoy(g_name, sl, with_code ? code : NULL) != 0 || write_spare_lock(g_name, &g_held.lock, sl) != 0)) {
        write_chaff(g_name, needs);
        copy_str(g_why, "couldn't write the decoy's files", sizeof g_why);
        rc = -1;
    }
    crypto_wipe(code, sizeof code);
    crypto_wipe(sl, sizeof *sl);
    if (rc == 0) remove_old_decoy(g_name);
    else if (rc != PASS_NOMEM && !g_why[0]) copy_str(g_why, "the save's files can't be read", sizeof g_why);
    g_decoy_state = -1;
    return rc;
}

// The decoy goes before the spare's lock says there's none, so a passphrase the save is said not to
// have never opens one.
int install_shadow_clear(void) {
    g_why[0] = '\0';
    if (!g_open) { copy_str(g_why, "no save is open", sizeof g_why); return -1; }
    int rc = write_chaff(g_name, g_held.lock.needs) == 0 && write_spare_lock(g_name, &g_held.lock, NULL) == 0 ? 0 : -1;
    if (rc == 0) remove_old_decoy(g_name);
    else copy_str(g_why, "couldn't write the spare's files", sizeof g_why);
    g_decoy_state = -1;
    return rc;
}

// ---- uninstalling ----

// Anything not chat's, and in the default save's folder, the saves folder if it has a save in it.
static void count_others(void *ctx, const char *name, int is_dir) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;
    for (size_t i = 0; i < N_FILES; i++) if (strcmp(name, FILES[i]) == 0) return;
    (void)is_dir;
    (*(int *)ctx)++;
}

static void count_all(void *ctx, const char *name, int is_dir) {
    (void)is_dir;
    if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) (*(int *)ctx)++;
}

static int is_empty(const char *dir) {
    int others = 0;
    return platform_list_dir(dir, count_others, &others) == 0 && others == 0;
}

// Nothing at all in it: the default save's files count too.
static int is_bare(const char *dir) {
    int n = 0;
    return platform_list_dir(dir, count_all, &n) == 0 && n == 0;
}

int install_remove(const char *name) {
    char dir[960], path[1000];
    name = stored_name(name);
    if (save_dir(name, dir, sizeof dir, 0) != 0) return -1;
    int left = 0;
    for (size_t i = 0; i < N_FILES; i++) {
        if (strcmp(FILES[i], DEVICE_NAME) == 0) continue;
        snprintf(path, sizeof path, "%s/%s", dir, FILES[i]);
        if (platform_remove(path) != 0 && path_exists(path)) left = 1;
    }
    // The device's part goes last, once nothing sealed with it is left.
    if (!left) {
        forget_device(name);
        snprintf(path, sizeof path, "%s/" DEVICE_NAME, dir);
        if (path_exists(path)) left = 1;
    }
    if (!left && strcmp(name, g_name) == 0) install_forget();
    if (left) return -1;
    // Another program could have a folder called chat too.
    if (is_empty(dir)) platform_remove_tree(dir);
    if (name[0]) {
        char top[900], saves[960];
        if (platform_config_dir(top, sizeof top, 0) != 0) return 0;
        snprintf(saves, sizeof saves, "%s/" SAVES_DIR, top);
        if (is_bare(saves)) platform_remove_tree(saves);
        if (is_bare(top)) platform_remove_tree(top);
    }
    return 0;
}
