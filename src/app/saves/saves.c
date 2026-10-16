// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The save files: their folders, sealing and opening them, what they hold (settings, keys, histories
// and tor's state), the tries file, the lock screen, and uninstalling.
#include "app/saves/store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CACHE_FILE_MAX (INSTALL_TOR_MAX + PASS_SEAL_OVERHEAD)
#define TRIES_MAGIC "CT1"   // then one byte each: the limit, the count so far
#define TRIES_LIMIT_AT (sizeof TRIES_MAGIC - 1)
#define TRIES_COUNT_AT (TRIES_LIMIT_AT + 1)
#define TRIES_LEN (TRIES_COUNT_AT + 1)
// The settings are padded with NULs to a multiple of this, so the file's size says little about
// what's in them: how many rooms they keep, say.
#define SETTINGS_PAD 4096
#define KEY_FILE_MAX (INSTALL_KEY_MAX + PASS_SEAL_OVERHEAD)
#define CODE_PLAIN_LEN (1 + TOTP_SECRET_LEN)
#define CODE_FILE_MAX (CODE_PLAIN_LEN + PASS_SEAL_OVERHEAD)

_Static_assert(DEVICE_SECRET_LEN == PASS_DEVICE_SECRET_LEN, "the device's secret is what a device lock mixes in");
_Static_assert(F_DEVICE == PASS_NEEDS_DEVICE && F_KEY == PASS_NEEDS_KEY && F_CODE == PASS_NEEDS_CODE,
               "a save's factors are its lock's");
_Static_assert(INSTALL_SETTINGS_MAX % SETTINGS_PAD == 0 && INSTALL_SETTINGS_MAX <= INSTALL_VERIFIED_MAX,
               "padded settings fit, and read_text's buffer holds them");

// Also removes any .new files left by a crash while writing.
static const char *const FILES[] = { SETTINGS_NAME, KEY_NAME, VERIFIED_NAME, CODE_NAME, SECKEY_NAME,
                                     TRIES_NAME, SPARE_NAME, SPARE_LOCK_NAME, OLD_DECOY_SETTINGS, OLD_DECOY_KEY,
                                     OLD_DECOY_VERIFIED, OLD_DECOY_CODE,
                                     SETTINGS_NAME ".new", KEY_NAME ".new", VERIFIED_NAME ".new", CODE_NAME ".new",
                                     SECKEY_NAME ".new", TRIES_NAME ".new", SPARE_NAME ".new", SPARE_LOCK_NAME ".new",
                                     OLD_DECOY_SETTINGS ".new", OLD_DECOY_KEY ".new", OLD_DECOY_VERIFIED ".new",
                                     OLD_DECOY_CODE ".new", DEVICE_NAME ".new", DEVICE_NAME, CACHE_NAME,
                                     CACHE_NAME ".new" };
#define N_FILES (sizeof FILES / sizeof FILES[0])

#define SAVES_DIR "saves"

held_t g_held;   // the open save's
int g_open;
char g_name[INSTALL_NAME_MAX + 1];
// A save opened that waits for its code: nothing of it is used, and the save that was open stays
// as it was, until install_check_code takes the code. Then it's finished with g_pend_all.
static held_t g_pend;
static held_t g_opening;   // what install_lock_new and install_unlock put together
static char g_pend_name[INSTALL_NAME_MAX + 1];
static int g_pending;
static uint8_t g_code[TOTP_SECRET_LEN];
static unsigned g_pend_all;
char g_why[256];
static int g_relocked;

void pin_secrets(void) {
    static int pinned;
    if (pinned) return;
    crypto_lock(&g_held, sizeof g_held);
    crypto_lock(&g_pend, sizeof g_pend);
    crypto_lock(&g_opening, sizeof g_opening);
    crypto_lock(g_code, sizeof g_code);
    crypto_lock(&g_spare_lock, sizeof g_spare_lock);
    pin_factor_secrets();
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

const char *stored_name(const char *name) {
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
    char dir[INSTALL_TOP_MAX];
    if (platform_config_dir(dir, sizeof dir, create) != 0) return -1;
    if (!name[0]) { copy_str(out, dir, cap); return strlen(dir) < cap ? 0 : -1; }
    int n = snprintf(out, cap, "%s/" SAVES_DIR, dir);
    if (n <= 0 || (size_t)n >= cap || (create && platform_private_dir(out) != 0)) return -1;
    n = snprintf(out, cap, "%s/" SAVES_DIR "/%s", dir, name);
    if (n <= 0 || (size_t)n >= cap || (create && platform_private_dir(out) != 0)) return -1;
    return 0;
}

int save_path(const char *name, const char *file, char *out, size_t cap, int create) {
    char dir[INSTALL_DIR_MAX];
    if (save_dir(name, dir, sizeof dir, create) != 0) return -1;
    int n = snprintf(out, cap, "%s/%s", dir, file);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

int install_where(const char *name, char *out, size_t cap) {
    char dir[INSTALL_DIR_MAX];
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

int has(const char *name, const char *file) {
    char path[INSTALL_PATH_MAX];
    return save_path(name, file, path, sizeof path, 0) == 0 && path_exists(path);
}

void remove_file(const char *name, const char *file) {
    char path[INSTALL_PATH_MAX];
    if (save_path(name, file, path, sizeof path, 0) == 0) platform_remove(path);
}

int install_has_settings(const char *name) { return has(name, SETTINGS_NAME); }
int install_has_key(const char *name) { return has(name, KEY_NAME); }

static int is_history(const char *file) { return starts_with(file, HISTORY_PREFIX); }

size_t file_max(const char *file) {
    return strcmp(file, SETTINGS_NAME) == 0 ? SETTINGS_FILE_MAX : strcmp(file, KEY_NAME) == 0 ? KEY_FILE_MAX
         : strcmp(file, CODE_NAME) == 0 ? CODE_FILE_MAX : is_history(file) ? HISTORY_FILE_MAX : VERIFIED_FILE_MAX;
}


static void add_history(void *ctx, const char *name, int is_dir) {
    history_list_t *l = ctx;
    if (!is_dir && is_history(name) && strlen(name) == HISTORY_NAME_LEN && l->n < HISTORIES_MAX)
        copy_str(l->names[l->n++], name, sizeof l->names[0]);
}

// The histories in a save's folder.
history_list_t *list_histories(const char *name) {
    static history_list_t l;
    char dir[INSTALL_DIR_MAX];
    l.n = 0;
    if (save_dir(name, dir, sizeof dir, 0) == 0) platform_list_dir(dir, add_history, &l);
    return &l;
}

static unsigned file_needs(const char *name, const char *file) {
    char path[INSTALL_PATH_MAX];
    uint8_t head[8];
    if (save_path(name, file, path, sizeof path, 0) != 0 || platform_read_file(path, head, sizeof head) != (long)sizeof head)
        return 0;
    return pass_needs(head, sizeof head);
}

// What the save's files but one need.
unsigned needs_but(const char *name, const char *skip) {
    unsigned all = 0;
    for (size_t i = 0; i < N_SEALED; i++)
        if (!skip || strcmp(SEALED[i], skip) != 0) all |= file_needs(name, SEALED[i]);
    return all;
}

unsigned install_factors(const char *name) { return needs_but(name, NULL); }

// The file that says how the save is locked: the settings, or the key if there are no settings.
// install_unlock opens it first.
const char *lock_file(const char *name) {
    return install_has_settings(name) ? SETTINGS_NAME : KEY_NAME;
}

static int fill_save(install_save_t *s, const char *name) {
    memset(s, 0, sizeof *s);
    copy_str(s->name, name, sizeof s->name);
    s->settings = install_has_settings(name);
    s->key = install_has_key(name);
    if (!s->settings && !s->key) return -1;
    s->factors = install_factors(name);
    char path[INSTALL_PATH_MAX];
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
    char dir[INSTALL_TOP_MAX], saves[INSTALL_DIR_MAX];
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
int read_sealed(const char *save, const char *file, uint8_t *buf, size_t max, size_t *len) {
    char path[INSTALL_PATH_MAX];
    if (save_path(save, file, path, sizeof path, 0) != 0) return INSTALL_NO_FILE;
    long n = platform_read_file(path, buf, max + 1);
    if (n < 0) return INSTALL_NO_FILE;
    if ((size_t)n > max) return PASS_FORMAT;
    *len = (size_t)n;
    return 0;
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
    char path[INSTALL_PATH_MAX];
    if (save_path(name, DEVICE_NAME, path, sizeof path, 0) != 0) return -1;
    long n = platform_read_file(path, buf, DEVICE_SEALED_MAX + 1);
    return n > 0 && n <= DEVICE_SEALED_MAX ? n : -1;
}

// The device's secret for a save. 0, or -1 with g_why set.
int device_unseal(const char *name, uint8_t secret[DEVICE_SECRET_LEN], device_kind_t *kind) {
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
void forget_device(const char *name) {
    static uint8_t sealed[DEVICE_SEALED_MAX + 1];
    char path[INSTALL_PATH_MAX];
    if (save_path(name, DEVICE_NAME, path, sizeof path, 0) != 0) return;
    long n = read_device(name, sealed);
    if (n > 0) platform_device_forget(sealed, (size_t)n);
    platform_remove(path);
}

// secret sealed to this device, in place of a save's device file, which is read back to be sure.
// What the device kept for the one it replaces is destroyed. 0, or -1 with g_why set.
int device_seal(const char *name, const uint8_t secret[DEVICE_SECRET_LEN], device_kind_t *kind) {
    static uint8_t sealed[DEVICE_SEALED_MAX], old[DEVICE_SEALED_MAX + 1], back[DEVICE_SEALED_MAX + 1];
    char path[INSTALL_PATH_MAX];
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

// ---- sealing and opening files ----

// A crash while the lock was being changed can leave a file sealed with other factors. One sealed
// with all of the save's and more is still read, if their secrets are held, but never one sealed with
// fewer.
int unseal_with(const held_t *h, const uint8_t *sealed, size_t n, void *plain, size_t cap, size_t *len) {
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

int unseal(const uint8_t *sealed, size_t n, void *plain, size_t cap, size_t *len) {
    return g_open ? unseal_with(&g_held, sealed, n, plain, cap, len) : PASS_WRONG;
}

int write_sealed_to(const char *name, const pass_lock_t *lk, const char *file, const void *plain, size_t len) {
    char path[INSTALL_PATH_MAX];
    static uint8_t sealed[HISTORY_FILE_MAX];
    size_t n;
    if (save_path(name, file, path, sizeof path, 1) != 0) return -1;
    if (pass_seal(lk, plain, len, sealed, sizeof sealed, &n) != 0) return -1;
    return platform_write_private(path, sealed, n);
}

int write_sealed_with(const pass_lock_t *lk, const char *file, const void *plain, size_t len) {
    return g_open ? write_sealed_to(g_name, lk, file, plain, len) : -1;
}

int write_settings_to(const char *name, const pass_lock_t *lk, const char *text) {
    static char padded[INSTALL_SETTINGS_MAX];
    size_t len = strlen(text), n = len / SETTINGS_PAD * SETTINGS_PAD + SETTINGS_PAD;
    if (n > sizeof padded) return -1;
    memset(padded, 0, n);
    memcpy(padded, text, len);
    int rc = write_sealed_to(name, lk, SETTINGS_NAME, padded, n);
    crypto_wipe(padded, n);
    return rc;
}

int write_code_to(const char *name, const pass_lock_t *lk, const uint8_t secret[TOTP_SECRET_LEN]) {
    uint8_t plain[CODE_PLAIN_LEN];
    plain[0] = 1;
    memcpy(plain + 1, secret, TOTP_SECRET_LEN);
    int rc = write_sealed_to(name, lk, CODE_NAME, plain, sizeof plain);
    crypto_wipe(plain, sizeof plain);
    return rc;
}

int write_code(const pass_lock_t *lk, const uint8_t secret[TOTP_SECRET_LEN]) {
    return g_open ? write_code_to(g_name, lk, secret) : -1;
}

int read_code(const char *name, const held_t *h, uint8_t secret[TOTP_SECRET_LEN]) {
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

// ---- the tries file ----

static int read_tries(const char *name, unsigned *limit, unsigned *count) {
    char path[INSTALL_PATH_MAX];
    uint8_t b[TRIES_LEN];
    if (save_path(name, TRIES_NAME, path, sizeof path, 0) != 0) return -1;
    if (platform_read_file(path, b, sizeof b) != (long)sizeof b || memcmp(b, TRIES_MAGIC, TRIES_LIMIT_AT) != 0) return -1;
    *limit = b[TRIES_LIMIT_AT];
    *count = b[TRIES_COUNT_AT];
    return 0;
}

static int write_tries(const char *name, unsigned limit, unsigned count) {
    char path[INSTALL_PATH_MAX];
    uint8_t b[TRIES_LEN];
    if (save_path(name, TRIES_NAME, path, sizeof path, 1) != 0) return -1;
    memcpy(b, TRIES_MAGIC, TRIES_LIMIT_AT);
    b[TRIES_LIMIT_AT] = (uint8_t)limit;
    b[TRIES_COUNT_AT] = (uint8_t)count;
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
    if (limit > UINT8_MAX) limit = UINT8_MAX;
    if (limit == 0) { remove_file(name, TRIES_NAME); return 0; }
    return write_tries(name, limit, 0);
}

// ---- making a save, and unlocking one ----

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
int parse_code(const char *code, uint32_t *out) {
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
int code_matches(const uint8_t secret[TOTP_SECRET_LEN], uint32_t code) {
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
        enum { WRONG_CODE_PAUSE_MS = 1500 };
        platform_sleep_ms(WRONG_CODE_PAUSE_MS);
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

long install_read_settings(char *buf, size_t cap) {
    long n = read_text(SETTINGS_NAME, SETTINGS_FILE_MAX, buf, cap);
    return n < 0 ? n : (long)strlen(buf);
}
long install_read_verified(char *buf, size_t cap) { return read_text(VERIFIED_NAME, VERIFIED_FILE_MAX, buf, cap); }

static int write_sealed(const char *file, const void *plain, size_t len) {
    return write_sealed_with(&g_held.lock, file, plain, len);
}

int install_write_settings(const char *text) { return g_open ? write_settings_to(g_name, &g_held.lock, text) : -1; }

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

// ---- histories ----

static void history_name(const uint8_t id[INSTALL_HISTORY_ID_LEN], char out[HISTORY_NAME_LEN + 1]) {
    memcpy(out, HISTORY_PREFIX, sizeof HISTORY_PREFIX - 1);
    hex_encode(id, INSTALL_HISTORY_ID_LEN, out + sizeof HISTORY_PREFIX - 1);
}

long install_read_history(const uint8_t id[INSTALL_HISTORY_ID_LEN], char *buf, size_t cap) {
    static uint8_t sealed[HISTORY_FILE_MAX + 1];
    char file[HISTORY_NAME_LEN + 1];
    size_t n = 0, len = 0;
    if (!g_open) return INSTALL_NO_FILE;
    history_name(id, file);
    int rc = read_sealed(g_name, file, sealed, HISTORY_FILE_MAX, &n);
    if (rc == 0) rc = unseal(sealed, n, buf, cap, &len);
    return rc == 0 ? (long)len : rc;
}

int install_write_history(const uint8_t id[INSTALL_HISTORY_ID_LEN], const char *text, size_t len) {
    char file[HISTORY_NAME_LEN + 1];
    if (len > INSTALL_HISTORY_MAX) return -1;
    history_name(id, file);
    return write_sealed(file, text, len);
}

int install_forget_history(const uint8_t *id) {
    if (!g_open) return -1;
    if (id) {
        char file[HISTORY_NAME_LEN + 1];
        history_name(id, file);
        remove_file(g_name, file);
        return 0;
    }
    history_list_t *hl = list_histories(g_name);
    for (int i = 0; i < hl->n; i++) remove_file(g_name, hl->names[i]);
    return 0;
}

int install_histories(void) { return g_open ? list_histories(g_name)->n : 0; }

// ---- tor's state ----

// Read at the size it is, since it can be tens of MB.
int install_read_tor(uint8_t **out, size_t *len) {
    char path[INSTALL_PATH_MAX];
    uint64_t size = 0;
    *out = NULL;
    *len = 0;
    FILE *f = NULL;
    if (g_open && save_path(g_name, CACHE_NAME, path, sizeof path, 0) == 0) f = platform_open_regular(path, &size);
    if (!f) return INSTALL_NO_FILE;
    if (size < PASS_SEAL_OVERHEAD || size > CACHE_FILE_MAX) { fclose(f); return PASS_FORMAT; }
    size_t n = (size_t)size, cap = n - PASS_SEAL_OVERHEAD;
    uint8_t *sealed = malloc(n), *plain = malloc(cap ? cap : 1);
    int rc = sealed && plain && fread(sealed, 1, n, f) == n ? unseal(sealed, n, plain, cap, len) : PASS_FORMAT;
    fclose(f);
    free(sealed);
    if (rc == 0) { *out = plain; return 0; }
    if (plain) crypto_wipe(plain, cap ? cap : 1);
    free(plain);
    *len = 0;
    return rc;
}

static int write_tor_with(const pass_lock_t *lk, const uint8_t *data, size_t len) {
    char path[INSTALL_PATH_MAX];
    size_t cap = len + PASS_SEAL_OVERHEAD, n;
    if (!g_open || len > INSTALL_TOR_MAX || save_path(g_name, CACHE_NAME, path, sizeof path, 1) != 0) return -1;
    uint8_t *sealed = malloc(cap);
    int rc = sealed && pass_seal(lk, data, len, sealed, cap, &n) == 0 ? platform_write_private(path, sealed, n) : -1;
    free(sealed);
    return rc;
}

int install_write_tor(const uint8_t *data, size_t len) { return write_tor_with(&g_held.lock, data, len); }

void install_forget_tor(void) {
    if (g_open) remove_file(g_name, CACHE_NAME);
}

// Only a cache: one that can't be read or sealed again goes, and tor starts afresh.
void reseal_tor(const pass_lock_t *lk) {
    uint8_t *plain;
    size_t len;
    int rc = install_read_tor(&plain, &len);
    if (rc == INSTALL_NO_FILE) return;
    if (rc != 0 || write_tor_with(lk, plain, len) != 0) install_forget_tor();
    if (plain) { crypto_wipe(plain, len); free(plain); }
}

// ---- the lock screen ----

// The lock held is checked rather than the save's settings file, so someone who can change the files
// can't make its own passphrase fail, and with self-destruct on, delete it.
int install_lock_try(const char *passphrase) {
    static uint8_t spare[SETTINGS_FILE_MAX + 1], plain[SETTINGS_FILE_MAX];
    g_why[0] = '\0';
    if (!g_open) return PASS_WRONG;
    pin_secrets();
    pass_lock_t *lk = &g_opening.lock, *sl = &g_spare_lock;
    size_t sn = 0, got = 0;
    int old = 0, sr = read_sealed(g_name, SPARE_NAME, spare, SETTINGS_FILE_MAX, &sn);
    if (sr == INSTALL_NO_FILE) {
        sr = read_sealed(g_name, OLD_DECOY_SETTINGS, spare, SETTINGS_FILE_MAX, &sn);
        old = sr == 0;
    }
    int rc = pass_lock_like(passphrase, &g_held.lock, lk);
    if (sr == 0) sr = pass_lock_of(passphrase, spare, sn, sl);
    if (sr != 0 && sr != PASS_NOMEM) sr = pass_lock_new(passphrase, sl) == PASS_NOMEM ? PASS_NOMEM : -1;
    if (rc == 0 && sr == PASS_NOMEM) rc = PASS_NOMEM;
    if (rc == 0 && crypto_equal(lk->base, g_held.lock.base, sizeof lk->base) != 0) rc = PASS_WRONG;
    crypto_wipe(lk, sizeof *lk);
    int decoy = 0;
    if (rc == PASS_WRONG && sr == 0) {
        unsigned sneeds = pass_needs(spare, sn);
        if ((!(sneeds & F_DEVICE) || g_held.have_device) && (!(sneeds & F_KEY) || g_held.have_key)) {
            pass_lock_set(sl, sneeds, g_held.device, g_held.key);
            decoy = pass_unseal(sl, spare, sn, plain, sizeof plain, &got) == 0
                 && (old || (got == SPARE_PLAIN_LEN && plain[0] == 1 && plain[1] <= 1));
        }
    }
    char name[INSTALL_NAME_MAX + 1];
    copy_str(name, g_name, sizeof name);
    unsigned limit = 0, count = 0;
    if (decoy) {
        install_forget();
        promote(name, sl, plain, old);
        rc = INSTALL_DECOY;
    } else if (rc == PASS_WRONG) {
        rc = wrong_pass(name);
    }
    if ((rc == 0 || rc == INSTALL_DECOY) && read_tries(name, &limit, &count) == 0 && limit) write_tries(name, limit, 0);
    crypto_wipe(plain, sizeof plain);
    crypto_wipe(sl, sizeof *sl);
    return rc;
}

// ---- uninstalling ----

// Anything not chat's, and in the default save's folder, the saves folder if it has a save in it.
static void count_others(void *ctx, const char *name, int is_dir) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0 || is_history(name)) return;
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
    char dir[INSTALL_DIR_MAX], path[INSTALL_PATH_MAX];
    name = stored_name(name);
    if (save_dir(name, dir, sizeof dir, 0) != 0) return -1;
    int left = 0;
    for (size_t i = 0; i < N_FILES; i++) {
        if (strcmp(FILES[i], DEVICE_NAME) == 0) continue;
        snprintf(path, sizeof path, "%s/%s", dir, FILES[i]);
        if (platform_remove(path) != 0 && path_exists(path)) left = 1;
    }
    history_list_t *hl = list_histories(name);
    for (int i = 0; i < hl->n; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, hl->names[i]);
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
        char top[INSTALL_TOP_MAX], saves[INSTALL_DIR_MAX];
        if (platform_config_dir(top, sizeof top, 0) != 0) return 0;
        snprintf(saves, sizeof saves, "%s/" SAVES_DIR, top);
        if (is_bare(saves)) platform_remove_tree(saves);
        if (is_bare(top)) platform_remove_tree(top);
    }
    return 0;
}
