// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/install.h"
#include "crypto/crypto.h"
#include "platform/platform.h"
#include "common/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SETTINGS_NAME "settings"
#define KEY_NAME "key"
#define VERIFIED_NAME "verified"
#define DEVICE_NAME "device"
#define SETTINGS_FILE_MAX (INSTALL_SETTINGS_MAX + PASS_SEAL_OVERHEAD)
#define KEY_FILE_MAX (INSTALL_KEY_MAX + PASS_SEAL_OVERHEAD)
#define VERIFIED_FILE_MAX (INSTALL_VERIFIED_MAX + PASS_SEAL_OVERHEAD)

_Static_assert(DEVICE_SECRET_LEN == PASS_DEVICE_SECRET_LEN, "the device's secret is what a device lock mixes in");

// Also removes any .new files left by a crash while writing.
static const char *const FILES[] = { SETTINGS_NAME, KEY_NAME, VERIFIED_NAME, SETTINGS_NAME ".new", KEY_NAME ".new",
                                     VERIFIED_NAME ".new", DEVICE_NAME ".new", DEVICE_NAME };
#define N_FILES (sizeof FILES / sizeof FILES[0])
static const char *const SEALED[] = { SETTINGS_NAME, KEY_NAME, VERIFIED_NAME };
#define N_SEALED (sizeof SEALED / sizeof SEALED[0])

#define SAVES_DIR "saves"

static pass_lock_t g_lock;
static int g_open;
static char g_name[INSTALL_NAME_MAX + 1];
// The open save's device secret, while it's known.
static uint8_t g_device[DEVICE_SECRET_LEN];
static int g_have_device;
static device_kind_t g_device_kind;
static char g_why[256];
static int g_relocked;

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

int install_has_settings(const char *name) { return has(name, SETTINGS_NAME); }
int install_has_key(const char *name) { return has(name, KEY_NAME); }

static size_t file_max(const char *file) {
    return strcmp(file, SETTINGS_NAME) == 0 ? SETTINGS_FILE_MAX : strcmp(file, KEY_NAME) == 0 ? KEY_FILE_MAX : VERIFIED_FILE_MAX;
}

static int file_needs_device(const char *name, const char *file) {
    char path[1000];
    uint8_t head[8];
    return save_path(name, file, path, sizeof path, 0) == 0 && platform_read_file(path, head, sizeof head) == (long)sizeof head
        && pass_needs_device(head, sizeof head);
}

static int any_needs_device(const char *name) {
    for (size_t i = 0; i < N_SEALED; i++) if (file_needs_device(name, SEALED[i])) return 1;
    return 0;
}

// The file that says how the save is locked: the settings, or the key if there are no settings.
// install_unlock opens it first.
static const char *lock_file(const char *name) {
    return install_has_settings(name) ? SETTINGS_NAME : KEY_NAME;
}

int install_locked_to_device(const char *name) { return file_needs_device(name, lock_file(name)); }

static int fill_save(install_save_t *s, const char *name) {
    memset(s, 0, sizeof *s);
    copy_str(s->name, name, sizeof s->name);
    s->settings = install_has_settings(name);
    s->key = install_has_key(name);
    if (!s->settings && !s->key) return -1;
    s->device = install_locked_to_device(name);
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
    static int pinned;
    if (!pinned) { crypto_lock(g_device, sizeof g_device); pinned = 1; }
    if (secret) memcpy(g_device, secret, sizeof g_device);
    else crypto_wipe(g_device, sizeof g_device);
    g_have_device = secret != NULL;
    g_device_kind = secret ? kind : DEVICE_NONE;
}

static void hold(const char *name, const pass_lock_t *lk, const uint8_t *secret, device_kind_t kind) {
    static int pinned;
    if (!pinned) { crypto_lock(&g_lock, sizeof g_lock); pinned = 1; }
    copy_str(g_name, stored_name(name), sizeof g_name);
    g_lock = *lk;
    g_open = 1;
    hold_device(secret, kind);
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

int install_lock_new(const char *name, const char *passphrase, int device) {
    pass_lock_t lk;
    uint8_t secret[DEVICE_SECRET_LEN];
    device_kind_t kind = DEVICE_NONE;
    int rc = pass_lock_new(passphrase, &lk);
    if (rc == 0 && device) {
        gen_random(secret, sizeof secret);
        if (device_seal(name, secret, &kind) != 0) rc = INSTALL_DEVICE;
        else pass_lock_device(&lk, secret);
    }
    if (rc == 0) hold(name, &lk, device ? secret : NULL, kind);
    crypto_wipe(&lk, sizeof lk);
    crypto_wipe(secret, sizeof secret);
    return rc;
}

// Tried on the settings file, which exists whenever the key file does, unless writing it failed.
// A save locked to the device needs it before anything else: elsewhere no passphrase can open it,
// so none is tried. A save that isn't may still have files a crash left locked to it.
int install_unlock(const char *name, const char *passphrase) {
    static uint8_t sealed[SETTINGS_FILE_MAX + 1], plain[SETTINGS_FILE_MAX];
    size_t n = 0, got;
    g_relocked = 0;
    int rc = read_sealed(name, SETTINGS_NAME, sealed, SETTINGS_FILE_MAX, &n);
    if (rc == INSTALL_NO_FILE) rc = read_sealed(name, KEY_NAME, sealed, KEY_FILE_MAX, &n);
    if (rc != 0) return rc;
    uint8_t secret[DEVICE_SECRET_LEN];
    device_kind_t kind = DEVICE_NONE;
    int locked = pass_needs_device(sealed, n), have = 0;
    if (locked || any_needs_device(name)) {
        have = device_unseal(name, secret, &kind) == 0;
        if (!have && locked) { crypto_wipe(secret, sizeof secret); return INSTALL_DEVICE; }
    }
    pass_lock_t lk;
    rc = pass_lock_of(passphrase, sealed, n, &lk);
    if (rc == 0 && locked) pass_lock_device(&lk, secret);
    if (rc == 0) rc = pass_unseal(&lk, sealed, n, plain, sizeof plain, &got);
    if (rc == 0) hold(name, &lk, have ? secret : NULL, kind);
    crypto_wipe(&lk, sizeof lk);
    crypto_wipe(secret, sizeof secret);
    crypto_wipe(plain, sizeof plain);
    // Part locked: chat stopped while the lock was changing, or a file was swapped for one the
    // passphrase alone opens. It's finished the safer way, so nothing is written unlocked from here.
    if (rc == 0 && !locked && have) g_relocked = install_set_device_lock(1) == 0 ? 1 : -1;
    return rc;
}

int install_relocked(void) { return g_relocked; }

void install_forget(void) {
    crypto_wipe(&g_lock, sizeof g_lock);
    hold_device(NULL, DEVICE_NONE);
    g_open = 0;
}

device_kind_t install_device_lock(void) { return g_open && g_lock.device ? g_device_kind : DEVICE_NONE; }

const char *install_device_why(void) { return g_why; }

// A crash while the lock was being changed can leave a file sealed the other way. One that needs
// the device too is still read, but a save locked to the device never takes one that doesn't.
static int unseal(const uint8_t *sealed, size_t n, void *plain, size_t cap, size_t *len) {
    if (!g_open) return PASS_WRONG;
    int rc = pass_unseal(&g_lock, sealed, n, plain, cap, len);
    if (rc == PASS_WRONG && !g_lock.device && g_have_device && pass_needs_device(sealed, n)) {
        pass_lock_t dev = g_lock;
        pass_lock_device(&dev, g_device);
        rc = pass_unseal(&dev, sealed, n, plain, cap, len);
        crypto_wipe(&dev, sizeof dev);
    }
    return rc;
}

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

static int write_sealed_with(const pass_lock_t *lk, const char *file, const void *plain, size_t len) {
    char path[1000];
    static uint8_t sealed[VERIFIED_FILE_MAX];
    size_t n;
    if (!g_open || save_path(g_name, file, path, sizeof path, 1) != 0) return -1;
    if (pass_seal(lk, plain, len, sealed, sizeof sealed, &n) != 0) return -1;
    return platform_write_private(path, sealed, n);
}

static int write_sealed(const char *file, const void *plain, size_t len) {
    return write_sealed_with(&g_lock, file, plain, len);
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
    if (rc == 0) g_lock = *next;
    return rc == 0 ? 0 : -1;
}

int install_set_device_lock(int on) {
    g_why[0] = '\0';
    if (!g_open) { copy_str(g_why, "no save is open", sizeof g_why); return -1; }
    // Unlocked with its device secret still held, some files may be left locked to it.
    if (on ? g_lock.device : !g_lock.device && !g_have_device) return 0;
    pass_lock_t next = g_lock;
    if (on) {
        uint8_t secret[DEVICE_SECRET_LEN];
        device_kind_t kind = g_device_kind;
        // A secret this device unsealed already is kept: files a crash left locked to it need it. If
        // the device file no longer gives it back, it's sealed again before anything depends on it.
        int sealed = 0;
        if (g_have_device) {
            uint8_t back[DEVICE_SECRET_LEN];
            device_kind_t was;
            memcpy(secret, g_device, sizeof secret);
            sealed = device_unseal(g_name, back, &was) == 0 && crypto_equal(back, secret, sizeof back) == 0;
            crypto_wipe(back, sizeof back);
        } else if (any_needs_device(g_name)) {
            copy_str(g_why, "some of its files are locked to a device secret this device can't unseal", sizeof g_why);
            return -1;
        } else {
            gen_random(secret, sizeof secret);
        }
        if (!sealed && device_seal(g_name, secret, &kind) != 0) { crypto_wipe(secret, sizeof secret); return -1; }
        hold_device(secret, kind);
        pass_lock_device(&next, secret);
        crypto_wipe(secret, sizeof secret);
    } else {
        pass_lock_portable(&next);
    }
    // The lock file says how the save is locked, so it's sealed again last when locking and first
    // when unlocking. A crash in between leaves it as it was, or unlocked with files still locked to
    // the device, and either way it opens.
    const char *first = lock_file(g_name);
    int rc = on ? 0 : reseal_lock_file(first, &next), skipped = 0;
    for (size_t i = 0; i < N_SEALED && rc == 0; i++) {
        if (strcmp(SEALED[i], first) == 0) continue;
        int r = reseal(SEALED[i], &next);
        if (r > 0) skipped++;
        else rc = r;
    }
    if (on && rc == 0) rc = reseal_lock_file(first, &next);
    crypto_wipe(&next, sizeof next);
    if (rc != 0) return -1;
    if (!on) {
        forget_device(g_name);
        hold_device(NULL, DEVICE_NONE);
    }
    if (skipped)
        snprintf(g_why, sizeof g_why, "%d of its files can't be read (damaged, or sealed some other way), and %s left as %s",
                 skipped, skipped == 1 ? "is" : "are", skipped == 1 ? "it was" : "they were");
    return 0;
}

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
