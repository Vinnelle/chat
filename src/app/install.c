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
#define SETTINGS_FILE_MAX (INSTALL_SETTINGS_MAX + PASS_SEAL_OVERHEAD)
#define KEY_FILE_MAX (INSTALL_KEY_MAX + PASS_SEAL_OVERHEAD)

// Also removes any .new files left by a crash while writing.
static const char *const FILES[] = { SETTINGS_NAME, KEY_NAME, SETTINGS_NAME ".new", KEY_NAME ".new" };
#define N_FILES (sizeof FILES / sizeof FILES[0])

#define SAVES_DIR "saves"

static pass_lock_t g_lock;
static int g_open;
static char g_name[INSTALL_NAME_MAX + 1];

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

static int fill_save(install_save_t *s, const char *name) {
    memset(s, 0, sizeof *s);
    copy_str(s->name, name, sizeof s->name);
    s->settings = install_has_settings(name);
    s->key = install_has_key(name);
    if (!s->settings && !s->key) return -1;
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

static void hold(const char *name, const pass_lock_t *lk) {
    static int pinned;
    if (!pinned) { crypto_lock(&g_lock, sizeof g_lock); pinned = 1; }
    copy_str(g_name, stored_name(name), sizeof g_name);
    g_lock = *lk;
    g_open = 1;
}

int install_lock_new(const char *name, const char *passphrase) {
    pass_lock_t lk;
    int rc = pass_lock_new(passphrase, &lk);
    if (rc == 0) hold(name, &lk);
    crypto_wipe(&lk, sizeof lk);
    return rc;
}

// Tried on the settings file, which exists whenever the key file does, unless writing it failed.
int install_unlock(const char *name, const char *passphrase) {
    static uint8_t sealed[SETTINGS_FILE_MAX + 1], plain[SETTINGS_FILE_MAX];
    size_t n = 0, got;
    int rc = read_sealed(name, SETTINGS_NAME, sealed, SETTINGS_FILE_MAX, &n);
    if (rc == INSTALL_NO_FILE) rc = read_sealed(name, KEY_NAME, sealed, KEY_FILE_MAX, &n);
    if (rc != 0) return rc;
    pass_lock_t lk;
    rc = pass_lock_of(passphrase, sealed, n, &lk);
    if (rc == 0) rc = pass_unseal(&lk, sealed, n, plain, sizeof plain, &got);
    if (rc == 0) hold(name, &lk);
    crypto_wipe(&lk, sizeof lk);
    crypto_wipe(plain, sizeof plain);
    return rc;
}

void install_forget(void) {
    crypto_wipe(&g_lock, sizeof g_lock);
    g_open = 0;
}

long install_read_settings(char *buf, size_t cap) {
    uint8_t sealed[SETTINGS_FILE_MAX + 1];
    size_t n = 0, len = 0;
    if (cap < 1) return PASS_FORMAT;
    int rc = read_sealed(g_name, SETTINGS_NAME, sealed, SETTINGS_FILE_MAX, &n);
    if (rc == 0) rc = g_open ? pass_unseal(&g_lock, sealed, n, buf, cap - 1, &len) : PASS_WRONG;
    if (rc != 0) return rc;
    buf[len] = '\0';
    return (long)len;
}

static int write_sealed(const char *file, const void *plain, size_t len) {
    char path[1000];
    uint8_t sealed[SETTINGS_FILE_MAX];
    size_t n;
    if (!g_open || save_path(g_name, file, path, sizeof path, 1) != 0) return -1;
    if (pass_seal(&g_lock, plain, len, sealed, sizeof sealed, &n) != 0) return -1;
    return platform_write_private(path, sealed, n);
}

int install_write_settings(const char *text) { return write_sealed(SETTINGS_NAME, text, strlen(text)); }

int install_write_key(const void *secret, size_t len) {
    return len > INSTALL_KEY_MAX ? -1 : write_sealed(KEY_NAME, secret, len);
}

int install_read_key(void *secret, size_t cap, size_t *len) {
    uint8_t sealed[KEY_FILE_MAX + 1];
    size_t n = 0;
    int rc = read_sealed(g_name, KEY_NAME, sealed, KEY_FILE_MAX, &n);
    if (rc == 0) rc = g_open ? pass_unseal(&g_lock, sealed, n, secret, cap, len) : PASS_WRONG;
    return rc;
}

// Anything not chat's, and in the default save's folder, the saves folder if it has a save in it.
static void count_others(void *ctx, const char *name, int is_dir) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;
    for (size_t i = 0; i < N_FILES; i++) if (strcmp(name, FILES[i]) == 0) return;
    (void)is_dir;
    (*(int *)ctx)++;
}

static int is_empty(const char *dir) {
    int others = 0;
    return platform_list_dir(dir, count_others, &others) == 0 && others == 0;
}

int install_remove(const char *name) {
    char dir[960], path[1000];
    name = stored_name(name);
    if (save_dir(name, dir, sizeof dir, 0) != 0) return -1;
    int left = 0;
    for (size_t i = 0; i < N_FILES; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, FILES[i]);
        if (platform_remove(path) != 0 && path_exists(path)) left = 1;
    }
    if (!left && strcmp(name, g_name) == 0) install_forget();
    if (left) return -1;
    // Another program could have a folder called chat too.
    if (is_empty(dir)) platform_remove_tree(dir);
    if (name[0]) {
        char top[900], saves[960];
        if (platform_config_dir(top, sizeof top, 0) != 0) return 0;
        snprintf(saves, sizeof saves, "%s/" SAVES_DIR, top);
        if (is_empty(saves)) platform_remove_tree(saves);
        if (is_empty(top)) platform_remove_tree(top);
    }
    return 0;
}
