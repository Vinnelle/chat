// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/install.h"
#include "crypto/crypto.h"
#include "platform/platform.h"
#include "common/util.h"
#include <stdio.h>
#include <string.h>

#define SETTINGS_NAME "settings"
#define KEY_NAME "key"
#define SETTINGS_FILE_MAX (INSTALL_SETTINGS_MAX + PASS_SEAL_OVERHEAD)
#define KEY_FILE_MAX (INSTALL_KEY_MAX + PASS_SEAL_OVERHEAD)

// With the .new files a crash mid-write leaves.
static const char *const FILES[] = { SETTINGS_NAME, KEY_NAME, SETTINGS_NAME ".new", KEY_NAME ".new" };
#define N_FILES (sizeof FILES / sizeof FILES[0])

static pass_lock_t g_lock;
static int g_open;

static int install_path(const char *name, char *out, size_t cap, int create) {
    char dir[900];
    if (platform_config_dir(dir, sizeof dir, create) != 0) return -1;
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

int install_where(char *out, size_t cap) {
    char dir[900];
    if (platform_config_dir(dir, sizeof dir, 0) != 0) return -1;
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

static int has(const char *name) {
    char path[1000];
    return install_path(name, path, sizeof path, 0) == 0 && path_exists(path);
}

int install_has_settings(void) { return has(SETTINGS_NAME); }
int install_has_key(void) { return has(KEY_NAME); }

// buf holds max + 1, to tell a file too long for one chat wrote.
static int read_sealed(const char *name, uint8_t *buf, size_t max, size_t *len) {
    char path[1000];
    if (install_path(name, path, sizeof path, 0) != 0) return INSTALL_NO_FILE;
    long n = platform_read_file(path, buf, max + 1);
    if (n < 0) return INSTALL_NO_FILE;
    if ((size_t)n > max) return PASS_FORMAT;
    *len = (size_t)n;
    return 0;
}

static void hold(const pass_lock_t *lk) {
    static int pinned;
    if (!pinned) { crypto_lock(&g_lock, sizeof g_lock); pinned = 1; }
    g_lock = *lk;
    g_open = 1;
}

int install_lock_new(const char *passphrase) {
    pass_lock_t lk;
    int rc = pass_lock_new(passphrase, &lk);
    if (rc == 0) hold(&lk);
    crypto_wipe(&lk, sizeof lk);
    return rc;
}

// Tried on the settings, which are there whenever the key is unless writing them failed.
int install_unlock(const char *passphrase) {
    static uint8_t sealed[SETTINGS_FILE_MAX + 1], plain[SETTINGS_FILE_MAX];
    size_t n = 0, got;
    int rc = read_sealed(SETTINGS_NAME, sealed, SETTINGS_FILE_MAX, &n);
    if (rc == INSTALL_NO_FILE) rc = read_sealed(KEY_NAME, sealed, KEY_FILE_MAX, &n);
    if (rc != 0) return rc;
    pass_lock_t lk;
    rc = pass_lock_of(passphrase, sealed, n, &lk);
    if (rc == 0) rc = pass_unseal(&lk, sealed, n, plain, sizeof plain, &got);
    if (rc == 0) hold(&lk);
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
    int rc = read_sealed(SETTINGS_NAME, sealed, SETTINGS_FILE_MAX, &n);
    if (rc == 0) rc = g_open ? pass_unseal(&g_lock, sealed, n, buf, cap - 1, &len) : PASS_WRONG;
    if (rc != 0) return rc;
    buf[len] = '\0';
    return (long)len;
}

static int write_sealed(const char *name, const void *plain, size_t len) {
    char path[1000];
    uint8_t sealed[SETTINGS_FILE_MAX];
    size_t n;
    if (!g_open || install_path(name, path, sizeof path, 1) != 0) return -1;
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
    int rc = read_sealed(KEY_NAME, sealed, KEY_FILE_MAX, &n);
    if (rc == 0) rc = g_open ? pass_unseal(&g_lock, sealed, n, secret, cap, len) : PASS_WRONG;
    return rc;
}

static void count_others(void *ctx, const char *name, int is_dir) {
    (void)is_dir;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;
    for (size_t i = 0; i < N_FILES; i++) if (strcmp(name, FILES[i]) == 0) return;
    (*(int *)ctx)++;
}

int install_remove(void) {
    char dir[900], path[1000];
    if (platform_config_dir(dir, sizeof dir, 0) != 0) return -1;
    int left = 0;
    for (size_t i = 0; i < N_FILES; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, FILES[i]);
        if (platform_remove(path) != 0 && path_exists(path)) left = 1;
    }
    // Another program could have a folder called chat too.
    int others = 0;
    if (!left && platform_list_dir(dir, count_others, &others) == 0 && others == 0) platform_remove_tree(dir);
    if (!left) install_forget();
    return left ? -1 : 0;
}
