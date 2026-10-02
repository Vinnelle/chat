// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_INSTALL_H
#define CHAT_INSTALL_H

#include <stddef.h>

// What :install keeps in platform_config_dir: the settings, the signing key and the verified
// signing keys of peers, all sealed under one passphrase. Nothing is written there before :install.
// There can be more than one save: the one in that folder itself, named "" here and default to the
// user, and named ones in saves/NAME under it, each with its own passphrase. One of them is in use
// at a time.

#define INSTALL_SETTINGS_MAX 8192
#define INSTALL_KEY_MAX 1280
#define INSTALL_VERIFIED_MAX 24576
#define INSTALL_NO_FILE -4
#define INSTALL_NAME_MAX 32
#define INSTALL_SAVES_MAX 32

typedef struct {
    char name[INSTALL_NAME_MAX + 1];
    int settings, key;    // which of the two files it has
    char modified[17];    // when its settings (or key) were last written: "YYYY-MM-DD HH:MM"
} install_save_t;

// 0 if name can name a save: 1 to 32 letters, digits, - and _. "default" is the save in the
// folder itself, the same as "".
int install_name_ok(const char *name);
// The name as the user sees it: "default" for "".
const char *install_shown_name(const char *name);
// The saves there, the default one first and the rest by name. Returns how many.
int install_list(install_save_t *out, int max);

// The save in use. Choosing one forgets the passphrase held for the last one.
const char *install_current(void);
void install_use(const char *name);

// A save's folder, with ~ for the home folder, to show the user. -1 if there isn't one.
int install_where(const char *name, char *out, size_t cap);
int install_has_settings(const char *name);
int install_has_key(const char *name);

// Both run Argon2id and keep the result until install_forget, so saving doesn't need the
// passphrase again. On success, the save named is the one in use. A new passphrase, for files not
// written yet: 0 or PASS_NOMEM.
int install_lock_new(const char *name, const char *passphrase);
// The passphrase of the files there: 0, INSTALL_NO_FILE, or a PASS_ code.
int install_unlock(const char *name, const char *passphrase);
void install_forget(void);

// These use the save in use and the passphrase already held. Returns the length, or
// INSTALL_NO_FILE or a PASS_ code.
long install_read_settings(char *buf, size_t cap);
// 0 or -1.
int install_write_settings(const char *text);
int install_write_key(const void *secret, size_t len);
// 0, INSTALL_NO_FILE, or a PASS_ code.
int install_read_key(void *secret, size_t cap, size_t *len);
// The verified keys (core/trust.h trust_text). The same as for the settings.
long install_read_verified(char *buf, size_t cap);
int install_write_verified(const char *text);

// Deletes a save's files, then its folder and the folders above it that nothing else is in. If
// it's the save in use, its passphrase is forgotten.
int install_remove(const char *name);

#endif
