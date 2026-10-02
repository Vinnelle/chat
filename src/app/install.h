// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_INSTALL_H
#define CHAT_INSTALL_H

#include <stddef.h>

// What :install keeps in platform_config_dir: the settings and the signing key, both sealed under
// one passphrase. Nothing is written there before :install.

#define INSTALL_SETTINGS_MAX 8192
#define INSTALL_KEY_MAX 1280
#define INSTALL_NO_FILE -4

// The folder, with ~ for the home folder, to show the user. -1 if there isn't one.
int install_where(char *out, size_t cap);
int install_has_settings(void);
int install_has_key(void);

// Both run Argon2id and keep the result until install_forget, so saving doesn't need the
// passphrase again. A new passphrase, for files not written yet: 0 or PASS_NOMEM.
int install_lock_new(const char *passphrase);
// The passphrase of the files there: 0, INSTALL_NO_FILE, or a PASS_ code.
int install_unlock(const char *passphrase);
void install_forget(void);

// These use the passphrase already held. Returns the length, or INSTALL_NO_FILE or a PASS_ code.
long install_read_settings(char *buf, size_t cap);
// 0 or -1.
int install_write_settings(const char *text);
int install_write_key(const void *secret, size_t len);
// 0, INSTALL_NO_FILE, or a PASS_ code.
int install_read_key(void *secret, size_t cap, size_t *len);

// Deletes the files, and the folder if nothing else is in it, and forgets the passphrase.
int install_remove(void);

#endif
