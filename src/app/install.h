// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_INSTALL_H
#define CHAT_INSTALL_H

#include <stddef.h>
#include "platform/platform.h"

// What :install keeps in platform_config_dir: the settings, the signing key and the verified
// signing keys of peers, all sealed under one passphrase. Nothing is written there before :install.
// There can be more than one save: the one in that folder itself, named "" here and default to the
// user, and named ones in saves/NAME under it, each with its own passphrase. One of them is in use
// at a time.
//
// A save can need more than its passphrase, in any mix: a secret only this device can unseal
// (platform_device_seal), kept sealed in its device file; a security key's secret (platform_seckey),
// with what the key needs to give it back in its securitykey file; and a code from an authenticator
// app. The first two go into the key the files are sealed with, so without them the passphrase opens
// nothing. The code can't: the secret an app makes its codes from has to be kept with the save,
// sealed in its authenticator file, so it's a check chat makes before the save is used.

#define INSTALL_SETTINGS_MAX 8192
#define INSTALL_KEY_MAX 1280
#define INSTALL_VERIFIED_MAX 24576
#define INSTALL_NO_FILE -4
#define INSTALL_DEVICE -5    // it's locked to a device, and this one can't unseal it: install_why says why
#define INSTALL_KEY -6       // it needs its security key's secret first (install_key_open)
#define INSTALL_LOST -7      // a file a factor needs is missing or damaged: install_why says which
#define INSTALL_NAME_MAX 32
#define INSTALL_SAVES_MAX 32

#define INSTALL_FACTOR_DEVICE 1u
#define INSTALL_FACTOR_KEY    2u
#define INSTALL_FACTOR_CODE   4u

typedef struct {
    char name[INSTALL_NAME_MAX + 1];
    int settings, key;    // which of the two files it has
    unsigned factors;     // what it needs as well as its passphrase
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
// What a save needs as well as its passphrase (INSTALL_FACTOR_), from all its files, so one left
// part way through a change needs the safer set.
unsigned install_factors(const char *name);

// Both run Argon2id and keep the result until install_forget, so saving doesn't need the
// passphrase again. On success, the save named is the one in use. A new passphrase, for files not
// written yet, needing the factors as well: the device's secret is sealed here, and a security key
// and an authenticator code must be set up first (install_key_make, install_code_new). 0,
// PASS_NOMEM, INSTALL_DEVICE, or -1 with install_why.
int install_lock_new(const char *name, const char *passphrase, unsigned factors);
// The passphrase of the files there: 0, INSTALL_NO_FILE, INSTALL_DEVICE, INSTALL_KEY, INSTALL_LOST,
// or a PASS_ code. A save that needs a code waits for install_check_code to take one before it's the
// save in use, and the save open before stays as it was until then.
int install_unlock(const char *name, const char *passphrase);
// After install_unlock: whether a save waits for its authenticator code.
int install_code_pending(void);
// 0 for the code the authenticator app shows now (or 30 seconds before or after), PASS_WRONG for
// another, after a pause, or PASS_FORMAT if it isn't 6 digits.
int install_check_code(const char *code);
// The save waiting for its code isn't opened after all.
void install_code_cancel(void);
// Once the save is usable: 1 if it was only part way through a change to its factors (chat stopped,
// or a file was replaced) and has been sealed again with all of them, -1 if that failed (install_why
// says why), otherwise 0.
int install_relocked(void);
void install_forget(void);

// What the open save needs as well as its passphrase.
unsigned install_open_factors(void);
// What the open save is locked to: DEVICE_NONE when it isn't locked to the device.
device_kind_t install_device_lock(void);
// Seals the open save again, needing a factor as well, or no longer. Turning on the security key
// or the code takes what install_key_make or install_code_new set up. On Windows, unlocking from
// the device deletes its TPM key. 0, or -1 with install_why.
int install_set_factor(unsigned factor, int on);
// Why the last step that needed a factor failed.
const char *install_why(void);

// A security key waits for a touch, so these run on a thread of their own, one at a time.
// install_key_make registers a security key, for the next save install_lock_new makes, or for the
// open save with install_set_factor. install_key_open reads the secret of the one a save (not open
// yet) needs, which install_unlock then uses. pin may be NULL. Both return -1 if one is running.
int install_key_make(const char *pin);
int install_key_open(const char *name, const char *pin);
typedef enum {
    INSTALL_KEY_IDLE, INSTALL_KEY_RUNNING, INSTALL_KEY_DONE, INSTALL_KEY_PIN, INSTALL_KEY_FAILED, INSTALL_KEY_CANCELLED
} install_key_state_t;
// What the one running is doing (stage: seckey_stage_t, touches: how many it has had), or once,
// how it ended. INSTALL_KEY_PIN: it needs the security key's PIN, or another one (install_key_why).
install_key_state_t install_key_poll(int *stage, int *touches);
void install_key_cancel(void);
const char *install_key_why(void);
// Whether install_unlock has the secret of name's security key.
int install_key_ready(const char *name);

// A new authenticator secret, for the save name, for install_lock_new or install_set_factor: b32
// gets it in base32 (at least 33 bytes), uri the otpauth:// link an app scans.
void install_code_new(const char *name, char *b32, size_t b32_cap, char *uri, size_t uri_cap);
// 0 if code is what an app with the new secret shows now, which the new secret needs before it's used.
int install_code_try(const char *code);
// Drops a security key and an authenticator secret set up and not used.
void install_setup_forget(void);

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

// Deletes a save's files, what this device keeps for it if it's locked to it, then its folder and
// the folders above it that nothing else is in. If it's the save in use, its passphrase is forgotten.
int install_remove(const char *name);

#endif
