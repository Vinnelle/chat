// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What the save files' code shares: saves.c, spare.c and factors.c. The rest of chat uses saves.h.
#ifndef CHAT_SAVES_STORE_H
#define CHAT_SAVES_STORE_H

#include "app/saves/saves.h"
#include "crypto/crypto.h"
#include "platform/platform.h"
#include "common/util.h"

#define SETTINGS_NAME "settings"
#define KEY_NAME "key"
#define VERIFIED_NAME "verified"
#define CODE_NAME "authenticator"
#define DEVICE_NAME "device"
#define SECKEY_NAME "securitykey"
#define TRIES_NAME "tries"
#define SPARE_NAME "spare"
#define SPARE_LOCK_NAME "spare-lock"
// What chat's own tor keeps between runs (install_write_tor), named so it doesn't say so.
#define CACHE_NAME "cache"
// A decoy as 0.5.0's betas made it, in files only a save with a decoy had: still opened, until the
// shadow passphrase is set again.
#define OLD_DECOY_SETTINGS "shadow-settings"
#define OLD_DECOY_KEY "shadow-key"
#define OLD_DECOY_VERIFIED "shadow-verified"
#define OLD_DECOY_CODE "shadow-authenticator"
// The spare: 1, whether the decoy asks for a code, and the code's secret, sealed under the decoy's
// lock. Without a decoy it's chaff: random bytes with the same size and header.
#define SPARE_HEAD 2
#define SPARE_PLAIN_LEN (SPARE_HEAD + TOTP_SECRET_LEN)
#define SPARE_FILE_LEN (SPARE_PLAIN_LEN + PASS_SEAL_OVERHEAD)
// A session's history: this, then its id in hex. As many as the folder has, up to HISTORIES_MAX.
#define HISTORY_PREFIX "history-"
#define HISTORY_NAME_LEN (sizeof HISTORY_PREFIX - 1 + INSTALL_HISTORY_ID_LEN * 2)
#define HISTORY_FILE_MAX (INSTALL_HISTORY_MAX + PASS_SEAL_OVERHEAD)
#define HISTORIES_MAX 1024
#define SETTINGS_FILE_MAX (INSTALL_SETTINGS_MAX + PASS_SEAL_OVERHEAD)
#define VERIFIED_FILE_MAX (INSTALL_VERIFIED_MAX + PASS_SEAL_OVERHEAD)
#define KEYS_MAX 4

#define F_DEVICE INSTALL_FACTOR_DEVICE
#define F_KEY    INSTALL_FACTOR_KEY
#define F_CODE   INSTALL_FACTOR_CODE

static const char *const SEALED[] = { SETTINGS_NAME, KEY_NAME, VERIFIED_NAME, CODE_NAME, SPARE_LOCK_NAME };
#define N_SEALED (sizeof SEALED / sizeof SEALED[0])

// A save's lock, and the secrets of its factors while they're known.
typedef struct {
    pass_lock_t lock;
    uint8_t device[DEVICE_SECRET_LEN];
    int have_device;
    device_kind_t device_kind;
    uint8_t key[PASS_KEY_SECRET_LEN];
    int have_key;
} held_t;

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

typedef struct { int have; key_file_t file; uint8_t secret[PASS_KEY_SECRET_LEN]; } new_key_t;
typedef struct { int have, confirmed; uint8_t secret[TOTP_SECRET_LEN]; } new_code_t;

typedef struct { char names[HISTORIES_MAX][HISTORY_NAME_LEN + 1]; int n; } history_list_t;

// saves.c
extern held_t g_held;
extern int g_open;
extern char g_name[INSTALL_NAME_MAX + 1];
extern char g_why[256];
void pin_secrets(void);
const char *stored_name(const char *name);
int save_path(const char *name, const char *file, char *out, size_t cap, int create);
int has(const char *name, const char *file);
void remove_file(const char *name, const char *file);
size_t file_max(const char *file);
history_list_t *list_histories(const char *name);
unsigned needs_but(const char *name, const char *skip);
const char *lock_file(const char *name);
int read_sealed(const char *save, const char *file, uint8_t *buf, size_t max, size_t *len);
int device_unseal(const char *name, uint8_t secret[DEVICE_SECRET_LEN], device_kind_t *kind);
void forget_device(const char *name);
int device_seal(const char *name, const uint8_t secret[DEVICE_SECRET_LEN], device_kind_t *kind);
int unseal_with(const held_t *h, const uint8_t *sealed, size_t n, void *plain, size_t cap, size_t *len);
int unseal(const uint8_t *sealed, size_t n, void *plain, size_t cap, size_t *len);
int write_sealed_to(const char *name, const pass_lock_t *lk, const char *file, const void *plain, size_t len);
int write_sealed_with(const pass_lock_t *lk, const char *file, const void *plain, size_t len);
int write_settings_to(const char *name, const pass_lock_t *lk, const char *text);
int write_code_to(const char *name, const pass_lock_t *lk, const uint8_t secret[TOTP_SECRET_LEN]);
int write_code(const pass_lock_t *lk, const uint8_t secret[TOTP_SECRET_LEN]);
int read_code(const char *name, const held_t *h, uint8_t secret[TOTP_SECRET_LEN]);
int parse_code(const char *code, uint32_t *out);
int code_matches(const uint8_t secret[TOTP_SECRET_LEN], uint32_t code);
void reseal_tor(const pass_lock_t *lk);

// spare.c
extern pass_lock_t g_spare_lock;
extern int g_decoy_state;
extern int g_decoy_lost;
int old_decoy(const char *name);
int write_spare_lock(const char *name, const pass_lock_t *lk, const pass_lock_t *decoy);
int write_chaff(const char *name, unsigned needs);
int spare_fit(const char *name, const held_t *h, unsigned needs);
void refresh(const char *name, const held_t *h);
void promote(const char *name, const pass_lock_t *sl, const uint8_t *spare_plain, int old);

// factors.c
extern new_key_t g_new_key;
extern new_code_t g_new_code;
extern uint8_t g_try_key[PASS_KEY_SECRET_LEN];
void pin_factor_secrets(void);
void forget_try_key(void);
int write_key_file(const char *name, const key_file_t *f);
int set_lock(unsigned target);

#endif
