// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// A save's spare: its decoy, sealed under the shadow passphrase, or chaff the same shape.
#include "app/saves/store.h"
#include <string.h>

// The spare's lock, sealed with the save's other files: 1, whether there's a decoy, then the decoy
// lock's header and the key its passphrase made (or random bytes), so the decoy can be sealed again
// when the save's factors change.
#define SPARE_LOCK_PLAIN_LEN (SPARE_HEAD + PASS_HEADER_LEN + PASS_KEY_LEN)
#define SPARE_LOCK_FILE_LEN (SPARE_LOCK_PLAIN_LEN + PASS_SEAL_OVERHEAD)

static const char *const OLD_DECOY[] = { OLD_DECOY_SETTINGS, OLD_DECOY_KEY, OLD_DECOY_VERIFIED, OLD_DECOY_CODE };
#define N_OLD_DECOY (sizeof OLD_DECOY / sizeof OLD_DECOY[0])

pass_lock_t g_spare_lock;
int g_decoy_state = -1;   // whether the open save has a decoy, -1 until it's read
int g_decoy_lost;

int old_decoy(const char *name) { return has(name, OLD_DECOY_SETTINGS); }

static void remove_old_decoy(const char *name) {
    for (size_t i = 0; i < N_OLD_DECOY; i++) remove_file(name, OLD_DECOY[i]);
}

int write_spare_lock(const char *name, const pass_lock_t *lk, const pass_lock_t *decoy) {
    uint8_t plain[SPARE_LOCK_PLAIN_LEN];
    plain[0] = 1;
    plain[1] = decoy != NULL;
    if (decoy) {
        memcpy(plain + SPARE_HEAD, decoy->header, PASS_HEADER_LEN);
        memcpy(plain + SPARE_HEAD + PASS_HEADER_LEN, decoy->base, sizeof decoy->base);
    } else {
        gen_random(plain + SPARE_HEAD, sizeof plain - SPARE_HEAD);
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
            memcpy(decoy->header, plain + SPARE_HEAD, PASS_HEADER_LEN);
            memcpy(decoy->base, plain + SPARE_HEAD + PASS_HEADER_LEN, sizeof decoy->base);
        }
    }
    crypto_wipe(plain, sizeof plain);
    return out;
}

int write_chaff(const char *name, unsigned needs) {
    uint8_t buf[SPARE_FILE_LEN];
    char path[INSTALL_PATH_MAX];
    pass_chaff(needs, SPARE_PLAIN_LEN, buf);
    return save_path(name, SPARE_NAME, path, sizeof path, 1) == 0 ? platform_write_private(path, buf, sizeof buf) : -1;
}

static int write_decoy(const char *name, const pass_lock_t *sl, const uint8_t *code) {
    uint8_t plain[SPARE_PLAIN_LEN] = { 1, code != NULL };
    if (code) memcpy(plain + SPARE_HEAD, code, TOTP_SECRET_LEN);
    int rc = write_sealed_to(name, sl, SPARE_NAME, plain, sizeof plain);
    crypto_wipe(plain, sizeof plain);
    return rc;
}

// The spare made to need what the save needs: a decoy sealed again with the key its passphrase made,
// which the spare's lock keeps, and with the save's code if it asks for one; otherwise new chaff.
// 1 if the save has a decoy, 0 if not, -1 if it had one that couldn't be kept.
int spare_fit(const char *name, const held_t *h, unsigned needs) {
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

static void rewrite(const char *name, const char *file) {
    static uint8_t buf[HISTORY_FILE_MAX + 1];
    char path[INSTALL_PATH_MAX];
    if (save_path(name, file, path, sizeof path, 0) != 0) return;
    long n = platform_read_file(path, buf, sizeof buf);
    if (n > 0 && (size_t)n <= HISTORY_FILE_MAX) platform_write_private(path, buf, (size_t)n);
}

// Opened with its own passphrase, a save is written just as when its decoy takes its place: every
// sealed file and the spare, so the files' times don't say which passphrase opened it.
void refresh(const char *name, const held_t *h) {
    for (size_t i = 0; i < N_SEALED; i++) rewrite(name, SEALED[i]);
    history_list_t *hl = list_histories(name);
    for (int i = 0; i < hl->n; i++) rewrite(name, hl->names[i]);
    // A decoy the betas made can't be sealed again without its passphrase, so it stays as it is.
    if (!old_decoy(name) && spare_fit(name, h, h->lock.needs) < 0) g_decoy_lost = 1;
}

// The decoy takes the save's place, settings first, so from then on the real passphrase opens
// nothing. The save's key goes. Its device and securitykey files stay, since the decoy needs them
// too. Then it gets a spare of chaff, as a save without a decoy has.
void promote(const char *name, const pass_lock_t *sl, const uint8_t *spare_plain, int old) {
    if (old) {
        static const char *const to[] = { SETTINGS_NAME, KEY_NAME, VERIFIED_NAME, CODE_NAME };
        static uint8_t buf[VERIFIED_FILE_MAX + 1];
        char path[INSTALL_PATH_MAX];
        for (size_t i = 0; i < N_OLD_DECOY; i++) {
            long n = save_path(name, OLD_DECOY[i], path, sizeof path, 0) == 0 ? platform_read_file(path, buf, sizeof buf) : -1;
            if (n > 0 && (size_t)n <= VERIFIED_FILE_MAX && save_path(name, to[i], path, sizeof path, 1) == 0)
                platform_write_private(path, buf, (size_t)n);
            else
                remove_file(name, to[i]);
        }
    } else {
        write_settings_to(name, sl, "");
        remove_file(name, KEY_NAME);
        write_sealed_to(name, sl, VERIFIED_NAME, "", 0);
        if (spare_plain[1]) write_code_to(name, sl, spare_plain + SPARE_HEAD);
        else remove_file(name, CODE_NAME);
    }
    history_list_t *hl = list_histories(name);
    for (int i = 0; i < hl->n; i++) remove_file(name, hl->names[i]);
    remove_file(name, CACHE_NAME);
    write_spare_lock(name, sl, NULL);
    write_chaff(name, sl->needs);
    remove_old_decoy(name);
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
