// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// A save's factors: its securitykey file, sealing the save again when one changes, security keys,
// and authenticator codes.
#include "app/saves/store.h"
#include <stdio.h>
#include <string.h>

// The securitykey file: this, the salt, how many keys, then for each whether it needs its PIN, its
// credential's length (2 bytes, big-endian), the credential, and the lock's secret wrapped by it.
#define KEY_FILE_MAGIC "CSK1"
#define KEY_SALT_AT (sizeof KEY_FILE_MAGIC - 1)
#define KEY_COUNT_AT (KEY_SALT_AT + SECKEY_SALT_LEN)
#define KEY_FILE_HEAD (KEY_COUNT_AT + 1)
#define KEY_ENTRY_HEAD 3
#define KEY_ENTRY_MAX (KEY_ENTRY_HEAD + SECKEY_CRED_MAX + WRAP_LEN)
#define SECKEY_FILE_MAX (KEY_FILE_HEAD + KEYS_MAX * KEY_ENTRY_MAX)

_Static_assert(SECKEY_SECRET_LEN == 32 && PASS_KEY_SECRET_LEN == 32, "a security key's secret wraps the lock's");

// Set up and not used yet: a security key install_key_make registered, with the secret it wraps,
// and an authenticator secret from install_code_new.
new_key_t g_new_key;
new_code_t g_new_code;
// The security key secret of a save being opened, from install_key_open, until install_unlock takes it.
uint8_t g_try_key[PASS_KEY_SECRET_LEN];
static int g_have_try_key;
static char g_try_name[INSTALL_NAME_MAX + 1];

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

void pin_factor_secrets(void) {
    crypto_lock(g_try_key, sizeof g_try_key);
    crypto_lock(&g_new_key, sizeof g_new_key);
    crypto_lock(&g_new_code, sizeof g_new_code);
    crypto_lock(&g_job, sizeof g_job);
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

void forget_try_key(void) {
    crypto_wipe(g_try_key, sizeof g_try_key);
    g_have_try_key = 0;
    g_try_name[0] = '\0';
}

// ---- the securitykey file ----

// The file's magic and salt, then the entry's PIN flag and credential.
static size_t entry_ad(const uint8_t salt[SECKEY_SALT_LEN], const key_entry_t *e, uint8_t *ad) {
    memcpy(ad, KEY_FILE_MAGIC, KEY_SALT_AT);
    memcpy(ad + KEY_SALT_AT, salt, SECKEY_SALT_LEN);
    size_t n = KEY_COUNT_AT;
    ad[n++] = (uint8_t)e->uv;
    memcpy(ad + n, e->cred, e->cred_len);
    return n + e->cred_len;
}

static size_t key_file_pack(const key_file_t *f, uint8_t *out) {
    memcpy(out, KEY_FILE_MAGIC, KEY_SALT_AT);
    memcpy(out + KEY_SALT_AT, f->salt, SECKEY_SALT_LEN);
    out[KEY_COUNT_AT] = (uint8_t)f->n;
    size_t n = KEY_FILE_HEAD;
    for (int i = 0; i < f->n; i++) {
        const key_entry_t *e = &f->e[i];
        out[n] = (uint8_t)e->uv;
        store_be16(out + n + 1, (uint16_t)e->cred_len);
        n += KEY_ENTRY_HEAD;
        memcpy(out + n, e->cred, e->cred_len);
        n += e->cred_len;
        memcpy(out + n, e->wrapped, WRAP_LEN);
        n += WRAP_LEN;
    }
    return n;
}

static int key_file_parse(const uint8_t *in, size_t len, key_file_t *f) {
    if (len < KEY_FILE_HEAD || memcmp(in, KEY_FILE_MAGIC, KEY_SALT_AT) != 0) return -1;
    memcpy(f->salt, in + KEY_SALT_AT, SECKEY_SALT_LEN);
    f->n = in[KEY_COUNT_AT];
    if (f->n < 1 || f->n > KEYS_MAX) return -1;
    size_t p = KEY_FILE_HEAD;
    for (int i = 0; i < f->n; i++) {
        key_entry_t *e = &f->e[i];
        if (len - p < KEY_ENTRY_HEAD) return -1;
        e->uv = in[p];
        e->cred_len = load_be16(in + p + 1);
        p += KEY_ENTRY_HEAD;
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
    char path[INSTALL_PATH_MAX];
    if (save_path(name, SECKEY_NAME, path, sizeof path, 0) != 0) return -1;
    long n = platform_read_file(path, buf, sizeof buf);
    return n > 0 && (size_t)n <= SECKEY_FILE_MAX ? key_file_parse(buf, (size_t)n, f) : -1;
}

// Read back to be sure, since the save can't be opened without it.
int write_key_file(const char *name, const key_file_t *f) {
    static uint8_t buf[SECKEY_FILE_MAX], back[SECKEY_FILE_MAX + 1];
    char path[INSTALL_PATH_MAX];
    if (save_path(name, SECKEY_NAME, path, sizeof path, 1) != 0) return -1;
    size_t n = key_file_pack(f, buf);
    if (platform_write_private(path, buf, n) != 0) return -1;
    long got = platform_read_file(path, back, sizeof back);
    return got == (long)n && memcmp(back, buf, n) == 0 ? 0 : -1;
}

// ---- changing the factors ----

// One of the open save's files sealed again under lk. 0 once it is (or if there's no such file),
// 1 if it can't be read and stays as it was, -1 if it can't be written.
static int reseal(const char *file, const pass_lock_t *lk) {
    static uint8_t sealed[HISTORY_FILE_MAX + 1], plain[HISTORY_FILE_MAX];
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
int set_lock(unsigned target) {
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
    history_list_t *hl = list_histories(g_name);
    for (int i = 0; i < hl->n && rc == 0; i++) {
        int r = reseal(hl->names[i], &next);
        if (r > 0) skipped++;
        else rc = r;
    }
    if (rc == 0) reseal_tor(&next);
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
