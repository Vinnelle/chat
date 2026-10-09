// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/app.h"

// ---- :install, and what it saved ----

// Shown once the screen is up.
#define MAX_SAVED_NOTES 8

static char g_saved_notes[MAX_SAVED_NOTES][240];

static int g_n_saved_notes;

void saved_note(const char *fmt, ...) {
    if (g_n_saved_notes >= MAX_SAVED_NOTES) return;
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_saved_notes[g_n_saved_notes++], sizeof g_saved_notes[0], fmt, ap);
    va_end(ap);
}

void say_saved_notes(void) {
    for (int i = 0; i < g_n_saved_notes; i++) push_log("%s", g_saved_notes[i]);
    g_n_saved_notes = 0;
}

// A row's value from the settings file in the form :set takes, otherwise what it should have been.
static const char *row_from_toml(const setting_def_t *d, const toml_value *v, char *out, size_t cap) {
    if (d->kind == K_TOGGLE) {
        if (v->type != TOML_BOOL) return "true or false";
        copy_str(out, v->b ? "on" : "off", cap);
    } else if (d->id == SET_RELAYS) {
        if (v->type != TOML_ARRAY) return "a list of \"wss://...\" strings";
        size_t p = 0;
        out[0] = '\0';
        for (int k = 0; k < v->n; k++) {
            if (k) p = put_text(out, p, cap, " ");
            p = put_text(out, p, cap, v->items[k]);
        }
        if (p >= cap) return "fewer relays";
    } else if (v->type == TOML_INT && (d->id == SET_PORT || d->id == SET_FILE_LIMIT)) {
        snprintf(out, cap, "%lld", v->i);
    } else if (v->type == TOML_STRING && d->id != SET_PORT) {
        copy_str(out, v->s, cap);
    } else {
        return d->id == SET_PORT ? "a number" : "a string in quotes";
    }
    return NULL;
}

// Sets a row from a value in the form :set takes. If it isn't one of the row's values, or can't be
// used, g_app.message says why.
static void apply_row(const setting_def_t *d, const char *value) {
    const char *const *names;
    int n;
    if (setting_options(d->id, &names, &n) >= 0) {
        int i = 0;
        while (i < n && strcmp(value, names[i]) != 0) i++;
        if (i < n) setting_choose(d->id, i);
        else snprintf(g_app.message, sizeof g_app.message, "it takes %s", d->values);
    } else {
        setting_apply_text(d->id, value);
    }
}

typedef struct { char where[INSTALL_PATH_MAX]; } loading_t;

static void load_setting(void *ctx, const char *table, const char *key, const toml_value *tv) {
    loading_t *l = ctx;
    const setting_def_t *d = setting_by_key(key);
    char value[ROW_TEXT_MAX], before[ROW_TEXT_MAX], now[ROW_TEXT_MAX];
    if (!d || strcmp(setting_table(d->id), table) != 0 || !setting_text(d->id, before, sizeof before)) {
        saved_note("* %s: [%.20s] %.40s isn't a setting this chat saves - left out", l->where, table, key);
        return;
    }
    const char *want = row_from_toml(d, tv, value, sizeof value);
    if (want) {
        saved_note("* %s: %s takes %s - left out", l->where, d->key, want);
        return;
    }
    g_app.message[0] = '\0';
    apply_row(d, value);
    // One that didn't apply stays saved anyway, since a tor that's gone now may be back next time.
    setting_text(d->id, now, sizeof now);
    int took = strcmp(now, value) == 0 || strcmp(now, before) != 0;
    if (!took) saved_note("* %s: %s %.60s wasn't used - %s", l->where, d->key, value, g_app.message);
    copy_str(g_saved_rows[settings_index(d->id)], took ? now : value, ROW_TEXT_MAX);
    if (took && d->id == SET_ROUTING) g_app.route_chosen = 1;
}

static void load_saved_settings(void) {
    static char text[INSTALL_SETTINGS_MAX];
    loading_t l;
    char where[APP_PATH_MAX] = "";
    install_where(install_current(), where, sizeof where);
    snprintf(l.where, sizeof l.where, "%s/settings", where);
    long n = install_read_settings(text, sizeof text);
    if (n == INSTALL_NO_FILE) return;
    if (n < 0) { saved_note("* %s is damaged, or isn't sealed with this passphrase - left out", l.where); return; }
    // Like the startup settings page, nothing goes on the network meanwhile.
    int was = g_app.onboarding, bad_line = 0;
    g_app.onboarding = 1;
    int bad = toml_parse(text, load_setting, &l, &bad_line);
    g_app.onboarding = was;
    g_app.message[0] = '\0';
    crypto_wipe(text, sizeof text);
    if (bad) saved_note("* %s: %d line%s it can't read, from line %d - left out", l.where, bad, bad == 1 ? "" : "s", bad_line);
}

// Format, kind, origin, scalar flag, and the creation time a PGP key made here has (its
// fingerprint covers it), then the public key. Format 1 follows it with the secret key. Format 2,
// for a key from a file, with the file's full path instead, so the secret key isn't copied: the
// file is read again when it's opened. The public key tells whether the file still holds that key.
enum { KB_FORMAT_AT, KB_SOURCE_AT, KB_ORIGIN_AT, KB_SCALAR_AT, KB_CREATED_AT, KB_PUB_AT = KB_CREATED_AT + 4 };
enum { KEY_FORMAT_KEY = 1, KEY_FORMAT_PATH = 2 };
#define KEY_BLOB_HEAD (KB_PUB_AT + ID_SIGN_PUB_LEN)

#define KEY_BLOB_LEN (KEY_BLOB_HEAD + ID_SIGN_PRIV_LEN)

#define KEY_BLOB_MAX (KEY_BLOB_HEAD + KEY_PATH_MAX)

_Static_assert(KEY_BLOB_MAX <= INSTALL_KEY_MAX, "a sealed key has room for the signing key or its path");

int key_saved_as_path(void) {
    return g_app.key_origin == KEY_FILE && g_app.key_path[0];
}

// Returns the length.
static size_t identity_pack(uint8_t out[KEY_BLOB_MAX]) {
    int path = key_saved_as_path();
    out[KB_FORMAT_AT] = path ? KEY_FORMAT_PATH : KEY_FORMAT_KEY;
    out[KB_SOURCE_AT] = (uint8_t)g_app.identity_source;
    out[KB_ORIGIN_AT] = (uint8_t)g_app.key_origin;
    out[KB_SCALAR_AT] = (uint8_t)(g_app.identity.scalar != 0);
    store_be32(out + KB_CREATED_AT, g_app.pgp_created);
    memcpy(out + KB_PUB_AT, g_app.identity.pub, ID_SIGN_PUB_LEN);
    if (!path) {
        memcpy(out + KEY_BLOB_HEAD, g_app.identity.priv, ID_SIGN_PRIV_LEN);
        return KEY_BLOB_LEN;
    }
    size_t n = strlen(g_app.key_path);
    memcpy(out + KEY_BLOB_HEAD, g_app.key_path, n);
    return KEY_BLOB_HEAD + n;
}

// The saved key's public half (and path) is kept even when it isn't used, to tell whether the key
// in use is the same one. A key file that's gone or changed is said why with saved_note.
static int identity_unpack(const uint8_t *in, size_t len, int use) {
    if (len < KEY_BLOB_HEAD || (in[KB_FORMAT_AT] != KEY_FORMAT_KEY && in[KB_FORMAT_AT] != KEY_FORMAT_PATH)
        || (in[KB_SOURCE_AT] != IDENT_AGE && in[KB_SOURCE_AT] != IDENT_PGP) || in[KB_ORIGIN_AT] > KEY_PASTED
        || in[KB_SCALAR_AT] > 1)
        return -1;
    int path = in[KB_FORMAT_AT] == KEY_FORMAT_PATH;
    if (path ? in[KB_ORIGIN_AT] != KEY_FILE || len == KEY_BLOB_HEAD || len >= KEY_BLOB_MAX : len != KEY_BLOB_LEN) return -1;
    char saved_path[KEY_PATH_MAX] = "";
    if (path) {
        memcpy(saved_path, in + KEY_BLOB_HEAD, len - KEY_BLOB_HEAD);
        saved_path[len - KEY_BLOB_HEAD] = '\0';
        if (strlen(saved_path) != len - KEY_BLOB_HEAD) return -1;
    }
    memcpy(g_app.saved_key_pub, in + KB_PUB_AT, ID_SIGN_PUB_LEN);
    copy_str(g_app.saved_key_path, saved_path, sizeof g_app.saved_key_path);
    g_app.saved_key_known = 1;
    if (!use) return 0;
    identity_source_t kind = (identity_source_t)in[KB_SOURCE_AT];
    identity_keypair_t kp;
    char full[KEY_PATH_MAX];
    if (path) {
        char shown[KEY_PATH_MAX];
        tilde_path(saved_path, shown, sizeof shown);
        if (read_key_file(kind, saved_path, &kp, full, sizeof full) != 0) {
            saved_note("* your saved signing key's file %.200s can't be read, or no longer holds %s secret key - "
                       "it isn't used, and :set sign picks a key", shown, kind == IDENT_AGE ? "an AGE" : "a PGP");
            crypto_wipe(&kp, sizeof kp);
            return 0;
        }
        if (crypto_equal(kp.pub, g_app.saved_key_pub, ID_SIGN_PUB_LEN) != 0)
            saved_note("* %.200s holds a different key from the one :install saved - chat signs with it, and "
                       ":install records it", shown);
    } else {
        kp.scalar = in[KB_SCALAR_AT];
        memcpy(kp.pub, in + KB_PUB_AT, ID_SIGN_PUB_LEN);
        memcpy(kp.priv, in + KEY_BLOB_HEAD, ID_SIGN_PRIV_LEN);
    }
    g_app.identity = kp;
    crypto_wipe(&kp, sizeof kp);
    g_app.identity_source = kind;
    g_app.key_origin = (key_origin_t)in[KB_ORIGIN_AT];
    g_app.pgp_created = load_be32(in + KB_CREATED_AT);
    // A key file saved as the key itself, before :install saved paths, has no path to show.
    copy_str(g_app.key_path, saved_path, sizeof g_app.key_path);
    return 0;
}

// 0, a PASS_ code or INSTALL_NO_FILE. The identity in use is only changed on success.
static int open_saved_key(int use) {
    uint8_t blob[INSTALL_KEY_MAX];
    size_t len = 0;
    int rc = install_read_key(blob, sizeof blob, &len);
    if (rc == 0 && identity_unpack(blob, len, use) != 0) rc = PASS_FORMAT;
    crypto_wipe(blob, sizeof blob);
    return rc;
}

// A save needing a code that wasn't given, by open_saved.
#define OPEN_NO_CODE (-20)

static const char *open_error(int rc) {
    static char why[320];
    switch (rc) {
        case PASS_WRONG:
            return install_factors(install_current()) & INSTALL_FACTOR_KEY
                ? "that passphrase doesn't open what :install saved, with that security key"
                : "that passphrase doesn't open what :install saved";
        case PASS_NOMEM:      return "opening what :install saved needs 512 MiB of free memory for a moment";
        case INSTALL_NO_FILE: return "what :install saved isn't there any more";
        case INSTALL_KEY:     return "what :install saved needs its security key";
        case INSTALL_DEVICE:
            snprintf(why, sizeof why, "what :install saved only opens on the device it's locked to: %s", install_why());
            return why;
        case INSTALL_LOST:
            snprintf(why, sizeof why, "what :install saved can't be opened: %s", install_why());
            return why;
        case INSTALL_DESTROYED:
            snprintf(why, sizeof why, "what :install saved has been deleted - %s", install_why());
            return why;
        case OPEN_NO_CODE:    return "what :install saved needs the code your authenticator app shows";
        default:              return "what :install saved is damaged, or isn't something chat wrote";
    }
}

// The verified keys (core/trust.h) are saved each time they change, while what :install saved is
// open, its verified file could be read and autosave is on. trust_saved() says whether they are.
static int g_verified_ok;

static void verified_saving(int ok) {
    g_verified_ok = ok;
    trust_set_saved(ok && g_app.autosave);
}

void save_verified(void) {
    if (!trust_saved() || !g_app.installed || g_app.locked) return;
    static char text[TRUST_TEXT_MAX];
    if (trust_text(text, sizeof text) == 0 && install_write_verified(text) == 0) return;
    char where[APP_PATH_MAX] = "";
    install_where(install_current(), where, sizeof where);
    push_log("* couldn't save the verified keys in %s/verified - they last until chat exits", where);
}

// Turned on, it saves the keys verified or forgotten meanwhile. The rows are keep_settings_saved's.
void autosave_changed(void) {
    verified_saving(g_verified_ok);
    if (g_app.autosave) save_verified();
}

// Adds the saved verified keys to the ones in use. 0, or a PASS_ code.
static int load_saved_verified(void) {
    static char text[INSTALL_VERIFIED_MAX + 1];
    char where[APP_PATH_MAX] = "";
    install_where(install_current(), where, sizeof where);
    long n = install_read_verified(text, sizeof text);
    if (n == INSTALL_NO_FILE) return 0;
    if (n < 0) {
        saved_note("* %s/verified is damaged, or isn't sealed with this passphrase - left out", where);
        return (int)n;
    }
    int bad = trust_load(text);
    crypto_wipe(text, sizeof text);
    if (bad) saved_note("* %s/verified: %d line%s it can't read - left out", where, bad, bad == 1 ? "" : "s");
    return 0;
}

// The factors the open save needs, as its rows show them.
static void factors_in_use(void) {
    unsigned f = install_open_factors();
    g_app.device_lock = (f & INSTALL_FACTOR_DEVICE) != 0;
    g_app.key_factor = (f & INSTALL_FACTOR_KEY) != 0;
    g_app.code_factor = (f & INSTALL_FACTOR_CODE) != 0;
}

static int *factor_flag(unsigned factor) {
    return factor == INSTALL_FACTOR_DEVICE ? &g_app.device_lock
         : factor == INSTALL_FACTOR_KEY ? &g_app.key_factor : &g_app.code_factor;
}

static const char *factor_label(unsigned factor) {
    return factor == INSTALL_FACTOR_DEVICE ? "Device lock"
         : factor == INSTALL_FACTOR_KEY ? "Security key" : "Authenticator app";
}

// What f needs, for a sentence: "this device and the security key".
void factors_text(unsigned f, char *out, size_t cap) {
    const char *part[3];
    int n = 0;
    if (f & INSTALL_FACTOR_DEVICE) part[n++] = "this device";
    if (f & INSTALL_FACTOR_KEY) part[n++] = "the security key";
    if (f & INSTALL_FACTOR_CODE) part[n++] = "an authenticator code";
    size_t p = 0;
    out[0] = '\0';
    for (int i = 0; i < n; i++) {
        if (i) p = put_text(out, p, cap, i < n - 1 ? ", " : n == 2 ? " and " : ", and ");
        p = put_text(out, p, cap, part[i]);
    }
}

// What there is to say about the open save's decoy, or NULL.
static const char *shadow_news(void) {
    static char text[320];
    const char *shown = install_shown_name(install_current());
    switch (install_shadow_news()) {
        case INSTALL_SHADOW_OLD:
            snprintf(text, sizeof text, "* the save %s's shadow password was set by a beta of chat, which kept its decoy "
                     "in files only a save with a decoy has. It still works, but :set shadow off, then :set shadow on, "
                     "sets it again in the files every save has", shown);
            return text;
        case INSTALL_SHADOW_LOST:
            snprintf(text, sizeof text, "* the save %s's decoy couldn't be kept, so its shadow passphrase opens nothing "
                     "now - :set shadow on sets one again", shown);
            return text;
        default:
            return NULL;
    }
}

// The save just opened is the one in use from now on: its settings, then the command line options
// again so they still override them, then the key unless --identity chose another. Rows its
// settings don't have keep their value. loaded, if given, gets each row's value before the options
// are applied again.
static void use_opened_save(char (*loaded)[ROW_TEXT_MAX]) {
    g_app.installed = 1;
    g_app.locked = 0;
    factors_in_use();
    g_app.destroy_limit = install_destroy_limit(install_current());
    char needs[96];
    factors_text(install_open_factors(), needs, sizeof needs);
    if (install_relocked() > 0)
        saved_note("* the save %s was only part way through a change to what it needs: chat stopped while changing it, "
                   "or one of its files was replaced. It's sealed again needing %s - :set changes that",
                   install_shown_name(install_current()), needs);
    else if (install_relocked() < 0)
        saved_note("* the save %s is only part way through a change to what it needs, and couldn't be sealed again: %s",
                   install_shown_name(install_current()), install_why());
    const char *news = shadow_news();
    if (news) saved_note("%s", news);
    memcpy(g_saved_rows, g_setting_defaults, sizeof g_saved_rows);
    load_saved_settings();
    for (int i = 0; loaded && i < N_SETTINGS; i++)
        if (!setting_text(SETTINGS[i].id, loaded[i], ROW_TEXT_MAX)) loaded[i][0] = '\0';
    // A damaged file isn't overwritten by the keys verified this run.
    verified_saving(load_saved_verified() == 0);
    reapply_options();
    note_settings_seen();
    g_app.saved_key_known = 0;
    g_app.saved_key_path[0] = '\0';
    int rc = open_saved_key(!g_opts.identity[0]);
    if (rc != 0 && rc != INSTALL_NO_FILE)
        saved_note("* your saved signing key is damaged, or isn't sealed with this passphrase - it's left out");
}

// Before the screen is up, how often a security key, a code and a passphrase are asked for, and how
// often the security key's progress is looked at.
enum { PIN_TRIES = 4, CODE_TRIES = 5, PICK_TRIES = 3, PASS_TRIES = 3, KEY_POLL_MS = 50 };

// Before the screen is up: the save's security key, waited for here. 0 once it's given its secret.
static int key_in_terminal(const char *name) {
    char pin[64] = "";
    for (int tries = 0; tries < PIN_TRIES; tries++) {
        if (install_key_open(name, pin[0] ? pin : NULL) != 0) break;
        crypto_wipe(pin, sizeof pin);
        int stage = -1, said = -1;
        install_key_state_t st;
        while ((st = install_key_poll(&stage, NULL)) == INSTALL_KEY_RUNNING) {
            if (stage != said && stage != SECKEY_BUSY) {
                fprintf(stderr, "chat: %s\n", stage == SECKEY_LOOKING ? "plug in the save's security key"
                                              : "touch your security key (it's blinking)");
                said = stage;
            }
            platform_sleep_ms(KEY_POLL_MS);
        }
        if (st == INSTALL_KEY_DONE) return 0;
        if (st != INSTALL_KEY_PIN || !term_is_tty()) break;
        fprintf(stderr, "chat: %s\n", install_key_why());
        if (term_read_password("security key PIN: ", pin, sizeof pin) != 0 || !pin[0]) return -1;
    }
    crypto_wipe(pin, sizeof pin);
    fprintf(stderr, "chat: the security key: %s\n", install_key_why());
    return -1;
}

static int code_in_terminal(void) {
    for (int tries = 0; tries < CODE_TRIES && term_is_tty(); tries++) {
        char line[32] = "";
        if (term_read_line("the code your authenticator app shows: ", line, sizeof line) != 0 || !line[0]) return -1;
        int rc = install_check_code(line);
        if (rc == 0) return 0;
        fprintf(stderr, "chat: %s\n", rc == PASS_FORMAT ? "a code is 6 digits"
                                      : "that isn't the code it shows - check the clocks of this computer and the phone");
    }
    return -1;
}

// 0, or the reason it stayed sealed. Before the screen is up, so a security key is waited for, and a
// code typed, in the terminal. probe: the passphrase may be another save's, so it's tried with
// install_probe.
static int open_saved(const char *name, const char *passphrase, int probe) {
    if ((install_factors(name) & INSTALL_FACTOR_KEY) && !install_key_ready(name) && key_in_terminal(name) != 0)
        return INSTALL_KEY;
    int rc = probe ? install_probe(name, passphrase) : install_unlock(name, passphrase);
    if (rc != 0) return rc;
    if (install_code_pending() && code_in_terminal() != 0) {
        install_code_cancel();
        return OPEN_NO_CODE;
    }
    use_opened_save(NULL);
    return 0;
}

// What a save holds, what it needs to open and when it was last written, for the list to pick one from.
void save_detail(const install_save_t *sv, char *out, size_t cap) {
    snprintf(out, cap, "%s%s%s%s%s%s", sv->settings && sv->key ? "settings and key" : sv->settings ? "settings" : "key",
             sv->factors & INSTALL_FACTOR_DEVICE ? DOT_SEP "this device only" : "",
             sv->factors & INSTALL_FACTOR_KEY ? DOT_SEP "security key" : "",
             sv->factors & INSTALL_FACTOR_CODE ? DOT_SEP "code" : "", sv->modified[0] ? DOT_SEP : "", sv->modified);
}

// With more than one save and no --save, one is picked from a list before its passphrase is asked for.
int save_to_pick(void) { return g_app.n_saves > 1 && !g_opts.save[0]; }

// The saves, numbered, then a number or name typed in. 0 once one is in use, -1 for none.
static int pick_save_in_terminal(void) {
    printf("chat: :install made %d saves here, each sealed with its own passphrase:\n", g_app.n_saves);
    for (int i = 0; i < g_app.n_saves; i++) {
        char detail[112];
        save_detail(&g_app.saves[i], detail, sizeof detail);
        enum { NAME_COLS = 16 };
        printf("  %2d  %-*s  %s\n", i + 1, INSTALL_NAME_MAX < NAME_COLS ? INSTALL_NAME_MAX : NAME_COLS,
               install_shown_name(g_app.saves[i].name), detail);
    }
    for (int tries = 0; tries < PICK_TRIES; tries++) {
        char line[64] = "";
        if (term_read_line("which one to open (number or name, blank: none): ", line, sizeof line) != 0) return -1;
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r' || line[n - 1] == ' ')) line[--n] = '\0';
        if (!line[0]) return -1;
        char *end;
        long num = strtol(line, &end, 10);
        for (int i = 0; i < g_app.n_saves; i++) {
            if ((!*end && num == i + 1) || strcmp(line, install_shown_name(g_app.saves[i].name)) == 0) {
                install_use(g_app.saves[i].name);
                return 0;
            }
        }
        fprintf(stderr, "chat: there's no save %s\n", line);
    }
    return -1;
}

// From CHAT_INSTALL_PASSWORD, otherwise asked for in a box once the screen is up, or in the terminal.
// With more than one save and no --save, CHAT_INSTALL_PASSWORD opens the first one it can that needs
// no security key or code, and otherwise the one to open is picked first. A save that needs them
// takes the passphrase from it, and asks for them in the box, or in the terminal.
void unlock_at_start(int in_box) {
    g_app.locked = 1;
    char pw[INSTALL_PASS_MAX] = "";
    int from_env = platform_env_take("CHAT_INSTALL_PASSWORD", pw, sizeof pw) == 0;
    const unsigned more = INSTALL_FACTOR_KEY | INSTALL_FACTOR_CODE;
    if (from_env && in_box && !save_to_pick() && (install_factors(install_current()) & more)) {
        copy_str(g_app.install_pass, pw, sizeof g_app.install_pass);
        crypto_wipe(pw, sizeof pw);
        g_app.unlock_env = g_app.unlock_at_start = 1;
        return;
    }
    if (from_env) {
        int rc = PASS_WRONG, elsewhere = 0;
        if (!save_to_pick()) rc = open_saved(install_current(), pw, 0);
        else for (int i = 0; i < g_app.n_saves && (rc == PASS_WRONG || rc == INSTALL_DEVICE); i++) {
            if (g_app.saves[i].factors & more) continue;
            // Saves it doesn't fit aren't counted towards self-destruct, and no decoy opens.
            rc = open_saved(g_app.saves[i].name, pw, 1);
            elsewhere |= rc == INSTALL_DEVICE;
        }
        crypto_wipe(pw, sizeof pw);
        if (rc == 0) return;
        saved_note("* CHAT_INSTALL_PASSWORD: %s", rc == PASS_WRONG && save_to_pick()
                   ? (elsewhere ? "that passphrase doesn't open any of the saves :install made that open on this device"
                                : "that passphrase doesn't open any of the saves :install made")
                   : open_error(rc));
    }
    if (in_box) { g_app.unlock_at_start = 1; return; }
    int picked = !save_to_pick() || (term_is_tty() && pick_save_in_terminal() == 0);
    for (int tries = 0; tries < PASS_TRIES && picked && term_is_tty(); tries++) {
        char prompt[96];
        snprintf(prompt, sizeof prompt, "passphrase for %s%s (blank: start without it): ",
                 g_app.n_saves > 1 ? "the save " : "what :install saved",
                 g_app.n_saves > 1 ? install_shown_name(install_current()) : "");
        if (term_read_password(prompt, pw, sizeof pw) != 0 || !pw[0]) break;
        int rc = open_saved(install_current(), pw, 0);
        crypto_wipe(pw, sizeof pw);
        if (rc == 0) return;
        fprintf(stderr, "chat: %s\n", open_error(rc));
        if (rc != PASS_WRONG) break;
    }
    crypto_wipe(pw, sizeof pw);
    saved_note("* what :install saved stays sealed: this run starts from chat's defaults and saves nothing%s",
               from_env ? "" : " (CHAT_INSTALL_PASSWORD opens it)");
}

// The same key, saved the same way: by its file's path for a key file, otherwise as the key. A key
// file saved as the key, before :install saved paths, counts as saved until it's picked again.
int key_in_use_saved(void) {
    return g_app.identity_source != IDENT_NONE && g_app.saved_key_known
        && crypto_equal(g_app.saved_key_pub, g_app.identity.pub, ID_SIGN_PUB_LEN) == 0
        && strcmp(g_app.saved_key_path, key_saved_as_path() ? g_app.key_path : "") == 0;
}

// The verified keys in use when the open save was uninstalled. They last until chat exits, or until
// :install opens another save, which has its own.
static uint8_t g_uninstalled_keys[TRUST_MAX][ID_SIGN_PUB_LEN];

static int g_n_uninstalled_keys;

// A new passphrase first, since Argon2id is the slow part and can fail if there isn't enough
// memory. Then the settings, which are always there, then a key not saved yet, sealed under the
// same passphrase.
static void finish_install(const char *passphrase) {
    int resave = !passphrase && g_app.installed && is_current_save(g_app.save_target);
    char where[APP_PATH_MAX] = "";
    install_where(g_app.save_target, where, sizeof where);
    if (passphrase) {
        note(g_app.device_lock ? "sealing, and locking it to this device..." : "sealing...");
        render();
        // With the device lock on, a save that can't be locked isn't made at all, and likewise for the
        // security key and the code set up for it.
        unsigned factors = (g_app.device_lock ? INSTALL_FACTOR_DEVICE : 0) | (g_app.key_factor ? INSTALL_FACTOR_KEY : 0)
                         | (g_app.code_factor ? INSTALL_FACTOR_CODE : 0);
        histories_write();
        int rc = install_lock_new(g_app.save_target, passphrase, factors);
        if (rc == INSTALL_DEVICE) {
            push_log("* not installed: it can't be locked to this device - %s", install_why());
            note("not installed: it can't be locked to this device - %s", install_why());
            install_setup_forget();
            return;
        }
        if (rc == PASS_NOMEM) {
            note("not installed: sealing needs 512 MiB of free memory for a moment");
            install_setup_forget();
            return;
        }
        if (rc != 0) {
            note("not installed: %s", install_why());
            install_setup_forget();
            return;
        }
        // A new save has no key in it yet.
        g_app.saved_key_known = 0;
        g_app.saved_key_path[0] = '\0';
    }
    // Everything in use, including the options.
    note_settings_seen();
    memcpy(g_saved_rows, g_seen_rows, sizeof g_saved_rows);
    static char text[INSTALL_SETTINGS_MAX];
    if (settings_text(text, sizeof text) != 0 || install_write_settings(text) != 0) {
        if (passphrase) {
            // A new save leaves nothing behind, not even its device or security key files.
            if (install_open_factors()) install_remove(g_app.save_target);
            install_forget();
            g_app.installed = 0;
        }
        note("couldn't write your settings to %s%s", where, g_app.installed ? "" : " - not installed");
        return;
    }
    g_app.installed = 1;
    g_app.locked = 0;
    factors_in_use();
    install_arm_destroy(g_app.save_target, (unsigned)g_app.destroy_limit);
    // A new save, or one saved over, gets every key in use.
    g_n_uninstalled_keys = 0;
    static char vtext[TRUST_TEXT_MAX];
    int verified = trust_text(vtext, sizeof vtext) == 0 && install_write_verified(vtext) == 0;
    verified_saving(verified);
    if (!verified) push_log("* couldn't write the verified keys to %s - they last until chat exits", where);
    int key = g_app.identity_source != IDENT_NONE && !key_in_use_saved();
    int path = key && key_saved_as_path();
    if (key) {
        uint8_t blob[KEY_BLOB_MAX];
        size_t len = identity_pack(blob);
        int rc = install_write_key(blob, len);
        crypto_wipe(blob, sizeof blob);
        if (rc != 0) { note("your settings are saved, but your signing key couldn't be written to %s", where); return; }
        memcpy(g_app.saved_key_pub, g_app.identity.pub, ID_SIGN_PUB_LEN);
        copy_str(g_app.saved_key_path, path ? g_app.key_path : "", sizeof g_app.saved_key_path);
        g_app.saved_key_known = 1;
    }
    char needs[96], also[120] = "";
    factors_text(install_open_factors(), needs, sizeof needs);
    if (needs[0]) snprintf(also, sizeof also, ", needing %s as well as the passphrase", needs);
    push_log("* %s: your settings%s are in %s, sealed%s, for next time. :uninstall deletes them",
             resave ? "saved" : "installed", path ? " and your signing key's path" : key ? " and signing key" : "", where,
             also);
    if (passphrase && g_app.device_lock) push_log("%s", DEVICE_REMINDER);
    if (passphrase && g_app.key_factor) push_log("%s", KEY_REMINDER);
    note("%s in %s", resave ? "saved" : "installed", where);
}

// If installed, it saves under the passphrase it has. Otherwise existing files need their own
// passphrase, and if there's nothing there it needs a new one, with or without a key.
// Another save than the one in use is switched to only once it's sealed or opened.
int is_current_save(const char *name) {
    return strcmp(install_shown_name(name), install_shown_name(install_current())) == 0;
}

int save_exists(const char *name) { return install_has_settings(name) || install_has_key(name); }

void pick_random_save_name(void) {
    do random_nickname(g_app.save_random, sizeof g_app.save_random);
    while (save_exists(g_app.save_random));
}

// :install for the save that's open and installed already only saves what's in use to it.
int install_resaves(void) { return g_app.installed && is_current_save(g_app.save_target); }

// :install is over, whether or not it made or opened a save, and its boxes go. A new save has the
// factor it was for set up already; a save it opened is asked about it now; with nothing open, the
// row is off again.
static void install_ended(void) {
    unsigned f = g_app.install_for;
    g_app.install_for = 0;
    if (g_app.install_back == MODE_SETTINGS && g_app.mode == MODE_CHAT) g_app.mode = MODE_SETTINGS;
    if (!f) return;
    if (!g_app.installed) *factor_flag(f) = 0;
    else if (install_open_factors() & f) return;
    else if (f == INSTALL_FACTOR_DEVICE) device_lock_choose(1);
    else factor_choose(f, 1);
}

void cancel_install(void) {
    crypto_wipe(g_app.install_pass, sizeof g_app.install_pass);
    install_setup_forget();
    end_prompt();
    note(install_resaves() ? "not saved - nothing was written" : "not installed - nothing was written");
    install_ended();
}

static void to_install_mode(app_mode_t mode) {
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    g_app.mode = mode;
    g_app.dirty = 1;
}

static void not_installed(const char *fmt, const char *why) {
    install_setup_forget();
    end_prompt();
    note(fmt, why);
    install_ended();
}

// What a new save needs is set up before its passphrase, one box after another: the device lock's,
// which says what would lose the save for good, then the security key's, with its touches, then the
// authenticator's QR code. after is the step just done.
enum { STEP_START, STEP_DEVICE, STEP_KEY, STEP_CODE };

static void install_step(int after) {
    if (after < STEP_DEVICE && g_app.device_lock) {
        device_check();
        if (g_app.device_kind == DEVICE_NONE) {
            not_installed("not installed: it can't be locked to this device - %s", g_app.device_why);
            return;
        }
        g_app.device_want = g_app.device_new = 1;
        g_app.device_back = g_app.install_back;
        g_app.mode = MODE_DEVICE_LOCK;
        g_app.dirty = 1;
        return;
    }
    g_app.factor_want = g_app.factor_new = 1;
    g_app.factor_back = g_app.install_back;
    if (after < STEP_KEY && g_app.key_factor) {
        device_check();
        if (!g_app.seckey_ok) {
            not_installed("not installed: a security key can't be used here - %s", g_app.seckey_why);
            return;
        }
        g_app.factor = INSTALL_FACTOR_KEY;
        to_install_mode(MODE_FACTOR);
        return;
    }
    if (after < STEP_CODE && g_app.code_factor) {
        g_app.factor = INSTALL_FACTOR_CODE;
        install_code_new(g_app.save_target, g_app.code_b32, sizeof g_app.code_b32, g_app.code_uri, sizeof g_app.code_uri);
        g_app.code_qr = 0;
        to_install_mode(MODE_CODE_SETUP);
        return;
    }
    g_app.factor_new = 0;
    to_install_mode(MODE_INSTALL_PASS);
}

void install_confirmed(void) {
    if (install_resaves()) {
        end_prompt();
        finish_install(NULL);
        install_ended();
        return;
    }
    install_step(STEP_START);
}

// No save is open and there are saves: use one, which needs its passphrase, or make a new save.
void install_use_existing(void) {
    g_app.install_overwrite = 0;
    to_install_mode(g_app.install_pick ? MODE_INSTALL_PICK : MODE_INSTALL_UNLOCK);
}

void install_new_save(void) {
    pick_random_save_name();
    to_install_mode(MODE_INSTALL_NAME);
}

static void back_to_existing(void) { to_install_mode(MODE_INSTALL_EXISTING); }

// With no saves there, the name was the first box: there's nothing to go back to.
void back_from_install_name(void) {
    if (g_app.n_saves > 0) back_to_existing();
    else cancel_install();
}

void install_pick_key(const tui_key_t *key) {
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT:
            copy_str(g_app.save_target, g_app.saves[g_app.save_sel].name, sizeof g_app.save_target);
            to_install_mode(MODE_INSTALL_UNLOCK);
            break;
        case LIST_LEFT:
        case LIST_BACK:  back_to_existing(); break;
        case LIST_CLOSE: cancel_install(); break;
        default:
            list_move(k, &g_app.save_sel, g_app.n_saves);
            g_app.dirty = 1;
            break;
    }
}

// While a save is open, saving over another one needs that save's passphrase.
void install_overwrite_yes(void) {
    g_app.install_overwrite = 1;
    to_install_mode(MODE_INSTALL_UNLOCK);
}

void back_from_install_unlock(void) {
    to_install_mode(g_app.install_overwrite ? MODE_INSTALL_OVERWRITE
                    : g_app.install_pick ? MODE_INSTALL_PICK : MODE_INSTALL_EXISTING);
}

// y, n, or Esc and q.
void choice_key(const tui_key_t *key, void (*yes)(void), void (*no)(void), void (*esc)(void)) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (ch == 'y' || ch == 'Y') yes();
    else if (ch == 'n' || ch == 'N') no();
    else if (ch == 'q' || key->type == TUI_KEY_ESCAPE) esc();
}

void commit_install_name(void) {
    char name[64];
    copy_str(name, g_app.input.buf, sizeof name);
    size_t n = strlen(name);
    while (n > 0 && name[n - 1] == ' ') name[--n] = '\0';
    const char *p = name;
    while (*p == ' ') p++;
    if (!*p) p = g_app.save_random;
    if (install_name_ok(p) != 0) { note("a save's name is 1 to %d letters, digits, - and _", INSTALL_NAME_MAX); return; }
    if (save_exists(p)) { note("there's a save called %s already - pick another name", install_shown_name(p)); return; }
    copy_str(g_app.save_target, strcmp(p, "default") == 0 ? "" : p, sizeof g_app.save_target);
    // What it leaves on disk, then its passphrase.
    to_install_mode(MODE_INSTALL);
}

void commit_install_pass(void) {
    if (!g_app.input.buf[0]) { note("what's saved needs a passphrase - or Esc to cancel"); return; }
    copy_str(g_app.install_pass, g_app.input.buf, sizeof g_app.install_pass);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    g_app.mode = MODE_INSTALL_PASS2;
    g_app.dirty = 1;
}

void commit_install_pass2(void) {
    int same = strcmp(g_app.input.buf, g_app.install_pass) == 0;
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    if (!same) {
        crypto_wipe(g_app.install_pass, sizeof g_app.install_pass);
        g_app.mode = MODE_INSTALL_PASS;
        note("they weren't the same - type the passphrase again");
        return;
    }
    char pw[sizeof g_app.install_pass];
    copy_str(pw, g_app.install_pass, sizeof pw);
    crypto_wipe(g_app.install_pass, sizeof g_app.install_pass);
    end_prompt();
    finish_install(pw);
    crypto_wipe(pw, sizeof pw);
    install_ended();
}

// The save :install just opened is used from now on, as if it had been opened at the start, with
// these differences. A setting changed this run isn't put back to its command line option. One the
// save doesn't have keeps its value and is saved to it, and so are keys verified this run. Keys from
// a save uninstalled this run are left out.
static void use_save_now(void) {
    static char ran[N_SETTINGS][ROW_TEXT_MAX], loaded[N_SETTINGS][ROW_TEXT_MAX];
    int changed[N_SETTINGS];
    for (int i = 0; i < N_SETTINGS; i++) {
        if (!setting_text(SETTINGS[i].id, ran[i], sizeof ran[i])) ran[i][0] = '\0';
        changed[i] = strcmp(ran[i], g_seen_rows[i]) != 0;
    }
    int dropped = 0;
    for (int i = trust_count() - 1; i >= 0; i--)
        for (int k = 0; k < g_n_uninstalled_keys; k++)
            if (crypto_equal(trust_at(i)->pub, g_uninstalled_keys[k], ID_SIGN_PUB_LEN) == 0) {
                trust_remove(i);
                dropped++;
                break;
            }
    g_n_uninstalled_keys = 0;
    int verified_here = trust_count();
    identity_source_t src = g_app.identity_source;
    uint8_t pub[ID_SIGN_PUB_LEN];
    memcpy(pub, g_app.identity.pub, sizeof pub);

    g_hold_sessions = 1;
    int was = g_app.onboarding;
    g_app.onboarding = 1;
    use_opened_save(loaded);
    // A row the save doesn't have is at its default in g_saved_rows.
    int keep = 0;
    for (int i = 0; i < N_SETTINGS; i++) {
        const setting_def_t *d = &SETTINGS[i];
        char now[ROW_TEXT_MAX];
        if (!changed[i] || !setting_text(d->id, now, sizeof now)) continue;
        if (strcmp(now, loaded[i]) != 0) {
            g_app.message[0] = '\0';
            apply_row(d, loaded[i]);
            setting_text(d->id, now, sizeof now);
            if (strcmp(now, loaded[i]) != 0) saved_note("* %s %.60s wasn't used - %s", d->key, loaded[i], g_app.message);
            else if (d->id == SET_ROUTING) g_app.route_chosen = 1;
        }
        if (strcmp(g_saved_rows[i], g_setting_defaults[i]) != 0 || strcmp(now, ran[i]) != 0) continue;
        copy_str(g_saved_rows[i], now, sizeof g_saved_rows[i]);
        keep = 1;
    }
    g_app.message[0] = '\0';
    g_app.onboarding = was;
    g_hold_sessions = 0;
    note_settings_seen();

    const char *shown = install_shown_name(install_current());
    char where[APP_PATH_MAX] = "";
    install_where(install_current(), where, sizeof where);
    if (keep) {
        static char text[INSTALL_SETTINGS_MAX];
        if (settings_text(text, sizeof text) != 0 || install_write_settings(text) != 0)
            push_log("* couldn't save the settings changed this run in %s/settings - they last until chat exits", where);
    }
    if (verified_here > 0) save_verified();
    settings_to_sessions();
    // As at the end of the startup settings page: :update's proxy, and a tor for Tor mode.
    if (!g_app.onboarding) {
        sync_update_proxy();
        tor_link_ensure(now_seconds());
    }
    say_saved_notes();
    // The rows the save changed, by name. All the names fit.
    char rows[320] = "";
    size_t rp = 0;
    int row_ids[N_SETTINGS], n_rows = 0;
    for (int i = 0; i < N_SETTINGS; i++) {
        char now[ROW_TEXT_MAX];
        if (setting_text(SETTINGS[i].id, now, sizeof now) && strcmp(now, ran[i]) != 0) row_ids[n_rows++] = i;
    }
    for (int k = 0; k < n_rows; k++) {
        rp = put_text(rows, rp, sizeof rows, k == 0 ? "" : k == n_rows - 1 ? " and " : ", ");
        rp = put_text(rows, rp, sizeof rows, SETTINGS[row_ids[k]].key);
    }
    if (n_rows) push_log("* the save %s changed %s - :set shows the values", shown, rows);
    if (dropped)
        push_log("* %d verified key%s from the save you uninstalled %s left out: each save keeps its own "
                 "(:verified lists them)", dropped, dropped == 1 ? "" : "s", dropped == 1 ? "is" : "are");
    if (g_app.identity_source != src || crypto_equal(pub, g_app.identity.pub, ID_SIGN_PUB_LEN) != 0) identity_chosen();
    else say_key_saved_state();
    push_log("* opened the save %s in %s: its settings are in use%s, and %s", shown, where,
             keep ? ", with the ones changed this run that it doesn't have" : "",
             g_app.autosave ? "changes are saved to it" : "autosave is off, so :save saves changes to it");
    note("opened the save %s", shown);
}

static void install_unlock_done(int rc) {
    end_prompt();
    if (rc != 0) {
        if (rc == INSTALL_NO_FILE && is_current_save(g_app.save_target)) g_app.locked = 0;
        note("%s: %s", g_app.install_overwrite ? "not installed" : "not opened", open_error(rc));
        install_ended();
        return;
    }
    if (!g_app.install_overwrite) { use_save_now(); install_ended(); return; }
    g_app.saved_key_known = 0;
    g_app.saved_key_path[0] = '\0';
    open_saved_key(0);
    // The keys verified in an earlier run are kept, with the ones verified in this one added.
    load_saved_verified();
    say_saved_notes();
    finish_install(NULL);
    install_ended();
}

// The passphrase is in install_pass, and the save's security key has given its secret, if it needs one.
static void install_unlock_result(int rc) {
    g_app.mode = MODE_INSTALL_UNLOCK;
    if (rc == PASS_WRONG) { note("that passphrase doesn't open the save %s", install_shown_name(g_app.save_target)); return; }
    if (rc == PASS_NOMEM) { note("%s", open_error(rc)); return; }
    if (rc == 0 && install_code_pending()) {
        g_app.key_purpose = KP_INSTALL_UNLOCK;
        g_app.message[0] = '\0';
        to_install_mode(MODE_UNLOCK_CODE);
        return;
    }
    install_unlock_done(rc);
}

// What's in use stays in use. The passphrase only opens what's saved, so it can be overwritten.
void commit_install_unlock(void) {
    if (!g_app.input.buf[0]) { note("type its passphrase - or Esc to go back"); return; }
    copy_str(g_app.install_pass, g_app.input.buf, sizeof g_app.install_pass);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    unlock_go(KP_INSTALL_UNLOCK);
}

void uninstall_confirmed(void) {
    end_prompt();
    char where[APP_PATH_MAX] = "";
    install_where(g_app.save_target, where, sizeof where);
    if (install_remove(g_app.save_target) != 0) { note("couldn't delete everything chat saved in %s", where); return; }
    if (!is_current_save(g_app.save_target)) {
        push_log("* uninstalled: the save %s in %s is deleted", install_shown_name(g_app.save_target), where);
        note("uninstalled %s", install_shown_name(g_app.save_target));
        return;
    }
    g_app.installed = g_app.locked = 0;
    factors_in_use();
    verified_saving(0);
    g_n_uninstalled_keys = 0;
    for (int i = 0; i < trust_count(); i++)
        memcpy(g_uninstalled_keys[g_n_uninstalled_keys++], trust_at(i)->pub, ID_SIGN_PUB_LEN);
    g_app.saved_key_known = 0;
    g_app.saved_key_path[0] = '\0';
    push_log("* uninstalled: chat's files in %s are deleted. What's in use now lasts until chat exits", where);
    note("uninstalled");
}

// What the run starts with (the options, what's saved, a random nick) doesn't count as a change to save.
void settle_start(void) {
    if (!g_app.nick[0]) {
        random_nickname(g_app.nick, sizeof g_app.nick);
        push_log("welcome to chat. you're %s for now - :set nick NAME renames you anytime",
                 g_app.nick);
    }
    note_settings_seen();
    say_saved_notes();
}

// Once opened, chat starts with its saved settings straight away. Otherwise it opens on the settings page.
static void end_unlock(void) {
    end_prompt();
    settle_start();
    if (g_app.installed && install_has_settings(install_current())) settings_done();
    else g_app.mode = MODE_SETTINGS;
}

static void unlock_done(int rc) {
    if (rc == 0) use_opened_save(NULL);
    // Deleted after too many wrong tries: there's nothing to open any more.
    if (rc == INSTALL_DESTROYED) { g_app.installed = 0; verified_saving(0); }
    // The key before chat starts, so a --session opens signed.
    if (key_in_use_saved()) identity_chosen();
    end_unlock();
    if (rc != 0) note("%s", open_error(rc));
}

static void unlock_result(int rc) {
    g_app.mode = MODE_UNLOCK;
    if (rc == PASS_WRONG || rc == PASS_NOMEM || rc == INSTALL_DEVICE || rc == INSTALL_KEY) { note("%s", open_error(rc)); return; }
    if (rc == 0 && install_code_pending()) {
        g_app.key_purpose = KP_UNLOCK;
        g_app.message[0] = '\0';
        to_install_mode(MODE_UNLOCK_CODE);
        return;
    }
    unlock_done(rc);
}

void commit_unlock(void) {
    if (!g_app.input.buf[0]) { note("type its passphrase - or Esc to start without it"); return; }
    copy_str(g_app.install_pass, g_app.input.buf, sizeof g_app.install_pass);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    unlock_go(KP_UNLOCK);
}

static void skip_unlock(void) {
    end_unlock();
    note("what :install saved stays sealed: chat starts from its defaults, and saves nothing until :install opens a save");
}

// Esc on the passphrase goes back to the list, if it came from one.
void back_from_unlock(void) {
    if (!save_to_pick()) { skip_unlock(); return; }
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    g_app.mode = MODE_SAVES;
    g_app.dirty = 1;
}

void saves_key(const tui_key_t *key) {
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT:
            install_use(g_app.saves[g_app.save_sel].name);
            g_app.mode = MODE_UNLOCK;
            break;
        case LIST_BACK:
            skip_unlock();
            break;
        default:
            list_move(k, &g_app.save_sel, g_app.n_saves);
            break;
    }
    g_app.dirty = 1;
}

void cancel_uninstall(void) {
    end_prompt();
    note("nothing was deleted");
}

// ---- a factor turned on with no save open ----
//
// It's for a save, so a box asks to :install first. Yes turns it on for the new save :install makes,
// which sets it up before the passphrase, and install_ended sets it up for a save :install opens.

static void install_first(unsigned factor) {
    g_app.install_for = factor;
    g_app.install_back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    g_app.n_saves = install_list(g_app.saves, INSTALL_SAVES_MAX);
    begin_prompt(MODE_INSTALL_FIRST);
}

void install_first_yes(void) {
    end_prompt();
    if (g_app.install_back == MODE_SETTINGS) g_app.mode = MODE_SETTINGS;
    *factor_flag(g_app.install_for) = 1;
    if (begin_install(NULL) != 0) install_ended();
}

void install_first_no(void) {
    const char *label = factor_label(g_app.install_for);
    end_prompt();
    install_ended();
    note("%s: off - nothing was installed", label);
}

// The open save is sealed again, after a box asks.
void device_lock_choose(int on) {
    device_check();
    if (on && g_app.device_kind == DEVICE_NONE) { note("Device lock: can't be used here - %s", g_app.device_why); return; }
    if (!g_app.installed && on) { install_first(INSTALL_FACTOR_DEVICE); return; }
    if (!g_app.installed) {
        g_app.device_lock = 0;
        note("Device lock: off");
        return;
    }
    if (!on == !g_app.device_lock) {
        // This also finishes one a failed write left half done.
        if (install_set_factor(INSTALL_FACTOR_DEVICE, on) == 0) note("Device lock: %s already", on ? "on" : "off");
        else note("Device lock: %s - %s", on ? "on" : "off", install_why());
        return;
    }
    g_app.device_want = on;
    g_app.device_new = 0;
    g_app.device_back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    if (g_app.device_back == MODE_CHAT) begin_prompt(MODE_DEVICE_LOCK);
    else { g_app.mode = MODE_DEVICE_LOCK; g_app.dirty = 1; }
}

static void device_lock_back(void) {
    if (g_app.device_back == MODE_CHAT) { end_prompt(); return; }
    g_app.mode = g_app.device_back;
    g_app.dirty = 1;
}

void device_lock_yes(void) {
    if (g_app.device_new) {
        g_app.device_new = 0;
        install_step(STEP_DEVICE);
        return;
    }
    int on = g_app.device_want;
    device_lock_back();
    const char *shown = install_shown_name(install_current());
    char where[APP_PATH_MAX] = "";
    install_where(install_current(), where, sizeof where);
    // A TPM can take a few seconds to make a key.
    note(on ? "locking %s to this device..." : "unlocking %s from this device...", shown);
    render();
    int rc = install_set_factor(INSTALL_FACTOR_DEVICE, on);
    device_kind_t kind = install_device_lock();
    g_app.device_lock = kind != DEVICE_NONE;
    const char *also = install_why();
    if (rc != 0) {
        push_log("* device lock: %s for the save %s - %s", g_app.device_lock ? "on" : "off", shown, also);
        note("Device lock: %s - %s", g_app.device_lock ? "on" : "off", also);
        return;
    }
    factors_in_use();
    if (on) {
        push_log("* device lock: the save %s in %s is locked to this device. It uses %s", shown, where,
                 platform_device_uses(kind));
        push_log("%s", DEVICE_REMINDER);
    } else {
        push_log("* device lock: the save %s in %s isn't locked to this device any more, and opens wherever its files "
                 "are", shown, where);
    }
    if (also[0]) push_log("* device lock: %s", also);
    const char *news = shadow_news();
    if (news) push_log("%s", news);
    note(on ? "Device lock: on - %s only opens on this device" : "Device lock: off - %s opens on any device", shown);
}

void device_lock_no(void) {
    if (g_app.device_new) {
        g_app.device_new = 0;
        cancel_install();
        return;
    }
    device_lock_back();
    note("nothing was changed");
}

// ---- the security key and the authenticator app ----
//
// Like the device lock: with no save open, turning one on asks to :install first. For the open
// save, a box asks first, and the save is sealed again.

static void key_start(key_purpose_t why);

static void key_ended(install_key_state_t st);

// The factor boxes open over the settings page or the chat, and their fields take the input line,
// saved meanwhile.
static void factor_close(void) {
    app_mode_t back = g_app.factor_back;
    end_prompt();
    if (back == MODE_SETTINGS) g_app.mode = MODE_SETTINGS;
}

void factor_choose(unsigned factor, int on) {
    const char *label = factor_label(factor);
    int *flag = factor_flag(factor);
    device_check();
    if (on && factor == INSTALL_FACTOR_KEY && !g_app.seckey_ok) {
        note("Security key: can't be used here - %s", g_app.seckey_why);
        return;
    }
    if (!g_app.installed && on) { install_first(factor); return; }
    if (!g_app.installed) {
        *flag = 0;
        note("%s: off", label);
        return;
    }
    if (!on == !*flag) {
        // This also finishes one a failed write left half done.
        if (install_set_factor(factor, on) == 0) note("%s: %s already", label, on ? "on" : "off");
        else note("%s: %s - %s", label, on ? "on" : "off", install_why());
        factors_in_use();
        return;
    }
    g_app.factor = factor;
    g_app.factor_want = on;
    g_app.factor_new = 0;
    g_app.factor_back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    if (factor == INSTALL_FACTOR_CODE && on) {
        install_code_new(install_current(), g_app.code_b32, sizeof g_app.code_b32, g_app.code_uri, sizeof g_app.code_uri);
        g_app.code_qr = 0;
        begin_prompt(MODE_CODE_SETUP);
    } else {
        begin_prompt(MODE_FACTOR);
    }
}

// Seals the open save again with the factor box's change, once a security key or an authenticator
// app has been set up for turning it on.
static void factor_apply(void) {
    unsigned factor = g_app.factor;
    int on = g_app.factor_want, key = factor == INSTALL_FACTOR_KEY;
    const char *shown = install_shown_name(install_current());
    factor_close();
    note("sealing %s again...", shown);
    render();
    int rc = install_set_factor(factor, on);
    install_setup_forget();
    factors_in_use();
    const char *also = install_why();
    if (rc != 0) {
        push_log("* %s: not changed for the save %s - %s", key ? "security key" : "authenticator app", shown, also);
        note("%s: not changed - %s", factor_label(factor), also);
        return;
    }
    if (key && on) {
        push_log("* security key: the save %s needs your security key now, as well as its passphrase. Without it, "
                 "nothing opens the save", shown);
        push_log("%s", KEY_REMINDER);
    } else if (key) {
        push_log("* security key: the save %s opens without a security key again", shown);
    } else if (on) {
        push_log("* authenticator app: the save %s asks for the code your app shows each time it opens. Keep a copy of "
                 "the secret somewhere safe: without the app or the secret, chat won't open the save", shown);
    } else {
        push_log("* authenticator app: the save %s doesn't ask for a code any more, and the secret is deleted: remove "
                 "its entry from your app", shown);
    }
    if (also[0]) push_log("* %s", also);
    const char *news = shadow_news();
    if (news) push_log("%s", news);
    note("%s: %s for %s", factor_label(factor), on ? "on" : "off", shown);
}

void factor_yes(void) {
    // Registering takes two touches: one for the credential, one for its secret.
    if (g_app.factor == INSTALL_FACTOR_KEY && g_app.factor_want) {
        key_start(g_app.factor_new ? KP_NEW_SAVE : KP_FACTOR);
        return;
    }
    factor_apply();
}

void factor_no(void) {
    if (g_app.factor_new) { cancel_install(); return; }
    factor_close();
    note("nothing was changed");
}

static void commit_code_setup(void) {
    char code[32];
    copy_str(code, g_app.input.buf, sizeof code);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    if (!code[0]) { note("type the code your app shows for it - or Esc to cancel"); return; }
    int rc = install_code_try(code);
    if (rc == PASS_FORMAT) { note("a code is 6 digits, as your app shows it"); return; }
    if (rc != 0) {
        note("that isn't the code for this secret - check the app has the new one, and the clocks of this computer and "
             "the phone");
        return;
    }
    if (g_app.factor_new) { install_step(STEP_CODE); return; }
    factor_apply();
}

static void cancel_code_setup(void) {
    install_setup_forget();
    if (g_app.factor_new) { cancel_install(); return; }
    factor_close();
    note("Authenticator app: not changed - delete the entry you added to your app, if you did");
}

// ---- self-destruct, and the shadow passphrase ----

void destroy_choose(int limit) {
    g_app.destroy_limit = limit;
    const char *shown = install_shown_name(install_current());
    if (!g_app.installed) {
        if (limit) note("Self-destruct: on - the save :install makes next deletes itself after %d wrong passphrases", limit);
        else note("Self-destruct: off");
        return;
    }
    if (install_arm_destroy(install_current(), (unsigned)limit) != 0) {
        g_app.destroy_limit = install_destroy_limit(install_current());
        note("Self-destruct: couldn't write the save's tries file");
        return;
    }
    if (limit) {
        push_log("* self-destruct: the save %s deletes everything chat saved for it after %d wrong passphrases in a "
                 "row. A right one clears the count", shown, limit);
        note("Self-destruct: on - after %d wrong passphrases", limit);
    } else {
        push_log("* self-destruct: off for the save %s", shown);
        note("Self-destruct: off");
    }
}

// The decoy is a clean save with no signing key or verified peers: it looks like a fresh install.
static void shadow_set_decoy(void) {
    const char *shown = install_shown_name(install_current());
    int rc = install_shadow_set(g_app.shadow_pass);
    crypto_wipe(g_app.shadow_pass, sizeof g_app.shadow_pass);
    factor_close();
    if (rc == PASS_NOMEM) { note("Shadow password: setting it up needs 512 MiB of free memory for a moment"); return; }
    if (rc != 0) { note("Shadow password: couldn't set it - %s", install_why()); return; }
    push_log("* shadow password: the save %s now has a decoy. Opening it with the shadow passphrase puts the decoy in "
             "the real save's place and deletes the real save's files. Don't forget which passphrase is which", shown);
    note("Shadow password: on for %s", shown);
}

void shadow_off(void) {
    if (install_shadow_clear() != 0) {
        note("Shadow password: couldn't remove it - %s", install_why());
        return;
    }
    push_log("* shadow password: removed for the save %s - there's no decoy now", install_shown_name(install_current()));
    note("Shadow password: off");
}

void begin_shadow(void) {
    if (!g_app.installed || g_app.locked) {
        note("Shadow password: open a save first - :install, then set it while the save is open");
        return;
    }
    if (install_has_shadow()) {
        shadow_off();
        return;
    }
    crypto_wipe(g_app.shadow_pass, sizeof g_app.shadow_pass);
    g_app.factor_back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    begin_prompt(MODE_SHADOW_PASS);
}

void commit_shadow_pass(void) {
    if (!g_app.input.buf[0]) { note("type the shadow passphrase - or Esc to cancel"); return; }
    copy_str(g_app.shadow_pass, g_app.input.buf, sizeof g_app.shadow_pass);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    g_app.mode = MODE_SHADOW_PASS2;
    g_app.dirty = 1;
}

void commit_shadow_pass2(void) {
    int same = strcmp(g_app.input.buf, g_app.shadow_pass) == 0;
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    if (!same) {
        crypto_wipe(g_app.shadow_pass, sizeof g_app.shadow_pass);
        g_app.mode = MODE_SHADOW_PASS;
        note("they weren't the same - type the shadow passphrase again");
        return;
    }
    note("setting up the decoy...");
    render();
    shadow_set_decoy();
}

void cancel_shadow_pass(void) {
    crypto_wipe(g_app.shadow_pass, sizeof g_app.shadow_pass);
    factor_close();
    note("Shadow password: not changed");
}

// The security key's thread starts, and its box shows what it's waiting for until it's done.
static void key_start(key_purpose_t why) {
    const char *pin = g_app.key_pin[0] ? g_app.key_pin : NULL;
    g_app.key_purpose = why;
    if (why != KP_FACTOR) g_app.factor_back = why == KP_UNLOCK ? MODE_CHAT : g_app.install_back;
    int rc = why == KP_FACTOR || why == KP_NEW_SAVE
        ? install_key_make(pin)
        : install_key_open(why == KP_INSTALL_UNLOCK ? g_app.save_target : install_current(), pin);
    crypto_wipe(g_app.key_pin, sizeof g_app.key_pin);
    g_app.key_stage = SECKEY_BUSY;
    g_app.key_touches = 0;
    to_install_mode(MODE_KEY_WAIT);
    if (rc != 0) key_ended(INSTALL_KEY_FAILED);
}

// Where what the security key's thread came to leads, for what it was touched for.
static void key_ended(install_key_state_t st) {
    key_purpose_t why = g_app.key_purpose;
    if (st == INSTALL_KEY_PIN) {
        to_install_mode(MODE_KEY_PIN);
        note("%s", install_key_why());
        return;
    }
    if (st == INSTALL_KEY_DONE) {
        if (why == KP_NEW_SAVE) install_step(STEP_KEY);
        else if (why == KP_FACTOR) factor_apply();
        else unlock_go(why);
        return;
    }
    const char *what = st == INSTALL_KEY_CANCELLED ? "stopped" : install_key_why();
    switch (why) {
        case KP_NEW_SAVE:
            not_installed("not installed - security key: %s", what);
            return;
        case KP_FACTOR:
            install_setup_forget();
            factor_close();
            note("Security key: not changed - %s", what);
            return;
        default:
            crypto_wipe(g_app.install_pass, sizeof g_app.install_pass);
            to_install_mode(why == KP_INSTALL_UNLOCK ? MODE_INSTALL_UNLOCK : MODE_UNLOCK);
            note("not opened - security key: %s", what);
            return;
    }
}

void commit_key_pin(void) {
    if (!g_app.input.buf[0]) { note("type the security key's PIN - or Esc to cancel"); return; }
    copy_str(g_app.key_pin, g_app.input.buf, sizeof g_app.key_pin);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    key_start(g_app.key_purpose);
}

void cancel_key_pin(void) { key_ended(INSTALL_KEY_CANCELLED); }

void key_wait_key(const tui_key_t *key) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (key->type != TUI_KEY_ESCAPE && ch != 'q') return;
    install_key_cancel();
    note("stopping...");
}

// Each time round the main loop while the box waits: what it's waiting for, and when it's done.
void key_wait_tick(void) {
    int s, t;
    install_key_state_t st = install_key_poll(&s, &t);
    if (st == INSTALL_KEY_RUNNING) {
        if (s != g_app.key_stage || t != g_app.key_touches) g_app.dirty = 1;
        g_app.key_stage = s;
        g_app.key_touches = t;
        return;
    }
    g_app.key_stage = SECKEY_LOOKING;
    g_app.key_touches = 0;
    if (st != INSTALL_KEY_IDLE) key_ended(st);
}

// Opening a save: its security key's secret first, then the passphrase in install_pass, then a code
// it needs.
void unlock_go(key_purpose_t why) {
    const char *name = why == KP_INSTALL_UNLOCK ? g_app.save_target : install_current();
    if ((install_factors(name) & INSTALL_FACTOR_KEY) && !install_key_ready(name)) {
        key_start(why);
        return;
    }
    // Argon2id takes a few seconds, so say so before the screen freezes.
    if (why == KP_INSTALL_UNLOCK) note("opening the save %s...", install_shown_name(name));
    else note("opening what :install saved...");
    render();
    histories_write();
    int rc = install_unlock(name, g_app.install_pass);
    crypto_wipe(g_app.install_pass, sizeof g_app.install_pass);
    if (why == KP_INSTALL_UNLOCK) install_unlock_result(rc);
    else unlock_result(rc);
}

void commit_unlock_code(void) {
    char code[32];
    copy_str(code, g_app.input.buf, sizeof code);
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    tui_input_clear(&g_app.input);
    if (!code[0]) { note("type the code your authenticator app shows - or Esc to go back"); return; }
    note("checking the code...");
    render();
    int rc = install_check_code(code);
    crypto_wipe(code, sizeof code);
    if (rc == PASS_FORMAT) { note("a code is 6 digits, as your authenticator app shows it"); return; }
    if (rc != 0) {
        note("that isn't the code your authenticator app shows for it - check the clocks of this computer and the phone");
        return;
    }
    if (g_app.key_purpose == KP_INSTALL_UNLOCK) install_unlock_done(0);
    else unlock_done(0);
}

void back_from_unlock_code(void) {
    install_code_cancel();
    to_install_mode(g_app.key_purpose == KP_INSTALL_UNLOCK ? MODE_INSTALL_UNLOCK : MODE_UNLOCK);
    note("not opened: it needs its passphrase, then the code");
}

// Enter doesn't answer. A question takes y or n.
void confirm_key(const tui_key_t *key, void (*yes)(void), void (*no)(void)) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (ch == 'y' || ch == 'Y') yes();
    else if (ch == 'n' || ch == 'N' || ch == 'q' || key->type == TUI_KEY_ESCAPE) no();
}

// Only y quits: not a second Ctrl+C, the easy mistake, nor q, which closes boxes elsewhere. Staying
// leaves whatever the box was over as it was.
void quit_key(const tui_key_t *key) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (ch == 'y' || ch == 'Y') g_interrupted = 1;
    else if (ch == 'n' || ch == 'N' || key->type == TUI_KEY_ESCAPE) { g_app.asking_quit = 0; g_app.dirty = 1; }
}

void field_key(const tui_key_t *key, void (*enter)(void), void (*esc)(void)) {
    if (key->type == TUI_KEY_ESCAPE) esc();
    else if (key->type == TUI_KEY_ENTER) enter();
    else if (tui_input_feed(&g_app.input, key)) g_app.dirty = 1;
}

// Tab is only offered when the text and the QR code don't fit together, and then picks between them.
void code_setup_key(const tui_key_t *key) {
    if (key->type == TUI_KEY_TAB) { g_app.code_qr = !g_app.code_qr; g_app.dirty = 1; }
    else field_key(key, commit_code_setup, cancel_code_setup);
}
