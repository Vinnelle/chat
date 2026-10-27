// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The signing identity: the picker's choices, a key made from a password or read from a file or a
// paste, and what's shown and copied of it.
#include "app/app.h"

const sign_pick_row_t SIGN_PICKS[N_PICKS] = {
    { NULL, "Off", "Don't sign. Peers see you as unverified." },
    { "AGE", "Native", "A key made here, with an age1... recipient others can encrypt files to you with "
                       "(age -r). Enter asks for a password: the same password on this device and OS always makes "
                       "the same key, so always use the same one to keep an established signing identity. Blank "
                       "makes a new key that lasts until chat exits." },
    { NULL, "Pick a key file", "Your own AGE key, picked in a file browser: the file age-keygen writes. "
                               WHY_SECRET "It stays in memory and isn't sent. :install saves the file's path, not "
                               "the key." },
    { NULL, "Type a key file path", "Your own AGE key from a file whose path you type, such as "
                                    "~/.config/age/key.txt. " WHY_SECRET ":install saves the path, not the key." },
    { NULL, "Paste a key", "Your own AGE key pasted in: the AGE-SECRET-KEY-1... line. " WHY_SECRET "There's no "
                           "file to point to, so :install seals the key itself to disk." },
    { "PGP", "Native", "A PGP key made here, whose public key is in the settings and the console for others "
                       "to import. Enter asks for a password: the same password on this device and OS always makes "
                       "the same key, so always use the same one to keep an established signing identity. Blank "
                       "makes a new key that lasts until chat exits." },
    { NULL, "Pick a key file", "Your own key, picked in a file browser: an unencrypted EdDSA/Ed25519 secret key, "
                               "armored, as gpg --export-secret-keys --armor writes it. " WHY_SECRET ":install "
                               "saves the file's path, not the key." },
    { NULL, "Type a key file path", "Your own key from a file whose path you type: an unencrypted, armored "
                                    "EdDSA/Ed25519 secret key. " WHY_SECRET ":install saves the path, not the key." },
    { NULL, "Paste a key", "Your own key pasted in, armored. " WHY_SECRET "There's no file to point to, so "
                           ":install seals the key itself to disk." },
};

// Why chat asks for your secret key, and what happens to it, for the pages that take one.
const char KEY_WHY[] =
    "**Why the secret key:** chat signs the handshake of every session you join, so peers can check it's "
    "you. Only the secret key can make a signature; the public key can only check one. The key is kept in "
    "memory and never sent: peers get your public key and the signatures.";

const char KEY_FILE_SAVED[] =
    "**What :install keeps:** this file's path, not the key. chat reads the file again each time it starts, "
    "so leave it where it is.";

const char KEY_PASTE_SAVED[] =
    "**What :install keeps:** with no file to point to, the key itself, sealed with your passphrase. Until "
    "then it's only in memory. To keep it out of chat's files, save it to a file and pick that instead.";

const char AGE_PASTE_HELP[] =
    "Paste your AGE secret key now: the AGE-SECRET-KEY-1... line, or the whole file age-keygen wrote. It's read "
    "when its line ends (Enter, if the paste didn't end it).";

const char PGP_PASTE_HELP[] =
    "Paste your armored PGP private key now, BEGIN line to END line. It's read as soon as the END line "
    "arrives. It has to be an unencrypted EdDSA/Ed25519 key (gpg --export-secret-keys --armor, from a key "
    "with no passphrase).";

const char AGE_PATH_HELP[] =
    "Type the path to your AGE key file, as age-keygen writes it. ~ is your home folder.";

const char PGP_PATH_HELP[] =
    "Type the path to your PGP key file: an unencrypted, armored EdDSA/Ed25519 secret key, as gpg "
    "--export-secret-keys --armor writes it from a key with no passphrase. ~ is your home folder.";

const char SIGN_PASSWORD_HELP[] =
    "Type the password to make your key from. The same password on this device and OS always makes the same "
    "key and fingerprint, so always use the same password to keep an established signing identity: a different "
    "one, or a typo, makes a different key. Make it long, since anyone who learns this device's id can guess at "
    "it. Blank makes a new key that lasts until chat exits. Nothing is written to disk unless you :install.";

int sign_row_in_use(void) {
    int age = g_app.identity_source == IDENT_AGE;
    if (!age && g_app.identity_source != IDENT_PGP) return PICK_OFF;
    switch (g_app.key.origin) {
        case KEY_FILE:   return age ? PICK_AGE_FILE : PICK_PGP_FILE;
        case KEY_PASTED: return age ? PICK_AGE_PASTE : PICK_PGP_PASTE;
        default:         return age ? PICK_AGE_MADE : PICK_PGP_MADE;
    }
}

// Opens the picker from the Signing identity row, on the choice in use.
void begin_sign(void) {
    g_app.key.sel = sign_row_in_use();
    g_app.mode = MODE_SIGN_CHOICE;
    g_app.dirty = 1;
}

// Passes the identity just chosen to every open session.
void identity_chosen(void) {
    int any = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i] || g_app.sessions[i].initialising) continue;
        chat_set_identity(g_app.sessions[i].engine, g_app.identity_source, &g_app.identity);
        any = 1;
    }
    show_identity_result();
    say_key_saved_state();
    char v[160]; setting_value(SET_SIGN, v, sizeof v);
    note("Signing identity: %s%s", v, any ? " - applied to open sessions too" : "");
}

// Whether the key in use is the one saved, once a save is open.
void say_key_saved_state(void) {
    if (g_app.installed && g_app.identity_source != IDENT_NONE && !key_in_use_saved())
        push_log("* this signing key isn't saved: :save %s with your settings' passphrase%s",
                 g_app.key.origin == KEY_FILE && g_app.key.path[0] ? "saves its file's path, sealed" : "seals it",
                 install_has_key(install_current()) ? ", in place of the saved one" : "");
    else if (g_app.installed && g_app.identity_source == IDENT_NONE && install_has_key(install_current()))
        push_log("* the saved signing key stays saved, and signs again the next time chat starts");
}

// A key of kind (AGE or PGP) made here: from password and this device's id, the same every time,
// or a new random one if password is empty. Returns NULL once it's the identity in use, otherwise
// the reason it isn't, and the current identity stays.
const char *make_identity(identity_source_t kind, const char *password) {
    if (!password[0]) {
        gen_identity_keypair(&g_app.identity);
        g_app.key.origin = KEY_MADE;
        g_app.key.pgp_created = (uint32_t)time(NULL);
    } else {
        char device[128];
        if (platform_machine_id(device, sizeof device) != 0)
            return "this system has no machine id to make the key with - leave the password blank for a new key";
        if (identity_from_password(password, device, &g_app.identity) != 0)
            return "couldn't make the key - it needs 512 MiB of free memory for a moment";
        g_app.key.origin = KEY_DERIVED;
        g_app.key.pgp_created = DERIVED_PGP_CREATED;
    }
    g_app.identity_source = kind;
    return NULL;
}

// The password a native key is made from, typed on the bottom bar with the picker still up.
static void begin_sign_password(identity_source_t kind) {
    g_app.key.load_kind = kind;
    g_app.saved_input = g_app.input;
    tui_input_clear(&g_app.input);
    g_app.input.modal = 0;
    g_app.mode = MODE_SIGN_PASSWORD;
    g_app.dirty = 1;
}

void end_sign_password(void) {
    crypto_wipe(g_app.input.buf, sizeof g_app.input.buf);
    g_app.input = g_app.saved_input;
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    g_app.mode = MODE_SIGN_CHOICE;
    g_app.dirty = 1;
}

void commit_sign_password(void) {
    char pw[sizeof g_app.input.buf];
    copy_str(pw, g_app.input.buf, sizeof pw);
    end_sign_password();
    if (pw[0]) {
        // Argon2id takes a few seconds, so say so before the screen freezes.
        note("making your key from the password...");
        render();
    }
    const char *why = make_identity(g_app.key.load_kind, pw);
    crypto_wipe(pw, sizeof pw);
    if (why) { note("%s", why); return; }
    identity_chosen();
    g_app.mode = MODE_SETTINGS;
}

// A typed path with a leading ~ (alone, or followed by /) as the home folder.
static void expand_home(const char *path, char *out, size_t cap) {
    const char *home = platform_home_dir();
    if (home && path[0] == '~' && (path[1] == '\0' || path[1] == '/')) snprintf(out, cap, "%s%s", home, path + 1);
    else copy_str(out, path, cap);
}

// path with the home folder as ~, to show.
void tilde_path(const char *path, char *out, size_t cap) {
    const char *home = platform_home_dir();
    size_t hl = home ? strlen(home) : 0;
    if (hl > 1 && strncmp(path, home, hl) == 0 && (path[hl] == '/' || path[hl] == '\0'))
        snprintf(out, cap, "~%s", path + hl);
    else copy_str(out, path, cap);
}

// kind's key (AGE or PGP) from the file at path, into kp. Its full path goes in full, for :install to
// save. Returns 0, or -1 if the file isn't such a key.
int read_key_file(identity_source_t kind, const char *path, identity_keypair_t *kp, char *full, size_t cap) {
    char p[KEY_PATH_MAX];
    expand_home(path, p, sizeof p);
    int rc = kind == IDENT_AGE ? age_import_secret_key(p, kp) : pgp_import_secret_key(p, kp);
    if (rc != 0) return -1;
    if (platform_full_path(p, full, cap) != 0) copy_str(full, p, cap);
    return 0;
}

// kind's key (AGE or PGP) from the file at path. Returns 0 once it's the identity in use.
int load_key_file(identity_source_t kind, const char *path) {
    identity_keypair_t kp;
    char full[KEY_PATH_MAX];
    int rc = read_key_file(kind, path, &kp, full, sizeof full);
    if (rc == 0) {
        g_app.identity = kp;
        g_app.identity_source = kind;
        g_app.key.origin = KEY_FILE;
        copy_str(g_app.key.path, full, sizeof g_app.key.path);
    }
    crypto_wipe(&kp, sizeof kp);
    return rc;
}

// The key file in use, if it's kind's, for the browser and the path field to start at.
static const char *key_path_of(identity_source_t kind) {
    return g_app.key.origin == KEY_FILE && g_app.identity_source == kind && g_app.key.path[0] ? g_app.key.path : NULL;
}

// Opens in the folder of the key file in use, if there is one, otherwise the home folder.
static void begin_key_browse(identity_source_t kind) {
    g_app.key.load_kind = kind;
    const char *home = platform_home_dir();
    char dir[KEY_PATH_MAX] = "", name[200] = "";
    if (key_path_of(kind)) {
        copy_str(dir, g_app.key.path, sizeof dir);
        const char *slash = strrchr(g_app.key.path, '/');
        if (slash) copy_str(name, slash + 1, sizeof name);
        path_parent(dir);
    }
    if (dir[0] && browser_load(&g_app.browser, dir) == 0) browser_select(&g_app.browser, name);
    else if (!home || browser_load(&g_app.browser, home) != 0) browser_load(&g_app.browser, "/");
    g_app.mode = MODE_SIGN_BROWSE;
    g_app.dirty = 1;
}

// The field for a key file's path, on the picker or the browser, starting with start (or empty).
void begin_key_path(identity_source_t kind, const char *start, int from_browser) {
    g_app.key.load_kind = kind;
    g_app.key.path_from_browser = from_browser;
    g_app.saved_input = g_app.input;
    tui_input_clear(&g_app.input);
    g_app.input.modal = 0;
    if (start) {
        char shown[sizeof g_app.input.buf];
        tilde_path(start, shown, sizeof shown);
        copy_str(g_app.input.buf, shown, sizeof g_app.input.buf);
        g_app.input.len = g_app.input.cursor = (int)strlen(g_app.input.buf);
    }
    g_app.mode = MODE_SIGN_PATH;
    g_app.dirty = 1;
}

void end_key_path(void) {
    g_app.input = g_app.saved_input;
    crypto_wipe(&g_app.saved_input, sizeof g_app.saved_input);
    g_app.mode = g_app.key.path_from_browser ? MODE_SIGN_BROWSE : MODE_SIGN_CHOICE;
    g_app.dirty = 1;
}

// A path that isn't a key stays in the field to be fixed.
void commit_key_path(void) {
    char path[sizeof g_app.input.buf];
    copy_str(path, g_app.input.buf, sizeof path);
    if (!path[0]) { note("type the key file's path - or Esc to go back"); return; }
    if (load_key_file(g_app.key.load_kind, path) != 0) {
        if (g_app.key.load_kind == IDENT_AGE) note("%.80s can't be read, or holds no AGE secret key", path);
        else note("%.80s can't be read, or isn't an unencrypted EdDSA/Ed25519 secret key", path);
        return;
    }
    end_key_path();
    identity_chosen();
    g_app.mode = MODE_SETTINGS;
}

void paste_clear(void) {
    crypto_wipe(g_app.paste.buf, sizeof g_app.paste.buf);
    g_app.paste.len = 0;
    copy_str(g_app.paste.status, "waiting for the paste", sizeof g_app.paste.status);
}

static void begin_key_paste(identity_source_t kind) {
    g_app.key.load_kind = kind;
    paste_clear();
    g_app.mode = MODE_SIGN_PASTE;
    g_app.dirty = 1;
}

// Loads the key file picked in the browser. Returns 0 once it's the identity in use.
int try_load_key_from_browser(void) {
    const dir_entry_t *sel = &g_app.browser.items[g_app.browser.selected];
    char full[1200]; browser_entry_path(&g_app.browser, sel, full, sizeof full);
    if (load_key_file(g_app.key.load_kind, full) != 0) {
        if (g_app.key.load_kind == IDENT_AGE) note("%.80s can't be read, or holds no AGE secret key", sel->name);
        else note("%.80s can't be read, or isn't an unencrypted EdDSA/Ed25519 secret key", sel->name);
        return -1;
    }
    identity_chosen();
    return 0;
}

// Off takes effect immediately. A key made here asks for its password first, and a key file or
// paste opens its own page.
void sign_pick(int pick) {
    switch (pick) {
        case PICK_OFF:
            g_app.identity_source = IDENT_NONE;
            crypto_wipe(&g_app.identity, sizeof g_app.identity);
            identity_chosen();
            return;
        case PICK_AGE_MADE:  begin_sign_password(IDENT_AGE); return;
        case PICK_PGP_MADE:  begin_sign_password(IDENT_PGP); return;
        case PICK_AGE_FILE:  begin_key_browse(IDENT_AGE); return;
        case PICK_AGE_PATH:  begin_key_path(IDENT_AGE, key_path_of(IDENT_AGE), 0); return;
        case PICK_AGE_PASTE: begin_key_paste(IDENT_AGE); return;
        case PICK_PGP_FILE:  begin_key_browse(IDENT_PGP); return;
        case PICK_PGP_PATH:  begin_key_path(IDENT_PGP, key_path_of(IDENT_PGP), 0); return;
        case PICK_PGP_PASTE: begin_key_paste(IDENT_PGP); return;
        default: return;
    }
}

void copy_age_recipient(void) {
    if (g_app.identity_source != IDENT_AGE) return;
    char recipient[AGE_RECIPIENT_STRLEN + 1];
    age_export_recipient(&g_app.identity, recipient);
    osc52_copy(recipient);
    note("AGE recipient copied to the clipboard (OSC 52)");
}

void copy_pgp_public_key(void) {
    if (!pgp_key_made_here()) return;
    char armor[PGP_ARMOR_MAX]; uint8_t fp[PGP_FP_LEN];
    pgp_public_key(armor, fp);
    osc52_copy(armor);
    note("PGP public key copied to the clipboard (OSC 52)");
}

int pgp_key_made_here(void) {
    return g_app.identity_source == IDENT_PGP && (g_app.key.origin == KEY_MADE || g_app.key.origin == KEY_DERIVED);
}

static const char *pgp_uid_nick(void) { return g_app.nick[0] ? g_app.nick : "chat"; }

// The PGP key made here, armored, with the nick as it is now in its user id.
void pgp_public_key(char armor[PGP_ARMOR_MAX], uint8_t fp[PGP_FP_LEN]) {
    pgp_export_public_key(&g_app.identity, pgp_uid_nick(), g_app.key.pgp_created, armor, PGP_ARMOR_MAX, fp);
}

void show_identity_result(void) {
    if (g_app.identity_source == IDENT_NONE) return;
    uint8_t fp[ID_FP_LEN]; identity_fingerprint(g_app.identity.pub, fp);
    char fphex[HEX_GROUPS_LEN(ID_FP_LEN)]; hex_groups(fp, ID_FP_LEN, fphex);
    push_log("your identity fingerprint: %s - compare it with peers over another channel", fphex);
    if (g_app.identity_source == IDENT_AGE) {
        char recipient[AGE_RECIPIENT_STRLEN + 1];
        age_export_recipient(&g_app.identity, recipient);
        push_log("AGE recipient (others can `age -r` encrypt files to you): %s", recipient);
    }
    if (pgp_key_made_here()) {
        char armor[PGP_ARMOR_MAX]; uint8_t pgp_fp[PGP_FP_LEN];
        pgp_public_key(armor, pgp_fp);
        push_log("PGP public key (others can `gpg --import` it; Enter on it in the settings copies it):");
        // Line by line, including the blank one after BEGIN, which gpg needs.
        for (char *line = armor, *nl; *line; line = nl + 1) {
            nl = strchr(line, '\n');
            if (!nl) { push_log("%s", line); break; }
            *nl = '\0';
            push_log("%s", line);
        }
    }
}

// ---- :exportkey ----

// A PGP key from a file or a paste came with user ids and signatures chat doesn't keep, so only where
// it came from has the whole key.
const char *key_export_refusal(void) {
    if (g_app.identity_source == IDENT_NONE) return "no signing key in use - :set sign picks or makes one";
    if (g_app.identity_source == IDENT_PGP && !pgp_key_made_here())
        return "only a PGP key made here is exported - gpg --export-secret-keys gives one from a file or a paste";
    return NULL;
}

const char *key_export_name(void) {
    return g_app.identity_source == IDENT_AGE ? "age-secret-key.txt" : "pgp-secret-key.asc";
}

// The first of the name, "name (2).ext" and so on that nothing in dir has, as a saved file is named.
#define EXPORT_NAME_TRIES 100
static int export_free_path(const char *dir, char *out, size_t cap) {
    const char *name = key_export_name(), *dot = strrchr(name, '.');
    file_info_t info;
    for (int k = 1; k < EXPORT_NAME_TRIES; k++) {
        char file[64];
        if (k == 1) copy_str(file, name, sizeof file);
        else snprintf(file, sizeof file, "%.*s (%d)%s", (int)(dot - name), name, k, dot);
        path_join(out, cap, dir, file);
        if (platform_file_info(out, &info) != 0) return 0;
    }
    return -1;
}

// s on :exportkey's browser: the box asks before anything is written.
void begin_export_ask(const char *dir) {
    if (export_free_path(dir, g_app.key.export_path, sizeof g_app.key.export_path) != 0) {
        note("%.120s has no free name for the key - pick another folder", dir);
        return;
    }
    g_app.mode = MODE_EXPORT_ASK;
    g_app.dirty = 1;
}

// An AGE key as age-keygen writes it, with its recipient as a comment, or the PGP key made here with
// its secret.
static int export_key_text(char *out, size_t cap) {
    if (g_app.identity_source == IDENT_AGE) {
        char recipient[AGE_RECIPIENT_STRLEN + 1], key[AGE_SECRET_KEY_STRLEN + 1];
        age_export_recipient(&g_app.identity, recipient);
        age_export_secret_key(&g_app.identity, key);
        snprintf(out, cap, "# public key: %s\n%s\n", recipient, key);
        crypto_wipe(key, sizeof key);
        return 0;
    }
    uint8_t fp[PGP_FP_LEN];
    return pgp_export_secret_key(&g_app.identity, pgp_uid_nick(), g_app.key.pgp_created, out, cap, fp);
}

// Unbuffered, so stdio's buffer never holds a copy of the key. A file only partly written is removed.
void export_key_yes(void) {
    char shown[KEY_PATH_MAX], text[PGP_ARMOR_MAX];
    tilde_path(g_app.key.export_path, shown, sizeof shown);
    FILE *f = export_key_text(text, sizeof text) == 0 ? platform_create_new(g_app.key.export_path) : NULL;
    int ok = f != NULL;
    if (f) {
        size_t n = strlen(text);
        ok = setvbuf(f, NULL, _IONBF, 0) == 0 && fwrite(text, 1, n, f) == n;
        ok = fclose(f) == 0 && ok;
        if (!ok) platform_remove(g_app.key.export_path);
    }
    crypto_wipe(text, sizeof text);
    g_app.dirty = 1;
    if (!ok) {
        g_app.mode = MODE_EXPORT_BROWSE;
        note("couldn't write %.100s%s", shown, g_app.sandboxed & PLATFORM_SANDBOX_FILES
             ? " - the sandbox only lets chat write in the folders in your home that aren't hidden" : "");
        return;
    }
    g_app.mode = g_app.key.export_back;
    note("your signing key is in %.100s, which only you can open - :set sign %s:PATH loads it elsewhere", shown,
         g_app.identity_source == IDENT_AGE ? "age" : "pgp");
}

void export_key_no(void) {
    g_app.mode = MODE_EXPORT_BROWSE;
    g_app.dirty = 1;
}
