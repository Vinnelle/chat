// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/app.h"

// ---- the dialogs ----

#define MAX_DIALOG_PARAS 48

int add_para(tui_para_t *p, int n, tui_para_kind_t kind, const char *text) {
    p[n] = (tui_para_t){ .kind = kind, .text = text };
    return n + 1;
}

static int install_paras(tui_para_t *p) {
    static char settings[1200], key[1400], intro[600], verified[1200], outro[400], device[1200], factors[300];
    char where[APP_PATH_MAX] = "";
    const char *target = g_app.save_target;
    install_where(target, where, sizeof where);
    snprintf(settings, sizeof settings, "`%s/settings`: the settings you've changed - your nickname, colour, routing, "
             "relays and the like. Never the Tor control password.", where);
    int same = is_current_save(target), exists = save_exists(target), open = g_app.installed && same;
    snprintf(verified, sizeof verified, "`%s/verified`: the signing keys of peers whose verify code you compared "
             "(`:verify NICK ok`), with their nicks, so they don't need comparing again (%d now). `:verified` lists "
             "them.", where, trust_count());
    int saved = install_has_key(target);
    if (g_app.identity_source == IDENT_NONE && saved)
        snprintf(key, sizeof key, "`%s/key`: the signing key saved there stays as it is, though signing is off now.", where);
    else if (g_app.identity_source == IDENT_NONE)
        copy_str(key, "No signing key: signing is off. One you choose later (`:set sign`) is kept by `:install` again, "
                 "under the same passphrase.", sizeof key);
    else if (same && key_in_use_saved())
        snprintf(key, sizeof key, "`%s/key`: your signing key%s, saved already. It stays as it is.", where,
                 g_app.saved_key_path[0] ? "'s path" : "");
    else if (key_saved_as_path()) {
        char shown[KEY_PATH_MAX];
        tilde_path(g_app.key_path, shown, sizeof shown);
        snprintf(key, sizeof key, "`%s/key`: the path to your signing key, `%.600s`. The key itself isn't copied: "
                 "chat reads the file each time it starts.%s", where, shown, saved ? " It replaces what's saved there now." : "");
    } else
        snprintf(key, sizeof key, "`%s/key`: your signing key.%s", where, saved ? " It replaces the key saved there now." : "");
    int others = 0;
    for (int i = 0; i < g_app.n_saves; i++) others += !exists || strcmp(g_app.saves[i].name, target) != 0;
    if (open)
        snprintf(intro, sizeof intro, "`%s` is already installed, in `%s`, and open. Save what's in use now to it, in "
                 "place of what's saved there:", install_shown_name(target), where);
    else if (exists)
        snprintf(intro, sizeof intro, "chat is installed here%s%s%s: this saves what's in use now in place of what's "
                 "saved. **The files are a trail**: they tell anyone who can read this disk (an admin, malware, a "
                 "backup, forensics) that chat is used here.", target[0] ? " as `" : "", target, target[0] ? "`" : "");
    else if (others > 0 || g_app.installed)
        snprintf(intro, sizeof intro, "This makes a new save, `%s`, next to what `:install` saved already, with its "
                 "own passphrase. When there's more than one save, chat asks which one to open when it starts, or "
                 "`--save NAME` picks it. **The files are a trail**: they tell anyone who can read this disk (an admin, "
                 "malware, a backup, forensics) that chat is used here.", install_shown_name(target));
    else
        copy_str(intro, "Until you install, chat keeps nothing on disk. **Installing leaves a trail**: files that tell "
                 "anyone who can read this disk (an admin, malware, a backup, forensics) that chat is used here.",
                 sizeof intro);
    int n = add_para(p, 0, TUI_P_TEXT, intro);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_BULLET, settings);
    n = add_para(p, n, TUI_P_BULLET, key);
    n = add_para(p, n, TUI_P_BULLET, verified);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, open
        ? "It's all sealed (Argon2id, XChaCha20-Poly1305) with the passphrase it's sealed with now: there's "
          "nothing to type."
        : exists
        ? "It's all sealed (Argon2id, XChaCha20-Poly1305) with the passphrase of what's saved there now, asked for next."
        : "It's all sealed (Argon2id, XChaCha20-Poly1305) with one passphrase you choose next, which chat asks for "
          "when it starts.");
    n = add_para(p, n, TUI_P_BLANK, "");
    device[0] = '\0';
    if (!exists && g_app.device_lock && g_app.device_kind == DEVICE_NONE)
        copy_str(device, "**Device lock is on**, but this device can't lock anything now, so installing stops there and "
                 "says why.", sizeof device);
    else if (!exists && g_app.device_lock)
        copy_str(device, "**Locked to this device** as well: its files won't open anywhere else, even with the "
                 "passphrase. The next box says what would lose it for good.", sizeof device);
    else if (!exists && g_app.device_kind != DEVICE_NONE)
        copy_str(device, "Not locked to this device: a copy of the files opens anywhere with the passphrase. "
                 "`:set devicelock on` locks it to this device as well, once it's installed.", sizeof device);
    else if (!exists)
        snprintf(device, sizeof device, "Not locked to this device, which can't lock a save to it: %s.",
                 g_app.device_why);
    else if (open && install_device_lock() != DEVICE_NONE)
        copy_str(device, "It stays locked to this device.", sizeof device);
    if (device[0]) {
        n = add_para(p, n, TUI_P_TEXT, device);
        n = add_para(p, n, TUI_P_BLANK, "");
    }
    if (!exists && (g_app.key_factor || g_app.code_factor)) {
        snprintf(factors, sizeof factors, "%s%s%s",
                 g_app.key_factor ? "**It needs your security key** as well: a box registers it next, with two touches."
                                  : "",
                 g_app.key_factor && g_app.code_factor ? " " : "",
                 g_app.code_factor ? "**It asks for an authenticator code** as well: a box shows a QR code to scan." : "");
        n = add_para(p, n, TUI_P_TEXT, factors);
        n = add_para(p, n, TUI_P_BLANK, "");
    }
    snprintf(outro, sizeof outro, "%s Never saved: sessions, their passwords, messages or files. `:uninstall` deletes "
             "it all - but a disk and its backups can keep traces of deleted files.", g_app.autosave
             ? "Settings and verified keys you change from then on are saved as you change them (`:set autosave off` "
               "stops that)."
             : "Autosave is off: what you change from then on lasts until you `:save` again (`:set autosave on` saves "
               "it as you go).");
    return add_para(p, n, TUI_P_TEXT, outro);
}

static int install_first_paras(tui_para_t *p) {
    static char text[500];
    unsigned f = g_app.install_for;
    const char *what = f == INSTALL_FACTOR_DEVICE ? "The device lock"
                     : f == INSTALL_FACTOR_KEY ? "A security key" : "An authenticator app";
    const char *then = f == INSTALL_FACTOR_DEVICE ? "locks it to this device"
                     : f == INSTALL_FACTOR_KEY ? "registers your security key for it, with two touches"
                     : "shows a QR code that adds it to your authenticator app";
    if (g_app.n_saves > 0)
        snprintf(text, sizeof text, "**%s needs a save open first**, and none is. Install now? Yes goes through "
                 "`:install`, which opens a save here or makes a new one, and %s.", what, then);
    else
        snprintf(text, sizeof text, "**%s needs chat installed first.** Until `:install` saves your settings, sealed "
                 "with a passphrase, chat keeps nothing on disk. Install now? Yes goes through `:install`, which makes "
                 "a save and %s.", what, then);
    return add_para(p, 0, TUI_P_TEXT, text);
}

// What would lose the save comes straight after the intro, since a box too tall for the screen
// loses its end.
static int device_lock_paras(tui_para_t *p) {
    static char intro[600], lead[160], uses[900];
    static const char *losses[DEVICE_LOSSES_MAX + 2];
    const char *shown = install_shown_name(g_app.device_new ? g_app.save_target : install_current());
    if (!g_app.device_want) {
        snprintf(intro, sizeof intro, "This seals the save `%s` again with its passphrase alone: its files open wherever "
                 "they're copied, for anyone with the passphrase, as if it had never been locked. `:set devicelock on` "
                 "locks it again.", shown);
        return add_para(p, 0, TUI_P_TEXT, intro);
    }
    snprintf(intro, sizeof intro, "%s `%s` %s: it only opens here, with its passphrase. A copy of its files anywhere "
             "else, from a backup or from the disk itself, can't be opened, even with the passphrase.",
             g_app.device_new ? "The new save" : "This locks the save", shown,
             g_app.device_new ? "is locked to this device" : "to this device");
    int key = g_app.device_new ? g_app.identity_source != IDENT_NONE && !key_saved_as_path()
                               : install_has_key(install_current()) && !g_app.saved_key_path[0];
    snprintf(lead, sizeof lead, "**The save is gone for good%s, with no way back, if:**",
             key ? ", and the signing key only saved in it" : "");
    int n_losses = platform_device_losses(g_app.device_kind, losses, DEVICE_LOSSES_MAX);
    losses[n_losses++] = "its `device` file is deleted: a backup it's restored from needs that file too";
    losses[n_losses++] = "this computer breaks or is lost";
    snprintf(uses, sizeof uses, "It uses %s.", platform_device_uses(g_app.device_kind));
    int n = add_para(p, 0, TUI_P_TEXT, intro);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, lead);
    for (int i = 0; i < n_losses; i++) n = add_para(p, n, TUI_P_BULLET, losses[i]);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, "Before one of those you can see coming, like a firmware update or a reinstall, "
                                   "`:set devicelock off` here first, then lock it again after.");
    n = add_para(p, n, TUI_P_BLANK, "");
    return add_para(p, n, TUI_P_TEXT, uses);
}

// The save a factor box is for: the new one :install is making, or the open one.
static const char *factor_save(void) {
    return install_shown_name(g_app.factor_new ? g_app.save_target : install_current());
}

static int factor_paras(tui_para_t *p) {
    static char intro[800], lead[160];
    const char *shown = factor_save();
    if (g_app.factor == INSTALL_FACTOR_CODE) {
        snprintf(intro, sizeof intro, "This stops the save `%s` asking for the code your authenticator app shows. Its "
                 "`authenticator` file is deleted, and with it the secret the codes come from: delete the save's entry "
                 "from the app too. `:set authenticator on` sets up a new one.", shown);
        return add_para(p, 0, TUI_P_TEXT, intro);
    }
    if (!g_app.factor_want) {
        snprintf(intro, sizeof intro, "This seals the save `%s` again without the security key, as if it had never needed "
                 "one: a copy of its files opens with what else it needs. Its `securitykey` file is deleted. The security "
                 "key keeps nothing for it, so there's nothing to delete from the key.", shown);
        return add_para(p, 0, TUI_P_TEXT, intro);
    }
    snprintf(intro, sizeof intro, "%s `%s` %s your security key as well as its passphrase: a FIDO2 key with hmac-secret, "
             "which most have (YubiKey 5, Nitrokey 3, SoloKey 2, Google Titan...). Each time it opens, chat asks you to "
             "touch the key, which gives back a secret that goes into the key the files are sealed with. Without the "
             "security key, the passphrase opens nothing, wherever the files are copied.",
             g_app.factor_new ? "The new save" : "This makes the save", shown, g_app.factor_new ? "needs" : "need");
    int key = g_app.factor_new ? g_app.identity_source != IDENT_NONE && !key_saved_as_path()
                               : install_has_key(install_current()) && !g_app.saved_key_path[0];
    snprintf(lead, sizeof lead, "**The save is gone for good%s, with no way back, if:**",
             key ? ", and the signing key only saved in it" : "");
    int n = add_para(p, 0, TUI_P_TEXT, intro);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, lead);
    n = add_para(p, n, TUI_P_BULLET, "the security key is lost or broken");
    n = add_para(p, n, TUI_P_BULLET, "it's reset: a FIDO reset (from its maker's app, or `ykman fido reset`) wipes what "
                                     "it needs to give the secret back");
    n = add_para(p, n, TUI_P_BULLET, "its `securitykey` file is deleted: a backup it's restored from needs that file too");
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, "Before you reset it or stop using it, `:set securitykey off` first.");
    n = add_para(p, n, TUI_P_BLANK, "");
#ifdef _WIN32
    return add_para(p, n, TUI_P_TEXT, "Windows asks for the security key in a window of its own, twice: once to register "
                                      "it and once to read its secret.");
#else
    return add_para(p, n, TUI_P_TEXT, "Registering it takes two touches, one after the other: plug it in now. chat asks "
                                      "for its PIN only if the key wants it.");
#endif
}

// The authenticator secret's QR code: a row for two modules, with the 4 modules of light margin a
// scanner needs. Drawn in the terminal's own foreground, which is the light modules on a dark theme
// and the dark ones on a light theme, so it comes out dark on light either way.
#define QR_ROWS_MAX ((QR_MAX_SIZE + 9) / 2)

#define QR_ROW_BYTES ((QR_MAX_SIZE + 8) * 3 + 1)

_Static_assert(QR_ROWS_MAX + 8 <= MAX_DIALOG_PARAS, "the authenticator's box holds its QR code and its text");

static int qr_ink(const uint8_t *m, int size, int x, int y, int light) {
    int dark = x >= 0 && y >= 0 && x < size && y < size && m[y * size + x];
    return light ? dark : !dark;
}

// Returns how many rows, each as wide as the first is long in columns, or 0.
static int qr_rows(const char *text, char rows[QR_ROWS_MAX][QR_ROW_BYTES], int *cols) {
    static uint8_t m[QR_MAX_SIZE * QR_MAX_SIZE];
    int size = qr_encode(text, m);
    if (size < 0) return 0;
    int full = size + 8, light = tui_background_light(), n = 0;
    for (int y = 0; y < full; y += 2) {
        char *o = rows[n++];
        for (int x = 0; x < full; x++) {
            int top = qr_ink(m, size, x - 4, y - 4, light);
            int bottom = y + 1 < full && qr_ink(m, size, x - 4, y - 3, light);
            const char *g = top && bottom ? "\xe2\x96\x88" : top ? "\xe2\x96\x80" : bottom ? "\xe2\x96\x84" : " ";
            size_t gl = strlen(g);
            memcpy(o, g, gl);
            o += gl;
        }
        *o = '\0';
    }
    *cols = full;
    return n;
}

static int code_setup_text(tui_para_t *p, int n, int qr) {
    static char scan[400];
    snprintf(scan, sizeof scan, "%s your authenticator app (Aegis, Google Authenticator, 2FAS...)%s, then type the 6-digit "
             "code it shows for `chat:%s`, to be sure it has it.", qr ? "Scan this with" : "Type the secret below into",
             qr ? ", or type in the secret below" : "", factor_save());
    n = add_para(p, n, TUI_P_TEXT, scan);
    n = add_para(p, n, TUI_P_BLANK, "");
    n = add_para(p, n, TUI_P_TEXT, "**A check chat makes, not a lock on the files:** the secret the codes come from is "
                                   "kept in the save, sealed with it, so whoever can open its files (with the passphrase, "
                                   "and the device or security key if they're on) can make the codes too. It stops "
                                   "someone who knows your passphrase opening the save in chat without your phone. The "
                                   "security key or the device lock protect the files themselves.");
    n = add_para(p, n, TUI_P_BLANK, "");
    return add_para(p, n, TUI_P_TEXT, "Lose the app's entry and chat won't open the save, so keep a copy of the secret "
                                      "somewhere safe, or `:set authenticator off` first.");
}

// The QR code goes over the text only when neither is cut off: a cut QR code can't be scanned, and
// the text's warning is at its end. Otherwise Tab swaps the text for the QR code alone, if that fits.
static void code_setup_dialog(tui_dialog_t *d, tui_para_t *p) {
    static char rows[QR_ROWS_MAX][QR_ROW_BYTES], secret[200], keys[80];
    const char *enter = g_app.factor_new ? "enter next" : "enter turn on";
    int term_rows, term_cols, qr_cols = 0, alone = 0;
    term_get_size(&term_rows, &term_cols);
    int nq = qr_rows(g_app.code_uri, rows, &qr_cols);
    char grouped[48];
    size_t g = 0;
    enum { CODE_GROUP = 4 };
    for (size_t i = 0; g_app.code_b32[i] && g + 2 < sizeof grouped; i++) {
        if (i && i % CODE_GROUP == 0) grouped[g++] = ' ';
        grouped[g++] = g_app.code_b32[i];
    }
    grouped[g] = '\0';
    snprintf(secret, sizeof secret, "Secret: %s", grouped);
    crypto_wipe(grouped, sizeof grouped);

    if (nq > 0 && term_cols >= qr_cols + 12) {
        for (int i = 0; i < nq; i++) add_para(p, i, TUI_P_ART, rows[i]);
        d->n_text = code_setup_text(p, add_para(p, nq, TUI_P_BLANK, ""), 1);
        d->note = secret;
        snprintf(keys, sizeof keys, "%s" DOT_SEP "esc cancel", enter);
        d->keys = keys;
        if (tui_dialog_rows(term_cols, d) <= term_rows) return;
        d->n_text = nq;
        d->note = NULL;
        alone = tui_dialog_rows(term_cols, d) <= term_rows;
        if (alone && g_app.code_qr) {
            snprintf(keys, sizeof keys, "%s" DOT_SEP "tab text" DOT_SEP "esc cancel", enter);
            return;
        }
    }
    d->n_text = code_setup_text(p, 0, 0);
    size_t sl = strlen(secret);
    if (nq > 0 && !alone) snprintf(secret + sl, sizeof secret - sl, DOT_SEP "a bigger window shows a QR code");
    d->note = secret;
    snprintf(keys, sizeof keys, "%s%s" DOT_SEP "esc cancel", enter, alone ? DOT_SEP "tab QR code" : "");
    d->keys = keys;
}

static int key_wait_paras(tui_para_t *p) {
    static char text[300];
    int making = g_app.key_purpose == KP_FACTOR || g_app.key_purpose == KP_NEW_SAVE;
#ifdef _WIN32
    (void)making;
    copy_str(text, "Windows asks for the security key in a window of its own: follow it there.", sizeof text);
#else
    const char *shown = install_shown_name(g_app.key_purpose == KP_INSTALL_UNLOCK ? g_app.save_target : install_current());
    if (g_app.key_stage == SECKEY_LOOKING && making)
        copy_str(text, "Plug in your security key.", sizeof text);
    else if (g_app.key_stage == SECKEY_LOOKING)
        snprintf(text, sizeof text, "Plug in the security key the save `%s` was locked with.", shown);
    else if (g_app.key_stage == SECKEY_TOUCH && making)
        snprintf(text, sizeof text, "**Touch your security key now** (%d of 2): it's blinking.", g_app.key_touches + 1);
    else if (g_app.key_stage == SECKEY_TOUCH)
        snprintf(text, sizeof text, "**Touch your security key now**, to open `%s`: it's blinking.", shown);
    else
        copy_str(text, "Asking the security key...", sizeof text);
#endif
    return add_para(p, 0, TUI_P_TEXT, text);
}

static int uninstall_paras(tui_para_t *p) {
    static char what[1200];
    char where[APP_PATH_MAX] = "";
    const char *target = g_app.save_target;
    install_where(target, where, sizeof where);
    int settings = install_has_settings(target), key = install_has_key(target), same = is_current_save(target);
    snprintf(what, sizeof what, "This deletes what `:install` saved in `%s`: your %s, and the signing keys of peers "
             "you verified.%s%s", where,
             settings && key ? "sealed settings and signing key" : settings ? "sealed settings" : "sealed signing key",
             install_factors(target) & INSTALL_FACTOR_DEVICE ? " It's locked to this device, and the secret the device "
                                                               "sealed for it goes too." : "",
             same ? " What's in use now lasts until chat exits." : "");
    int n = add_para(p, 0, TUI_P_TEXT, what);
    if (key && same && g_app.saved_key_known && g_app.saved_key_path[0]) {
        n = add_para(p, n, TUI_P_BLANK, "");
        n = add_para(p, n, TUI_P_TEXT, "The saved key is only the path to your key file. The file itself isn't touched.");
    } else if (key) {
        n = add_para(p, n, TUI_P_BLANK, "");
        n = add_para(p, n, TUI_P_TEXT, "**A key saved only there is gone for good**, and with it the fingerprint peers "
                                       "know you by.");
    }
    n = add_para(p, n, TUI_P_BLANK, "");
    return add_para(p, n, TUI_P_TEXT, "Deleting isn't erasing: the disk, its snapshots and its backups can keep "
                                      "traces of the files.");
}

static const tui_dialog_t *quit_dialog(void) {
    static tui_dialog_t d;
    static tui_para_t paras[MAX_DIALOG_PARAS];
    static char what[240], files[120], unsaved[200];
    int n_sessions = 0, online = 0, downloads = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i]) continue;
        n_sessions++;
        if (g_app.sessions[i].initialising) continue;
        const chat_t *e = &g_app.sessions[i].engine;
        online += chat_online_count(e);
        for (int f = 0; f < FILE_OFFERS_MAX; f++)
            downloads += e->files[f].used && (e->files[f].dl == DL_ACTIVE || e->files[f].dl == DL_QUEUED);
    }
    const char *tor = g_tor.proc ? " Chat's own tor stops too." : "";
    if (n_sessions == 0)
        snprintf(what, sizeof what, "No sessions are open.%s", tor);
    else
        snprintf(what, sizeof what, "Quitting leaves %d session%s, with %d peer%s online: each says bye, then closes, "
                 "and its keys are wiped from memory.%s", n_sessions, n_sessions == 1 ? "" : "s",
                 online, online == 1 ? "" : "s", tor);
    int n = add_para(paras, 0, TUI_P_TEXT, what);

    const char *lost[3];
    int n_lost = 0;
    if (downloads == 1) lost[n_lost++] = "A file that's still downloading stops, and what's come of it is deleted.";
    else if (downloads) {
        snprintf(files, sizeof files, "%d files that are still downloading stop, and what's come of them is deleted.", downloads);
        lost[n_lost++] = files;
    }
    int rows = 0;
    if (g_app.installed && !g_app.autosave)
        for (int i = 0; i < N_SETTINGS; i++) rows += g_unsaved_rows[i] != 0;
    int key = g_app.installed && g_app.identity_source != IDENT_NONE && !key_in_use_saved();
    if (rows || key) {
        char settings[64];
        snprintf(settings, sizeof settings, "%d changed setting%s", rows, rows == 1 ? "" : "s");
        snprintf(unsaved, sizeof unsaved, "%s%s%s %s saved: n, then `:save`, keeps %s.",
                 rows ? settings : "", rows && key ? " and " : "", key ? (rows ? "the signing key in use" : "The signing key in use") : "",
                 rows + key > 1 ? "aren't" : "isn't", rows + key > 1 ? "them" : "it");
        lost[n_lost++] = unsaved;
    }
    update_view_t v;
    update_view(&v);
    if (v.running) lost[n_lost++] = "An update is still running, and won't be installed.";
    if (n_lost) n = add_para(paras, n, TUI_P_BLANK, "");
    for (int i = 0; i < n_lost; i++) n = add_para(paras, n, TUI_P_BULLET, lost[i]);

    d = (tui_dialog_t){ .title = "QUIT", .text = paras, .n_text = n, .keys = "y quit" DOT_SEP "n stay" };
    return &d;
}

// Its field is the input line, saved meanwhile by begin_prompt and similar.
static const tui_dialog_t *current_dialog(void) {
    static tui_dialog_t d;
    static tui_para_t paras[MAX_DIALOG_PARAS];
    static char title[64], note_text[MAX_SESSION_NAME + 64];
    d = (tui_dialog_t){ .input = &g_app.input, .mask = 1, .text = paras };
    switch (g_app.mode) {
        case MODE_NEW_PASSWORD:
            d.title = "NEW SESSION";
            d.placeholder = "password";
            d.note = "Blank is fine: it still encrypts. Whoever you invite needs the password and the session's id.";
            d.keys = "enter create" DOT_SEP "esc cancel";
            break;
        case MODE_JOIN_ID:
            d.title = "JOIN SESSION";
            d.mask = 0;
            d.placeholder = "session id";
            d.note = "The id you were given. Its password comes next.";
            d.keys = "enter next" DOT_SEP "esc cancel";
            break;
        case MODE_JOIN_PASSWORD:
            d.title = "JOIN SESSION";
            d.placeholder = "password";
            snprintf(note_text, sizeof note_text, "The password for %s, as you were given it.", g_app.pending_session_id);
            d.note = note_text;
            d.keys = "enter join" DOT_SEP "esc cancel";
            break;
        case MODE_SIGN_PASSWORD:
            d.title = g_app.load_kind == IDENT_AGE ? "NATIVE AGE KEY" : "NATIVE PGP KEY";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, SIGN_PASSWORD_HELP);
            d.placeholder = "password (blank: a new key until chat exits)";
            d.keys = "enter make the key" DOT_SEP "esc back";
            break;
        case MODE_SIGN_PATH: {
            int age = g_app.load_kind == IDENT_AGE;
            d.title = age ? "AGE KEY FILE" : "PGP KEY FILE";
            int n = add_para(paras, 0, TUI_P_TEXT, age ? AGE_PATH_HELP : PGP_PATH_HELP);
            n = add_para(paras, n, TUI_P_BLANK, "");
            n = add_para(paras, n, TUI_P_TEXT, KEY_WHY);
            n = add_para(paras, n, TUI_P_BLANK, "");
            d.n_text = add_para(paras, n, TUI_P_TEXT, KEY_FILE_SAVED);
            d.mask = 0;
            d.placeholder = age ? "~/.config/age/key.txt" : "~/key.asc";
            d.keys = "enter use this key" DOT_SEP "esc back";
            break;
        }
        case MODE_SIGN_PASTE: {
            int n = add_para(paras, 0, TUI_P_TEXT, g_app.load_kind == IDENT_AGE ? AGE_PASTE_HELP : PGP_PASTE_HELP);
            n = add_para(paras, n, TUI_P_BLANK, "");
            n = add_para(paras, n, TUI_P_TEXT, KEY_WHY);
            n = add_para(paras, n, TUI_P_BLANK, "");
            d.n_text = add_para(paras, n, TUI_P_TEXT, KEY_PASTE_SAVED);
            d.title = g_app.load_kind == IDENT_AGE ? "PASTE AN AGE KEY" : "PASTE A PGP KEY";
            d.input = NULL;
            d.status = g_app.paste_status;
            d.keys = "esc back";
            break;
        }
        case MODE_SETTINGS_EDIT: {
            const setting_def_t *sd = setting_def(g_edit_id);
            size_t i = 0;
            for (; sd->label[i] && i < sizeof title - 1; i++) title[i] = (char)toupper((unsigned char)sd->label[i]);
            title[i] = '\0';
            d.title = title;
            d.mask = sd->kind == K_SECRET;
            d.placeholder = sd->values;
            d.note = sd->help;
            d.keys = "enter save" DOT_SEP "esc cancel";
            break;
        }
        case MODE_INSTALL:
            d.title = install_resaves() ? "SAVE" : "INSTALL";
            d.n_text = install_paras(paras);
            d.input = NULL;
            d.keys = install_resaves() ? "y save" DOT_SEP "n cancel" : "y install" DOT_SEP "n cancel";
            break;
        case MODE_INSTALL_FIRST:
            d.title = g_app.install_for == INSTALL_FACTOR_DEVICE ? "DEVICE LOCK"
                    : g_app.install_for == INSTALL_FACTOR_KEY ? "SECURITY KEY" : "AUTHENTICATOR APP";
            d.n_text = install_first_paras(paras);
            d.input = NULL;
            d.keys = "y install" DOT_SEP "n cancel";
            break;
        case MODE_INSTALL_PASS:
        case MODE_INSTALL_PASS2: {
            int first = g_app.mode == MODE_INSTALL_PASS;
            d.title = "INSTALL" DOT_SEP "PASSPHRASE";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, !first ? "Type it again, to be sure of it."
                : g_app.identity_source != IDENT_NONE && g_app.device_lock
                ? "Your settings and signing key are sealed with this passphrase, which chat asks for when it starts. "
                  "Make it long: anyone who gets onto this device can try passphrases against them. Forget it, and "
                  "they're lost."
                : g_app.device_lock
                ? "Your settings are sealed with this passphrase, which chat asks for when it starts, and so is a "
                  "signing key you `:install` later. Make it long: anyone who gets onto this device can try passphrases "
                  "against them. Forget it, and they're lost."
                : g_app.identity_source != IDENT_NONE
                ? "Your settings and signing key are sealed with this passphrase, which chat asks for when it starts. "
                  "Make it long: anyone who gets the files can try passphrases against them. Forget it, and they're lost."
                : "Your settings are sealed with this passphrase, which chat asks for when it starts, and so is a "
                  "signing key you `:install` later. Make it long: anyone who gets the files can try passphrases "
                  "against them. Forget it, and they're lost.");
            d.placeholder = first ? "passphrase" : "the same passphrase";
            d.keys = first ? "enter next" DOT_SEP "esc cancel" : "enter install" DOT_SEP "esc cancel";
            break;
        }
        case MODE_INSTALL_EXISTING:
        case MODE_INSTALL_PICK:
        case MODE_INSTALL_OVERWRITE:
        case MODE_INSTALL_UNLOCK:
        case MODE_INSTALL_NAME: {
            static char text[900];
            static const char *names[INSTALL_SAVES_MAX], *details[INSTALL_SAVES_MAX];
            static char detail_text[INSTALL_SAVES_MAX][112];
            char where[APP_PATH_MAX] = "";
            const char *shown = install_shown_name(g_app.save_target);
            install_where(g_app.save_target, where, sizeof where);
            d.title = "INSTALL";
            if (g_app.mode == MODE_INSTALL_EXISTING) {
                if (g_app.install_pick)
                    snprintf(text, sizeof text, "There are %d saves here already, each sealed with its own passphrase, "
                             "and none is open in this run. Use one of them? Yes lists them to pick one, then asks for "
                             "its passphrase, and what's saved there is used from then on. No makes a new save, with a "
                             "name and a passphrase of its own.", g_app.n_saves);
                else
                    snprintf(text, sizeof text, "There's a save here already: `%s`, in `%s`, sealed with its own "
                             "passphrase and not open in this run. Use it? Yes asks for its passphrase, and what's "
                             "saved there is used from then on. No makes a new save, with a name and a passphrase of "
                             "its own.", shown, where);
                d.input = NULL;
                d.keys = "y use it" DOT_SEP "n new save" DOT_SEP "esc cancel";
            } else if (g_app.mode == MODE_INSTALL_PICK) {
                for (int i = 0; i < g_app.n_saves; i++) {
                    names[i] = install_shown_name(g_app.saves[i].name);
                    save_detail(&g_app.saves[i], detail_text[i], sizeof detail_text[i]);
                    details[i] = detail_text[i];
                }
                copy_str(text, "Pick the save to use. Its passphrase is asked for next.", sizeof text);
                d.input = NULL;
                d.items = names;
                d.details = details;
                d.n_items = g_app.n_saves;
                d.sel = g_app.save_sel;
                d.keys = "enter choose" DOT_SEP "j/k move" DOT_SEP "esc back";
            } else if (g_app.mode == MODE_INSTALL_OVERWRITE) {
                snprintf(text, sizeof text, "`%s` is another save, in `%s`, sealed with its own passphrase. Save what's "
                         "in use now over it? That's your settings, %s and the keys you verified, which are added to "
                         "the ones saved there. Its passphrase is asked for next, and from then on `%s` is the save in "
                         "use. To use what's saved there as it is, start chat with `--save %s`. `:install NEWNAME` "
                         "makes a new save instead.", shown, where,
                         g_app.identity_source == IDENT_NONE ? "not your signing key (signing is off),"
                         : !install_has_key(g_app.save_target)
                         ? (key_saved_as_path() ? "the path to your signing key's file," : "your signing key,")
                         : key_saved_as_path() ? "the path to your signing key's file in place of the key saved there,"
                         : "your signing key in place of the one saved there,", shown, shown);
                d.input = NULL;
                d.keys = "y overwrite" DOT_SEP "n cancel";
            } else if (g_app.mode == MODE_INSTALL_UNLOCK) {
                snprintf(text, sizeof text, "Its passphrase opens `%s`, %s Forgot it? Esc goes back%s, and "
                         "`:uninstall %s` deletes it.", shown, g_app.install_overwrite
                         ? "and what's in use now is saved over it under the same one."
                         : "and what's saved there is used from now on.",
                         g_app.install_overwrite ? "" : g_app.install_pick ? " to the list"
                         : ", where n makes a new save instead", shown);
                d.title = "INSTALL" DOT_SEP "PASSPHRASE";
                d.placeholder = "passphrase";
                d.keys = g_app.install_overwrite ? "enter install" DOT_SEP "esc back" : "enter open" DOT_SEP "esc back";
            } else {
                snprintf(text, sizeof text, "A name for the new save: 1 to %d letters, digits, - and _, or blank for "
                         "`%s`, picked at random. It goes in `saves/NAME` in chat's folder (`default` is the folder "
                         "itself), and anyone who can read the disk can see the folder's name. What it leaves on disk "
                         "is shown next.", INSTALL_NAME_MAX, g_app.save_random);
                d.title = "INSTALL" DOT_SEP "NEW SAVE";
                d.mask = 0;
                d.placeholder = g_app.save_random;
                d.keys = g_app.n_saves > 0 ? "enter next" DOT_SEP "esc back" : "enter next" DOT_SEP "esc cancel";
            }
            d.n_text = add_para(paras, 0, TUI_P_TEXT, text);
            break;
        }
        case MODE_UNINSTALL:
            d.title = "UNINSTALL";
            d.n_text = uninstall_paras(paras);
            d.input = NULL;
            d.keys = "y delete" DOT_SEP "n cancel";
            break;
        case MODE_DEVICE_LOCK:
            d.title = "DEVICE LOCK";
            d.n_text = device_lock_paras(paras);
            d.input = NULL;
            d.keys = g_app.device_new ? "y lock it" DOT_SEP "n cancel"
                   : g_app.device_want ? "y lock" DOT_SEP "n cancel" : "y unlock" DOT_SEP "n cancel";
            break;
        case MODE_FILE_ASK:
            d.n_text = file_ask_paras(paras, &d.title, &d.keys);
            d.input = NULL;
            break;
        case MODE_UPDATE: {
            static update_view_t v;
            static const char *lines[UPDATE_LOG_MAX];
            static tui_progress_t pg;
            update_view(&v);
            for (int i = 0; i < v.n_log; i++) lines[i] = v.log[i];
            pg.permille = v.permille;
            copy_str(pg.text, v.amount, sizeof pg.text);
            d.title = "UPDATE";
            d.console = 1;
            d.log = lines;
            d.log_kind = v.kind;
            d.n_log = v.n_log;
            d.progress = &pg;
            d.step = v.step;
            d.step_kind = v.running ? TUI_LOG_INFO : v.ok ? TUI_LOG_GOOD : TUI_LOG_BAD;
            d.input = NULL;
            d.keys = v.running ? "esc hide" : "enter close";
            break;
        }
        case MODE_SAVES: {
            static const char *names[INSTALL_SAVES_MAX], *details[INSTALL_SAVES_MAX];
            static char detail_text[INSTALL_SAVES_MAX][112];
            for (int i = 0; i < g_app.n_saves; i++) {
                names[i] = install_shown_name(g_app.saves[i].name);
                save_detail(&g_app.saves[i], detail_text[i], sizeof detail_text[i]);
                details[i] = detail_text[i];
            }
            d.title = "UNLOCK";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, "`:install` made more than one save here, each sealed with its "
                                "own passphrase. Pick the one to open; Esc starts without any, from chat's defaults, "
                                "and saves nothing until `:install` opens a save or makes a new one.");
            d.input = NULL;
            d.items = names;
            d.details = details;
            d.n_items = g_app.n_saves;
            d.sel = g_app.save_sel;
            d.keys = "enter open" DOT_SEP "j/k move" DOT_SEP "esc skip";
            break;
        }
        case MODE_UNLOCK: {
            static char text[500];
            const char *name = install_current();
            int key = install_has_key(name);
            unsigned f = install_factors(name);
            const char *here = f & INSTALL_FACTOR_DEVICE ? " and locked to this device" : "";
            char more[120] = "", then[96];
            factors_text(f & (INSTALL_FACTOR_KEY | INSTALL_FACTOR_CODE), then, sizeof then);
            if (then[0]) snprintf(more, sizeof more, ", then %s", then);
            if (g_app.n_saves > 1 || name[0])
                snprintf(text, sizeof text, "`:install` saved your settings%s here as `%s`, sealed%s. Its passphrase "
                         "opens it%s; Esc %s.", key ? " and signing key" : "", install_shown_name(name), here, more,
                         save_to_pick() ? "goes back to the list"
                                        : "starts without it, from chat's defaults, and saves nothing until `:install` opens a "
                                          "save or makes a new one");
            else
                snprintf(text, sizeof text, "`:install` saved your settings%s here, sealed%s. Their passphrase opens "
                         "them%s; Esc starts without them, from chat's defaults, and saves nothing until `:install` opens a "
                         "save or makes a new one.",
                         key ? " and signing key" : "", here, more);
            d.n_text = add_para(paras, 0, TUI_P_TEXT, text);
            d.title = "UNLOCK";
            d.placeholder = "passphrase";
            d.keys = save_to_pick() ? "enter open" DOT_SEP "esc back" : "enter open" DOT_SEP "esc skip";
            break;
        }
        case MODE_FACTOR:
            d.title = g_app.factor == INSTALL_FACTOR_KEY ? "SECURITY KEY" : "AUTHENTICATOR APP";
            d.n_text = factor_paras(paras);
            d.input = NULL;
            d.keys = g_app.factor_want ? "y register" DOT_SEP "n cancel" : "y turn off" DOT_SEP "n cancel";
            break;
        case MODE_CODE_SETUP:
            d.title = "AUTHENTICATOR APP";
            d.mask = 0;
            d.placeholder = "6-digit code";
            code_setup_dialog(&d, paras);
            break;
        case MODE_KEY_WAIT:
            d.title = "SECURITY KEY";
            d.n_text = key_wait_paras(paras);
            d.input = NULL;
            d.keys = "esc cancel";
            break;
        case MODE_KEY_PIN:
            d.title = "SECURITY KEY" DOT_SEP "PIN";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, "Your security key wants its PIN for this. chat sends it to the key "
                                "encrypted, and doesn't keep it.");
            d.note = install_key_why();
            d.placeholder = "PIN";
            d.keys = "enter send" DOT_SEP "esc cancel";
            break;
        case MODE_UNLOCK_CODE: {
            static char text[300];
            const char *shown = install_shown_name(g_app.key_purpose == KP_INSTALL_UNLOCK ? g_app.save_target : install_current());
            snprintf(text, sizeof text, "The save `%s` also asks for the 6-digit code your authenticator app shows for "
                     "`chat:%s`.", shown, shown);
            d.n_text = add_para(paras, 0, TUI_P_TEXT, text);
            d.title = g_app.key_purpose == KP_INSTALL_UNLOCK ? "INSTALL" DOT_SEP "CODE" : "UNLOCK" DOT_SEP "CODE";
            d.mask = 0;
            d.placeholder = "6-digit code";
            d.keys = "enter open" DOT_SEP "esc back";
            break;
        }
        case MODE_SHADOW_PASS:
        case MODE_SHADOW_PASS2: {
            int first = g_app.mode == MODE_SHADOW_PASS;
            d.title = "SHADOW PASSWORD";
            d.n_text = add_para(paras, 0, TUI_P_TEXT, first
                ? "A second passphrase for this save. Opening the save with it puts a decoy in the real save's place "
                  "and deletes the real save's files - a clean, empty account that needs the same security key, "
                  "device and code. Make it different from the real one, and don't forget which is which."
                : "Type the shadow passphrase again, to be sure of it.");
            d.placeholder = first ? "shadow passphrase" : "the same passphrase";
            d.keys = first ? "enter next" DOT_SEP "esc cancel" : "enter set" DOT_SEP "esc cancel";
            break;
        }
        default:
            return NULL;
    }
    return &d;
}

// The bottom row for the current screen: the chip names it, and the hint says what the keys do there.
static tui_bar_t current_bar(void) {
    tui_bar_t b = {
        .chip = "SETTINGS",
        .tone = TUI_TONE_PAGE,
        .message = g_app.message,
        .badge = (tui_identity_badge_t)g_app.identity_source,
        .nick = g_app.nick,
        .nick_color = g_app.color,
    };
    switch (g_app.mode) {
        case MODE_CHANGELOG:
            b.chip = "CHANGELOG";
            b.hint = "j/k scroll" DOT_SEP "space/b page" DOT_SEP "g/G top/bottom" DOT_SEP "q close";
            break;
        case MODE_HELP:
            b.chip = "HELP";
            b.hint = "enter use" DOT_SEP "j/k move" DOT_SEP "tab section" DOT_SEP "esc close";
            break;
        case MODE_SETTINGS:        b.hint = settings_hint(); break;
        case MODE_SIGN_CHOICE:     b.hint = "enter choose" DOT_SEP "j/k move" DOT_SEP "esc back" DOT_SEP "q close"; break;
        case MODE_SIGN_BROWSE:
            b.hint = "enter open" DOT_SEP "h up" DOT_SEP "/ type a path" DOT_SEP "~ home" DOT_SEP "esc back" DOT_SEP "q close";
            break;
        case MODE_SEND_BROWSE:
            b.chip = "SEND";
            b.hint = "enter send" DOT_SEP "h up" DOT_SEP "~ home" DOT_SEP "j/k move" DOT_SEP "esc close";
            break;
        case MODE_SAVE_BROWSE:
            b.chip = "SAVE";
            b.hint = "s save here" DOT_SEP "enter open" DOT_SEP "h up" DOT_SEP "~ home" DOT_SEP "j/k move" DOT_SEP "esc close";
            break;
        case MODE_FILES:
            b.chip = "FILES";
            b.hint = files_hint();
            break;
        case MODE_FILE_VIEW:
            b.chip = "PICTURE";
            b.hint = viewer_hint();
            break;
        case MODE_FILE_ASK:
            b.chip = g_app.file_back == MODE_FILE_VIEW ? "PICTURE" : "FILES";
            b.tone = TUI_TONE_PROMPT;
            break;
        case MODE_DEVICE_LOCK:
            if (g_app.device_back == MODE_CHAT) chat_input(&b, &g_app.saved_input);
            b.chip = g_app.device_new ? "INSTALL" : "SETTINGS";
            b.tone = TUI_TONE_PROMPT;
            break;
        case MODE_FACTOR:
        case MODE_CODE_SETUP:
        case MODE_KEY_WAIT:
        case MODE_KEY_PIN:
        case MODE_UNLOCK_CODE: {
            int unlocking = g_app.mode == MODE_UNLOCK_CODE || g_app.mode == MODE_KEY_WAIT || g_app.mode == MODE_KEY_PIN;
            key_purpose_t why = unlocking ? g_app.key_purpose : g_app.factor_new ? KP_NEW_SAVE : KP_FACTOR;
            if (on_chat_screen()) chat_input(&b, &g_app.saved_input);
            b.chip = why == KP_UNLOCK ? "UNLOCK" : why == KP_FACTOR ? "SETTINGS" : "INSTALL";
            b.tone = TUI_TONE_PROMPT;
            break;
        }
        case MODE_SHADOW_PASS:
        case MODE_SHADOW_PASS2:
            if (g_app.factor_back == MODE_CHAT) chat_input(&b, &g_app.saved_input);
            b.chip = g_app.factor_back == MODE_CHAT ? "CHAT" : "SETTINGS";
            b.tone = TUI_TONE_PROMPT;
            break;
        case MODE_CHAT:
            chat_input(&b, &g_app.input);
            break;
        case MODE_SAVES:
        case MODE_UNLOCK:
        case MODE_NEW_PASSWORD:
        case MODE_JOIN_ID:
        case MODE_JOIN_PASSWORD:
        case MODE_INSTALL:
        case MODE_INSTALL_PASS:
        case MODE_INSTALL_PASS2:
        case MODE_INSTALL_UNLOCK:
        case MODE_INSTALL_EXISTING:
        case MODE_INSTALL_PICK:
        case MODE_INSTALL_OVERWRITE:
        case MODE_INSTALL_NAME:
        case MODE_INSTALL_FIRST:
        case MODE_UNINSTALL:
        case MODE_UPDATE:
            if (on_chat_screen()) chat_input(&b, &g_app.saved_input);
            b.chip = g_app.mode == MODE_NEW_PASSWORD ? "NEW"
                   : g_app.mode == MODE_JOIN_ID || g_app.mode == MODE_JOIN_PASSWORD ? "JOIN"
                   : g_app.mode == MODE_UNLOCK || g_app.mode == MODE_SAVES ? "UNLOCK"
                   : g_app.mode == MODE_UNINSTALL ? "UNINSTALL"
                   : g_app.mode == MODE_UPDATE ? "UPDATE"
                   : g_app.mode == MODE_INSTALL && install_resaves() ? "SAVE" : "INSTALL";
            b.tone = TUI_TONE_PROMPT;
            break;
        default:
            break;
    }
    b.dialog = current_dialog();
    if (g_app.asking_quit) {
        b.dialog = quit_dialog();
        b.chip = "QUIT";
        b.tone = TUI_TONE_PROMPT;
    }
    if (b.dialog) b.hint = b.dialog->keys;
    return b;
}

void render_bar(void) {
    if (!on_chat_screen()) { render(); return; }
    int rows_n, cols_n; term_get_size(&rows_n, &cols_n);
    char sub[64]; tui_view_t view = current_view(sub, sizeof sub);
    tui_bar_t bar = current_bar();
    // The text wrapped onto one row more or fewer, so the chat above it moves too.
    if (tui_render_bar(rows_n, cols_n, &view, &bar, g_app.color_enabled) != 0) render();
}

// How the selected session reaches its peers, for the sidebar: the route, its port or tor, the
// relays and port mapping, the DHT, and the traffic so far.
#define MAX_NET 10
#define NET_VALUE_MAX 32

static int build_net(tui_kv_t kv[MAX_NET], char vals[MAX_NET][NET_VALUE_MAX]) {
    if (!g_app.selected || g_app.selected->initialising) return 0;
    const chat_t *e = &g_app.selected->engine;
    int n = 0;
#define KV(l, ...) do { snprintf(vals[n], NET_VALUE_MAX, __VA_ARGS__); kv[n].label = (l); kv[n].value = vals[n]; n++; } while (0)
    if (e->route.mode == ROUTE_TOR) {
        char t[32];
        tor_link_line(t, sizeof t);
        KV("route", "tor");
        static const char tor[] = "tor: ";
        KV("tor", "%s", starts_with(t, tor) ? t + sizeof tor - 1 : t);
        KV("onion", "%s", e->tor && tor_my_onion(e->tor)[0] ? "published" : "waiting");
    } else {
        KV("route", "dht");
        KV("port", "udp/%u", (unsigned)e->port);
        KV("portmap", "%s", !e->pm ? "off" : portmap_mapped(e->pm, NULL) ? "mapped" : "not yet");
    }
    if (e->nostr && !nostr_active(e->nostr)) KV("relays", "not needed");
    else if (e->nostr) KV("relays", "%d/%d up", nostr_relays_up(e->nostr), nostr_relay_total(e->nostr));
    else KV("relays", "off");
    if (e->route.mode != ROUTE_TOR) {
        if (e->dht_on) {
            KV("dht", "%d nodes", dht_queried_count(&e->dht));
            KV("found", "%d peers", dht_found_count(&e->dht));
        } else {
            KV("dht", "off");
        }
    }
    KV("cands", "%d", chat_candidate_count(e));
    KV("pending", "%d", chat_pending_count(e));
    KV("rx", "%u packets", e->st.rx);
#undef KV
    return n;
}

_Static_assert((int)TUI_VERIFY_BAD == (int)VERIFY_FAILED && (int)TUI_CODE_KEY_CHANGED == (int)CODE_KEY_CHANGED,
               "the sidebar takes the engine's verify states and codes as they are");

void render(void) {
    tui_session_row_t rows[MAX_SESSIONS];
    int n = 0, sel = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_app.used[i]) continue;
        session_slot_t *s = &g_app.sessions[i];
        tui_session_row_t *r = &rows[n];
        copy_str(r->label, s->name, sizeof r->label);
        r->online = s->initialising ? 1 : chat_online_count(&s->engine) + 1;
        r->unread = s->unread;
        r->mention = s->mentioned;
        r->state = session_state(s);
        if (s == g_app.selected) sel = n;
        n++;
    }

    int rows_n, cols_n; term_get_size(&rows_n, &cols_n);
    tui_bar_t bar = current_bar();
    char hhmm[HHMM_LEN]; current_hhmm(hhmm);

    if (install_mode(g_app.mode) && g_app.install_back == MODE_SETTINGS) { render_settings(rows_n, cols_n, hhmm, &bar); return; }
    switch (g_app.mode) {
        case MODE_HELP:            render_help(rows_n, cols_n, hhmm, &bar); return;
        case MODE_CHANGELOG:       render_changelog(rows_n, cols_n, hhmm, &bar); return;
        case MODE_SETTINGS:
        case MODE_SETTINGS_EDIT:   render_settings(rows_n, cols_n, hhmm, &bar); return;
        case MODE_DEVICE_LOCK:
            if (g_app.device_back == MODE_SETTINGS) { render_settings(rows_n, cols_n, hhmm, &bar); return; }
            break;
        case MODE_FACTOR:
        case MODE_CODE_SETUP:
        case MODE_KEY_WAIT:
        case MODE_KEY_PIN:
        case MODE_SHADOW_PASS:
        case MODE_SHADOW_PASS2:
            if (g_app.factor_back == MODE_SETTINGS) { render_settings(rows_n, cols_n, hhmm, &bar); return; }
            break;
        case MODE_SIGN_CHOICE:
        case MODE_SIGN_PASTE:
        case MODE_SIGN_PASSWORD:   render_sign_picker(rows_n, cols_n, hhmm, &bar); return;
        case MODE_SIGN_PATH:
            if (g_app.path_from_browser) render_browser(rows_n, cols_n, hhmm, &bar);
            else render_sign_picker(rows_n, cols_n, hhmm, &bar);
            return;
        case MODE_SIGN_BROWSE:     render_browser(rows_n, cols_n, hhmm, &bar); return;
        case MODE_SEND_BROWSE:     render_send_browser(rows_n, cols_n, hhmm, &bar); return;
        case MODE_SAVE_BROWSE:     render_save_browser(rows_n, cols_n, hhmm, &bar); return;
        case MODE_FILES:           render_files(rows_n, cols_n, hhmm, &bar); return;
        case MODE_FILE_VIEW:       render_viewer(rows_n, cols_n, hhmm, &bar); return;
        case MODE_FILE_ASK:
            if (g_app.file_back == MODE_FILE_VIEW) render_viewer(rows_n, cols_n, hhmm, &bar);
            else render_files(rows_n, cols_n, hhmm, &bar);
            return;
        default: break;
    }

    static tui_peer_row_t peer_rows[MAX_PEERS + MAX_PENDING_PEERS + 1];
    int n_peers = 0;
    if (g_app.selected && !g_app.selected->initialising) {
        chat_t *e = &g_app.selected->engine;
        tui_peer_row_t *me = &peer_rows[n_peers++];
        memset(me, 0, sizeof *me);
        copy_str(me->nick, e->nick, sizeof me->nick);
        memcpy(me->color, e->my_color, 3);
        me->you = 1;
        me->history = e->persist;
        for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS && n_peers < MAX_PEERS + MAX_PENDING_PEERS + 1; i++) {
            peer_t *p = &e->peers[i];
            if (!p->used || !p->ok) continue;
            tui_peer_row_t *r = &peer_rows[n_peers++];
            memset(r, 0, sizeof *r);
            // Nicks can't contain '#', so one here is the id added to tell lookalikes apart, which the sidebar
            // never cuts off.
            char name[CHAT_NAME_LEN]; chat_peer_name(e, p, name);
            char *tag = strchr(name, '#');
            if (tag) { copy_str(r->tag, tag, sizeof r->tag); *tag = '\0'; }
            copy_str(r->nick, name, sizeof r->nick);
            memcpy(r->color, p->color, 3);
            r->verify = (tui_verify_t)p->identity_state;
            r->code = (tui_code_t)chat_code_state(e, p);
            r->modified = p->build_state == BUILD_MODIFIED;
            r->history = p->persists;
        }
    }

    tui_scrollback_t *sb = g_app.selected ? &g_app.selected->sb : NULL;
    tui_scrollback_t *console = g_app.selected ? &g_app.selected->console : &g_app.log;
    char sub[64]; tui_view_t view = current_view(sub, sizeof sub);
    view.clock = hhmm;
    tui_kv_t net[MAX_NET];
    char net_vals[MAX_NET][NET_VALUE_MAX];
    int n_net = build_net(net, net_vals);
    tui_render(rows_n, cols_n, rows, n, sel, peer_rows, n_peers, net, n_net, sb, console, &view, &bar,
               g_app.color_enabled);
}
