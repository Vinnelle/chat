// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The app's own commands (APP_COMMANDS), :move's boxes, the help page, and running a command.
#include "app/app.h"

// ---- the help page: every key, then every command ----

// The keys the settings choose, as help_rows last named them.
static char g_lock_keys[16], g_panic_keys[16];

static const struct { const char *section, *keys, *what; } HELP_KEYS[] = {
    { "Sessions",    "ctrl+n",          "start a new session" },
    { NULL,          "ctrl+j",          "join a session by its id and password, or one you kept (:keep)" },
    { NULL,          "tab  shift+tab",  "next / previous session" },
    { NULL,          "ctrl+s",          "settings" },
    { NULL,          "ctrl+c",          "quit, pressed twice (or y) - sessions leave, or go offline if kept" },
    { NULL,          g_lock_keys,       "lock the screen, as :lock does (:set lockkey)" },
    { NULL,          g_panic_keys,      "panic: clear the screen and quit at once (:set panickey)" },
    { "Screen",      "ctrl+b",          "show or hide the sidebar" },
    { NULL,          "ctrl+o",          "show or hide the console" },
    { NULL,          "ctrl+t",          "show or hide the chat" },
    { NULL,          "pgup  pgdn",      "scroll the chat back / forward" },
    { NULL,          "up  down",        "scroll the chat by a message" },
    { NULL,          "mouse wheel",     "scroll what it's over: chat, console, sessions, peers" },
    { NULL,          "shift+drag",      "select text with the mouse" },
    { NULL,          "f1",              "this page" },
    { "Typing",      "enter",           "send" },
    { NULL,          "/",               "on an empty line: a command (what isn't one stays text)" },
    { NULL,          "@nick  tab",      "finish a nick" },
    { NULL,          "ctrl+w  ctrl+u",  "delete a word / back to the start" },
    { NULL,          "esc",             "NORMAL mode" },
    { "Normal mode", "i  a  I  A",      "type: at / after the cursor, at the start / end" },
    { NULL,          "h  l  0  $  x",   "move, to the start / end, delete" },
    { NULL,          "j  k",            "next / previous session" },
    { NULL,          "ctrl+u  ctrl+d",  "scroll the chat back / forward" },
    { NULL,          "G",               "back to the newest message and console line" },
    { NULL,          "s  c  C",         "show or hide the sidebar / console / chat" },
    { NULL,          "f",               "the files" },
    { NULL,          ":  /",            "the command line" },
    { NULL,          "?",               "this page" },
    { "Files",       "ctrl+f",          "the files offered here, and yours (f in NORMAL)" },
    { NULL,          "enter",           "show a picture big, fetching it first, or download a file" },
    { NULL,          "d  s",            "save in Downloads / in a folder you pick" },
    { NULL,          "v",               "show or hide a picture in the chat" },
    { NULL,          "x",               "stop fetching it, or stop offering yours" },
    { NULL,          "y",               "copy where it was saved" },
    { NULL,          "n",               "send a file" },
    { NULL,          "j  k",            "on a picture: the next / previous one" },
    { "Pages",       "j  k  g  G",      "move, to the first / last" },
    { NULL,          "h  l  enter",     "change a value, go in, choose" },
    { NULL,          "tab  shift+tab",  "next / previous section (pgdn / pgup too)" },
    { NULL,          "1 - 9",           "the first to ninth section" },
    { NULL,          "esc  q",          "back / close" },
};

#define N_HELP_KEYS ((int)COUNT_OF(HELP_KEYS))

#define MAX_HELP_COMMANDS 32

#define MAX_HELP_ROWS (N_HELP_KEYS + MAX_HELP_COMMANDS)

void begin_help(void) {
    if (g_app.mode != MODE_CHAT) return;
    g_app.mode = MODE_HELP;
    g_app.dirty = 1;
}

// ---- commands ----

// :set opens the settings page and :set NAME opens it on that row. :set NAME VALUE sets the row
// without opening it, the same as the page would.
static cmd_result_t app_set(void *ctx, const char *arg) {
    (void)ctx;
    char key[CMD_WORD_MAX];
    const char *value = cmd_parse(arg, key);
    if (!key[0]) { begin_settings(); return CMD_OK; }
    const setting_def_t *d = setting_by_key(key);
    if (!d) { note("no setting called %s - :set opens the page with all of them", key); return CMD_OK; }
    if (!value[0]) { settings_open_at(d->id); return CMD_OK; }

    const char *const *names;
    int n;
    if (setting_options(d->id, &names, &n) >= 0) {
        for (int i = 0; i < n; i++)
            if (strcmp(value, names[i]) == 0) { setting_choose(d->id, i); return CMD_OK; }
        note("%s takes %s, not %.40s", d->key, d->values, value);
        return CMD_OK;
    }
    switch (d->kind) {
        case K_TEXT:
            setting_apply_text(d->id, value);
            return CMD_OK;
        case K_SECRET:
            // On the command line it would be visible. The page's field hides it.
            settings_open_at(d->id);
            if (!setting_shown(d->id)) return CMD_OK;   // settings_open_at said why it isn't there
            begin_setting_edit(d->id);
            note("type the %s here instead, where it's hidden", d->label);
            return CMD_OK;
        default:
            break;
    }
    if (d->id == SET_SHADOW) {
        int on = g_app.installed && !g_app.locked && install_has_shadow();
        if (strcmp(value, "off") == 0) {
            if (!on) { note("Shadow password: off already"); return CMD_OK; }
            shadow_off();
        } else if (strcmp(value, "on") == 0) {
            if (on) note("Shadow password: on already - :set shadow off removes it");
            else begin_shadow();
        } else {
            note("shadow takes on or off");
        }
        return CMD_OK;
    }
    if (d->id == SET_SIGN) {
        static const struct { const char *name; sign_pick_t pick; } SIGN_VALUES[] = {
            { "off", PICK_OFF }, { "age", PICK_AGE_MADE }, { "pgp", PICK_PGP_MADE },
        };
        int pick = -1;
        for (size_t i = 0; i < COUNT_OF(SIGN_VALUES); i++)
            if (strcmp(value, SIGN_VALUES[i].name) == 0) pick = SIGN_VALUES[i].pick;
        if (pick == PICK_OFF) { sign_pick(pick); return CMD_OK; }
        // age:PATH or pgp:PATH: a key file, like --identity takes.
        if ((starts_with(value, "age:") || starts_with(value, "pgp:")) && value[sizeof "age:" - 1]) {
            const char *path = value + sizeof "age:" - 1;
            identity_source_t kind = value[0] == 'a' ? IDENT_AGE : IDENT_PGP;
            if (load_key_file(kind, path) == 0) { identity_chosen(); return CMD_OK; }
            if (kind == IDENT_AGE) note("%.80s can't be read, or holds no AGE secret key", path);
            else note("%.80s can't be read, or isn't an unencrypted EdDSA/Ed25519 secret key", path);
            return CMD_OK;
        }
        settings_open_at(SET_SIGN);
        begin_sign();
        if (pick < 0) { note("sign takes off, age, pgp, age:PATH or pgp:PATH - a pasted key is chosen here"); return CMD_OK; }
        // The password is typed on the page, where it's hidden.
        g_app.key.sel = pick;
        sign_pick(pick);
        return CMD_OK;
    }
    settings_open_at(d->id);
    if (setting_shown(d->id)) note("%s comes from your signing key and can't be set - Enter copies it", d->label);
    return CMD_OK;
}

// The save named in arg, else the one in use. -1 if arg can't name a save.
static int pick_save_target(const char *arg) {
    while (arg && *arg == ' ') arg++;
    char name[64] = "";
    if (arg) copy_str(name, arg, sizeof name);
    size_t n = strlen(name);
    while (n > 0 && name[n - 1] == ' ') name[--n] = '\0';
    if (name[0] && install_name_ok(name) != 0) {
        note("a save's name is 1 to %d letters, digits, - and _", INSTALL_NAME_MAX);
        return -1;
    }
    copy_str(g_app.install.target, name[0] ? name : install_current(), sizeof g_app.install.target);
    if (strcmp(g_app.install.target, "default") == 0) g_app.install.target[0] = '\0';
    g_app.install.named = name[0] != '\0';
    return 0;
}

// 0 once its first box is open.
int begin_install(const char *arg) {
    if (pick_save_target(arg) != 0) return -1;
    device_check();
    char where[APP_PATH_MAX];
    if (install_where(g_app.install.target, where, sizeof where) != 0) { note("there's nowhere to install to - no home folder"); return -1; }
    g_app.install.n_saves = install_list(g_app.install.saves, INSTALL_SAVES_MAX);
    const char *t = g_app.install.target;
    int named = g_app.install.named || g_opts.save[0];
    app_mode_t mode = MODE_INSTALL;
    if (g_app.installed) {
        // The open save is saved to after the usual question. Another one that's there needs its
        // passphrase to be saved over.
        if (!is_current_save(t) && save_exists(t)) mode = MODE_INSTALL_OVERWRITE;
    } else if (save_exists(t) || (!named && g_app.install.n_saves > 0)) {
        // Nothing is open: the saves there are offered before a new one is made. Without a NAME or
        // --save, the only save is offered, or one is picked from a list.
        if (!named && g_app.install.n_saves == 1) copy_str(g_app.install.target, g_app.install.saves[0].name, sizeof g_app.install.target);
        g_app.install.pick = !named && g_app.install.n_saves > 1;
        g_app.install.sel = 0;
        for (int i = 0; i < g_app.install.n_saves; i++)
            if (strcmp(g_app.install.saves[i].name, t) == 0) g_app.install.sel = i;
        mode = MODE_INSTALL_EXISTING;
    } else if (!named) {
        pick_random_save_name();
        mode = MODE_INSTALL_NAME;
    }
    g_app.install.back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    begin_prompt(mode);
    return 0;
}

static cmd_result_t app_install(void *ctx, const char *arg) {
    (void)ctx;
    g_app.install.for_factor = 0;
    begin_install(arg);
    return CMD_OK;
}

// The same as :install, for the save in use.
static cmd_result_t app_save(void *ctx, const char *arg) {
    (void)arg;
    return app_install(ctx, NULL);
}

static cmd_result_t app_uninstall(void *ctx, const char *arg) {
    (void)ctx;
    if (pick_save_target(arg) != 0) return CMD_OK;
    if (!save_exists(g_app.install.target)) {
        if (arg && arg[0]) note("nothing to uninstall - there's no save called %s", install_shown_name(g_app.install.target));
        else note("nothing to uninstall - chat has saved nothing here");
        return CMD_OK;
    }
    begin_prompt(MODE_UNINSTALL);
    return CMD_OK;
}

// ":history" says whether this session's is kept, ":history forget" deletes it, and ":history forget
// all" every session's in the save.
static cmd_result_t app_history(void *ctx, const char *arg) {
    (void)ctx;
    session_slot_t *s = g_app.selected && !g_app.selected->initialising ? g_app.selected : NULL;
    char word[CMD_WORD_MAX], what[CMD_WORD_MAX];
    cmd_parse(cmd_parse(arg ? arg : "", word), what);
    const char *shown = install_shown_name(install_current());
    if (strcmp(word, "forget") == 0) {
        if (!g_app.installed || g_app.locked) { note("no save is open, so none is kept"); return CMD_OK; }
        if (strcmp(what, "all") == 0) {
            install_forget_history(NULL);
            for (int i = 0; i < MAX_SESSIONS; i++) {
                session_slot_t *o = &g_app.sessions[i];
                if (g_app.used[i] && o->hist) { crypto_wipe(o->hist, o->hist_len); o->hist_len = 0; o->hist_dirty = 0; }
            }
            push_log("* history: every session's history in the save %s is deleted", shown);
            note("deleted every session's history%s", g_app.history ? " - each is kept again from here" : "");
            return CMD_OK;
        }
        if (what[0]) { note("history forget takes all, or nothing for this session's"); return CMD_OK; }
        if (!s) { note("open a session first - :history forget all deletes every session's"); return CMD_OK; }
        uint8_t id[CHAT_HISTORY_ID_LEN];
        chat_history_id(&s->engine, id);
        install_forget_history(id);
        if (s->hist) { crypto_wipe(s->hist, s->hist_len); s->hist_len = 0; s->hist_dirty = 0; }
        note("deleted this session's history%s", g_app.history ? " - it's kept again from here" : "");
        return CMD_OK;
    }
    if (word[0]) { note("history takes forget, or forget all"); return CMD_OK; }
    int kept = g_app.installed && !g_app.locked ? install_histories() : 0;
    if (!g_app.installed || g_app.locked) note("history: off - it's kept sealed in a save, so it needs one open (:install)");
    else if (!g_app.history) note("history: off - :set history on keeps it in the save %s (%d session%s there)", shown, kept,
                                  kept == 1 ? " has one" : "s have one");
    else if (s && s->hist) {
        int lines = 0;
        for (size_t i = 0; i < s->hist_len; i++) lines += s->hist[i] == '\n';
        note("history: on - %d line%s kept for this session in the save %s, and everyone here is told", lines,
             lines == 1 ? "" : "s", shown);
    } else {
        note("history: on - in the save %s (%d session%s there)", shown, kept, kept == 1 ? " has one" : "s have one");
    }
    return CMD_OK;
}

// ---- :move ----

// A request to move that comes up by itself ignores keys for this long, so a word being typed when it
// appears doesn't answer it.
#define MOVE_KEY_GUARD 1.0

// :move asks whether to move, in a box that says who comes and who's left behind. With a request to
// move waiting, it shows that again instead.
static cmd_result_t app_move(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    session_slot_t *s = g_app.selected;
    if (!s || s->initialising) { note("open a session first"); return CMD_OK; }
    if (chat_move_asked(&s->engine)) {
        g_app.mode = MODE_MOVE_ASK;
        g_app.move_shown = 0.0;
        g_app.dirty = 1;
        return CMD_OK;
    }
    chat_move_plan_t plan;
    chat_move_plan(&s->engine, &plan);
    if (!plan.coming) {
        note(plan.left ? "nobody can come along yet - compare verify codes with them first (:peers lists them)"
                       : "nobody else is here to move with");
        return CMD_OK;
    }
    g_app.mode = MODE_MOVE;
    g_app.dirty = 1;
    return CMD_OK;
}

// The new room opens, selected, and the one being left goes off the screen until it's done.
static void move_to_room(session_slot_t *old, const chat_move_to_t *to) {
    session_slot_t *s = start_moved_session(to);
    if (!s) { select_session(old); return; }
    chat_move_go(&old->engine, to, &s->engine, now_seconds());
    old->leaving = 1;
}

void move_yes(void) {
    session_slot_t *s = g_app.selected;
    g_app.mode = MODE_CHAT;
    g_app.dirty = 1;
    if (!s || s->initialising) return;
    chat_move_to_t to;
    // Peers may have gone since the box came up, and the engine says so on the bar.
    g_echo = 1;
    int ok = chat_move_begin(&s->engine, &to) == 0;
    g_echo = 0;
    if (ok) move_to_room(s, &to);
    crypto_wipe(&to, sizeof to);
}

void move_no(void) {
    g_app.mode = MODE_CHAT;
    g_app.dirty = 1;
}

// y goes and n stays, which can't be undone, so Esc only puts the box away until :move.
void move_ask_key(const tui_key_t *key) {
    session_slot_t *s = g_app.selected;
    const chat_move_ask_t *a = s && !s->initialising ? chat_move_asked(&s->engine) : NULL;
    if (!a) { g_app.mode = MODE_CHAT; g_app.dirty = 1; return; }
    if (now_seconds() - g_app.move_shown < MOVE_KEY_GUARD) return;
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (ch == 'y' || ch == 'Y') {
        g_app.mode = MODE_CHAT;
        g_app.dirty = 1;
        chat_move_to_t to;
        if (chat_move_accept(&s->engine, &to) == 0) move_to_room(s, &to);
        crypto_wipe(&to, sizeof to);
    } else if (ch == 'n' || ch == 'N') {
        g_app.mode = MODE_CHAT;
        g_app.dirty = 1;
        chat_move_decline(&s->engine);
        note("you stay in this room");
    } else if (ch == 'q' || key->type == TUI_KEY_ESCAPE) {
        s->move_later = a->seq;
        g_app.mode = MODE_CHAT;
        g_app.dirty = 1;
        note("the request to move waits - :move shows it again");
    }
}

// Closes the rooms that were left once they're done, and asks about a request to move in the session
// on screen.
void move_tick(double now) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_slot_t *s = &g_app.sessions[i];
        if (!g_app.used[i] || !s->leaving || !chat_move_finished(&s->engine, now)) continue;
        for (int j = 0; j < MAX_SESSIONS; j++)
            if (g_app.used[j] && &g_app.sessions[j].engine == s->engine.move_to)
                console_note(&g_app.sessions[j], "* left %s, the room you moved from", s->name);
        close_session(s);
    }
    session_slot_t *s = g_app.selected;
    const chat_move_ask_t *a = s && !s->initialising ? chat_move_asked(&s->engine) : NULL;
    if (a && g_app.mode == MODE_CHAT && !g_app.asking_quit && !g_app.lock.on && !g_app.lock.pin_step
        && s->move_later != a->seq) {
        g_app.mode = MODE_MOVE_ASK;
        g_app.move_shown = now;
        g_app.dirty = 1;
    }
}

// Checked before CHAT_COMMANDS, so entries here shadow the per-session ones of the same name.
const command_t APP_COMMANDS[] = {
    { "help",    NULL,                  NULL,     "list all commands and keybinds (F1)",          app_help },
    { "new",     NULL,                  NULL,     "create a session (Ctrl+N)",                       app_new },
    { "join",    NULL,                  NULL,     "join a session by id, or one you kept (Ctrl+J)",  app_join },
    { "keep",    NULL,      "[LABEL | forget]", "keep this room in the open save, to join it again from Ctrl+J; forget lets it go", app_keep },
    { "call",    NULL,                  "NICK",   "open the room only you and a verified key can work out; they :call you too", app_call },
    { "quit",    "q exit close bd bw",  NULL,     "leave this session; quits if none are open",       app_quit },
    { "quitall", "qa qall",             NULL,     "leave every session and quit, kept ones too",     app_quitall },
    { "lock",    NULL,                  NULL,     "lock the screen until the save's passphrase, or a PIN, unlocks it", app_lock },
    { "set",     NULL,        "[NAME [VALUE]]",   "change a setting; alone, opens them all (Ctrl+S)", app_set },
    { "copyid",  NULL,                  NULL,     "copy this session's id to the clipboard",         app_copyid },
    { "invite",  NULL,                  NULL,     "copy this session's id and password as one invite, which Ctrl+J takes", app_invite },
    { "move",    NULL,                  NULL,     "move to a new room with the peers whose codes you compared, leaving the rest behind", app_move },
    { "newtor",  NULL,                  NULL,     "new Tor circuits and onion addresses for every session that goes through Tor", app_newtor },
    { "update",  NULL,                  NULL,     "install the latest release from GitHub",          app_update },
    { "install", NULL,                  "[NAME]", "save your settings and signing key on this computer (NAME: as a save of that name)", app_install },
    { "save",    NULL,                  NULL,     "save what's in use now to the open save, after asking (or :install it)", app_save },
    { "uninstall", NULL,                "[NAME]", "delete what :install saved (NAME: that save)",    app_uninstall },
    { "history", NULL,                  "[forget [all]]", "whether this session's history is kept; forget deletes it (all: every session's)", app_history },
    { "changelog", "news",              NULL,     "show changelog",                    app_changelog },
    { "files",   NULL,                  NULL,     "the files offered here: show, save or stop them (Ctrl+F)", app_files },
    { "show",    NULL,                  "N [anyway]", "show picture N in the chat, where it was offered", app_show },
    { "hide",    NULL,                  "N",      "tuck picture N away again",                       app_hide },
    { "saveto",  NULL,                  "N [anyway]", "pick a folder in a file browser and save file N there", app_saveto },
    { NULL, NULL, NULL, NULL, NULL }
};

const command_t *const ALL_COMMANDS[] = { APP_COMMANDS, CHAT_COMMANDS, NULL };

cmd_result_t app_help(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_help();
    return CMD_OK;
}

cmd_result_t app_changelog(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_changelog();
    return CMD_OK;
}

// "N" or "N anyway": the number, and whether anyway was given. 0 if it's neither.
int file_arg(const char *arg, int *anyway) {
    char *end;
    long n = strtol(arg, &end, 10);
    while (*end == ' ') end++;
    *anyway = strcmp(end, "anyway") == 0;
    return n > 0 && n <= FILE_NUM_MAX && (!*end || *anyway) ? (int)n : 0;
}

// Pictures are only fetched when you ask to show them, and drawn where they were offered.
cmd_result_t app_show(void *ctx, const char *arg) {
    (void)ctx;
    session_slot_t *s = g_app.selected;
    int anyway, n = file_arg(arg, &anyway);
    if (!s || s->initialising) { note("open a session first"); return CMD_OK; }
    if (!n) { note("usage: :show N [anyway] - N is the number in the offer"); return CMD_OK; }
    pic_t *p = pic_find(s, n);
    if (p && p->th.rgb) { p->shown = 1; g_app.dirty = 1; return CMD_OK; }
    echo_fetch(s, n, 1, anyway, NULL);
    return CMD_OK;
}

cmd_result_t app_files(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    begin_files();
    return CMD_OK;
}

cmd_result_t app_saveto(void *ctx, const char *arg) {
    (void)ctx;
    session_slot_t *s = g_app.selected;
    int anyway, n = file_arg(arg, &anyway);
    if (!s || s->initialising) { note("open a session first"); return CMD_OK; }
    if (!n) { note("usage: :saveto N [anyway] - N is the number in the offer"); return CMD_OK; }
    const file_entry_t *f = chat_file(&s->engine, n);
    if (!f) { note("there's no file %d - :files lists them", n); return CMD_OK; }
    if (f->mine) { note("file %d is yours", n); return CMD_OK; }
    begin_save_browse(n, anyway);
    return CMD_OK;
}

cmd_result_t app_hide(void *ctx, const char *arg) {
    (void)ctx;
    session_slot_t *s = g_app.selected;
    int anyway, n = file_arg(arg, &anyway);
    pic_t *p = s && n ? pic_find(s, n) : NULL;
    if (!p || !p->shown) { note("picture %s isn't shown", arg); return CMD_OK; }
    p->shown = 0;
    g_app.dirty = 1;
    return CMD_OK;
}

// The help page's rows, and each one's command (NULL for a key's).
static int help_rows(tui_row_t *rows, const command_t **cmds) {
    static char labels[MAX_HELP_COMMANDS][CMD_WORD_MAX + 24];
    int n = 0, k = 0;
    copy_str(g_lock_keys, LOCK_KEY_NAMES[g_app.lock.key], sizeof g_lock_keys);
    copy_str(g_panic_keys, PANIC_KEY_NAMES[g_app.panic.key], sizeof g_panic_keys);
    for (int i = 0; i < N_HELP_KEYS; i++) {
        rows[n] = (tui_row_t){ HELP_KEYS[i].section, HELP_KEYS[i].keys, HELP_KEYS[i].what, TUI_V_TEXT, NULL, NULL, 0, 0 };
        cmds[n++] = NULL;
    }
    for (const command_t *const *t = ALL_COMMANDS; *t; t++) {
        for (const command_t *cmd = *t; cmd->name && k < MAX_HELP_COMMANDS; cmd++) {
            if (*t != APP_COMMANDS && cmd_find(APP_COMMANDS, cmd->name)) continue;
            snprintf(labels[k], sizeof labels[k], ":%s%s%s", cmd->name, cmd->args ? " " : "", cmd->args ? cmd->args : "");
            rows[n] = (tui_row_t){ k == 0 ? "Commands" : NULL, labels[k], cmd->help, TUI_V_TEXT, NULL, NULL, 0, 0 };
            cmds[n++] = cmd;
            k++;
        }
    }
    return n;
}

void render_help(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    tui_row_t rows[MAX_HELP_ROWS];
    const command_t *cmds[MAX_HELP_ROWS];
    int n = help_rows(rows, cmds);
    if (g_app.help_sel >= n) g_app.help_sel = n - 1;
    const command_t *c = cmds[g_app.help_sel];
    char help[200] = "";
    if (c) {
        size_t p = (size_t)snprintf(help, sizeof help, "Enter puts it on the command line.");
        const char *sep = " Also";
        for (const char *a = c->aliases; a && *a && p < sizeof help; ) {
            size_t len = strcspn(a, " ");
            p += (size_t)snprintf(help + p, sizeof help - p, "%s :%.*s", sep, (int)len, a);
            sep = ",";
            a += len;
            while (*a == ' ') a++;
        }
        if (c->aliases && p < sizeof help) snprintf(help + p, sizeof help - p, ".");
    }
    tui_page_t page = {
        .title = "Keys & commands",
        .clock = clock,
        .rows = rows, .n_rows = n, .selected = g_app.help_sel,
        .help = help[0] ? help : NULL,
        .keys = 1,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

// Enter on a command puts it on the command line, to be completed and run. F1 and ? close the page
// as well as open it.
void help_key(const tui_key_t *key) {
    tui_row_t rows[MAX_HELP_ROWS];
    const command_t *cmds[MAX_HELP_ROWS];
    int n = help_rows(rows, cmds);
    int s = section_digit(key);
    if (s >= 0) {
        int i = page_section_nth(rows, n, s);
        if (i >= 0) g_app.help_sel = i;
        g_app.dirty = 1;
        return;
    }
    list_key_t k = list_key(key);
    if (key->type == TUI_KEY_HELP || (key->type == TUI_KEY_CHAR && key->ch[0] == '?')) k = LIST_CLOSE;
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT: {
            const command_t *c = cmds[g_app.help_sel];
            if (!c) break;
            g_app.mode = MODE_CHAT;
            char text[CMD_WORD_MAX + 2];
            snprintf(text, sizeof text, "%s%s", c->name, c->args ? " " : "");
            tui_input_command(&g_app.input, g_app.input.mode == TUI_IMODE_NORMAL ? ':' : '/', text);
            break;
        }
        case LIST_LEFT:
        case LIST_BACK:
        case LIST_CLOSE: g_app.mode = MODE_CHAT; break;
        case LIST_NEXT_SECTION: g_app.help_sel = page_section_step(rows, n, g_app.help_sel, 1); break;
        case LIST_PREV_SECTION: g_app.help_sel = page_section_step(rows, n, g_app.help_sel, -1); break;
        default: list_move(k, &g_app.help_sel, n); break;
    }
    g_app.dirty = 1;
}

// Runs "name args" typed on the COMMAND line, after ':'.
void run_command(const char *line) {
    char word[CMD_WORD_MAX];
    const char *arg = cmd_parse(line, word);
    if (!word[0]) return;
    const command_t *cmd = cmd_find(APP_COMMANDS, word);
    if (cmd) { cmd->run(NULL, arg); return; }
    if (!cmd_find(CHAT_COMMANDS, word)) { note("no command :%s - :help lists them", word); return; }
    if (!g_app.selected) {
        note(":%s needs a session - Ctrl+N (or :new) creates one, Ctrl+J (or :join) joins one", word);
        return;
    }
    // Without a path, a browser to pick the file in.
    if (strcmp(word, "send") == 0) {
        const char *rest = arg + strspn(arg, " ");
        int asis = strncmp(rest, "asis", 4) == 0 && !rest[4 + strspn(rest + 4, " ")];
        if (!rest[0] || asis) { begin_send_browse(asis); return; }
    }
    g_echo = strcmp(word, "download") == 0 || strcmp(word, "dl") == 0 || strcmp(word, "cancel") == 0 || strcmp(word, "send") == 0;
    cmd_result_t r = chat_run_command(&g_app.selected->engine, line);
    g_echo = 0;
    if (r == CMD_QUIT) close_session(g_app.selected);
}

cmd_result_t app_quit(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    if (g_app.selected) close_session(g_app.selected);
    else g_interrupted = 1;
    return CMD_OK;
}

cmd_result_t app_quitall(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    g_app.quit_leaving = 1;
    g_interrupted = 1;
    return CMD_OK;
}

cmd_result_t app_copyid(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    copy_session_id(g_app.selected);
    return CMD_OK;
}

cmd_result_t app_invite(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    copy_invite(g_app.selected);
    return CMD_OK;
}

cmd_result_t app_update(void *ctx, const char *arg) {
    (void)ctx; (void)arg;
    if ((g_app.sandboxed & PLATFORM_SANDBOX_FILES) && !update_helper_running()) {
        if (g_app.updater)
            note("the sandbox keeps chat from replacing itself, and the updater isn't running - quit and run chat "
                 "--update");
        else
            note("the sandbox keeps chat from replacing itself, and the updater is off - quit and run chat --update, "
                 "or :set updater on for the next start");
        return CMD_OK;
    }
    if (g_app.route.mode == ROUTE_TOR && g_tor.state != TL_READY) {
        push_log(UPDATE_PREFIX "Tor mode downloads through Tor, and there's no tor yet - try again once it's connected");
        return CMD_OK;
    }
    // If an update is already running, its box is shown again.
    if (update_start(g_app.betas) == 0)
        push_log(UPDATE_PREFIX "checking GitHub for a newer release%s (v" CHAT_VERSION " here)...", g_app.betas ? " or beta" : "");
    begin_prompt(MODE_UPDATE);
    return CMD_OK;
}

// The box only shows the update. Closing it leaves the update running, and the result goes to the
// console either way.
void update_key(const tui_key_t *key) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (key->type != TUI_KEY_ESCAPE && key->type != TUI_KEY_ENTER && ch != 'q') return;
    update_view_t v;
    update_view(&v);
    end_prompt();
    if (v.running) note("the update keeps running - :update shows it again");
}
