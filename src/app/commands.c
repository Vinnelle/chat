// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/app.h"

// ---- the help page: every key, then every command ----

static const struct { const char *section, *keys, *what; } HELP_KEYS[] = {
    { "Sessions",    "ctrl+n",          "start a new session" },
    { NULL,          "ctrl+j",          "join a session by its id and password" },
    { NULL,          "tab  shift+tab",  "next / previous session" },
    { NULL,          "ctrl+s",          "settings" },
    { NULL,          "ctrl+c",          "quit, after asking - every session leaves cleanly first" },
    { "Screen",      "ctrl+b",          "show or hide the sidebar" },
    { NULL,          "ctrl+o",          "show or hide the console" },
    { NULL,          "ctrl+t",          "show or hide the chat" },
    { NULL,          "pgup  pgdn",      "scroll the chat back / forward" },
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
    { NULL,          "G",               "back to the newest message" },
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

#define N_HELP_KEYS ((int)(sizeof HELP_KEYS / sizeof HELP_KEYS[0]))

#define MAX_HELP_COMMANDS 32

#define MAX_HELP_ROWS (N_HELP_KEYS + MAX_HELP_COMMANDS)

static void begin_help(void) {
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
        for (size_t i = 0; i < sizeof SIGN_VALUES / sizeof SIGN_VALUES[0]; i++)
            if (strcmp(value, SIGN_VALUES[i].name) == 0) pick = SIGN_VALUES[i].pick;
        if (pick == PICK_OFF) { sign_pick(pick); return CMD_OK; }
        // age:PATH or pgp:PATH: a key file, like --identity takes.
        if ((strncmp(value, "age:", 4) == 0 || strncmp(value, "pgp:", 4) == 0) && value[4]) {
            identity_source_t kind = value[0] == 'a' ? IDENT_AGE : IDENT_PGP;
            if (load_key_file(kind, value + 4) == 0) { identity_chosen(); return CMD_OK; }
            if (kind == IDENT_AGE) note("%.80s can't be read, or holds no AGE secret key", value + 4);
            else note("%.80s can't be read, or isn't an unencrypted EdDSA/Ed25519 secret key", value + 4);
            return CMD_OK;
        }
        settings_open_at(SET_SIGN);
        begin_sign();
        if (pick < 0) { note("sign takes off, age, pgp, age:PATH or pgp:PATH - a pasted key is chosen here"); return CMD_OK; }
        // The password is typed on the page, where it's hidden.
        g_app.sign_sel = pick;
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
    copy_str(g_app.save_target, name[0] ? name : install_current(), sizeof g_app.save_target);
    if (strcmp(g_app.save_target, "default") == 0) g_app.save_target[0] = '\0';
    g_app.save_named = name[0] != '\0';
    return 0;
}

// 0 once its first box is open.
int begin_install(const char *arg) {
    if (pick_save_target(arg) != 0) return -1;
    device_check();
    char where[900];
    if (install_where(g_app.save_target, where, sizeof where) != 0) { note("there's nowhere to install to - no home folder"); return -1; }
    g_app.n_saves = install_list(g_app.saves, INSTALL_SAVES_MAX);
    const char *t = g_app.save_target;
    int named = g_app.save_named || g_opts.save[0];
    app_mode_t mode = MODE_INSTALL;
    if (g_app.installed) {
        // The open save is saved to after the usual question. Another one that's there needs its
        // passphrase to be saved over.
        if (!is_current_save(t) && save_exists(t)) mode = MODE_INSTALL_OVERWRITE;
    } else if (save_exists(t) || (!named && g_app.n_saves > 0)) {
        // Nothing is open: the saves there are offered before a new one is made. Without a NAME or
        // --save, the only save is offered, or one is picked from a list.
        if (!named && g_app.n_saves == 1) copy_str(g_app.save_target, g_app.saves[0].name, sizeof g_app.save_target);
        g_app.install_pick = !named && g_app.n_saves > 1;
        g_app.save_sel = 0;
        for (int i = 0; i < g_app.n_saves; i++)
            if (strcmp(g_app.saves[i].name, t) == 0) g_app.save_sel = i;
        mode = MODE_INSTALL_EXISTING;
    } else if (!named) {
        pick_random_save_name();
        mode = MODE_INSTALL_NAME;
    }
    g_app.install_back = g_app.mode == MODE_SETTINGS ? MODE_SETTINGS : MODE_CHAT;
    begin_prompt(mode);
    return 0;
}

static cmd_result_t app_install(void *ctx, const char *arg) {
    (void)ctx;
    g_app.install_for = 0;
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
    if (!save_exists(g_app.save_target)) {
        if (arg && arg[0]) note("nothing to uninstall - there's no save called %s", install_shown_name(g_app.save_target));
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

// Checked before CHAT_COMMANDS, so entries here shadow the per-session ones of the same name.
static const command_t APP_COMMANDS[] = {
    { "help",    NULL,                  NULL,     "list all commands and keybinds (F1)",          app_help },
    { "new",     NULL,                  NULL,     "create a session (Ctrl+N)",                       app_new },
    { "join",    NULL,                  NULL,     "join a session by id (Ctrl+J)",                   app_join },
    { "quit",    "q exit close bd bw",  NULL,     "leave this session; quits if none are open",       app_quit },
    { "quitall", "qa qall",             NULL,     "leave every session and quit (Ctrl+C)",           app_quitall },
    { "set",     NULL,        "[NAME [VALUE]]",   "change a setting; alone, opens them all (Ctrl+S)", app_set },
    { "copyid",  NULL,                  NULL,     "copy this session's id to the clipboard",         app_copyid },
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

static const command_t *const ALL_COMMANDS[] = { APP_COMMANDS, CHAT_COMMANDS, NULL };

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
    return n > 0 && n < 1000000 && (!*end || *anyway) ? (int)n : 0;
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
static void help_key(const tui_key_t *key) {
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

// Whether a command's name or one of its aliases starts with word (or, with whole, is word). A line
// opened with '/' that can't be a command stays as text, for a message that starts with '/'.
int command_word(const char *word, int whole) {
    size_t n = strlen(word);
    for (const command_t *const *t = ALL_COMMANDS; *t; t++) {
        for (const command_t *c = *t; c->name; c++) {
            if (whole ? strcmp(c->name, word) == 0 : strncmp(c->name, word, n) == 0) return 1;
            for (const char *a = c->aliases; a && *a; ) {
                size_t len = strcspn(a, " ");
                if ((whole ? len == n : len >= n) && strncmp(a, word, n) == 0) return 1;
                a += len;
                while (*a == ' ') a++;
            }
        }
    }
    return 0;
}

static int nick_has_prefix(const char *nick, const char *typed) {
    for (; *typed; nick++, typed++)
        if (tolower((unsigned char)*nick) != tolower((unsigned char)*typed)) return 0;
    return 1;
}

// The selected session's engine, once there is one to name peers from.
static chat_t *peer_engine(void) {
    if (g_app.mode != MODE_CHAT || !g_app.selected || g_app.selected->initialising) return NULL;
    return &g_app.selected->engine;
}

// First online peer whose nick starts with typed, ignoring case.
const char *complete_mention(const char *typed) {
    chat_t *e = peer_engine();
    if (!e) return NULL;
    for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS; i++) {
        peer_t *p = &e->peers[i];
        if (p->used && p->ok && nick_has_prefix(p->nick, typed)) return p->nick;
    }
    return NULL;
}

static const command_t *find_command(const char *word) {
    const command_t *c = cmd_find(APP_COMMANDS, word);
    return c ? c : cmd_find(CHAT_COMMANDS, word);
}

// What commands' arguments can be, in order, for the menu over the COMMAND line.
enum { A_NICK = 1, A_WORD, A_FILE, A_PATH, A_FOLDER, A_SAVE, A_TRUSTED, A_KIND = 0xf };

#define A_TYPED 0x10  // Enter fills it in only once some of it is typed

#define A_SKIP  0x20  // A_TYPED, and it can be left out with the next one in its place, so that's listed too

#define A_PICK  0x40  // Enter never fills it in: it's typed in full or picked in the menu

static const struct { const char *cmd; int args[4]; } COMMAND_ARGS[] = {
    { "verify",    { A_NICK, A_WORD | A_TYPED } },
    { "verified",  { A_WORD | A_TYPED, A_TRUSTED | A_PICK } },
    { "send",      { A_PATH | A_PICK } },
    { "download",  { A_FILE | A_SKIP, A_WORD | A_SKIP, A_FOLDER | A_PICK } },
    { "cancel",    { A_FILE | A_TYPED } },
    { "show",      { A_FILE, A_WORD | A_TYPED } },
    { "hide",      { A_FILE } },
    { "saveto",    { A_FILE, A_WORD | A_TYPED } },
    { "install",   { A_SAVE | A_TYPED } },
    { "uninstall", { A_SAVE | A_TYPED } },
};

static const struct { const char *cmd, *word, *help; } ARG_WORDS[] = {
    { "verify",   "ok",     "their code is the same - what you send reaches them" },
    { "verify",   "no",     "their code differs - nothing you send reaches them" },
    { "verified", "forget", "remove a verified key" },
    { "show",     "anyway", "even if it's over your file size limit" },
    { "saveto",   "anyway", "even if it's over your file size limit" },
    { "download", "anyway", "even if it's over your file size limit" },
};

// Bumped when the menu is listed from the start, so the folders and saves it reads are read again.
static unsigned g_menu_gen;

typedef struct {
    const command_t *c;
    const char *typed;
    int *nth;
    tui_suggestion_t *out;
    const char *after;  // " " when another argument can follow, so Tab brings up its menu
} arg_menu_t;

// The next item in the menu: the line up to at, then text. 1 if it's the one asked for, with out
// filled in but for help. One the line can't hold isn't listed.
static int arg_item(arg_menu_t *m, const char *at, const char *text, const char *name, const char *group) {
    int n = snprintf(m->out->line, sizeof m->out->line, "%.*s%s%s", (int)(at - m->typed), m->typed, text, m->after);
    if (n < 0 || (size_t)n >= sizeof m->out->line || (*m->nth)-- > 0) return 0;
    copy_str(m->out->name, name, sizeof m->out->name);
    copy_str(m->out->group, group, sizeof m->out->group);
    return 1;
}

// The online peers whose nick starts with typed, ignoring case. An exact match comes first, so
// Enter on "id" doesn't run it as "ida". The rest are sorted by nick.
static int match_peers(const chat_t *e, const char *typed, const peer_t **m) {
    size_t tn = strlen(typed);
    int n = 0;
    for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS; i++) {
        const peer_t *p = &e->peers[i];
        if (!p->used || !p->ok || !nick_has_prefix(p->nick, typed)) continue;
        int exact = strlen(p->nick) == tn, j = n++;
        for (; j > 0; j--) {
            int prev_exact = strlen(m[j - 1]->nick) == tn;
            if (prev_exact > exact || (prev_exact == exact && strcasecmp(m[j - 1]->nick, p->nick) <= 0)) break;
            m[j] = m[j - 1];
        }
        m[j] = p;
    }
    return n;
}

static int arg_nicks(arg_menu_t *m, const char *rest) {
    chat_t *e = peer_engine();
    const peer_t *p[MAX_PEERS + MAX_PENDING_PEERS];
    int n = e ? match_peers(e, rest, p) : 0;
    for (int i = 0; i < n; i++) {
        char name[CHAT_NAME_LEN]; chat_peer_name(e, p[i], name);
        if (!arg_item(m, rest, p[i]->nick, name, "peers")) continue;
        snprintf(m->out->help, sizeof m->out->help, "%s%s",
                 p[i]->identity_source == IDENT_NONE ? "unsigned" : chat_verify_label(p[i]->identity_state),
                 p[i]->build_state == BUILD_MODIFIED ? " \xc2\xb7 modified client" : "");
        return 1;
    }
    return 0;
}

static int arg_words(arg_menu_t *m, const char *rest) {
    for (size_t i = 0; i < sizeof ARG_WORDS / sizeof *ARG_WORDS; i++) {
        const char *w = ARG_WORDS[i].word;
        if (strcmp(ARG_WORDS[i].cmd, m->c->name) != 0 || strncmp(w, rest, strlen(rest)) != 0) continue;
        if (!arg_item(m, rest, w, w, m->c->name)) continue;
        copy_str(m->out->help, ARG_WORDS[i].help, sizeof m->out->help);
        return 1;
    }
    return 0;
}

// Whether file f is one the command can take.
static int file_fits(const command_t *c, const file_entry_t *f) {
    pic_t *p = pic_find(g_app.selected, f->num);
    if (strcmp(c->name, "show") == 0) return f->image && !(p && p->shown && p->th.rgb);
    if (strcmp(c->name, "hide") == 0) return p && p->shown && p->th.rgb;
    if (strcmp(c->name, "cancel") == 0) return f->mine ? f->fp != NULL : f->dl == DL_ACTIVE || f->dl == DL_QUEUED;
    return !f->mine;
}

// Files by number: the one with the number typed first, then the newest.
static int arg_files(arg_menu_t *m, const char *rest) {
    chat_t *e = peer_engine();
    const file_entry_t *l[FILE_OFFERS_MAX];
    size_t rn = strlen(rest);
    int n = 0, exact = e && rn ? atoi(rest) : 0;
    for (int i = 0; e && i < FILE_OFFERS_MAX; i++) {
        const file_entry_t *f = &e->files[i];
        char ns[12]; snprintf(ns, sizeof ns, "%d", f->num);
        if (!f->used || strncmp(ns, rest, rn) != 0 || !file_fits(m->c, f)) continue;
        int j = n++;
        for (; j > 0 && l[j - 1]->num != exact && (f->num == exact || l[j - 1]->num < f->num); j--) l[j] = l[j - 1];
        l[j] = f;
    }
    for (int i = 0; i < n; i++) {
        const file_entry_t *f = l[i];
        char ns[12]; snprintf(ns, sizeof ns, "%d", f->num);
        if (!arg_item(m, rest, ns, ns, "files")) continue;
        char sz[32]; file_format_size(f->size, sz, sizeof sz);
        snprintf(m->out->help, sizeof m->out->help, "%s \xc2\xb7 %s%s", f->name, sz,
                 f->mine ? " \xc2\xb7 yours" : f->dl == DL_ACTIVE ? " \xc2\xb7 fetching" : f->dl == DL_QUEUED ? " \xc2\xb7 queued"
                 : f->saved[0] ? " \xc2\xb7 saved" : "");
        return 1;
    }
    return 0;
}

// The files and folders (or only folders) in the folder typed so far, as typed_path reads it.
// Hidden ones once a '.' is typed.
static int arg_paths(arg_menu_t *m, const char *rest, int folders) {
    static browser_t dir;
    static unsigned gen;
    const char *base = strrchr(rest, '/');
    base = base ? base + 1 : rest;
    char path[sizeof dir.path];
    const char *home = platform_home_dir();
    if (base == rest) copy_str(path, ".", sizeof path);
    else if (rest[0] == '~' && rest[1] == '/' && home) snprintf(path, sizeof path, "%s%.*s", home, (int)(base - rest - 1), rest + 1);
    else snprintf(path, sizeof path, "%.*s", (int)(base - rest), rest);
    if (gen != g_menu_gen || strcmp(dir.path, path) != 0) {
        gen = g_menu_gen;
        if (browser_load(&dir, path) != 0) { dir.n_items = 0; copy_str(dir.path, path, sizeof dir.path); }
    }
    size_t bn = strlen(base);
    for (int i = 0; i < dir.n_items; i++) {
        const dir_entry_t *d = &dir.items[i];
        if ((folders && !d->is_dir) || (d->name[0] == '.' && base[0] != '.') || strncmp(d->name, base, bn) != 0) continue;
        if (!arg_item(m, base, d->name, d->name, folders ? "folders" : "your files")) continue;
        copy_str(m->out->help, d->is_dir ? "folder" : "", sizeof m->out->help);
        return 1;
    }
    return 0;
}

static int arg_saves(arg_menu_t *m, const char *rest) {
    static install_save_t saves[INSTALL_SAVES_MAX];
    static int n;
    static unsigned gen;
    if (gen != g_menu_gen) { gen = g_menu_gen; n = install_list(saves, INSTALL_SAVES_MAX); }
    for (int i = 0; i < n; i++) {
        const char *name = install_shown_name(saves[i].name);
        if (strncmp(name, rest, strlen(rest)) != 0 || !arg_item(m, rest, name, name, "saves")) continue;
        snprintf(m->out->help, sizeof m->out->help, "saved %s%s", saves[i].modified,
                 g_app.installed && is_current_save(saves[i].name) ? " \xc2\xb7 open" : "");
        return 1;
    }
    return 0;
}

// The nicks of the verified keys, each once, then "all".
static int arg_trusted(arg_menu_t *m, const char *rest) {
    int n = trust_count();
    for (int i = 0; i < n; i++) {
        const char *nick = trust_at(i)->nick;
        int keys = 0, seen = 0;
        for (int j = 0; j < n; j++) {
            const trust_entry_t *t = trust_at(j);
            if (!t || strcmp(t->nick, nick) != 0) continue;
            keys++;
            seen |= j < i;
        }
        if (seen || !nick_has_prefix(nick, rest) || !arg_item(m, rest, nick, nick, "verified")) continue;
        snprintf(m->out->help, sizeof m->out->help, "%d verified key%s", keys, keys == 1 ? "" : "s");
        return 1;
    }
    if (n == 0 || strncmp("all", rest, strlen(rest)) != 0 || !arg_item(m, rest, "all", "all", "verified")) return 0;
    copy_str(m->out->help, "every verified key", sizeof m->out->help);
    return 1;
}

// Where the argument after a whole one of this kind at the start of rest begins, past its space, or
// NULL. Nicks can have spaces, so it's after the longest online one there. Paths, saves and
// verified nicks take the rest of the line.
static const char *arg_end(const command_t *c, int kind, const char *rest) {
    size_t n = 0;
    if (kind == A_FILE) n = strspn(rest, "0123456789");
    else if (kind == A_WORD) {
        for (size_t i = 0; i < sizeof ARG_WORDS / sizeof *ARG_WORDS; i++) {
            size_t wl = strlen(ARG_WORDS[i].word);
            if (strcmp(ARG_WORDS[i].cmd, c->name) == 0 && strncmp(rest, ARG_WORDS[i].word, wl) == 0) n = wl;
        }
    } else if (kind == A_NICK) {
        chat_t *e = peer_engine();
        for (int i = 0; e && i < MAX_PEERS + MAX_PENDING_PEERS; i++) {
            const peer_t *p = &e->peers[i];
            size_t pl = strlen(p->nick);
            if (p->used && p->ok && pl > n && nick_has_prefix(rest, p->nick) && rest[pl] == ' ') n = pl;
        }
    }
    return n > 0 && rest[n] == ' ' ? rest + n + 1 : NULL;
}

// The menu for args[0], with rest typed for it: what it can be, then what can follow once rest
// holds a whole one, then (if it can be left out) what can come in its place.
static int arg_suggest(arg_menu_t *m, const int *args, const char *rest) {
    int a = args[0], k = a & A_KIND, found = 0;
    if (!a) return 0;
    m->after = args[1] ? " " : "";
    switch (k) {
        case A_NICK: found = arg_nicks(m, rest); break;
        case A_WORD: found = arg_words(m, rest); break;
        case A_FILE: found = arg_files(m, rest); break;
        case A_PATH: case A_FOLDER: found = arg_paths(m, rest, k == A_FOLDER); break;
        case A_SAVE: found = arg_saves(m, rest); break;
        case A_TRUSTED: found = arg_trusted(m, rest); break;
    }
    if (found) {
        m->out->no_default = (a & A_PICK) || ((a & (A_TYPED | A_SKIP)) && !*rest);
        return 1;
    }
    const char *next = arg_end(m->c, k, rest);
    if (next && arg_suggest(m, args + 1, next)) return 1;
    return (a & A_SKIP) && arg_suggest(m, args + 1, rest);
}

// The menu above the COMMAND line: commands by name. After "set ", the settings with their current
// values. After "set NAME ", the values it takes. After other commands, what their arguments can be.
int suggest_command(const char *typed, int nth, tui_suggestion_t *out) {
    memset(out, 0, sizeof *out);
    if (nth == 0) g_menu_gen++;
    size_t wn = strcspn(typed, " ");
    char word[CMD_WORD_MAX];
    if (typed[wn] == ' ' && wn < sizeof word) {
        memcpy(word, typed, wn);
        word[wn] = '\0';
        const command_t *c = find_command(word);
        for (size_t i = 0; c && i < sizeof COMMAND_ARGS / sizeof *COMMAND_ARGS; i++) {
            if (strcmp(COMMAND_ARGS[i].cmd, c->name) != 0) continue;
            arg_menu_t m = { c, typed, &nth, out, "" };
            return arg_suggest(&m, COMMAND_ARGS[i].args, typed + wn + 1);
        }
    }
    if (strncmp(typed, "set ", 4) == 0) {
        copy_str(out->group, "settings", sizeof out->group);
        const char *key = typed + 4, *sp = strchr(key, ' ');
        const char *const *names;
        int n;
        if (sp) {
            char name[CMD_WORD_MAX];
            size_t kl = (size_t)(sp - key);
            if (kl >= sizeof name) return 0;
            memcpy(name, key, kl);
            name[kl] = '\0';
            const setting_def_t *d = setting_by_key(name);
            int cur = d ? setting_choices(d->id, &names, &n) : -1;
            if (cur < 0) return 0;
            const char *v = sp + 1;
            for (int i = 0; i < n; i++) {
                if (strncmp(names[i], v, strlen(v)) != 0 || nth-- > 0) continue;
                snprintf(out->line, sizeof out->line, "set %s %s", d->key, names[i]);
                copy_str(out->name, names[i], sizeof out->name);
                snprintf(out->help, sizeof out->help, "%s%s", d->label, i == cur ? " \xc2\xb7 now" : "");
                return 1;
            }
            return 0;
        }
        size_t kn = strlen(key);
        for (int i = 0; i < N_SETTINGS; i++) {
            const setting_def_t *d = &SETTINGS[i];
            if (strncmp(d->key, key, kn) != 0 || nth-- > 0) continue;
            int takes = setting_choices(d->id, &names, &n) >= 0 || d->kind == K_TEXT;
            snprintf(out->line, sizeof out->line, "set %s%s", d->key, takes ? " " : "");
            snprintf(out->name, sizeof out->name, "set %s", d->key);
            copy_str(out->args, d->values ? d->values : "", sizeof out->args);
            char v[96]; setting_value(d->id, v, sizeof v);
            snprintf(out->help, sizeof out->help, "%s \xc2\xb7 %s", d->label, v);
            return 1;
        }
        return 0;
    }
    if (strchr(typed, ' ')) return 0;
    copy_str(out->group, "commands", sizeof out->group);
    size_t tn = strlen(typed);
    for (const command_t *const *t = ALL_COMMANDS; *t; t++) {
        for (const command_t *c = *t; c->name; c++) {
            if (*t != APP_COMMANDS && cmd_find(APP_COMMANDS, c->name)) continue;
            if (strncmp(c->name, typed, tn) != 0 || nth-- > 0) continue;
            snprintf(out->line, sizeof out->line, "%s%s", c->name, c->args ? " " : "");
            copy_str(out->name, c->name, sizeof out->name);
            copy_str(out->args, c->args ? c->args : "", sizeof out->args);
            copy_str(out->help, c->help, sizeof out->help);
            return 1;
        }
    }
    return 0;
}

// Runs "name args" typed on the COMMAND line, after ':'.
static void run_command(const char *line) {
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
    if (strcmp(word, "send") == 0 && !arg[strspn(arg, " ")]) { begin_send_browse(); return; }
    g_echo = strcmp(word, "download") == 0 || strcmp(word, "dl") == 0 || strcmp(word, "cancel") == 0 || strcmp(word, "send") == 0;
    cmd_result_t r = chat_run_command(&g_app.selected->engine, line);
    g_echo = 0;
    if (r == CMD_QUIT) close_session(g_app.selected);
}

static void submit_prompt(void) {
    tui_input_t *input = &g_app.input;
    switch (g_app.mode) {
        case MODE_NEW_PASSWORD: {
            char session_id[MAX_SESSION_NAME + 1], pw[sizeof input->buf];
            random_session_id(session_id, 10);
            copy_str(pw, input->buf, sizeof pw);
            end_prompt();
            start_session(session_id, pw, 1, 0, NULL, 0);
            crypto_wipe(pw, sizeof pw);
            break;
        }
        case MODE_JOIN_ID:
            if (input->len == 0) break;
            copy_str(g_app.pending_session_id, input->buf, sizeof g_app.pending_session_id);
            tui_input_clear(input);
            g_app.mode = MODE_JOIN_PASSWORD;
            g_app.dirty = 1;
            break;
        case MODE_JOIN_PASSWORD: {
            char session_id[MAX_SESSION_NAME + 1], pw[sizeof input->buf];
            copy_str(session_id, g_app.pending_session_id, sizeof session_id);
            copy_str(pw, input->buf, sizeof pw);
            end_prompt();
            start_session(session_id, pw, 0, 0, NULL, 0);
            crypto_wipe(pw, sizeof pw);
            break;
        }
        default:
            break;
    }
}

static void submit_chat_line(void) {
    tui_input_t *input = &g_app.input;
    g_app.dirty = 1;

    if (input->mode == TUI_IMODE_COMMAND) {
        char line[sizeof input->cmd];
        copy_str(line, input->cmd, sizeof line);
        // Enter on a line the menu would complete runs what the menu has selected, so ":se" runs ":set",
        // as the menu shows.
        tui_suggestion_t s;
        size_t n = strlen(line);
        if ((n > 0 || input->menu_sel > 0) && tui_input_completion(input, &s)) copy_str(line, s.line, sizeof line);
        // Completing an argument leaves a space for the next one, which ":verify NICK " would take as
        // part of the nick.
        n = strlen(line);
        while (n > 0 && line[n - 1] == ' ') line[--n] = '\0';
        // If opened by typing '/', a line that turns out not to be a command is the start of a message.
        // It goes back in the input as text, for Enter to send.
        char word[CMD_WORD_MAX];
        cmd_parse(line, word);
        if (input->cmd_as_text && line[0] && !command_word(word, 1)) {
            tui_input_command_to_text(input);
            crypto_wipe(line, sizeof line);
            return;
        }
        tui_input_end_command(input);
        crypto_wipe(input->cmd, sizeof input->cmd);
        run_command(line);
        crypto_wipe(line, sizeof line);
        return;
    }

    const char *text = input->buf;
    while (*text == ' ') text++;
    if (!text[0]) return;
    if (!g_app.selected) {
        note("no session yet - ctrl+n starts one, ctrl+j joins one");
        return;
    }
    if (!session_ready(g_app.selected)) {
        note(g_app.selected->initialising ? "still starting - hold on a moment"
                                          : "not connected yet - your text is kept until someone answers");
        return;
    }
    // Over the limit the end would be cut off when sent. The count under the box is red, and this
    // explains why Enter didn't send.
    if (input->len > MAX_TEXT) {
        note("too long to send by %d - a message holds %d bytes", input->len - MAX_TEXT, MAX_TEXT);
        return;
    }
    chat_send_text(&g_app.selected->engine, input->buf, now_seconds());
    tui_input_clear(input);
    g_app.selected->scroll = 0;
    // Sending a reply counts as reading, so the new messages line is removed.
    g_app.selected->has_new = 0;
}

// PgUp and PgDn (Ctrl+U and Ctrl+D in NORMAL) scroll the chat by a third of the screen's rows. G
// goes back to the newest.
static void scroll_chat(int dir) {
    session_slot_t *s = g_app.selected;
    if (!s) return;
    int rows_n, cols_n;
    term_get_size(&rows_n, &cols_n);
    int page = rows_n / 3 > 1 ? rows_n / 3 : 1;
    long v = dir == 0 ? 0 : (long)s->scroll + (long)dir * page;
    if (v > s->sb.count - 1) v = s->sb.count - 1;
    if (v < 0) v = 0;
    s->scroll = (int)v;
    g_app.dirty = 1;
}

void handle_key(const tui_key_t *key) {
    tui_input_t *input = &g_app.input;

    // The terminal's reports aren't keys, so they don't clear the bar's message.
    if (key->type == TUI_KEY_BG_REPORT) {
        tui_set_background((const uint8_t *)key->ch);
        g_app.dirty = 1;
        return;
    }
    if (key->type == TUI_KEY_THEME_CHANGED) {
        platform_write_stdout(TUI_THEME_QUERY, sizeof TUI_THEME_QUERY - 1);
        g_app.dirty = 1;
        return;
    }

    // A message is the result of the previous key, so this key resets the bar.
    if (g_app.message[0]) { g_app.message[0] = '\0'; g_app.dirty = 1; }

    if (key->type == TUI_KEY_CTRL_C) { g_app.asking_quit = 1; g_app.dirty = 1; return; }
    if (g_app.asking_quit) { quit_key(key); return; }

    // The pages draw their fields in their rows, so a key there redraws the page.
    switch (g_app.mode) {
        case MODE_HELP:            help_key(key); return;
        case MODE_CHANGELOG:       changelog_key(key); return;
        case MODE_SETTINGS:        settings_key(key); return;
        case MODE_SIGN_CHOICE:     sign_picker_key(key); return;
        case MODE_SIGN_BROWSE: browser_key(key); return;
        case MODE_SEND_BROWSE: send_browser_key(key); return;
        case MODE_SAVE_BROWSE: save_browser_key(key); return;
        case MODE_FILES:       files_key(key); return;
        case MODE_FILE_VIEW:   viewer_key(key); return;
        case MODE_FILE_ASK:    confirm_key(key, file_ask_yes, file_ask_no); return;
        case MODE_SIGN_PASTE:  paste_key(key); return;
        case MODE_SIGN_PASSWORD:  field_key(key, commit_sign_password, end_sign_password); return;
        case MODE_SIGN_PATH:      field_key(key, commit_key_path, end_key_path); return;
        case MODE_SETTINGS_EDIT:  field_key(key, commit_setting_edit, end_setting_edit); return;
        case MODE_NEW_PASSWORD:
        case MODE_JOIN_ID:
        case MODE_JOIN_PASSWORD:  field_key(key, submit_prompt, end_prompt); return;
        case MODE_INSTALL:        confirm_key(key, install_confirmed, cancel_install); return;
        case MODE_INSTALL_PASS:   field_key(key, commit_install_pass, cancel_install); return;
        case MODE_INSTALL_PASS2:  field_key(key, commit_install_pass2, cancel_install); return;
        case MODE_INSTALL_UNLOCK: field_key(key, commit_install_unlock, back_from_install_unlock); return;
        case MODE_INSTALL_EXISTING:  choice_key(key, install_use_existing, install_new_save, cancel_install); return;
        case MODE_INSTALL_PICK:      install_pick_key(key); return;
        case MODE_INSTALL_OVERWRITE: confirm_key(key, install_overwrite_yes, cancel_install); return;
        case MODE_INSTALL_NAME:   field_key(key, commit_install_name, back_from_install_name); return;
        case MODE_INSTALL_FIRST:  confirm_key(key, install_first_yes, install_first_no); return;
        case MODE_UNINSTALL:      confirm_key(key, uninstall_confirmed, cancel_uninstall); return;
        case MODE_SAVES:          saves_key(key); return;
        case MODE_UNLOCK:         field_key(key, commit_unlock, back_from_unlock); return;
        case MODE_DEVICE_LOCK:    confirm_key(key, device_lock_yes, device_lock_no); return;
        case MODE_FACTOR:         confirm_key(key, factor_yes, factor_no); return;
        case MODE_CODE_SETUP:     code_setup_key(key); return;
        case MODE_KEY_WAIT:       key_wait_key(key); return;
        case MODE_KEY_PIN:        field_key(key, commit_key_pin, cancel_key_pin); return;
        case MODE_UNLOCK_CODE:    field_key(key, commit_unlock_code, back_from_unlock_code); return;
        case MODE_SHADOW_PASS:    field_key(key, commit_shadow_pass, cancel_shadow_pass); return;
        case MODE_SHADOW_PASS2:   field_key(key, commit_shadow_pass2, cancel_shadow_pass); return;
        case MODE_UPDATE:         update_key(key); return;
        default:
            break;
    }

    tui_input_mode_t was = input->mode;
    if (tui_input_feed(input, key)) {
        // The menu above the COMMAND line covers part of the chat, so it needs a full frame.
        if (was == TUI_IMODE_COMMAND || input->mode == TUI_IMODE_COMMAND) g_app.dirty = 1;
        else g_app.input_dirty = 1;
        return;
    }

    // NORMAL leaves these to the app: j and k switch sessions, like moving through a list, G goes back
    // to the newest message, ? opens the help, f the files, and c, C and s show or hide the console,
    // the chat and the sidebar.
    if (key->type == TUI_KEY_CHAR && input->mode == TUI_IMODE_NORMAL) {
        switch (key->ch[0]) {
            case 'j': select_step(1); break;
            case 'k': select_step(-1); break;
            case 'G': scroll_chat(0); break;
            case '?': begin_help(); break;
            case 'f': begin_files(); break;
            case 'c': g_app.show_console = !g_app.show_console; g_app.dirty = 1; break;
            case 'C': g_app.show_chat = !g_app.show_chat; g_app.dirty = 1; break;
            case 's': g_app.show_sidebar = !g_app.show_sidebar; g_app.dirty = 1; break;
            default: break;
        }
        return;
    }

    switch (key->type) {
        case TUI_KEY_TAB:            select_step(1); break;
        case TUI_KEY_BACKTAB:        select_step(-1); break;
        case TUI_KEY_NEW_SESSION:    begin_prompt(MODE_NEW_PASSWORD); break;
        case TUI_KEY_JOIN_SESSION:   begin_prompt(MODE_JOIN_ID); break;
        case TUI_KEY_TOGGLE_SIDEBAR: g_app.show_sidebar = !g_app.show_sidebar; g_app.dirty = 1; break;
        case TUI_KEY_TOGGLE_CONSOLE: g_app.show_console = !g_app.show_console; g_app.dirty = 1; break;
        case TUI_KEY_TOGGLE_CHAT:    g_app.show_chat = !g_app.show_chat; g_app.dirty = 1; break;
        case TUI_KEY_SETTINGS:       begin_settings(); break;
        case TUI_KEY_HELP:           begin_help(); break;
        case TUI_KEY_FILES:          begin_files(); break;
        case TUI_KEY_PAGE_UP:
        case TUI_KEY_CTRL_U:         scroll_chat(1); break;
        case TUI_KEY_PAGE_DOWN:
        case TUI_KEY_CTRL_D:         scroll_chat(-1); break;
        case TUI_KEY_ENTER:          submit_chat_line(); break;
        default: break;
    }
}

// :install's own boxes, over the page install_back says.
int install_mode(app_mode_t m) {
    switch (m) {
        case MODE_INSTALL: case MODE_INSTALL_PASS: case MODE_INSTALL_PASS2: case MODE_INSTALL_UNLOCK:
        case MODE_INSTALL_EXISTING: case MODE_INSTALL_PICK: case MODE_INSTALL_OVERWRITE: case MODE_INSTALL_NAME:
        case MODE_INSTALL_FIRST:
            return 1;
        case MODE_UNLOCK_CODE:
            return g_app.key_purpose == KP_INSTALL_UNLOCK;
        default:
            return 0;
    }
}

int on_chat_screen(void) {
    if (install_mode(g_app.mode)) return g_app.install_back == MODE_CHAT;
    switch (g_app.mode) {
        case MODE_CHAT: case MODE_NEW_PASSWORD: case MODE_JOIN_ID: case MODE_JOIN_PASSWORD:
        case MODE_UNINSTALL: case MODE_SAVES: case MODE_UNLOCK: case MODE_UPDATE: case MODE_UNLOCK_CODE:
            return 1;
        case MODE_DEVICE_LOCK:
            return g_app.device_back == MODE_CHAT;
        case MODE_FACTOR: case MODE_CODE_SETUP: case MODE_KEY_WAIT: case MODE_KEY_PIN:
        case MODE_SHADOW_PASS: case MODE_SHADOW_PASS2:
            return g_app.factor_back == MODE_CHAT;
        default:
            return 0;
    }
}

static int session_count(void) {
    int n = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) n += g_app.used[i] != 0;
    return n;
}

tui_session_state_t session_state(const session_slot_t *s) {
    if (s->initialising) return TUI_SESSION_STARTING;
    return chat_ready(&s->engine) ? TUI_SESSION_LIVE : TUI_SESSION_CONNECTING;
}

// What the chat shows while a session has no messages: its progress, and what to do next.
static const char *session_empty_text(const session_slot_t *s) {
    static char text[400];
    const chat_t *e = &s->engine;
    if (s->initialising)
        copy_str(text, "Starting the session\nDeriving its keys - this takes a moment.", sizeof text);
    else if (!chat_ready(e))
        snprintf(text, sizeof text, "Connecting to %s\nThe chat opens once someone in the session answers.\n"
                 "Finding them can take a minute%s.", s->name, e->route.mode == ROUTE_TOR ? " over Tor" : "");
    else if (chat_online_count(e) == 0)
        snprintf(text, sizeof text, "No one else is here yet\nTo invite peers, share the session id and its "
                 "password.\n\n%s\n/copyid copies the id", s->name);
    else
        copy_str(text, "No messages yet\nSay hello - it's end-to-end encrypted.", sizeof text);
    return text;
}

// The chat pane: the selected session's name, how it's connected, what to show while it's empty,
// where the messages that arrived while it was away start, and unread counts for other sessions.
tui_view_t current_view(char *sub, size_t cap) {
    tui_view_t v = { g_app.show_sidebar, g_app.show_console, g_app.show_chat, NULL, NULL, TUI_SESSION_LIVE,
                     NULL, NULL, 0, NULL, NULL, NULL, 0, 0, 0, NULL, TEST_BUILD ? TEST_LABEL : NULL };
    for (int i = 0; i < MAX_SESSIONS; i++) {
        const session_slot_t *o = &g_app.sessions[i];
        if (!g_app.used[i] || o == g_app.selected) continue;
        v.elsewhere += o->unread;
        v.elsewhere_mention |= o->mentioned;
    }
    const session_slot_t *s = g_app.selected;
    if (!s) return v;
    v.title = s->name;
    v.state = session_state(s);
    v.scroll = s->scroll;
    v.empty = session_empty_text(s);
    v.image = pic_for;
    v.image_ctx = s;
    if (!s->initialising) {
        v.self = s->engine.nick;
        v.progress = progress_for;
    }
    if (s->has_new) v.new_lines = (int)(s->sb.total - s->new_at);
    if (s->initialising) snprintf(sub, cap, "starting");
    else snprintf(sub, cap, "%d online \xc2\xb7 %s", chat_online_count(&s->engine) + 1, routing_mode_name(s->engine.route.mode));
    v.subtitle = sub;
    return v;
}

// Who in s doesn't get what you send until their verify code is compared, for the input box's title
// while that's the case, since the console's note that a message went to nobody is easy to miss.
// NULL when everyone gets it, or the setting sends to everyone anyway.
static const char *held_warning(const session_slot_t *s) {
    static char warn[64 + CHAT_NAME_LEN * 2];
    if (!s || !session_ready(s) || !s->engine.verify_required) return NULL;
    const chat_t *e = &s->engine;
    int held = 0;
    char first[CHAT_NAME_LEN] = "";
    for (int i = 0; i < MAX_PEERS + MAX_PENDING_PEERS; i++) {
        const peer_t *p = &e->peers[i];
        int code = chat_code_state(e, p);
        if (!p->used || !p->ok || (code != 1 && !(code == 4 && e->verify_required))) continue;
        if (held++ == 0) chat_peer_name(e, p, first);
    }
    if (held == 0) return NULL;
    if (held == 1)
        snprintf(warn, sizeof warn, "not sent to %s until you compare codes \xc2\xb7 :verify %s", first, first);
    else
        snprintf(warn, sizeof warn, "not sent to %d peers until you compare codes \xc2\xb7 :peers", held);
    return warn;
}

// The chat screen's input: its faint text while it's empty, and what the keys do there.
void chat_input(tui_bar_t *b, const tui_input_t *in) {
    static char placeholder[MAX_SESSION_NAME + 64];
    static char hint[160];
    const session_slot_t *s = g_app.selected;
    tui_input_mode_t m = in->mode;
    b->chip = tui_mode_name(m);
    b->tone = m == TUI_IMODE_NORMAL ? TUI_TONE_NORMAL : m == TUI_IMODE_COMMAND ? TUI_TONE_COMMAND : TUI_TONE_INSERT;
    b->input = in;
    b->limit = MAX_TEXT;
    b->warn = held_warning(s);
    if (m == TUI_IMODE_NORMAL) {
        b->placeholder = "i to type \xc2\xb7 : for a command";
        b->hint = s && !s->initialising ? "i type \xc2\xb7 : command \xc2\xb7 f files \xc2\xb7 j/k session \xc2\xb7 pgup/pgdn scroll \xc2\xb7 ? help"
                                        : "i type \xc2\xb7 : command \xc2\xb7 j/k session \xc2\xb7 pgup/pgdn scroll \xc2\xb7 ? help";
        return;
    }
    if (m == TUI_IMODE_COMMAND) {
        b->hint = "enter run \xc2\xb7 tab complete \xc2\xb7 \xe2\x86\x91\xe2\x86\x93 choose \xc2\xb7 esc back";
        return;
    }
    if (!s) {
        b->placeholder = "No session yet \xc2\xb7 ctrl+n starts one, ctrl+j joins one, / for commands";
        b->hint = "ctrl+n new \xc2\xb7 ctrl+j join \xc2\xb7 / commands \xc2\xb7 ctrl+s settings";
        return;
    }
    if (s->initialising) snprintf(placeholder, sizeof placeholder, "Starting %s\xe2\x80\xa6", s->name);
    else if (!session_ready(s)) snprintf(placeholder, sizeof placeholder, "Waiting for someone in %s to answer\xe2\x80\xa6", s->name);
    else snprintf(placeholder, sizeof placeholder, "Message %s", s->name);
    b->placeholder = placeholder;
    snprintf(hint, sizeof hint, "enter send \xc2\xb7 / commands%s%s \xc2\xb7 esc normal \xc2\xb7 f1 help",
             session_count() > 1 ? " \xc2\xb7 tab next session" : "",
             !s->initialising && s->engine.file_seq > 0 ? " \xc2\xb7 ctrl+f files" : "");
    b->hint = hint;
}
