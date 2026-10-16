// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The command line: completing a command, a nick or an argument, and the menu over the input box
// of what can go next.
#include "app/app.h"

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
    return g_app.selected->engine;
}

// First online peer whose nick starts with typed, ignoring case.
const char *complete_mention(const char *typed) {
    chat_t *e = peer_engine();
    if (!e) return NULL;
    for (int i = 0; i < CHAT_PEER_SLOTS; i++) {
        const peer_t *p = chat_peer_at(e, i);
        if (p && nick_has_prefix(chat_peer_nick(p), typed)) return chat_peer_nick(p);
    }
    return NULL;
}

static const command_t *find_command(const char *word) {
    const command_t *c = cmd_find(APP_COMMANDS, word);
    return c ? c : cmd_find(CHAT_COMMANDS, word);
}

// What commands' arguments can be, in order, for the menu over the COMMAND line.
enum { A_NICK = 1, A_WORD, A_FILE, A_PATH, A_FOLDER, A_SAVE, A_TRUSTED, A_CONTACT, A_KIND = 0xf };

#define A_TYPED 0x10  // Enter fills it in only once some of it is typed

#define A_SKIP  0x20  // A_TYPED, and it can be left out with the next one in its place, so that's listed too

#define A_PICK  0x40  // Enter never fills it in: it's typed in full or picked in the menu

static const struct { const char *cmd; int args[4]; } COMMAND_ARGS[] = {
    { "verify",    { A_NICK, A_WORD | A_TYPED } },
    { "ignore",    { A_NICK, A_WORD | A_TYPED } },
    { "msg",       { A_NICK, A_WORD | A_TYPED } },
    { "reply",     { A_NICK, A_WORD | A_TYPED } },
    { "verified",  { A_WORD | A_TYPED, A_TRUSTED | A_PICK } },
    { "send",      { A_WORD | A_SKIP, A_PATH | A_PICK } },
    { "download",  { A_FILE | A_SKIP, A_WORD | A_SKIP, A_FOLDER | A_PICK } },
    { "cancel",    { A_FILE | A_TYPED } },
    { "show",      { A_FILE, A_WORD | A_TYPED } },
    { "hide",      { A_FILE } },
    { "saveto",    { A_FILE, A_WORD | A_TYPED } },
    { "install",   { A_SAVE | A_TYPED } },
    { "uninstall", { A_SAVE | A_TYPED } },
    { "keep",      { A_WORD | A_TYPED } },
    { "call",      { A_CONTACT } },
};

static const struct { const char *cmd, *word, *help; } ARG_WORDS[] = {
    { "verify",   "ok",     "their code is the same - what you send reaches them" },
    { "verify",   "no",     "their code differs - nothing you send reaches them" },
    { "verified", "forget", "remove a verified key" },
    { "ignore",   "off",    "show what they say again" },
    { "send",     "asis",   "as it is: a picture keeps what it holds about where, when and with what it was made" },
    { "show",     "anyway", "even if it's over your file size limit" },
    { "saveto",   "anyway", "even if it's over your file size limit" },
    { "download", "anyway", "even if it's over your file size limit" },
    { "keep",     "forget", "stop keeping this room in the save" },
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
    for (int i = 0; i < CHAT_PEER_SLOTS; i++) {
        const peer_t *p = chat_peer_at(e, i);
        if (!p || !nick_has_prefix(chat_peer_nick(p), typed)) continue;
        int exact = strlen(chat_peer_nick(p)) == tn, j = n++;
        for (; j > 0; j--) {
            int prev_exact = strlen(chat_peer_nick(m[j - 1])) == tn;
            if (prev_exact > exact || (prev_exact == exact && strcasecmp(chat_peer_nick(m[j - 1]), chat_peer_nick(p)) <= 0)) break;
            m[j] = m[j - 1];
        }
        m[j] = p;
    }
    return n;
}

static int arg_nicks(arg_menu_t *m, const char *rest) {
    chat_t *e = peer_engine();
    const peer_t *p[CHAT_PEER_SLOTS];
    int n = e ? match_peers(e, rest, p) : 0;
    for (int i = 0; i < n; i++) {
        char name[CHAT_NAME_LEN]; chat_peer_name(e, p[i], name);
        if (!arg_item(m, rest, chat_peer_nick(p[i]), name, "peers")) continue;
        snprintf(m->out->help, sizeof m->out->help, "%s%s",
                 chat_peer_identity_source(p[i]) == IDENT_NONE ? "unsigned" : chat_verify_label(chat_peer_verify_state(p[i])),
                 chat_peer_build_state(p[i]) == BUILD_MODIFIED ? DOT_SEP "modified client" : "");
        return 1;
    }
    return 0;
}

static int arg_words(arg_menu_t *m, const char *rest) {
    for (size_t i = 0; i < COUNT_OF(ARG_WORDS); i++) {
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
        const file_entry_t *f = chat_file_at(e, i);
        if (!f) continue;
        char ns[12]; snprintf(ns, sizeof ns, "%d", f->num);
        if (strncmp(ns, rest, rn) != 0 || !file_fits(m->c, f)) continue;
        int j = n++;
        for (; j > 0 && l[j - 1]->num != exact && (f->num == exact || l[j - 1]->num < f->num); j--) l[j] = l[j - 1];
        l[j] = f;
    }
    for (int i = 0; i < n; i++) {
        const file_entry_t *f = l[i];
        char ns[12]; snprintf(ns, sizeof ns, "%d", f->num);
        if (!arg_item(m, rest, ns, ns, "files")) continue;
        char sz[32]; file_format_size(f->size, sz, sizeof sz);
        snprintf(m->out->help, sizeof m->out->help, "%s" DOT_SEP "%s%s", f->name, sz,
                 f->mine ? DOT_SEP "yours" : f->dl == DL_ACTIVE ? DOT_SEP "fetching" : f->dl == DL_QUEUED ? DOT_SEP "queued"
                 : f->saved[0] ? DOT_SEP "saved" : "");
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
                 g_app.installed && is_current_save(saves[i].name) ? DOT_SEP "open" : "");
        return 1;
    }
    return 0;
}

// The nicks of the verified keys, each once, then "all".
// all: "all" is listed after them, for :verified forget.
static int arg_trusted(arg_menu_t *m, const char *rest, int all) {
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
    if (!all || n == 0 || strncmp("all", rest, strlen(rest)) != 0 || !arg_item(m, rest, "all", "all", "verified"))
        return 0;
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
        for (size_t i = 0; i < COUNT_OF(ARG_WORDS); i++) {
            size_t wl = strlen(ARG_WORDS[i].word);
            if (strcmp(ARG_WORDS[i].cmd, c->name) == 0 && strncmp(rest, ARG_WORDS[i].word, wl) == 0) n = wl;
        }
    } else if (kind == A_NICK) {
        chat_t *e = peer_engine();
        for (int i = 0; e && i < CHAT_PEER_SLOTS; i++) {
            const peer_t *p = chat_peer_at(e, i);
            if (!p) continue;
            size_t pl = strlen(chat_peer_nick(p));
            if (pl > n && nick_has_prefix(rest, chat_peer_nick(p)) && rest[pl] == ' ') n = pl;
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
        case A_TRUSTED: found = arg_trusted(m, rest, 1); break;
        case A_CONTACT: found = arg_trusted(m, rest, 0); break;
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
        for (size_t i = 0; c && i < COUNT_OF(COMMAND_ARGS); i++) {
            if (strcmp(COMMAND_ARGS[i].cmd, c->name) != 0) continue;
            arg_menu_t m = { c, typed, &nth, out, "" };
            return arg_suggest(&m, COMMAND_ARGS[i].args, typed + wn + 1);
        }
    }
    static const char set[] = "set ";
    if (starts_with(typed, set)) {
        copy_str(out->group, "settings", sizeof out->group);
        const char *key = typed + sizeof set - 1, *sp = strchr(key, ' ');
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
                snprintf(out->help, sizeof out->help, "%s%s", d->label, i == cur ? DOT_SEP "now" : "");
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
            snprintf(out->help, sizeof out->help, "%s" DOT_SEP "%s", d->label, v);
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
