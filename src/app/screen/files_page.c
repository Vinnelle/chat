// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The files page, and a picture on a page of its own.
#include "app/app.h"

typedef enum { FS_NEW, FS_OVER, FS_COMING, FS_QUEUED, FS_FAILED, FS_SAVED, FS_HERE, FS_BROKEN, FS_MINE } file_state_t;

// What a y/n box over the files page or the picture asks.
enum { ASK_VIEW = 1, ASK_SHOW, ASK_FETCH, ASK_RETRY, ASK_SAVETO, ASK_STOP, ASK_UNOFFER };

static const pic_t *pic_of(const session_slot_t *s, int num) {
    for (int i = 0; i < MAX_PICS; i++) if (s->pics[i].used && s->pics[i].num == num) return &s->pics[i];
    return NULL;
}

static file_state_t file_state(const session_slot_t *s, const file_entry_t *f) {
    if (f->mine) return FS_MINE;
    if (f->dl == DL_ACTIVE) return FS_COMING;
    if (f->dl == DL_QUEUED) return FS_QUEUED;
    if (f->dl == DL_FAILED) return FS_FAILED;
    if (f->saved[0]) return FS_SAVED;
    const pic_t *p = pic_of(s, f->num);
    if (f->cache || (p && p->th.rgb)) return FS_HERE;
    if (p && p->why[0]) return FS_BROKEN;
    return f->size > chat_file_cap(s->engine) ? FS_OVER : FS_NEW;
}

// Fetching f now would take it past the size limit: it's over, and there's no copy here to use instead.
static int file_needs_anyway(const session_slot_t *s, const file_entry_t *f) {
    return !f->mine && f->size > chat_file_cap(s->engine) && !f->cache && !f->saved[0] && f->dl != DL_ACTIVE && f->dl != DL_QUEUED;
}

static int file_cmp(const void *a, const void *b) {
    const file_entry_t *x = *(const file_entry_t *const *)a, *y = *(const file_entry_t *const *)b;
    return x->mine != y->mine ? x->mine - y->mine : y->num - x->num;
}

// The session's files in the page's order: those offered to you, then yours, newest first.
static int files_list(const session_slot_t *s, const file_entry_t **l) {
    int n = 0;
    for (int i = 0; s && !s->initialising && i < FILE_OFFERS_MAX; i++) {
        const file_entry_t *f = chat_file_at(s->engine, i);
        if (f) l[n++] = f;
    }
    qsort(l, (size_t)n, sizeof *l, file_cmp);
    return n;
}

static int files_sel(const file_entry_t *const *l, int n) {
    for (int i = 0; i < n; i++) if (l[i]->num == g_app.files.num) return i;
    return 0;
}

static const file_entry_t *selected_file(void) {
    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(g_app.selected, l);
    return n ? l[files_sel(l, n)] : NULL;
}

static void file_owner_name(const chat_t *e, const file_entry_t *f, char out[CHAT_NAME_LEN]) {
    if (f->mine) { copy_str(out, "you", CHAT_NAME_LEN); return; }
    const peer_t *p = chat_peer_by_id(e, f->owner);
    if (p) { chat_peer_name(e, p, out); return; }
    copy_str(out, "someone who left", CHAT_NAME_LEN);
}

static tui_value_kind_t file_value(const session_slot_t *s, const file_entry_t *f, char *out, size_t cap, int *permille) {
    char sz[32]; file_format_size(f->size, sz, sizeof sz);
    *permille = 0;
    switch (file_state(s, f)) {
        case FS_MINE: {
            char name[CHAT_NAME_LEN], to[CHAT_NAME_LEN * 2 + 16];
            int pm, n = chat_file_sending(s->engine, f, now_seconds(), name, &pm);
            chat_file_sent_to(f, to, sizeof to);
            if (n) {
                *permille = pm;
                snprintf(out, cap, "%d%%" DOT_SEP "sending to %s%s", pm / 10, name, n > 1 ? " and others" : "");
                return TUI_V_PROGRESS;
            }
            if (to[0]) { snprintf(out, cap, "sent to %s", to); return TUI_V_ON; }
            if (!f->fp) { snprintf(out, cap, "no longer offered"); return TUI_V_MUTED; }
            snprintf(out, cap, "offered" DOT_SEP "%s", sz);
            return TUI_V_TEXT;
        }
        case FS_COMING:
        case FS_QUEUED: *permille = fetch_progress(s->engine, f, out, cap); return TUI_V_PROGRESS;
        case FS_FAILED: snprintf(out, cap, "%s", f->why[0] ? f->why : "it didn't finish"); return TUI_V_BAD;
        case FS_SAVED:  snprintf(out, cap, "saved" DOT_SEP "%s", sz); return TUI_V_ON;
        case FS_HERE: {
            const pic_t *p = pic_of(s, f->num);
            snprintf(out, cap, "%s" DOT_SEP "%s", p && p->shown && p->th.rgb ? "shown" : "here, hidden", sz);
            return TUI_V_ON;
        }
        case FS_BROKEN: snprintf(out, cap, "can't be shown"); return TUI_V_BAD;
        case FS_OVER:   snprintf(out, cap, "%s" DOT_SEP "over your size limit", sz); return TUI_V_OFF;
        default:        snprintf(out, cap, "%s" DOT_SEP "%s", f->image ? "picture" : "file", sz); return TUI_V_OFF;
    }
}

#define DETAIL_LINES 24
#define DETAIL_LINE_MAX 128

static int add_wrapped(char lines[][DETAIL_LINE_MAX], int n, const char *t, int width) {
    size_t len = strlen(t);
    if (len == 0 && n < DETAIL_LINES) lines[n++][0] = '\0';
    while (len > 0 && n < DETAIL_LINES) {
        size_t fit = utf8_fit_cols(t, len, width, NULL);
        if (fit == 0) utf8_char_cols(t, len, 0, &fit);
        if (fit < len) {
            size_t sp = fit;
            while (sp > 0 && t[sp] != ' ') sp--;
            if (sp > 0) fit = sp;
        }
        snprintf(lines[n++], DETAIL_LINE_MAX, "%.*s", (int)(fit < DETAIL_LINE_MAX - 1 ? fit : DETAIL_LINE_MAX - 1), t);
        t += fit;
        len -= fit;
        while (len > 0 && *t == ' ') { t++; len--; }
    }
    return n;
}

static int file_details(const session_slot_t *s, const file_entry_t *f, int width, const char **out) {
    static char lines[DETAIL_LINES][DETAIL_LINE_MAX];
    char t[900], sz[32], who[CHAT_NAME_LEN];
    int n = 0;
    if (width < 8) return 0;
    file_format_size(f->size, sz, sizeof sz);
    file_owner_name(s->engine, f, who);
    n = add_wrapped(lines, n, f->name, width);
    n = add_wrapped(lines, n, "", width);
    snprintf(t, sizeof t, "%s" DOT_SEP "%s", f->image ? "picture" : "file", sz);
    n = add_wrapped(lines, n, t, width);
    if (f->mine) copy_str(t, "yours", sizeof t);
    else snprintf(t, sizeof t, "from %s", who);
    n = add_wrapped(lines, n, t, width);
    snprintf(t, sizeof t, "file %d, at %s", f->num, f->at[0] ? f->at : "--:--");
    n = add_wrapped(lines, n, t, width);
    n = add_wrapped(lines, n, "", width);
    char name[CHAT_NAME_LEN], to[CHAT_NAME_LEN * 2 + 16];
    int pm;
    switch (file_state(s, f)) {
        case FS_MINE:
            chat_file_sent_to(f, to, sizeof to);
            if (chat_file_sending(s->engine, f, now_seconds(), name, &pm)) snprintf(t, sizeof t, "sending to %s: %d%%", name, pm / 10);
            else snprintf(t, sizeof t, "%s", f->fp ? "offered to everyone here" : "no longer offered");
            n = add_wrapped(lines, n, t, width);
            if (to[0]) { snprintf(t, sizeof t, "sent to %s", to); n = add_wrapped(lines, n, t, width); }
            break;
        case FS_COMING:
        case FS_QUEUED: {
            fetch_progress(s->engine, f, t, sizeof t);
            for (char *part = t, *next; part; part = next) {
                next = strstr(part, DOT_SEP);
                if (next) { *next = '\0'; next += sizeof DOT_SEP - 1; }
                n = add_wrapped(lines, n, part, width);
            }
            break;
        }
        case FS_FAILED:
            snprintf(t, sizeof t, "failed: %s", f->why[0] ? f->why : "it didn't finish");
            n = add_wrapped(lines, n, t, width);
            break;
        case FS_SAVED: {
            char where[sizeof f->saved];
            tilde_path(f->saved, where, sizeof where);
            char *slash = strrchr(where, '/');
            n = add_wrapped(lines, n, "saved in", width);
            if (slash) { *slash = '\0'; n = add_wrapped(lines, n, where[0] ? where : "/", width); }
            snprintf(t, sizeof t, "as %s", slash ? slash + 1 : where);
            n = add_wrapped(lines, n, t, width);
            break;
        }
        case FS_HERE: {
            const pic_t *p = pic_of(s, f->num);
            n = add_wrapped(lines, n, p && p->shown && p->th.rgb ? "shown in the chat" : "here, hidden in the chat", width);
            n = add_wrapped(lines, n, "only in memory", width);
            break;
        }
        case FS_BROKEN:
            snprintf(t, sizeof t, "can't be shown: %s", pic_why(s, f->num));
            n = add_wrapped(lines, n, t, width);
            break;
        case FS_OVER: {
            char lim[32]; file_format_size(chat_file_cap(s->engine), lim, sizeof lim);
            snprintf(t, sizeof t, "not fetched, and over your %s limit", lim);
            n = add_wrapped(lines, n, t, width);
            break;
        }
        default:
            n = add_wrapped(lines, n, "not fetched yet", width);
            break;
    }
    for (int i = 0; i < n; i++) out[i] = lines[i];
    return n;
}

// What Enter does with f, for the bottom row, or NULL for nothing.
static const char *file_enter(const session_slot_t *s, const file_entry_t *f) {
    file_state_t st = file_state(s, f);
    if (f->image && st != FS_BROKEN) return st == FS_NEW || st == FS_OVER || st == FS_FAILED ? "show" : "view";
    if (st == FS_NEW || st == FS_OVER) return "download";
    return st == FS_FAILED ? "retry" : NULL;
}

// usage gets the command that does what Enter does.
static void file_help(const session_slot_t *s, const file_entry_t *f, char *help, size_t cap, char *usage, size_t ucap) {
    char who[CHAT_NAME_LEN], where[sizeof f->saved] = "";
    file_owner_name(s->engine, f, who);
    if (f->saved[0]) tilde_path(f->saved, where, sizeof where);
    const char *save = "d saves it in Downloads, s in a folder you pick.";
    usage[0] = '\0';
    switch (file_state(s, f)) {
        case FS_MINE:
            if (!f->fp) snprintf(help, cap, "Yours, and no longer offered. :send offers it again, as a new file.");
            else snprintf(help, cap, "Yours, offered to everyone here%s.%s x stops offering it.",
                          chat_verify_required(s->engine) ? " whose verify code you've compared" : "",
                          f->image ? " Enter shows it big." : "");
            if (f->fp) snprintf(usage, ucap, ":cancel %d", f->num);
            return;
        case FS_COMING:
        case FS_QUEUED:
            snprintf(help, cap, "%s%s x stops it.", f->dl == DL_QUEUED ? "Queued: one file comes from each sender at a time." : "On its way.",
                     f->image ? " Enter shows how far it's got, then the picture." : "");
            snprintf(usage, ucap, ":cancel %d", f->num);
            return;
        case FS_FAILED:
            snprintf(help, cap, "Failed: %s. Enter tries again. %s", f->why[0] ? f->why : "it stopped", save);
            snprintf(usage, ucap, ":%s %d", f->image ? "show" : "download", f->num);
            return;
        case FS_SAVED:
            snprintf(help, cap, "Saved as %s.%s y copies where it is, s saves a copy in another folder.", where,
                     f->image ? " Enter shows it big, v in the chat." : "");
            snprintf(usage, ucap, ":saveto %d", f->num);
            return;
        case FS_HERE:
            snprintf(help, cap, "Enter shows it big, v shows or hides it in the chat. It's only in memory: %s", save);
            snprintf(usage, ucap, ":download %d", f->num);
            return;
        case FS_BROKEN:
            snprintf(help, cap, "chat can't show it (%s). d saves it in Downloads, to open with something else.", pic_why(s, f->num));
            snprintf(usage, ucap, ":download %d", f->num);
            return;
        default: {
            const char *over = file_state(s, f) == FS_OVER ? " It's over your file size limit, so chat asks first." : "";
            if (f->image)
                snprintf(help, cap, "%s offers it. Enter fetches it and shows it big, and in the chat under the offer. %s%s",
                         who, save, over);
            else
                snprintf(help, cap, "%s offers it. Enter saves it in Downloads, s in a folder you pick. Nothing is fetched until "
                         "you ask.%s", who, over);
            snprintf(usage, ucap, ":%s %d%s", f->image ? "show" : "download", f->num, *over ? " anyway" : "");
            return;
        }
    }
}

void file_ask(int what, const file_entry_t *f) {
    g_app.files.ask = what;
    g_app.files.ask_num = f->num;
    g_app.files.back = g_app.mode;
    g_app.mode = MODE_FILE_ASK;
}

// The engine's reply goes on the bottom bar, since the page covers the console.
int echo_fetch(session_slot_t *s, int num, int view, int anyway, const char *dir) {
    g_echo = 1;
    int r = chat_file_fetch(s->engine, num, view, anyway, dir);
    g_echo = 0;
    return r;
}

static void echo_cancel(session_slot_t *s, int num) {
    char cmd[32];
    snprintf(cmd, sizeof cmd, "cancel %d", num);
    g_echo = 1;
    chat_run_command(s->engine, cmd);
    g_echo = 0;
}

static void file_download(session_slot_t *s, const file_entry_t *f) {
    if (f->mine) note("file %d is yours", f->num);
    else if (file_needs_anyway(s, f)) file_ask(ASK_FETCH, f);
    else echo_fetch(s, f->num, 0, 0, NULL);
}

static void file_save_in(session_slot_t *s, const file_entry_t *f) {
    if (f->mine) note("file %d is yours", f->num);
    else if (file_needs_anyway(s, f)) file_ask(ASK_SAVETO, f);
    else begin_save_browse(f->num, 0);
}

static void file_toggle_shown(session_slot_t *s, const file_entry_t *f) {
    if (!f->image) { note("only pictures are shown in the chat - d saves %s", f->name); return; }
    pic_t *p = pic_find(s, f->num);
    if (p && p->th.rgb) {
        p->shown = !p->shown;
        note(p->shown ? "file %d is shown in the chat" : "file %d is hidden in the chat - v shows it again", f->num);
    } else if (file_needs_anyway(s, f)) {
        file_ask(ASK_SHOW, f);
    } else {
        echo_fetch(s, f->num, 1, 0, NULL);
    }
}

static void file_stop(session_slot_t *s, const file_entry_t *f) {
    if (f->mine && f->fp) file_ask(ASK_UNOFFER, f);
    else if (f->mine) note("file %d isn't offered any more", f->num);
    else if (f->dl == DL_ACTIVE) file_ask(ASK_STOP, f);
    else if (f->dl == DL_QUEUED) echo_cancel(s, f->num);
    else note("file %d isn't on its way - there's nothing to stop", f->num);
}

static void file_copy_path(const file_entry_t *f) {
    if (!f->saved[0]) { note(f->mine ? "file %d is yours, not a copy chat saved" : "file %d isn't saved - d saves it", f->num); return; }
    osc52_copy(f->saved);
    char where[sizeof f->saved];
    tilde_path(f->saved, where, sizeof where);
    note("copied %s to the clipboard (OSC 52)", where);
}

// The keys the files page and the picture share. Returns 1 if ch is one of them.
static int file_action(char ch, session_slot_t *s, const file_entry_t *f) {
    switch (ch) {
        case 'd': file_download(s, f); return 1;
        case 's': file_save_in(s, f); return 1;
        case 'v': file_toggle_shown(s, f); return 1;
        case 'x': file_stop(s, f); return 1;
        case 'y': file_copy_path(f); return 1;
        default:  return 0;
    }
}

// Enter: a picture opens on a page of its own, fetched first if it isn't here. A file is saved in
// Downloads, or where it was going if that failed.
static void file_open(session_slot_t *s, const file_entry_t *f) {
    file_state_t st = file_state(s, f);
    if (f->image && st != FS_BROKEN) {
        if (st == FS_NEW || st == FS_OVER || st == FS_FAILED) {
            if (file_needs_anyway(s, f)) { file_ask(ASK_VIEW, f); return; }
            if (echo_fetch(s, f->num, 1, 0, NULL) != 0) return;
        }
        g_app.mode = MODE_FILE_VIEW;
        return;
    }
    switch (st) {
        case FS_MINE:   note("file %d is yours - x stops offering it", f->num); break;
        case FS_BROKEN: note("chat can't show it (%s) - d saves it", pic_why(s, f->num)); break;
        case FS_COMING: note("file %d is on its way - x stops it", f->num); break;
        case FS_QUEUED: note("file %d is queued - x takes it off the queue", f->num); break;
        case FS_SAVED: {
            char where[sizeof f->saved];
            tilde_path(f->saved, where, sizeof where);
            note("saved as %s - y copies where it is", where);
            break;
        }
        case FS_FAILED:
            if (file_needs_anyway(s, f)) file_ask(ASK_RETRY, f);
            else echo_fetch(s, f->num, 0, 0, f->save_dir);
            break;
        default: file_download(s, f); break;
    }
}

void file_ask_yes(void) {
    session_slot_t *s = g_app.selected;
    int num = g_app.files.ask_num;
    g_app.mode = g_app.files.back;
    g_app.dirty = 1;
    const file_entry_t *f = s && !s->initialising ? chat_file(s->engine, num) : NULL;
    if (!f) return;
    switch (g_app.files.ask) {
        case ASK_VIEW:    if (echo_fetch(s, num, 1, 1, NULL) == 0) g_app.mode = MODE_FILE_VIEW; break;
        case ASK_SHOW:    echo_fetch(s, num, 1, 1, NULL); break;
        case ASK_FETCH:   echo_fetch(s, num, 0, 1, NULL); break;
        case ASK_RETRY: {
            char dir[sizeof f->save_dir];
            copy_str(dir, f->save_dir, sizeof dir);
            echo_fetch(s, num, 0, 1, dir);
            break;
        }
        case ASK_SAVETO:  begin_save_browse(num, 1); break;
        case ASK_STOP:
        case ASK_UNOFFER: echo_cancel(s, num); break;
        default: break;
    }
}

void file_ask_no(void) {
    g_app.mode = g_app.files.back;
    g_app.dirty = 1;
}

int file_ask_paras(tui_para_t *paras, const char **title, const char **keys) {
    static char text[900];
    session_slot_t *s = g_app.selected;
    const file_entry_t *f = s && !s->initialising ? chat_file(s->engine, g_app.files.ask_num) : NULL;
    if (!f) { *title = "FILES"; *keys = "n back"; return add_para(paras, 0, TUI_P_TEXT, "That file isn't here any more."); }
    char sz[32], lim[32];
    file_format_size(f->size, sz, sizeof sz);
    file_format_size(chat_file_cap(s->engine), lim, sizeof lim);
    switch (g_app.files.ask) {
        case ASK_STOP: {
            char got[32]; file_format_size(chat_file_got(f), got, sizeof got);
            *title = "STOP";
            *keys = "y stop" DOT_SEP "n keep it coming";
            snprintf(text, sizeof text, "Stop fetching `%s`? The %s that's come so far is thrown away, and fetching it again "
                     "starts from the beginning.", f->name, got);
            break;
        }
        case ASK_UNOFFER:
            *title = "STOP";
            *keys = "y stop offering" DOT_SEP "n keep offering";
            snprintf(text, sizeof text, "Stop offering `%s`? Nobody can fetch it after this, and anyone fetching it now stops. "
                     "`:send` offers it again, as a new file.", f->name);
            break;
        default: {
            char eta[48], took[160] = "";
            double left = chat_file_eta(s->engine, f, now_seconds());
            if (left >= 0.0) {
                char who[CHAT_NAME_LEN];
                file_owner_name(s->engine, f, who);
                file_format_duration(left, eta, sizeof eta);
                snprintf(took, sizeof took, " At chat's normal rate it takes %s to come, less if %s has fast transfers on.", eta, who);
            }
            int ask = g_app.files.ask;
            *title = "OVER YOUR LIMIT";
            *keys = "y fetch it" DOT_SEP "n cancel";
            snprintf(text, sizeof text, "`%s` is %s, over your %s file size limit. Fetch it anyway%s?%s", f->name, sz, lim,
                     ask == ASK_SAVETO ? ", into a folder you pick" : ask == ASK_VIEW || ask == ASK_SHOW ? ", to show it" : "", took);
            break;
        }
    }
    return add_para(paras, 0, TUI_P_TEXT, text);
}

const char *files_hint(void) {
    static char hint[200];
    session_slot_t *s = g_app.selected;
    const file_entry_t *f = selected_file();
    if (!f) return "n send a file" DOT_SEP "esc close";
    const char *enter = file_enter(s, f);
    file_state_t st = file_state(s, f);
    snprintf(hint, sizeof hint, "%s%s%s%s%s%sn send" DOT_SEP "esc close", enter ? "enter " : "", enter ? enter : "",
             enter ? DOT_SEP : "", f->saved[0] ? "y copy path" DOT_SEP : "",
             f->mine ? "" : "d download" DOT_SEP "s save in" DOT_SEP,
             (f->mine && f->fp) || st == FS_COMING || st == FS_QUEUED ? "x stop" DOT_SEP : "");
    return hint;
}

void begin_files(void) {
    if (g_app.mode != MODE_CHAT) return;
    session_slot_t *s = g_app.selected;
    if (!s || s->initialising) { note("no session open - ctrl+n starts one, ctrl+j joins one"); return; }
    // The newest file, since that's usually the one to do something with.
    g_app.files.num = chat_newest_file(s->engine);
    g_app.mode = MODE_FILES;
    g_app.dirty = 1;
}

void render_files(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    static tui_row_t rows[FILE_OFFERS_MAX];
    static char values[FILE_OFFERS_MAX][160], prefix[FILE_OFFERS_MAX][24];
    static char title[MAX_SESSION_NAME + 16], intro[200], help[1200], usage[64];
    session_slot_t *s = g_app.selected;
    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(s, l), sel = files_sel(l, n), digits = 1, theirs = 0, coming = 0;
    snprintf(title, sizeof title, "%s" CRUMB "Files", s ? s->name : "");
    for (int i = 0; i < n; i++) {
        char d[12];
        int w = snprintf(d, sizeof d, "%d", l[i]->num);
        if (w > digits) digits = w;
        theirs += !l[i]->mine;
        coming += l[i]->dl == DL_ACTIVE || l[i]->dl == DL_QUEUED;
    }
    for (int i = 0; i < n; i++) {
        int pm;
        tui_value_kind_t kind = file_value(s, l[i], values[i], sizeof values[i], &pm);
        snprintf(prefix[i], sizeof prefix[i], "%*d  ", digits, l[i]->num);
        const char *section = i == 0 || l[i]->mine != l[i - 1]->mine ? (l[i]->mine ? "Yours" : "Offered to you") : NULL;
        rows[i] = (tui_row_t){ section, l[i]->name, values[i], kind, NULL, prefix[i], pm, 0 };
    }
    char parts[3][40];
    int np = 0;
    if (theirs) snprintf(parts[np++], sizeof parts[0], "%d offered to you", theirs);
    if (coming) snprintf(parts[np++], sizeof parts[0], "%d on the way", coming);
    if (n - theirs) snprintf(parts[np++], sizeof parts[0], "%d yours", n - theirs);
    if (!n) snprintf(intro, sizeof intro, "Nothing's been offered here yet.");
    else snprintf(intro, sizeof intro, "%s%s%s%s%s", parts[0], np > 1 ? DOT_SEP : "", np > 1 ? parts[1] : "",
                  np > 2 ? DOT_SEP : "", np > 2 ? parts[2] : "");
    const char *nav[DETAIL_LINES];
    int n_nav = 0;
    usage[0] = '\0';
    if (n) {
        n_nav = file_details(s, l[sel], tui_nav_text_cols(cols_n), nav);
        file_help(s, l[sel], help, sizeof help, usage, sizeof usage);
    } else {
        snprintf(help, sizeof help, "n picks a file to send, or :send PATH. What others offer shows up here, and nothing is "
                 "fetched until you ask.");
    }
    tui_page_t page = {
        .title = title,
        .clock = clock,
        .intro = intro,
        .nav = n_nav ? nav : NULL, .n_nav = n_nav, .nav_sel = 0,
        .rows = rows, .n_rows = n, .selected = sel,
        .help = help, .usage = usage[0] ? usage : NULL,
    };
    tui_render_page(rows_n, cols_n, &page, bar, g_app.color_enabled);
}

void files_key(const tui_key_t *key) {
    session_slot_t *s = g_app.selected;
    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(s, l), sel = files_sel(l, n);
    const file_entry_t *f = n ? l[sel] : NULL;
    g_app.dirty = 1;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1) {
        if (key->ch[0] == 'n') { begin_send_browse(0); return; }
        if (f && file_action(key->ch[0], s, f)) return;
    }
    list_key_t k = list_key(key);
    switch (k) {
        case LIST_CHOOSE:
        case LIST_RIGHT: if (f) file_open(s, f); break;
        case LIST_LEFT:
        case LIST_BACK:
        case LIST_CLOSE: g_app.mode = MODE_CHAT; break;
        case LIST_NEXT_SECTION:
        case LIST_PREV_SECTION:
            for (int i = 0; i < n; i++) if (l[i]->mine != (f && f->mine)) { g_app.files.num = l[i]->num; break; }
            break;
        default:
            list_move(k, &sel, n);
            if (n) g_app.files.num = l[sel]->num;
            break;
    }
}

// The picture on its own page, decoded to fit the screen. It's decoded again for another file or
// size, or when its bytes may have come.
typedef struct {
    const session_slot_t *s;
    int num, w, h;
    unsigned sig;
    image_thumb_t th;
    tui_image_t ti;
    char why[160];
} picture_view_t;

static picture_view_t g_view;

static void view_drop(void) {
    thumb_free(&g_view.th);
    memset(&g_view, 0, sizeof g_view);
}

void view_forget(const session_slot_t *s) {
    if (g_view.s == s) view_drop();
}

// What the picture page shows for f depends on: its download's state, in the bits below SIG_CACHED, and these.
enum { SIG_CACHED = 8, SIG_SAVED = 16, SIG_OFFERED = 32 };

static unsigned view_sig(const file_entry_t *f) {
    return (unsigned)f->dl | (f->cache ? SIG_CACHED : 0u) | (f->saved[0] ? SIG_SAVED : 0u) | (f->fp ? SIG_OFFERED : 0u);
}

static void view_update(session_slot_t *s, const file_entry_t *f, int w, int h) {
    if (g_view.s == s && g_view.num == f->num && g_view.w == w && g_view.h == h && g_view.sig == view_sig(f)) return;
    view_drop();
    g_view.s = s;
    g_view.num = f->num;
    g_view.w = w;
    g_view.h = h;
    const uint8_t *b = f->dl == DL_ACTIVE || f->dl == DL_QUEUED ? NULL : chat_file_bytes(s->engine, f->num);
    static const uint8_t bg[3] = { 0, 0, 0 };
    if (b && thumb_decode(b, (size_t)f->size, w, h, bg, &g_view.th, g_view.why, sizeof g_view.why) == 0)
        g_view.ti = (tui_image_t){ g_view.th.w, g_view.th.h, g_view.th.rgb };
    g_view.sig = view_sig(f);
}

void render_viewer(int rows_n, int cols_n, const char *clock, const tui_bar_t *bar) {
    static char title[MAX_SESSION_NAME + FILE_NAME_MAX + 32], caption[400], text[700];
    static tui_progress_t pg;
    session_slot_t *s = g_app.selected;
    const file_entry_t *f = selected_file();
    tui_picture_t pic = { .title = title, .clock = clock, .caption = caption };
    caption[0] = '\0';
    if (!f || !f->image) {
        snprintf(title, sizeof title, "%s" CRUMB "Files", s ? s->name : "");
        pic.note = "That picture isn't here any more\nesc goes back to the files";
        tui_render_picture(rows_n, cols_n, &pic, bar, g_app.color_enabled);
        return;
    }
    snprintf(title, sizeof title, "%s" CRUMB "Files" CRUMB "%s", s->name, f->name);
    int w, h;
    tui_picture_room(rows_n, cols_n, &w, &h);
    view_update(s, f, w, h);

    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(s, l), at = 0, pics = 0;
    for (int i = 0; i < n; i++) if (l[i]->image) { pics++; if (l[i] == f) at = pics; }
    char sz[32], who[CHAT_NAME_LEN], dims[32] = "", of[40] = "";
    file_format_size(f->size, sz, sizeof sz);
    file_owner_name(s->engine, f, who);
    const pic_t *small = pic_of(s, f->num);
    file_state_t st = file_state(s, f);
    if (g_view.th.rgb) {
        pic.image = &g_view.ti;
        snprintf(dims, sizeof dims, "%d\xc3\x97%d" DOT_SEP, g_view.th.src_w, g_view.th.src_h);
    } else if (small && small->th.rgb && st != FS_COMING && st != FS_QUEUED) {
        // Only the small copy the chat shows is left: what was fetched has been dropped from memory.
        pic.image = &small->ti;
        snprintf(dims, sizeof dims, "small copy" DOT_SEP);
    }
    if (pics > 1) snprintf(of, sizeof of, DOT_SEP "%d of %d", at, pics);
    snprintf(caption, sizeof caption, "%s" DOT_SEP "%s%s" DOT_SEP "%s%s%s", f->name, dims, sz, f->mine ? "yours" : "from ",
             f->mine ? "" : who, of);
    if (!pic.image) {
        memset(&pg, 0, sizeof pg);
        switch (st) {
            case FS_COMING:
            case FS_QUEUED: {
                snprintf(text, sizeof text, "On its way\n%s from %s", sz, who);
                pg.permille = fetch_progress(s->engine, f, pg.text, sizeof pg.text);
                // The bar has the percentage already.
                char *after = f->dl == DL_ACTIVE ? strstr(pg.text, DOT_SEP) : NULL;
                if (after) memmove(pg.text, after + sizeof DOT_SEP - 1, strlen(after + sizeof DOT_SEP - 1) + 1);
                pic.progress = &pg;
                break;
            }
            case FS_FAILED:
                snprintf(text, sizeof text, "It didn't finish\n%s\nenter tries again", f->why[0] ? f->why : "it stopped");
                break;
            case FS_OVER:
                snprintf(text, sizeof text, "Not fetched yet\n%s, over your file size limit\nenter fetches it, after asking", sz);
                break;
            case FS_NEW:
                snprintf(text, sizeof text, "Not fetched yet\n%s from %s\nenter fetches it" DOT_SEP "d saves it in Downloads", sz, who);
                break;
            case FS_MINE:
                snprintf(text, sizeof text, "It can't be shown\n%s", g_view.why[0] ? g_view.why
                         : f->fp ? "it's changed since you offered it" : "it isn't offered any more");
                break;
            default:
                if (g_view.why[0] || st == FS_BROKEN)
                    snprintf(text, sizeof text, "chat can't show this picture\n%s\nd saves it, to open with something else",
                             g_view.why[0] ? g_view.why : pic_why(s, f->num));
                else
                    snprintf(text, sizeof text, "It isn't here any more\nthe copy shown was dropped from memory, or the "
                             "saved one has changed\nenter fetches it again");
                break;
        }
        pic.note = text;
    }
    tui_render_picture(rows_n, cols_n, &pic, bar, g_app.color_enabled);
}

static void view_fetch(session_slot_t *s, const file_entry_t *f) {
    if (g_view.th.rgb && g_view.num == f->num) return;
    file_state_t st = file_state(s, f);
    if (st == FS_COMING || st == FS_QUEUED) note("on its way - it's shown here once it's come");
    else if (st == FS_MINE) note("it can't be shown - it's changed since you offered it, or isn't offered any more");
    else if (st == FS_BROKEN || g_view.why[0]) note("chat can't show it - d saves it");
    else if (file_needs_anyway(s, f)) file_ask(ASK_SHOW, f);
    else echo_fetch(s, f->num, 1, 0, NULL);
}

// The picture page: j and k go to the next and previous picture in the files page's order.
void viewer_key(const tui_key_t *key) {
    session_slot_t *s = g_app.selected;
    const file_entry_t *l[FILE_OFFERS_MAX];
    int n = files_list(s, l), sel = files_sel(l, n);
    const file_entry_t *f = n ? l[sel] : NULL;
    g_app.dirty = 1;
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1 && f && file_action(key->ch[0], s, f)) return;
    int pics[FILE_OFFERS_MAX], np = 0, at = -1;
    for (int i = 0; i < n; i++) if (l[i]->image) { if (i == sel) at = np; pics[np++] = i; }
    switch (list_key(key)) {
        case LIST_DOWN:  if (at + 1 < np) g_app.files.num = l[pics[at + 1]]->num; break;
        case LIST_UP:    if (at > 0) g_app.files.num = l[pics[at - 1]]->num; break;
        case LIST_FIRST: if (np) g_app.files.num = l[pics[0]]->num; break;
        case LIST_LAST:  if (np) g_app.files.num = l[pics[np - 1]]->num; break;
        case LIST_CHOOSE:
        case LIST_RIGHT: if (f) view_fetch(s, f); break;
        case LIST_LEFT:
        case LIST_BACK:  view_drop(); g_app.mode = MODE_FILES; break;
        case LIST_CLOSE: view_drop(); g_app.mode = MODE_CHAT; break;
        default: break;
    }
}

const char *viewer_hint(void) {
    static char hint[200];
    const file_entry_t *f = selected_file();
    if (!f) return "esc back";
    file_state_t st = file_state(g_app.selected, f);
    int fetch = !(g_view.th.rgb && g_view.num == f->num) && st != FS_MINE && st != FS_COMING && st != FS_QUEUED && st != FS_BROKEN;
    snprintf(hint, sizeof hint, "%sj/k next/previous" DOT_SEP "%sv in chat" DOT_SEP "esc back", fetch ? "enter fetch" DOT_SEP : "",
             f->mine ? "x stop offering" DOT_SEP : "d download" DOT_SEP "s save in" DOT_SEP);
    return hint;
}
