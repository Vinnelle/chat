// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/app.h"

// ---- history ----

// A line of a session's history, for each line of its chat: when (local time), the colour of what
// comes before the message, or "-", how many bytes that is, whether it mentions you, then the line
// as shown, each after a tab.
#define HISTORY_LINE_MAX (TUI_LINE_MAX + 40)

#define HISTORY_WRITE_EVERY 30.0

// Only the full-screen UI keeps one, in the save that's open.
int history_possible(void) { return g_app.installed && !g_app.locked && !g_plain; }

void history_add(session_slot_t *s, const char *text, const uint8_t *rgb, int mention, int color_len) {
    char line[HISTORY_LINE_MAX], when[17], col[8] = "-";
    current_stamp(when);
    if (rgb) snprintf(col, sizeof col, "%02x%02x%02x", rgb[0], rgb[1], rgb[2]);
    int n = snprintf(line, sizeof line, "%s\t%s\t%d\t%d\t%s\n", when, col, color_len, mention != 0, text);
    if (n <= 0 || (size_t)n >= sizeof line) return;
    // The oldest lines make room.
    size_t drop = 0;
    while (s->hist_len - drop + (size_t)n > INSTALL_HISTORY_MAX) {
        const char *nl = memchr(s->hist + drop, '\n', s->hist_len - drop);
        drop = nl ? (size_t)(nl - s->hist) + 1 : s->hist_len;
    }
    if (drop) {
        memmove(s->hist, s->hist + drop, s->hist_len - drop);
        s->hist_len -= drop;
    }
    memcpy(s->hist + s->hist_len, line, (size_t)n);
    s->hist_len += (size_t)n;
    s->hist_dirty = 1;
    crypto_wipe(line, sizeof line);
}

static void history_write(session_slot_t *s) {
    if (!s->hist || !s->hist_dirty || !history_possible() || strcmp(s->hist_save, install_current()) != 0) return;
    uint8_t id[CHAT_HISTORY_ID_LEN];
    chat_history_id(&s->engine, id);
    if (install_write_history(id, s->hist, s->hist_len) == 0) s->hist_dirty = 0;
    else console_note(s, "couldn't write this session's history to the save - it's tried again in a moment");
}

// Before another save is opened, or this one closed.
void histories_write(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) if (g_app.used[i]) history_write(&g_app.sessions[i]);
}

// The lines kept from before, above the session's own.
static void history_show(session_slot_t *s) {
    char day[11] = "", line[HISTORY_LINE_MAX];
    size_t pos = 0;
    int shown = 0;
    while (pos < s->hist_len) {
        const char *nl = memchr(s->hist + pos, '\n', s->hist_len - pos);
        size_t end = nl ? (size_t)(nl - s->hist) : s->hist_len, len = end - pos;
        if (len >= sizeof line) len = sizeof line - 1;
        memcpy(line, s->hist + pos, len);
        line[len] = '\0';
        pos = end + 1;
        char *f[5], *q = line;
        int n = 0;
        for (; n < 4; n++) {
            char *tab = strchr(q, '\t');
            if (!tab) break;
            *tab = '\0';
            f[n] = q;
            q = tab + 1;
        }
        f[4] = q;
        if (n < 4 || strlen(f[0]) != 16) continue;
        if (!shown++)
            tui_scrollback_push(&s->sb, "", "* kept from before, sealed in your save (:history forget deletes it):", NULL, 0, 0);
        if (strncmp(f[0], day, 10) != 0) {
            char sep[24];
            memcpy(day, f[0], 10);
            day[10] = '\0';
            snprintf(sep, sizeof sep, "* %s", day);
            tui_scrollback_push(&s->sb, "", sep, NULL, 0, 0);
        }
        uint8_t rgb[3];
        int has_rgb = strlen(f[1]) == 6 && hex_decode(f[1], 6, rgb) == 0;
        char hhmm[6];
        memcpy(hhmm, f[0] + 11, 5);
        hhmm[5] = '\0';
        tui_scrollback_push(&s->sb, hhmm, f[4], has_rgb ? rgb : NULL, f[3][0] == '1', atoi(f[2]));
    }
    if (shown) tui_scrollback_push(&s->sb, "", "* new from here", NULL, 0, 0);
    crypto_wipe(line, sizeof line);
}

void history_start(session_slot_t *s, int show) {
    if (s->hist || s->initialising || !(s->hist = malloc(INSTALL_HISTORY_MAX))) return;
    crypto_lock(s->hist, INSTALL_HISTORY_MAX);
    s->hist_len = 0;
    s->hist_dirty = 0;
    copy_str(s->hist_save, install_current(), sizeof s->hist_save);
    uint8_t id[CHAT_HISTORY_ID_LEN];
    chat_history_id(&s->engine, id);
    long n = install_read_history(id, s->hist, INSTALL_HISTORY_MAX);
    if (n > 0) s->hist_len = (size_t)n;
    else if (n != 0 && n != INSTALL_NO_FILE)
        console_note(s, "this session's history in the save can't be read - it's kept again from here");
    if (show) history_show(s);
}

void history_stop(session_slot_t *s, int write) {
    if (!s->hist) return;
    if (write) history_write(s);
    crypto_unlock(s->hist, INSTALL_HISTORY_MAX);
    free(s->hist);
    s->hist = NULL;
    s->hist_len = 0;
    s->hist_dirty = 0;
}

// Each open session keeps its history while the setting's on and a save is open, in that save, and
// peers are told whenever that changes. Written every HISTORY_WRITE_EVERY seconds.
void history_sync(double now) {
    static double written;
    int want = g_app.history && history_possible();
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_slot_t *s = &g_app.sessions[i];
        if (!g_app.used[i] || s->initialising) continue;
        // Another save is open: this one's lines were written to the last before it opened.
        if (s->hist && strcmp(s->hist_save, install_current()) != 0) history_stop(s, 0);
        if (want && !s->hist) history_start(s, 0);
        else if (!want && s->hist) history_stop(s, 1);
        chat_set_history(&s->engine, s->hist != NULL);
    }
    if (now - written >= HISTORY_WRITE_EVERY) {
        written = now;
        histories_write();
    }
}
