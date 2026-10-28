// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// :open and o: a link from the chat, in a box that opens it in the browser or copies it.
#include "app/app.h"
#include <limits.h>

static void close_links(void) {
    crypto_wipe(&g_app.links, sizeof g_app.links);
    end_prompt();
}

static void show_link(void) {
    const char *text = g_app.links.shown.text;
    link_target(text, strlen(text), g_app.links.target, sizeof g_app.links.target);
    g_app.links.why[0] = '\0';
    g_app.dirty = 1;
}

// N counts from the newest link, so :open alone (and o) is the one just sent.
cmd_result_t app_open(void *ctx, const char *arg) {
    (void)ctx;
    session_slot_t *s = g_app.selected;
    size_t an = strlen(arg);
    crypto_wipe(&g_app.links, sizeof g_app.links);
    if (an > 0 && strspn(arg, "0123456789") != an) {
        size_t from = 0, at, len;
        if (!link_next(arg, an, &from, &at, &len) || at != 0 || len != an) {
            note("that isn't a link chat opens: an http:// or https:// address, or a domain name");
            return CMD_OK;
        }
        copy_str(g_app.links.shown.text, arg, sizeof g_app.links.shown.text);
        g_app.links.nth = -1;
        g_app.links.n = 1;
    } else {
        if (!s || s->initialising) { note("no session open - :open takes the links from its chat"); return CMD_OK; }
        long want = an > 0 ? strtol(arg, NULL, 10) : 1;
        int nth = want > 0 && want <= INT_MAX ? (int)want - 1 : INT_MAX;
        g_app.links.upto = s->sb.total;
        int n = tui_chat_link(&s->sb, g_app.links.upto, nth, &g_app.links.shown);
        if (n == 0) { note("no links in this chat yet"); return CMD_OK; }
        if (nth < 0 || nth >= n) { note("this chat has %d link%s - :open 1 is the newest", n, n == 1 ? "" : "s"); return CMD_OK; }
        g_app.links.nth = nth;
        g_app.links.n = n;
    }
    show_link();
    begin_prompt(MODE_OPEN_LINK);
    return CMD_OK;
}

static void step_link(int dir) {
    session_slot_t *s = g_app.selected;
    int nth = g_app.links.nth + dir;
    if (!s || g_app.links.nth < 0 || nth < 0 || nth >= g_app.links.n) return;
    tui_link_t l;
    int n = tui_chat_link(&s->sb, g_app.links.upto, nth, &l);
    // The message timer can take lines away while the box is open.
    g_app.links.n = n;
    if (nth < n) {
        g_app.links.shown = l;
        g_app.links.nth = nth;
        show_link();
    }
    crypto_wipe(&l, sizeof l);
}

void open_link_key(const tui_key_t *key) {
    char ch = key->type == TUI_KEY_CHAR && key->ch_len == 1 ? key->ch[0] : 0;
    if (ch == 'y' || ch == 'Y') {
        if (platform_open_url(g_app.links.target, g_app.links.why, sizeof g_app.links.why) != 0) { g_app.dirty = 1; return; }
        close_links();
        note("opening the link in your browser");
    } else if (ch == 'c' || ch == 'C') {
        osc52_copy(g_app.links.target);
        close_links();
        note("link copied to the clipboard (OSC 52)");
    } else if (ch == 'j' || key->type == TUI_KEY_DOWN) {
        step_link(1);
    } else if (ch == 'k' || key->type == TUI_KEY_UP) {
        step_link(-1);
    } else if (ch == 'n' || ch == 'N' || ch == 'q' || key->type == TUI_KEY_ESCAPE) {
        close_links();
    }
}
