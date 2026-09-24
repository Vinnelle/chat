// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_TUI_H
#define CHAT_TUI_H

#include <stdint.h>
#include <stddef.h>

#define TUI_SCROLLBACK 400
#define TUI_LINE_MAX 320

typedef struct {
    char hhmm[6];
    char text[TUI_LINE_MAX];
    uint8_t rgb[3];
    int has_color;
    int color_len;
    int mention;

} tui_line_t;

typedef struct {
    tui_line_t lines[TUI_SCROLLBACK];
    int head;
    int count;
} tui_scrollback_t;

void tui_scrollback_push(tui_scrollback_t *sb, const char *hhmm, const char *text, const uint8_t *rgb,
                         int mention, int color_len);

void tui_scrollback_clear(tui_scrollback_t *sb);

#define TUI_ROW_LABEL_MAX 40

typedef struct {
    char label[TUI_ROW_LABEL_MAX];
    int online;
    int unread;
    uint8_t color[3];
} tui_session_row_t;

typedef struct {
    char label[TUI_ROW_LABEL_MAX];
    uint8_t color[3];
} tui_peer_row_t;

typedef enum {
    TUI_KEY_NONE = 0,
    TUI_KEY_CHAR,
    TUI_KEY_ENTER,
    TUI_KEY_BACKSPACE,
    TUI_KEY_DELETE,
    TUI_KEY_LEFT,
    TUI_KEY_RIGHT,
    TUI_KEY_UP,
    TUI_KEY_DOWN,
    TUI_KEY_HOME,
    TUI_KEY_END,
    TUI_KEY_TAB,
    TUI_KEY_BACKTAB,
    TUI_KEY_NEW_SESSION,
    TUI_KEY_JOIN_SESSION,
    TUI_KEY_CLOSE_SESSION,
    TUI_KEY_TOGGLE_SIDEBAR,
    TUI_KEY_TOGGLE_CONSOLE,
    TUI_KEY_TOGGLE_CHAT,
    TUI_KEY_ESCAPE,
    TUI_KEY_UNKNOWN
} tui_keytype_t;

typedef struct {
    tui_keytype_t type;
    char ch[5];
    int ch_len;
} tui_key_t;

size_t tui_decode_key(const uint8_t *buf, size_t len, tui_key_t *out);

typedef enum { TUI_IMODE_INSERT = 0, TUI_IMODE_NORMAL, TUI_IMODE_COMMAND } tui_input_mode_t;

typedef struct {
    char buf[600];
    int len;
    int cursor;
    tui_input_mode_t mode;
    char cmd[64];
    int cmd_len;
} tui_input_t;

void tui_input_clear(tui_input_t *in);

int tui_input_feed(tui_input_t *in, const tui_key_t *key);

typedef enum { TUI_ID_NONE = 0, TUI_ID_NATIVE, TUI_ID_AGE, TUI_ID_PGP } tui_identity_badge_t;

typedef struct {
    int sidebar, console, chat;
    const char *title;
} tui_view_t;

int tui_pane_geometry(int rows, int cols, int *pane_x, int *pane_rows);

void tui_render(int rows, int cols,
                 const tui_session_row_t *sessions, int n_sessions, int selected,
                 const tui_peer_row_t *peers, int n_peers,
                 const tui_scrollback_t *sb, const tui_scrollback_t *console,
                 const tui_view_t *view,
                 const char *nick, const char *mode_prompt,
                 const tui_input_t *input, int color_enabled, int mask_input,
                 tui_identity_badge_t identity_badge, const char *status_right,
                 const char *const *net_lines, int n_net_lines);

void tui_render_input(int rows, int cols, const tui_view_t *view,
                      const char *nick, const char *mode_prompt,
                      const tui_input_t *input, int color_enabled, int mask_input,
                      tui_identity_badge_t identity_badge, const char *status_right);

#define TUI_MAX_LIST_ITEMS 512
#define TUI_LIST_LABEL_MAX 200

typedef struct {
    char label[TUI_LIST_LABEL_MAX];
    int is_dir;
} tui_list_item_t;

void tui_render_list(int rows, int cols,
                      const tui_session_row_t *sessions, int n_sessions, int selected_session,
                      const char *title, const tui_list_item_t *items, int n_items, int selected,
                      const char *hint, int color_enabled);

#endif
