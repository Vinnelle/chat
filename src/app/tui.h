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
    TUI_KEY_DELETE_WORD,
    TUI_KEY_TOGGLE_SIDEBAR,
    TUI_KEY_TOGGLE_CONSOLE,
    TUI_KEY_TOGGLE_CHAT,
    TUI_KEY_SETTINGS,
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

typedef const char *(*tui_complete_fn)(const char *typed);

typedef struct {
    char buf[600];
    int len;
    int cursor;
    tui_input_mode_t mode;
    char cmd[64];
    int cmd_len;
    // modal: Esc enters NORMAL and ':' opens COMMAND. Off for one-shot prompts, where Esc
    // is left to the caller (cancel). complete: Tab completion for the COMMAND line.
    // mention: given the text after an '@' being typed, returns the full nick or NULL.
    int modal;
    tui_complete_fn complete;
    tui_complete_fn mention;
} tui_input_t;

// Empties the line and returns to INSERT; keeps modal and complete.
void tui_input_clear(tui_input_t *in);

int tui_input_feed(tui_input_t *in, const tui_key_t *key);

// "INSERT", "NORMAL" or "COMMAND".
const char *tui_mode_name(tui_input_mode_t mode);

typedef enum { TUI_ID_NONE = 0, TUI_ID_NATIVE, TUI_ID_AGE, TUI_ID_PGP } tui_identity_badge_t;

// title follows "chat" in the top bar, and clock (or nothing, if NULL) stands at its right end.
typedef struct {
    int sidebar, console, chat;
    const char *title;
    const char *clock;
} tui_view_t;

// The bottom row, the same on every screen: a chip saying where you are, the identity badge and
// version under the sidebar, then the input after its prompt (or a line of text), then
// status_right. message is the reply to the last thing done: it stands in bold where the input
// would be. hint is dim, and shows when there's no input or the input is empty.
typedef struct {
    const char *chip;
    const char *prompt;
    const tui_input_t *input;
    int mask_input;
    const char *message;
    const char *hint;
    tui_identity_badge_t badge;
    const char *status_right;
} tui_bar_t;

int tui_pane_geometry(int rows, int cols, int *pane_x, int *pane_rows);

void tui_render(int rows, int cols,
                 const tui_session_row_t *sessions, int n_sessions, int selected,
                 const tui_peer_row_t *peers, int n_peers,
                 const tui_scrollback_t *sb, const tui_scrollback_t *console,
                 const tui_view_t *view, const tui_bar_t *bar, int color_enabled,
                 const char *const *net_lines, int n_net_lines);

// Redraws only the bottom row.
void tui_render_bar(int rows, int cols, const tui_view_t *view, const tui_bar_t *bar, int color_enabled);

typedef struct {
    const char *section;   // starts a new section with this heading, or NULL
    const char *label;
    const char *value;     // in a column after the label, or NULL
} tui_row_t;

// A list page (settings, and the pages under it): rows by section with one selected, the selected
// row's help wrapped underneath, and a button after the rows if button is set (selected == n_rows
// selects it).
typedef struct {
    const tui_row_t *rows;
    int n_rows;
    int selected;
    const char *help;
    const char *button;
} tui_page_t;

// title goes in the top bar after "chat", as the page's place in the settings; clock goes at its
// right end, as in tui_view_t.
void tui_render_page(int rows, int cols,
                     const tui_session_row_t *sessions, int n_sessions, int selected_session,
                     const char *title, const char *clock, const tui_page_t *page, const tui_bar_t *bar,
                     int color_enabled);

#endif
