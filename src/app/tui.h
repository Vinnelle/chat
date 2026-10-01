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
    int file;          // the file this line offers (a picture can be drawn under it), or 0
} tui_line_t;

typedef struct {
    tui_line_t lines[TUI_SCROLLBACK];
    int head;
    int count;
} tui_scrollback_t;

void tui_scrollback_push(tui_scrollback_t *sb, const char *hhmm, const char *text, const uint8_t *rgb,
                         int mention, int color_len);

void tui_scrollback_clear(tui_scrollback_t *sb);
// Marks the newest line as the one offering file.
void tui_scrollback_mark_file(tui_scrollback_t *sb, int file);

// A picture shown under the line that offers it: w by h pixels, rgb, drawn two pixels to a row.
#define TUI_IMAGE_MAX_W 64
#define TUI_IMAGE_MAX_H 48
typedef struct {
    int w, h;
    const uint8_t *rgb;
} tui_image_t;

#define TUI_ROW_LABEL_MAX 40

typedef enum { TUI_SESSION_STARTING = 0, TUI_SESSION_CONNECTING, TUI_SESSION_LIVE } tui_session_state_t;

typedef struct {
    char label[TUI_ROW_LABEL_MAX];
    int online;
    int unread;
    tui_session_state_t state;
} tui_session_row_t;

// Someone in the selected session. The nick is cut to fit the sidebar; the tag and the verify state
// never are, so a long or lookalike nick can't push them out of view.
typedef struct {
    char nick[TUI_ROW_LABEL_MAX];
    char tag[12];      // "#1a2b3c4d" when another nick looks the same, else ""
    uint8_t color[3];
    int you;
    int verify;        // 0 unverified, 1 verified, 2 signature invalid
    int code;          // its verify code: 0 nothing to do, 1 to be compared, 2 compared, 3 different
    int modified;      // runs a modified client
} tui_peer_row_t;

// A label and its value, as the sidebar's network section lists them.
typedef struct {
    const char *label;
    const char *value;
} tui_kv_t;

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
    TUI_KEY_PAGE_UP,
    TUI_KEY_PAGE_DOWN,
    TUI_KEY_TAB,
    TUI_KEY_BACKTAB,
    TUI_KEY_NEW_SESSION,
    TUI_KEY_JOIN_SESSION,
    TUI_KEY_DELETE_WORD,
    TUI_KEY_CTRL_U,
    TUI_KEY_CTRL_D,
    TUI_KEY_TOGGLE_SIDEBAR,
    TUI_KEY_TOGGLE_CONSOLE,
    TUI_KEY_TOGGLE_CHAT,
    TUI_KEY_SETTINGS,
    TUI_KEY_HELP,
    TUI_KEY_ESCAPE,
    // Not keys: the terminal's answer to "what's your background?" (its r, g, b in ch[0..2]), and
    // its word that it switched between a light and a dark theme.
    TUI_KEY_BG_REPORT,
    TUI_KEY_THEME_CHANGED,
    TUI_KEY_UNKNOWN
} tui_keytype_t;

typedef struct {
    tui_keytype_t type;
    char ch[5];
    int ch_len;
} tui_key_t;

size_t tui_decode_key(const uint8_t *buf, size_t len, tui_key_t *out);

// Asks the terminal for its background colour (answered with TUI_KEY_BG_REPORT), and to say when
// its theme changes (TUI_KEY_THEME_CHANGED); TUI_THEME_UNWATCH stops the latter.
#define TUI_THEME_WATCH "\x1b]11;?\x1b\\\x1b[?2031h"
#define TUI_THEME_QUERY "\x1b]11;?\x1b\\"
#define TUI_THEME_UNWATCH "\x1b[?2031l"

// Everything is drawn in the terminal's own colours, so it follows the terminal's theme. Peers'
// colours are exact, though: once the terminal has told its background, they're eased toward
// readable on it.
void tui_set_background(const uint8_t rgb[3]);

typedef enum { TUI_IMODE_INSERT = 0, TUI_IMODE_NORMAL, TUI_IMODE_COMMAND } tui_input_mode_t;

// One entry in the menu over the COMMAND line: the line Tab puts there, and how the menu shows it.
typedef struct {
    char line[64];
    char name[40];
    char args[40];    // dim after the name
    char help[120];
    char group[16];   // what the menu lists, for its title: "commands", "settings", "peers"
} tui_suggestion_t;

// Fills out with the nth suggestion for what's typed on the COMMAND line, and returns 0 once there
// are no more.
typedef int (*tui_suggest_fn)(const char *typed, int nth, tui_suggestion_t *out);
typedef const char *(*tui_complete_fn)(const char *typed);
// Whether a command's name or alias starts with word (or, with whole, is word).
typedef int (*tui_command_fn)(const char *word, int whole);

typedef struct {
    char buf[600];
    int len;
    int cursor;
    tui_input_mode_t mode;
    char cmd[64];
    int cmd_len;
    // ':' from NORMAL or '/' on an empty line opens the COMMAND line; leaving it goes back to
    // whichever mode it came from. cmd_as_text: opened with '/' on an empty line, it may yet turn
    // back into text (see is_command), and then it's typed on in INSERT.
    char cmd_prefix;
    int cmd_from_insert;
    int cmd_as_text;
    int menu_sel;    // the suggestion selected in the menu
    // modal: Esc enters NORMAL and ':' (or '/') opens COMMAND. Off for one-shot prompts, where Esc
    // is left to the caller (cancel). suggest: the COMMAND line's menu and Tab completion.
    // is_command: a COMMAND line opened with '/' on an empty line goes back to being the text of
    // a message as soon as it can't be a command ("/shrug", "/usr/bin"), so a message can start
    // with '/'. mention: given the text after an '@' being typed, returns the full nick or NULL.
    int modal;
    tui_suggest_fn suggest;
    tui_command_fn is_command;
    tui_complete_fn mention;
} tui_input_t;

// Empties the line and returns to INSERT; keeps modal, suggest, is_command and mention.
void tui_input_clear(tui_input_t *in);

int tui_input_feed(tui_input_t *in, const tui_key_t *key);

// Leaves the COMMAND line for the mode it was opened from.
void tui_input_end_command(tui_input_t *in);

// Opens the COMMAND line with text already on it.
void tui_input_command(tui_input_t *in, char prefix, const char *text);

// Leaves a COMMAND line opened with '/' on an empty line as the text of a message, '/' and all, in
// INSERT.
void tui_input_command_to_text(tui_input_t *in);

// The suggestion selected in the COMMAND line's menu: 1 with it in out, or 0 if there is none.
int tui_input_suggestion(const tui_input_t *in, tui_suggestion_t *out);

// "INSERT", "NORMAL" or "COMMAND".
const char *tui_mode_name(tui_input_mode_t mode);

typedef enum { TUI_ID_NONE = 0, TUI_ID_NATIVE, TUI_ID_AGE, TUI_ID_PGP } tui_identity_badge_t;

// The colour of the mode chip, and of the border around where the keys go.
typedef enum { TUI_TONE_INSERT = 0, TUI_TONE_NORMAL, TUI_TONE_COMMAND, TUI_TONE_PROMPT, TUI_TONE_PAGE } tui_tone_t;

// The chat screen. title is the session's name, set into the chat pane's border with its state and
// subtitle after it; without one the pane shows the welcome card. empty is what the pane says while
// the session has no messages (lines split by '\n'), and scroll how many of the newest are hidden
// below it.
typedef struct {
    int sidebar, console, chat;
    const char *title;
    const char *subtitle;
    tui_session_state_t state;
    const char *clock;
    const char *empty;
    int scroll;
    // The picture shown under the line offering file, or NULL while it's hidden.
    const tui_image_t *(*image)(const void *ctx, int file);
    const void *image_ctx;
} tui_view_t;

// The bottom row and the input. The chip says where you are, then your identity and nick, then
// message (the reply to the last thing done, until the next key) and hint ("key action · key
// action") at the right. On the chat screen input is in the box over it, titled prompt, with
// placeholder while it's empty and a count against limit (if not 0); on a page it's the field
// being typed in.
typedef struct {
    const char *chip;
    tui_tone_t tone;
    const char *message;
    const char *hint;
    tui_identity_badge_t badge;
    const char *nick;
    const uint8_t *nick_color;
    const tui_input_t *input;
    const char *prompt;
    const char *placeholder;
    int mask_input;
    int limit;
} tui_bar_t;

void tui_render(int rows, int cols,
                const tui_session_row_t *sessions, int n_sessions, int selected,
                const tui_peer_row_t *peers, int n_peers, const tui_kv_t *net, int n_net,
                const tui_scrollback_t *sb, const tui_scrollback_t *console,
                const tui_view_t *view, const tui_bar_t *bar, int color_enabled);

// Redraws only the input box and the bottom row.
void tui_render_bar(int rows, int cols, const tui_view_t *view, const tui_bar_t *bar, int color_enabled);

// A whole frame the same as the last one drawn isn't sent again. After anything that may have
// changed the screen behind chat's back (a resize), this makes the next one go out regardless.
void tui_invalidate(void);

// How a row's value is drawn: as it is, as a switch, as a choice h/l steps through, as a way into
// another page, or dim.
typedef enum { TUI_V_TEXT = 0, TUI_V_ON, TUI_V_OFF, TUI_V_CHOICE, TUI_V_LINK, TUI_V_MUTED } tui_value_kind_t;

typedef struct {
    const char *section;   // starts a new section with this heading, or NULL
    const char *label;
    const char *value;     // in a column after the label, or NULL
    tui_value_kind_t kind;
    const uint8_t *swatch; // a sample of this colour before the value, or NULL
} tui_row_t;

// A list page (settings, the pages under it, and help): rows by section with one selected, the
// selected row's help and usage under them, and a button after the rows if button is set
// (selected == n_rows selects it). nav lists the sections on the left, nav_sel lit; without it they
// come from the rows. title goes in the page's border, as its place among the pages; clock at its
// right end. With editing, the selected row's value is bar->input, being typed. keys draws the
// labels as keys.
typedef struct {
    const char *title;
    const char *clock;
    const char *intro;
    const char *const *nav;
    int n_nav;
    int nav_sel;
    const tui_row_t *rows;
    int n_rows;
    int selected;
    const char *help;
    const char *usage;
    const char *button;
    int editing;
    int keys;
} tui_page_t;

void tui_render_page(int rows, int cols, const tui_page_t *page, const tui_bar_t *bar, int color_enabled);

// A page of text to read (the changelog): paragraphs wrapped to the page's width, headings bold,
// bullets hanging. *scroll is how many rows down from the top it starts, clamped to what the page
// can scroll; returns that most.
typedef enum { TUI_P_TEXT = 0, TUI_P_HEADING, TUI_P_SUBHEADING, TUI_P_BULLET, TUI_P_BLANK } tui_para_kind_t;
typedef struct {
    tui_para_kind_t kind;
    const char *text;
} tui_para_t;
int tui_render_text(int rows, int cols, const char *title, const char *clock, const tui_para_t *paras, int n,
                    int *scroll, const tui_bar_t *bar, int color_enabled);

#endif
