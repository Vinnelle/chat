// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/tui.h"
#include "crypto/crypto.h"
#include "platform/platform.h"
#include "common/util.h"
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#ifndef CHAT_VERSION
#define CHAT_VERSION "0.0.0"
#endif

#define G_H       "\xe2\x94\x80"   // ─
#define G_V       "\xe2\x94\x82"   // │
#define G_TL      "\xe2\x95\xad"   // ╭
#define G_TR      "\xe2\x95\xae"   // ╮
#define G_BL      "\xe2\x95\xb0"   // ╰
#define G_BR      "\xe2\x95\xaf"   // ╯
#define G_LT      "\xe2\x94\x9c"   // ├
#define G_RT      "\xe2\x94\xa4"   // ┤
#define G_TT      "\xe2\x94\xac"   // ┬
#define G_BT      "\xe2\x94\xb4"   // ┴
#define G_DOT     "\xe2\x97\x8f"   // ●
#define G_RING    "\xe2\x97\x8b"   // ○
#define G_DOTTED  "\xe2\x97\x8c"   // ◌
#define G_PTR     "\xe2\x9d\xaf"   // ❯
#define G_CHECK   "\xe2\x9c\x93"   // ✓
#define G_CROSS   "\xe2\x9c\x97"   // ✗
#define G_DIAMOND "\xe2\x97\x86"   // ◆
#define G_ELLIPSIS "\xe2\x80\xa6"  // …
#define G_MID     "\xc2\xb7"       // ·
#define G_LSAQ    "\xe2\x80\xb9"   // ‹
#define G_RSAQ    "\xe2\x80\xba"   // ›
#define G_DOWN    "\xe2\x86\x93"   // ↓
#define G_BLOCK   "\xe2\x96\x88"   // █
#define G_BULLET  "\xe2\x80\xa2"   // •

void tui_scrollback_push(tui_scrollback_t *sb, const char *hhmm, const char *text, const uint8_t *rgb,
                         int mention, int color_len) {
    tui_line_t *l = &sb->lines[sb->head];
    memcpy(l->hhmm, hhmm, 6);
    size_t n = strlen(text);
    if (n > TUI_LINE_MAX - 1) {
        // Cut before a character, never inside one.
        n = TUI_LINE_MAX - 1;
        while (n > 0 && ((unsigned char)text[n] & 0xc0) == 0x80) n--;
    }
    memcpy(l->text, text, n);
    l->text[n] = '\0';
    if (rgb) { memcpy(l->rgb, rgb, 3); l->has_color = 1; }
    else l->has_color = 0;
    l->mention = mention;
    l->color_len = color_len;
    sb->head = (sb->head + 1) % TUI_SCROLLBACK;
    if (sb->count < TUI_SCROLLBACK) sb->count++;
}

void tui_scrollback_clear(tui_scrollback_t *sb) {
    crypto_wipe(sb, sizeof *sb);
}

static int hex_digit(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// "11;rgb:RRRR/GGGG/BBBB" (1 to 4 hex digits each), the terminal's background colour, as 8-bit rgb.
static int parse_bg_report(const uint8_t *s, size_t n, uint8_t rgb[3]) {
    static const char head[] = "11;rgb:";
    if (n < sizeof head - 1 || memcmp(s, head, sizeof head - 1) != 0) return -1;
    size_t i = sizeof head - 1;
    for (int c = 0; c < 3; c++) {
        unsigned v = 0;
        int digits = 0;
        while (i < n && hex_digit(s[i]) >= 0) {
            if (digits < 4) v = v * 16 + (unsigned)hex_digit(s[i]);
            digits++;
            i++;
        }
        if (digits == 0 || digits > 4) return -1;
        rgb[c] = (uint8_t)(v * 255 / ((1u << (4 * digits)) - 1));
        if (c < 2) {
            if (i >= n || s[i] != '/') return -1;
            i++;
        }
    }
    return 0;
}

size_t tui_decode_key(const uint8_t *buf, size_t len, tui_key_t *out) {
    out->type = TUI_KEY_NONE;
    out->ch_len = 0;
    if (len == 0) return 0;
    uint8_t b0 = buf[0];

    if (b0 == 0x1b) {
        if (len == 1) { out->type = TUI_KEY_ESCAPE; return 1; }

        // An OSC is the terminal answering a query: swallowed whole, up to BEL or ST, so none of
        // it lands in the input.
        if (buf[1] == ']') {
            size_t k = 2;
            while (k < len && buf[k] != 0x07 && !(buf[k] == 0x1b && k + 1 < len && buf[k + 1] == '\\')) k++;
            uint8_t rgb[3];
            out->type = TUI_KEY_UNKNOWN;
            if (k < len && parse_bg_report(buf + 2, k - 2, rgb) == 0) {
                out->type = TUI_KEY_BG_REPORT;
                memcpy(out->ch, rgb, 3);
                out->ch_len = 3;
            }
            if (k >= len) return len;
            return buf[k] == 0x07 ? k + 1 : k + 2;
        }

        // Unknown CSI sequences (Ctrl+arrows, F-keys, focus reports) are swallowed whole, so
        // their tail doesn't land in the input as text.
        if (len >= 3 && buf[1] == '[') {
            switch (buf[2]) {
                case 'A': out->type = TUI_KEY_UP;    return 3;
                case 'B': out->type = TUI_KEY_DOWN;  return 3;
                case 'C': out->type = TUI_KEY_RIGHT; return 3;
                case 'D': out->type = TUI_KEY_LEFT;  return 3;
                case 'H': out->type = TUI_KEY_HOME;  return 3;
                case 'F': out->type = TUI_KEY_END;   return 3;
                case 'Z': out->type = TUI_KEY_BACKTAB; return 3;
                default: break;
            }
            if (len >= 4 && buf[3] == '~') {
                switch (buf[2]) {
                    case '1': case '7': out->type = TUI_KEY_HOME;      return 4;
                    case '3':           out->type = TUI_KEY_DELETE;    return 4;
                    case '4': case '8': out->type = TUI_KEY_END;       return 4;
                    case '5':           out->type = TUI_KEY_PAGE_UP;   return 4;
                    case '6':           out->type = TUI_KEY_PAGE_DOWN; return 4;
                    default: break;
                }
            }
            if (len >= 5 && buf[2] == '1' && buf[3] == '1' && buf[4] == '~') { out->type = TUI_KEY_HELP; return 5; }
            // Parameter and intermediate bytes run up to a final byte in 0x40-0x7e.
            size_t k = 2;
            while (k < len && buf[k] >= 0x20 && buf[k] <= 0x3f) k++;
            out->type = TUI_KEY_UNKNOWN;
            if (k < len && buf[k] >= 0x40 && buf[k] <= 0x7e) {
                // "?997;1n" or "?997;2n": the terminal went over to a dark or a light theme.
                if (buf[k] == 'n' && k >= 7 && memcmp(buf + 2, "?997;", 5) == 0) out->type = TUI_KEY_THEME_CHANGED;
                return k + 1;
            }
            return 1;
        } else if (len >= 3 && buf[1] == 'O') {
            switch (buf[2]) {
                case 'H': out->type = TUI_KEY_HOME; return 3;
                case 'F': out->type = TUI_KEY_END;  return 3;
                case 'P': out->type = TUI_KEY_HELP; return 3;
                default: out->type = TUI_KEY_UNKNOWN; return 3;
            }
        }

        // Esc and the next key arrived in one read (a fast ':' after Esc, say): the Esc stands
        // alone, like vim reads it.
        out->type = (buf[1] == '[' || buf[1] == 'O') ? TUI_KEY_UNKNOWN : TUI_KEY_ESCAPE;
        return 1;
    }

    if (b0 == '\r') { out->type = TUI_KEY_ENTER; return 1; }
    if (b0 == '\n') { out->type = TUI_KEY_JOIN_SESSION; return 1; }
    if (b0 == 0x7f || b0 == 0x08) { out->type = TUI_KEY_BACKSPACE; return 1; }
    if (b0 == '\t') { out->type = TUI_KEY_TAB; return 1; }
    if (b0 == 0x0e) { out->type = TUI_KEY_NEW_SESSION; return 1; }
    if (b0 == 0x17) { out->type = TUI_KEY_DELETE_WORD; return 1; }
    if (b0 == 0x15) { out->type = TUI_KEY_CTRL_U; return 1; }
    if (b0 == 0x04) { out->type = TUI_KEY_CTRL_D; return 1; }
    if (b0 == 0x02) { out->type = TUI_KEY_TOGGLE_SIDEBAR; return 1; }
    if (b0 == 0x0f) { out->type = TUI_KEY_TOGGLE_CONSOLE; return 1; }
    if (b0 == 0x14) { out->type = TUI_KEY_TOGGLE_CHAT; return 1; }
    if (b0 == 0x13) { out->type = TUI_KEY_SETTINGS; return 1; }
    if (b0 < 0x20) { out->type = TUI_KEY_UNKNOWN; return 1; }

    // Only whole, well-formed characters reach the input line; a stray byte (a C1 control
    // among them) is dropped rather than echoed to the terminal.
    size_t seqlen = 1;
    if ((b0 & 0xe0) == 0xc0) seqlen = 2;
    else if ((b0 & 0xf0) == 0xe0) seqlen = 3;
    else if ((b0 & 0xf8) == 0xf0) seqlen = 4;
    else if (b0 >= 0x80) { out->type = TUI_KEY_UNKNOWN; return 1; }
    if (seqlen > len) { out->type = TUI_KEY_UNKNOWN; return 1; }
    size_t adv;
    utf8_decode((const char *)buf, seqlen, 0, &adv);
    if (adv != seqlen) { out->type = TUI_KEY_UNKNOWN; return 1; }
    memcpy(out->ch, buf, seqlen);
    out->ch[seqlen] = '\0';
    out->ch_len = (int)seqlen;
    out->type = TUI_KEY_CHAR;
    return seqlen;
}

void tui_input_clear(tui_input_t *in) {
    in->len = 0; in->cursor = 0; in->buf[0] = '\0';
    in->mode = TUI_IMODE_INSERT;
    in->cmd_len = 0; in->cmd[0] = '\0';
    in->cmd_prefix = ':';
    in->cmd_from_insert = 0;
    in->cmd_as_text = 0;
    in->menu_sel = 0;
}

const char *tui_mode_name(tui_input_mode_t mode) {
    switch (mode) {
        case TUI_IMODE_NORMAL:  return "NORMAL";
        case TUI_IMODE_COMMAND: return "COMMAND";
        case TUI_IMODE_INSERT:
        default:                return "INSERT";
    }
}

static int step_left(const tui_input_t *in, int pos) {
    if (pos > 0) { pos--; while (pos > 0 && (in->buf[pos] & 0xc0) == 0x80) pos--; }
    return pos;
}
static int step_right(const tui_input_t *in, int pos) {
    if (pos < in->len) { pos++; while (pos < in->len && (in->buf[pos] & 0xc0) == 0x80) pos++; }
    return pos;
}

static void normal_clamp(tui_input_t *in) {
    if (in->len == 0) { in->cursor = 0; return; }
    int last = step_left(in, in->len);
    if (in->cursor > last) in->cursor = last;
}

static void enter_normal(tui_input_t *in) {
    in->mode = TUI_IMODE_NORMAL;
    in->cmd_len = 0; in->cmd[0] = '\0';
    normal_clamp(in);
}

// A '/' line may turn back into text only from an empty line: a draft stays put.
static void enter_command(tui_input_t *in, char prefix) {
    in->cmd_from_insert = in->mode == TUI_IMODE_INSERT;
    in->cmd_as_text = prefix == '/' && in->len == 0;
    in->mode = TUI_IMODE_COMMAND;
    in->cmd_len = 0; in->cmd[0] = '\0';
    in->cmd_prefix = prefix;
    in->menu_sel = 0;
}

void tui_input_end_command(tui_input_t *in) {
    int back = in->cmd_from_insert;
    in->cmd_from_insert = 0;
    in->cmd_as_text = 0;
    in->menu_sel = 0;
    if (back) { in->mode = TUI_IMODE_INSERT; in->cmd_len = 0; in->cmd[0] = '\0'; }
    else enter_normal(in);
}

void tui_input_command(tui_input_t *in, char prefix, const char *text) {
    enter_command(in, prefix);
    copy_str(in->cmd, text, sizeof in->cmd);
    in->cmd_len = (int)strlen(in->cmd);
}

static void delete_at_cursor(tui_input_t *in) {
    if (in->cursor >= in->len) return;
    int fwd = step_right(in, in->cursor) - in->cursor;
    memmove(in->buf + in->cursor, in->buf + in->cursor + fwd, (size_t)(in->len - in->cursor - fwd));
    in->len -= fwd;
    in->buf[in->len] = '\0';
}

static void insert_bytes(tui_input_t *in, const char *s, int n) {
    if (in->len + n >= (int)sizeof(in->buf)) return;
    memmove(in->buf + in->cursor + n, in->buf + in->cursor, (size_t)(in->len - in->cursor));
    memcpy(in->buf + in->cursor, s, (size_t)n);
    in->len += n;
    in->cursor += n;
    in->buf[in->len] = '\0';
}

// Start of the "@prefix" word ending at the cursor, or -1. Only offered at the end of the line.
static int mention_start(const tui_input_t *in) {
    if (!in->mention || in->cursor != in->len) return -1;
    int i = in->cursor;
    while (i > 0 && in->buf[i - 1] != ' ' && in->buf[i - 1] != '@') i--;
    if (i == 0 || in->buf[i - 1] != '@' || i == in->cursor) return -1;
    if (i >= 2 && in->buf[i - 2] != ' ') return -1;
    return i;
}

static const char *mention_suggestion(const tui_input_t *in) {
    int start = mention_start(in);
    if (start < 0) return NULL;
    const char *nick = in->mention(in->buf + start);
    if (!nick || strlen(nick) <= (size_t)(in->cursor - start)) return NULL;
    return nick;
}

static int insert_feed(tui_input_t *in, const tui_key_t *key) {
    switch (key->type) {
        case TUI_KEY_TAB: {
            const char *nick = mention_suggestion(in);
            if (!nick) return 0;
            int start = mention_start(in);
            size_t nlen = strlen(nick);
            if ((size_t)start + nlen + 1 >= sizeof in->buf) return 1;
            memcpy(in->buf + start, nick, nlen);
            in->buf[start + nlen] = ' ';
            in->len = in->cursor = start + (int)nlen + 1;
            in->buf[in->len] = '\0';
            return 1;
        }
        case TUI_KEY_CHAR:
            // '/' on an empty line opens the COMMAND line, as chat programs have it.
            if (in->modal && in->len == 0 && key->ch_len == 1 && key->ch[0] == '/') {
                enter_command(in, '/');
                return 1;
            }
            insert_bytes(in, key->ch, key->ch_len);
            return 1;
        case TUI_KEY_BACKSPACE: {
            if (in->cursor == 0) return 1;
            int back = in->cursor - step_left(in, in->cursor);
            memmove(in->buf + in->cursor - back, in->buf + in->cursor, (size_t)(in->len - in->cursor));
            in->len -= back;
            in->cursor -= back;
            in->buf[in->len] = '\0';
            return 1;
        }
        case TUI_KEY_DELETE: delete_at_cursor(in); return 1;
        case TUI_KEY_DELETE_WORD: {
            // Back over spaces, then the word before them, as vim and readline do.
            int start = in->cursor;
            while (start > 0 && in->buf[start - 1] == ' ') start--;
            while (start > 0 && in->buf[start - 1] != ' ') start--;
            memmove(in->buf + start, in->buf + in->cursor, (size_t)(in->len - in->cursor));
            in->len -= in->cursor - start;
            in->cursor = start;
            in->buf[in->len] = '\0';
            return 1;
        }
        case TUI_KEY_CTRL_U:
            // Everything before the cursor, as readline has it.
            memmove(in->buf, in->buf + in->cursor, (size_t)(in->len - in->cursor));
            in->len -= in->cursor;
            in->cursor = 0;
            in->buf[in->len] = '\0';
            return 1;
        case TUI_KEY_LEFT:  in->cursor = step_left(in, in->cursor); return 1;
        case TUI_KEY_RIGHT: in->cursor = step_right(in, in->cursor); return 1;
        case TUI_KEY_HOME: in->cursor = 0; return 1;
        case TUI_KEY_END:  in->cursor = in->len; return 1;
        case TUI_KEY_ESCAPE:
            if (!in->modal) return 0;
            enter_normal(in);
            return 1;
        default: return 0;
    }
}

static int normal_feed(tui_input_t *in, const tui_key_t *key) {
    if (key->type == TUI_KEY_CHAR && key->ch_len == 1) {
        switch (key->ch[0]) {
            case 'h': in->cursor = step_left(in, in->cursor); return 1;
            case 'l': in->cursor = step_right(in, in->cursor); normal_clamp(in); return 1;
            // Left to the caller: they step through the sessions, jump to the newest message, open
            // the help and show or hide the console, the chat and the sidebar.
            case 'j': case 'k': case 'G': case '?': case 'c': case 'C': case 's': return 0;
            case 'i': in->mode = TUI_IMODE_INSERT; return 1;
            case 'a': in->cursor = step_right(in, in->cursor); in->mode = TUI_IMODE_INSERT; return 1;
            case 'I': in->cursor = 0; in->mode = TUI_IMODE_INSERT; return 1;
            case 'A': in->cursor = in->len; in->mode = TUI_IMODE_INSERT; return 1;
            case 'x': delete_at_cursor(in); normal_clamp(in); return 1;
            case '0': in->cursor = 0; return 1;
            case '$': in->cursor = in->len; normal_clamp(in); return 1;
            case ':': enter_command(in, ':'); return 1;
            case '/': enter_command(in, '/'); return 1;
            default: return 1;
        }
    }
    switch (key->type) {
        case TUI_KEY_LEFT: case TUI_KEY_BACKSPACE: in->cursor = step_left(in, in->cursor); return 1;
        case TUI_KEY_RIGHT: in->cursor = step_right(in, in->cursor); normal_clamp(in); return 1;
        case TUI_KEY_DELETE: delete_at_cursor(in); normal_clamp(in); return 1;
        case TUI_KEY_HOME: in->cursor = 0; return 1;
        case TUI_KEY_END: in->cursor = in->len; normal_clamp(in); return 1;
        default: return 0;
    }
}

#define SUGGEST_MAX 64

static int suggestion_count(const tui_input_t *in) {
    if (!in->suggest) return 0;
    tui_suggestion_t s;
    int n = 0;
    while (n < SUGGEST_MAX && in->suggest(in->cmd, n, &s)) n++;
    return n;
}

int tui_input_suggestion(const tui_input_t *in, tui_suggestion_t *out) {
    int n = suggestion_count(in);
    if (n == 0) return 0;
    int sel = in->menu_sel < 0 ? 0 : in->menu_sel >= n ? n - 1 : in->menu_sel;
    return in->suggest(in->cmd, sel, out);
}

// Whether the COMMAND line could still be a command: its first word starts a command's name or
// alias, or, once a space follows it, is one.
static int could_be_command(const tui_input_t *in) {
    if (!in->is_command) return 1;
    char word[sizeof in->cmd];
    size_t n = strcspn(in->cmd, " ");
    memcpy(word, in->cmd, n);
    word[n] = '\0';
    return in->is_command(word, in->cmd[n] == ' ');
}

void tui_input_command_to_text(tui_input_t *in) {
    char text[sizeof in->cmd + 1];
    int n = snprintf(text, sizeof text, "/%s", in->cmd);
    tui_input_end_command(in);
    in->mode = TUI_IMODE_INSERT;
    insert_bytes(in, text, n);
}

// COMMAND mode owns every key except Enter, which the caller handles to run the line.
static int command_feed(tui_input_t *in, const tui_key_t *key) {
    switch (key->type) {
        case TUI_KEY_CHAR:
            // A second '/' straight after the first: a message that starts with '/'.
            if (in->cmd_len == 0 && in->cmd_as_text && key->ch_len == 1 && key->ch[0] == '/') {
                tui_input_command_to_text(in);
                return 1;
            }
            if (in->cmd_len + key->ch_len >= (int)sizeof(in->cmd)) return 1;
            memcpy(in->cmd + in->cmd_len, key->ch, (size_t)key->ch_len);
            in->cmd_len += key->ch_len;
            in->cmd[in->cmd_len] = '\0';
            in->menu_sel = 0;
            // Opened from typing, a line no command can start stays what it was: text.
            if (in->cmd_as_text && !could_be_command(in)) tui_input_command_to_text(in);
            return 1;
        case TUI_KEY_TAB: {
            tui_suggestion_t s;
            if (!tui_input_suggestion(in, &s)) return 1;
            size_t slen = strlen(s.line);
            if (slen >= sizeof in->cmd) return 1;
            memcpy(in->cmd, s.line, slen + 1);
            in->cmd_len = (int)slen;
            in->menu_sel = 0;
            return 1;
        }
        case TUI_KEY_UP:
            if (in->menu_sel > 0) in->menu_sel--;
            return 1;
        case TUI_KEY_DOWN:
            if (in->menu_sel + 1 < suggestion_count(in)) in->menu_sel++;
            return 1;
        case TUI_KEY_BACKSPACE:
            if (in->cmd_len == 0) { tui_input_end_command(in); return 1; }
            in->cmd_len--;
            while (in->cmd_len > 0 && (in->cmd[in->cmd_len] & 0xc0) == 0x80) in->cmd_len--;
            in->cmd[in->cmd_len] = '\0';
            in->menu_sel = 0;
            return 1;
        case TUI_KEY_DELETE_WORD:
            while (in->cmd_len > 0 && in->cmd[in->cmd_len - 1] == ' ') in->cmd_len--;
            while (in->cmd_len > 0 && in->cmd[in->cmd_len - 1] != ' ') in->cmd_len--;
            in->cmd[in->cmd_len] = '\0';
            in->menu_sel = 0;
            return 1;
        case TUI_KEY_CTRL_U:
            in->cmd_len = 0;
            in->cmd[0] = '\0';
            in->menu_sel = 0;
            return 1;
        case TUI_KEY_ESCAPE:
            tui_input_end_command(in);
            return 1;
        case TUI_KEY_ENTER:
            return 0;
        default:
            return 1;
    }
}

int tui_input_feed(tui_input_t *in, const tui_key_t *key) {
    if (!in->modal) return insert_feed(in, key);
    switch (in->mode) {
        case TUI_IMODE_INSERT:  return insert_feed(in, key);
        case TUI_IMODE_NORMAL:  return normal_feed(in, key);
        case TUI_IMODE_COMMAND: return command_feed(in, key);
        default: return 0;
    }
}

// ---- drawing ----
//
// Everything is drawn in the terminal's own colours: its default foreground and background, faint
// text for what's secondary, and its 16-colour palette for the accents. The UI so takes on the
// terminal's theme, whatever it is, and changes with it. Peers' colours are the one exception;
// see readable().

#define FRAME_CAP 262144
static char g_frame[FRAME_CAP];

typedef struct { char *buf; size_t cap; size_t len; } wbuf_t;

static void wapp(wbuf_t *w, const char *fmt, ...) {
    if (w->len >= w->cap) return;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(w->buf + w->len, w->cap - w->len, fmt, ap);
    va_end(ap);
    if (n > 0) w->len += (size_t)n < w->cap - w->len ? (size_t)n : w->cap - w->len;
}

// Appends as much of s as fits in width columns and returns the columns it takes. A malformed
// byte or a control character goes out as U+FFFD: all text reaches the terminal through here,
// and nothing in it may start an escape sequence, whatever the terminal's encoding.
static int wapp_trunc(wbuf_t *w, const char *s, int width) {
    static const char REPLACEMENT[] = "\xef\xbf\xbd";
    int used = 0;
    size_t n = strlen(s);
    for (size_t i = 0, adv; i < n; i += adv) {
        int cw = utf8_char_cols(s, n, i, &adv);
        if (used + cw > width) break;
        uint32_t cp = utf8_decode(s, n, i, &adv);
        int bad = cp < 0x20 || cp == 0x7f || (cp >= 0x80 && cp <= 0x9f) || (adv == 1 && cp >= 0x80);
        const char *src = bad ? REPLACEMENT : s + i;
        size_t len = bad ? sizeof REPLACEMENT - 1 : adv;
        if (len > w->cap - w->len) break;
        memcpy(w->buf + w->len, src, len);
        w->len += len;
        used += cw;
    }
    return used;
}

// As wapp_trunc, but text cut short ends in an ellipsis.
static int wapp_ell(wbuf_t *w, const char *s, int width) {
    if (width <= 0) return 0;
    if (utf8_str_cols(s) <= width) return wapp_trunc(w, s, width);
    int used = wapp_trunc(w, s, width - 1);
    wapp(w, G_ELLIPSIS);
    return used + 1;
}

static void at(wbuf_t *w, int row, int col) { wapp(w, "\x1b[%d;%dH", row, col); }

static int g_color;                  // this frame's: colours, or attributes alone (NO_COLOR)
static int g_have_bg;                // the terminal has told its background colour
static uint8_t g_bg[3];
static char g_sel_bg[32];            // a shade off that background, for the selected row
static const char *g_row_bg = "";    // the background of the row being drawn, kept through styles

typedef enum {
    S_PLAIN = 0, S_FAINT, S_BOLD, S_ACCENT, S_ACCENT_BOLD, S_GREEN, S_YELLOW, S_YELLOW_BOLD, S_RED, S_RED_BOLD
} style_t;

static const char *const STYLE_COLOR[] = {
    "", "\x1b[2m", "\x1b[1m", "\x1b[35m", "\x1b[1;35m", "\x1b[32m", "\x1b[33m", "\x1b[1;33m", "\x1b[31m", "\x1b[1;31m",
};
static const char *const STYLE_MONO[] = {
    "", "\x1b[2m", "\x1b[1m", "", "\x1b[1m", "", "", "\x1b[1m", "", "\x1b[1m",
};

// Every style starts from nothing but the row's background, so none carries into the next.
static void sty(wbuf_t *w, style_t s) {
    wapp(w, "\x1b[0m%s%s", g_row_bg, (g_color ? STYLE_COLOR : STYLE_MONO)[s]);
}

// The palette colour of each tone: INSERT green, NORMAL blue, COMMAND yellow, prompts and pages magenta.
static const char *const TONE_SGR[] = { "32", "34", "33", "35", "35" };

static const char *tone_sgr(tui_tone_t t) { return TONE_SGR[(unsigned)t < 5 ? (unsigned)t : 0]; }

static void sty_tone(wbuf_t *w, tui_tone_t t, int bold) {
    wapp(w, "\x1b[0m%s%s", g_row_bg, bold ? "\x1b[1m" : "");
    if (g_color) wapp(w, "\x1b[%sm", tone_sgr(t));
}

// Reversed, so the chip takes the palette colour and its text the terminal's background.
static void sty_pill(wbuf_t *w, tui_tone_t t) {
    wapp(w, "\x1b[0m\x1b[1;7m");
    if (g_color) wapp(w, "\x1b[%sm", tone_sgr(t));
}

// A box's border: faint, or in the tone of the keys it holds.
static const char *border_sgr(int tone) {
    static const char *const LIT[] = { "\x1b[32m", "\x1b[34m", "\x1b[33m", "\x1b[35m", "\x1b[35m" };
    if (!g_color) return "";
    return tone >= 0 && tone < 5 ? LIT[tone] : "\x1b[2m";
}

// Relative luminance, a gamma of 2 standing in for sRGB's curve.
static double lum(const uint8_t c[3]) {
    double r = c[0] / 255.0, g = c[1] / 255.0, b = c[2] / 255.0;
    return 0.2126 * r * r + 0.7152 * g * g + 0.0722 * b * b;
}

static double contrast(const uint8_t a[3], const uint8_t b[3]) {
    double la = lum(a) + 0.05, lb = lum(b) + 0.05;
    return la > lb ? la / lb : lb / la;
}

// A person's colour, eased toward the terminal's foreground side until it reads on its background:
// yellow on a light theme darkens, indigo on a dark one lightens. As it is until the terminal has
// told its background.
static void readable(const uint8_t in[3], uint8_t out[3]) {
    memcpy(out, in, 3);
    if (!g_have_bg) return;
    int toward = lum(g_bg) < 0.25 ? 255 : 0;
    for (int i = 0; i < 12 && contrast(out, g_bg) < 3.0; i++)
        for (int k = 0; k < 3; k++) out[k] = (uint8_t)(out[k] + (toward - out[k]) / 5);
}

void tui_set_background(const uint8_t rgb[3]) {
    memcpy(g_bg, rgb, 3);
    g_have_bg = 1;
    int dark = lum(rgb) < 0.25;
    uint8_t s[3];
    for (int k = 0; k < 3; k++) s[k] = (uint8_t)(dark ? rgb[k] + (255 - rgb[k]) / 9 : rgb[k] - rgb[k] / 16);
    snprintf(g_sel_bg, sizeof g_sel_bg, "\x1b[48;2;%u;%u;%um", s[0], s[1], s[2]);
}

// exact: as given (a colour sample), else made readable().
static void sty_rgb(wbuf_t *w, const uint8_t rgb[3], int bold, int exact) {
    wapp(w, "\x1b[0m%s%s", g_row_bg, bold ? "\x1b[1m" : "");
    if (!g_color) return;
    uint8_t c[3];
    if (exact) memcpy(c, rgb, 3);
    else readable(rgb, c);
    wapp(w, "\x1b[38;2;%u;%u;%um", c[0], c[1], c[2]);
}

// The selected row stands on a shade off the background once it's known, reversed without colour.
static void row_select(int on) {
    if (!on) g_row_bg = "";
    else if (!g_color) g_row_bg = "\x1b[7m";
    else g_row_bg = g_have_bg ? g_sel_bg : "";
}

// Writes styled text into a row from its left, room columns at most.
typedef struct { wbuf_t *w; int used, room; } pen_t;

static void ptext(pen_t *p, style_t s, const char *t) {
    sty(p->w, s);
    p->used += wapp_trunc(p->w, t, p->room - p->used);
}

static void pell(pen_t *p, style_t s, const char *t, int width) {
    int room = p->room - p->used;
    if (width > room) width = room;
    sty(p->w, s);
    p->used += wapp_ell(p->w, t, width);
}

static void prgb(pen_t *p, const uint8_t rgb[3], int bold, const char *t, int width) {
    int room = p->room - p->used;
    if (width > room) width = room;
    sty_rgb(p->w, rgb, bold, 0);
    p->used += wapp_ell(p->w, t, width);
}

static void pspace(pen_t *p, int to) {
    if (to > p->room) to = p->room;
    if (p->used >= to) return;
    sty(p->w, S_PLAIN);
    while (p->used < to) { wapp(p->w, " "); p->used++; }
}

// A row inside a box: a column of padding either side of the pen, which covers the rest.
static void inner_begin(wbuf_t *w, pen_t *p, int row, int left, int width) {
    at(w, row, left);
    sty(w, S_PLAIN);
    wapp(w, width > 0 ? " " : "");
    *p = (pen_t){ w, 0, width - 2 < 0 ? 0 : width - 2 };
}

static void inner_end(pen_t *p) {
    pspace(p, p->room);
    sty(p->w, S_PLAIN);
    wapp(p->w, " \x1b[0m");
}

static void blank_row(wbuf_t *w, int row, int left, int width) {
    pen_t p;
    inner_begin(w, &p, row, left, width);
    inner_end(&p);
}

// "key action · key action": each key lit, what it does faint. It takes as many columns as it has
// characters.
static void draw_hint(pen_t *p, const char *h) {
    static const char SEP[] = " " G_MID " ";
    for (const char *s = h; *s; ) {
        const char *end = strstr(s, SEP);
        size_t n = end ? (size_t)(end - s) : strlen(s);
        char part[96];
        if (n >= sizeof part) n = sizeof part - 1;
        memcpy(part, s, n);
        part[n] = '\0';
        char *sp = strchr(part, ' ');
        if (sp) *sp = '\0';
        ptext(p, S_ACCENT, part);
        if (sp) { ptext(p, S_FAINT, " "); ptext(p, S_FAINT, sp + 1); }
        if (!end) break;
        ptext(p, S_FAINT, SEP);
        s = end + sizeof SEP - 1;
    }
}

// Styled text built before its place is known: a box's titles.
typedef struct { char buf[1024]; wbuf_t w; pen_t p; } span_t;

static void span_init(span_t *s, int room) {
    s->w = (wbuf_t){ s->buf, sizeof s->buf, 0 };
    s->p = (pen_t){ &s->w, 0, room < 0 ? 0 : room };
}

// The room for a title in an edge width columns wide, beside one right_cols wide at its right.
static int title_room(int width, int right_cols) {
    int r = width - 6 - (right_cols > 0 ? right_cols + 2 : 0);
    return r < 0 ? 0 : r;
}

// A box's top or bottom edge, or a junction across it: lc, a rule with title near its left end and
// right near its right end, then rc. bs styles the rule.
static void edge(wbuf_t *w, int row, int left, int width, const char *lc, const char *rc, const char *bs,
                 const span_t *title, const span_t *right) {
    if (width < 4) return;
    int tc = title && title->p.used > 0 ? title->p.used + 2 : 0;
    int rc_w = right && right->p.used > 0 ? right->p.used + 2 : 0;
    if (4 + tc + rc_w > width) rc_w = 0;
    if (4 + tc > width) tc = 0;
    at(w, row, left);
    wapp(w, "\x1b[0m%s%s" G_H, bs, lc);
    if (tc) {
        wapp(w, " ");
        if (w->len + title->w.len < w->cap) { memcpy(w->buf + w->len, title->buf, title->w.len); w->len += title->w.len; }
        wapp(w, "\x1b[0m%s ", bs);
    }
    for (int i = 0; i < width - 4 - tc - rc_w; i++) wapp(w, G_H);
    if (rc_w) {
        wapp(w, " ");
        if (w->len + right->w.len < w->cap) { memcpy(w->buf + w->len, right->buf, right->w.len); w->len += right->w.len; }
        wapp(w, "\x1b[0m%s ", bs);
    }
    wapp(w, G_H "%s\x1b[0m", rc);
}

static void sides(wbuf_t *w, int top, int h, int left, int width, const char *bs) {
    for (int r = top; r < top + h; r++) {
        at(w, r, left);
        wapp(w, "\x1b[0m%s" G_V, bs);
        at(w, r, left + width - 1);
        wapp(w, G_V "\x1b[0m");
    }
}

typedef struct { int top, left, h, w; } rect_t;

// The screen is one frame. A box that isn't at the left edge shares its left side with the box
// before it, so its corners there join the frame's top and bottom edges.
static const char *top_left(rect_t r) { return r.left > 1 ? G_TT : G_TL; }
static const char *bottom_left(rect_t r) { return r.left > 1 ? G_BT : G_BL; }

static void box(wbuf_t *w, rect_t r, const char *bs, const span_t *title, const span_t *right, const span_t *foot) {
    edge(w, r.top, r.left, r.w, top_left(r), G_TR, bs, title, right);
    sides(w, r.top + 1, r.h - 2, r.left, r.w, bs);
    edge(w, r.top + r.h - 1, r.left, r.w, bottom_left(r), G_BR, bs, NULL, foot);
}

// The "◆ chat" and version every screen's left-hand box is titled with.
static void brand(span_t *title, span_t *right, int width) {
    span_init(right, width);
    ptext(&right->p, S_FAINT, "v" CHAT_VERSION);
    span_init(title, title_room(width, right->p.used));
    ptext(&title->p, S_ACCENT_BOLD, G_DIAMOND " chat");
}

// The last whole frame sent, by its hash.
static uint8_t g_last_frame[32];
static int g_last_frame_valid;

void tui_invalidate(void) { g_last_frame_valid = 0; }

static void lock_buffers(void);

// Autowrap is off while a frame draws: a character the width table guesses too narrow is clipped
// at the right edge instead of pushing the rest of the frame down a row.
static void begin_frame(wbuf_t *w) {
    lock_buffers();
    wapp(w, "\x1b[?2026h\x1b[?25l\x1b[?7l");
}

// whole: the frame covers the screen, and isn't sent if it's the one already there (the clock
// redraws every second, but shows minutes).
static void end_frame(wbuf_t *w, int whole) {
    // Written on its own so a frame that filled its buffer still turns autowrap back on.
    static const char tail[] = "\x1b[0m\x1b[?7h\x1b[?2026l";
    if (whole) {
        uint8_t h[32];
        sha256_hash(w->buf, w->len, h);
        int same = g_last_frame_valid && memcmp(h, g_last_frame, sizeof h) == 0;
        memcpy(g_last_frame, h, sizeof h);
        g_last_frame_valid = 1;
        if (same) return;
    } else {
        g_last_frame_valid = 0;
    }
    platform_write_stdout(w->buf, w->len);
    platform_write_stdout(tail, sizeof tail - 1);
}

static void place_cursor(wbuf_t *w, int row, int col, const tui_input_t *in) {
    if (row <= 0) { wapp(w, "\x1b[?25l"); return; }
    const char *shape = in && in->modal && in->mode == TUI_IMODE_NORMAL ? "\x1b[2 q" : "\x1b[6 q";
    wapp(w, "\x1b[0m%s\x1b[%d;%dH\x1b[?25h", shape, row, col);
}

#define MAX_ROWS 200
#define MAX_COLS 1000

static void clamp_size(int *rows, int *cols) {
    if (*rows < 6) *rows = 6;
    if (*cols < 30) *cols = 30;
    if (*rows > MAX_ROWS) *rows = MAX_ROWS;
    if (*cols > MAX_COLS) *cols = MAX_COLS;
}

// ---- the grid: rows drawn out of order (the chat fills from the bottom), then put on screen ----

#define GRID_ROWBYTES 3072

typedef struct {
    char buf[MAX_ROWS][GRID_ROWBYTES];
    int len[MAX_ROWS], used[MAX_ROWS];
    int rows, w;
} grid_t;

static grid_t g_grid;

// The frame and the grid hold the conversation as drawn: kept out of swap like the scrollbacks.
static void lock_buffers(void) {
    static int locked;
    if (locked) return;
    locked = 1;
    crypto_lock(g_frame, sizeof g_frame);
    crypto_lock(&g_grid, sizeof g_grid);
}

static void grid_reset(grid_t *g, int rows, int w) {
    if (rows > MAX_ROWS) rows = MAX_ROWS;
    g->rows = rows < 0 ? 0 : rows;
    g->w = w < 0 ? 0 : w;
    for (int r = 0; r < g->rows; r++) g->len[r] = g->used[r] = 0;
}

typedef struct { wbuf_t wb; pen_t p; } gpen_t;

static void grid_open(grid_t *g, int r, gpen_t *gp) {
    gp->wb = (wbuf_t){ g->buf[r], GRID_ROWBYTES, (size_t)g->len[r] };
    gp->p = (pen_t){ &gp->wb, g->used[r], g->w };
}

static void grid_close(grid_t *g, int r, const gpen_t *gp) {
    g->len[r] = (int)gp->wb.len;
    g->used[r] = gp->p.used;
}

// Puts the grid's rows on screen from (top, left), each padded to its full width, with pad
// columns more either side.
static void grid_emit(wbuf_t *w, const grid_t *g, int top, int left, int pad) {
    for (int r = 0; r < g->rows; r++) {
        at(w, top + r, left);
        wapp(w, "\x1b[0m");
        for (int i = 0; i < pad; i++) wapp(w, " ");
        if (g->len[r] > 0 && w->len + (size_t)g->len[r] < w->cap) {
            memcpy(w->buf + w->len, g->buf[r], (size_t)g->len[r]);
            w->len += (size_t)g->len[r];
        }
        wapp(w, "\x1b[0m");
        for (int i = g->used[r]; i < g->w + pad; i++) wapp(w, " ");
    }
}

// Bytes of s (len of them) that go on one row of width columns: up to the last space that
// leaves the row at least a third full, else as much as fits.
static size_t wrap_chunk(const char *s, size_t len, int width) {
    if (width < 1) width = 1;
    size_t n = utf8_fit_cols(s, len, width, NULL);
    if (n >= len) return len;
    if (n == 0) {
        // A character wider than the whole row still has to go somewhere.
        size_t adv;
        utf8_char_cols(s, len, 0, &adv);
        return adv;
    }
    size_t sp = n;
    while (sp > 0 && s[sp] != ' ') sp--;
    if (sp > n / 3) return sp;
    return n;
}

// Splits text into rows, the first first_w columns wide and the rest rest_w; returns how many.
static int wrap_rows(const char *text, int first_w, int rest_w, size_t *off, size_t *len, int max) {
    int n = 0;
    const char *tx = text;
    size_t remain = strlen(text);
    while (remain > 0 && n < max) {
        size_t take = wrap_chunk(tx, remain, n == 0 ? first_w : rest_w);
        off[n] = (size_t)(tx - text);
        len[n] = take;
        n++;
        tx += take; remain -= take;
        while (remain > 0 && *tx == ' ') { tx++; remain--; }
    }
    if (n == 0) { off[0] = 0; len[0] = 0; n = 1; }
    return n;
}

// ---- the chat and the console ----

// A chat line's name (its first color_len bytes, less a mention's "@ " and the ':' after it) and
// the text after it. 0 for a line that isn't one.
static int split_chat_line(const tui_line_t *l, char *name, size_t cap, const char **body) {
    size_t n = strlen(l->text);
    if (l->color_len <= 1 || (size_t)l->color_len > n || l->text[l->color_len - 1] != ':') return 0;
    const char *s = l->text;
    size_t len = (size_t)l->color_len - 1;
    if (l->mention && len >= 2 && s[0] == '@' && s[1] == ' ') { s += 2; len -= 2; }
    if (len >= cap) len = cap - 1;
    memcpy(name, s, len);
    name[len] = '\0';
    const char *b = l->text + l->color_len;
    while (*b == ' ') b++;
    *body = b;
    return 1;
}

// A name as the chat gives it: the nick in its colour, and what the UI adds to it - " (you)", a
// "#id" telling lookalikes apart - faint. No nick can hold '(' or '#', so those are the UI's own.
static void draw_name(pen_t *p, const char *name, const uint8_t *rgb) {
    size_t nick = strcspn(name, "#(");
    while (nick > 0 && name[nick - 1] == ' ') nick--;
    char buf[96];
    if (nick >= sizeof buf) nick = sizeof buf - 1;
    memcpy(buf, name, nick);
    buf[nick] = '\0';
    if (rgb) sty_rgb(p->w, rgb, 1, 0);
    else sty(p->w, S_BOLD);
    p->used += wapp_trunc(p->w, buf, p->room - p->used);
    ptext(p, S_FAINT, name + nick);
}

#define SB_AT(sb, k) (&(sb)->lines[((sb)->head - 1 - (k) + TUI_SCROLLBACK * 2) % TUI_SCROLLBACK])

// Lines from the bottom of nrows grid rows up, newest last, skipping the skip newest. Chat lines
// line up in columns - time, name, text - and a run from one person in one minute shows the time
// and name once. The console's lines are faint, its warnings yellow.
static void draw_lines(grid_t *g, int first, int nrows, const tui_scrollback_t *sb, int skip, int console) {
    if (!sb || nrows <= 0 || sb->count == 0) return;
    int W = g->w;
    if (skip >= sb->count) skip = sb->count - 1;
    if (skip < 0) skip = 0;
    int time_w = W >= 36 ? 7 : 0;
    int nw = 0;
    if (!console) {
        for (int k = skip; k < sb->count && k < skip + nrows; k++) {
            char name[96];
            const char *body;
            if (!split_chat_line(SB_AT(sb, k), name, sizeof name, &body)) continue;
            int c = utf8_str_cols(name);
            if (c > nw) nw = c;
        }
        if (nw > W / 3) nw = W / 3;
    }
    int aligned = W - time_w - nw - 2 >= 16;
    int bottom = first + nrows - 1;
    for (int k = skip; k < sb->count && bottom >= first; k++) {
        const tui_line_t *l = SB_AT(sb, k);
        char name[96];
        const char *body = l->text;
        int chat = split_chat_line(l, name, sizeof name, &body);
        if (!chat && body[0] == '*' && body[1] == ' ') body += 2;
        int name_c = chat ? utf8_str_cols(name) : 0;

        int first_pre, rest_pre;
        if (chat && aligned) { first_pre = time_w + (name_c > nw ? name_c : nw) + 2; rest_pre = time_w + nw + 2; }
        else if (chat) { first_pre = time_w + name_c + 1; rest_pre = time_w; }
        else first_pre = rest_pre = time_w;
        if (first_pre > W - 1) first_pre = W - 1 > 0 ? W - 1 : 0;
        if (rest_pre > W - 1) rest_pre = W - 1 > 0 ? W - 1 : 0;

        size_t off[64], len[64];
        int nch = wrap_rows(body, W - first_pre, W - rest_pre, off, len, 64);

        // Run on from the line above: same person, same minute, and that line in view to say who.
        int grouped = 0;
        if (chat && k + 1 < sb->count && bottom - nch >= first) {
            const tui_line_t *older = SB_AT(sb, k + 1);
            char oname[96];
            const char *ob;
            grouped = memcmp(older->hhmm, l->hhmm, 5) == 0 && older->mention == l->mention
                   && split_chat_line(older, oname, sizeof oname, &ob) && strcmp(oname, name) == 0;
        }

        int warn = console && strncmp(body, "warning:", 8) == 0;
        style_t body_style = l->mention ? S_BOLD : warn ? S_YELLOW : console ? S_FAINT : S_PLAIN;
        int body_rgb = !chat && l->has_color && !warn;

        for (int c = 0; c < nch; c++) {
            int row = bottom - (nch - 1 - c);
            if (row < first || row >= first + nrows || row >= g->rows) continue;
            gpen_t gp;
            grid_open(g, row, &gp);
            pen_t *p = &gp.p;
            if (c == 0) {
                if (time_w && !grouped) ptext(p, l->mention ? S_YELLOW_BOLD : S_FAINT, l->hhmm);
                pspace(p, time_w);
                if (chat && !grouped) {
                    if (aligned) pspace(p, time_w + nw - name_c);
                    draw_name(p, name, l->has_color ? l->rgb : NULL);
                }
                pspace(p, first_pre);
            } else {
                pspace(p, rest_pre);
            }
            char piece[TUI_LINE_MAX + 1];
            memcpy(piece, body + off[c], len[c]);
            piece[len[c]] = '\0';
            if (body_rgb) {
                sty_rgb(p->w, l->rgb, 0, 0);
                p->used += wapp_trunc(p->w, piece, p->room - p->used);
            } else {
                ptext(p, body_style, piece);
            }
            grid_close(g, row, &gp);
        }
        bottom -= nch;
    }
}

// Lines centred across the grid and a little above its middle: the first bold, the rest faint,
// but for a line that's just emph (the session's id, to be passed on), lit.
static void draw_center(grid_t *g, int first, int nrows, const char *text, const char *emph) {
    const char *lines[12];
    size_t lens[12];
    int n = 0;
    for (const char *s = text; *s && n < 12; ) {
        const char *nl = strchr(s, '\n');
        lines[n] = s;
        lens[n] = nl ? (size_t)(nl - s) : strlen(s);
        n++;
        if (!nl) break;
        s = nl + 1;
    }
    int top = first + (nrows - n) / 2 - nrows / 10;
    if (top < first) top = first;
    for (int i = 0; i < n && top + i < first + nrows; i++) {
        char buf[TUI_LINE_MAX];
        size_t l = lens[i] < sizeof buf - 1 ? lens[i] : sizeof buf - 1;
        memcpy(buf, lines[i], l);
        buf[l] = '\0';
        int c = utf8_str_cols(buf);
        if (c > g->w) c = g->w;
        gpen_t gp;
        grid_open(g, top + i, &gp);
        pspace(&gp.p, (g->w - c) / 2);
        style_t st = i == 0 ? S_BOLD : emph && strcmp(buf, emph) == 0 ? S_ACCENT_BOLD : S_FAINT;
        pell(&gp.p, st, buf, g->w);
        grid_close(g, top + i, &gp);
    }
}

// No session yet: what chat is, and the keys that start one.
static void draw_welcome(grid_t *g, int first, int nrows) {
    static const char *const KEYS[][2] = {
        { "ctrl+n", "start a new session" },
        { "ctrl+j", "join a session" },
        { "ctrl+s", "settings" },
        { "/help", "keys and commands" },
    };
    int nkeys = (int)(sizeof KEYS / sizeof KEYS[0]);
    int W = g->w;
    const char *tagline = W >= 52 ? "serverless " G_MID " end-to-end encrypted " G_MID " post-quantum"
                                  : "end-to-end encrypted";
    int n = 3 + nkeys;
    int top = first + (nrows - n) / 2 - nrows / 10;
    if (top < first) top = first;
    gpen_t gp;
    if (top < first + nrows) {
        grid_open(g, top, &gp);
        pspace(&gp.p, (W - 6) / 2);
        ptext(&gp.p, S_ACCENT_BOLD, G_DIAMOND " chat");
        grid_close(g, top, &gp);
    }
    if (top + 1 < first + nrows) {
        grid_open(g, top + 1, &gp);
        int c = utf8_str_cols(tagline);
        pspace(&gp.p, c < W ? (W - c) / 2 : 0);
        ptext(&gp.p, S_FAINT, tagline);
        grid_close(g, top + 1, &gp);
    }
    int block = 9 + 20;
    int left = block < W ? (W - block) / 2 : 0;
    for (int i = 0; i < nkeys; i++) {
        int row = top + 3 + i;
        if (row >= first + nrows) break;
        grid_open(g, row, &gp);
        pspace(&gp.p, left);
        ptext(&gp.p, S_ACCENT_BOLD, KEYS[i][0]);
        pspace(&gp.p, left + 9);
        ptext(&gp.p, S_PLAIN, KEYS[i][1]);
        grid_close(g, row, &gp);
    }
}

static void draw_chat_pane(grid_t *g, int first, int nrows, const tui_scrollback_t *sb, const tui_view_t *v) {
    if (!v->title) draw_welcome(g, first, nrows);
    else if ((!sb || sb->count == 0) && v->empty) draw_center(g, first, nrows, v->empty, v->title);
    else draw_lines(g, first, nrows, sb, v->scroll, 0);
}

static const char HIDDEN_HINT[] = "Chat and console are hidden\nctrl+t shows the chat " G_MID " ctrl+o the console";

static void chat_title(span_t *t, const tui_view_t *v) {
    if (!v->title) { ptext(&t->p, S_BOLD, "welcome"); return; }
    static const char *const GLYPH[] = { G_RING, G_DOTTED, G_DOT };
    static const style_t STYLE[] = { S_FAINT, S_YELLOW, S_GREEN };
    unsigned st = (unsigned)v->state < 3 ? (unsigned)v->state : 2;
    ptext(&t->p, STYLE[st], GLYPH[st]);
    ptext(&t->p, S_PLAIN, " ");
    ptext(&t->p, S_BOLD, v->title);
    if (v->subtitle && v->subtitle[0]) {
        ptext(&t->p, S_FAINT, " " G_MID " ");
        ptext(&t->p, S_FAINT, v->subtitle);
    }
}

// The console over the chat, sharing an edge, in one box; either fills it alone.
static void draw_main(wbuf_t *w, rect_t m, int boxed, const tui_scrollback_t *sb, const tui_scrollback_t *console,
                      const tui_view_t *v) {
    int show_con = console && v->console, show_chat = v->chat;
    if (!boxed) {
        grid_reset(&g_grid, m.h, m.w);
        if (show_chat) draw_chat_pane(&g_grid, 0, m.h, sb, v);
        else if (show_con) draw_lines(&g_grid, 0, m.h, console, 0, 1);
        else draw_center(&g_grid, 0, m.h, HIDDEN_HINT, NULL);
        grid_emit(w, &g_grid, m.top, m.left, 0);
        return;
    }
    const char *bs = border_sgr(-1);
    int inner = m.h - 2;
    int con_h = 0;
    if (show_con && show_chat) {
        con_h = inner / 4;
        if (con_h < 3) con_h = 3;
        if (con_h > 8) con_h = 8;
        if (inner - con_h - 1 < 4) con_h = inner - 1 - 4;
        if (con_h < 1) show_con = 0;
    }
    span_t clock, ctitle, ktitle;
    span_init(&clock, m.w);
    if (v->clock) ptext(&clock.p, S_FAINT, v->clock);
    span_init(&ctitle, title_room(m.w, clock.p.used));
    if (show_chat) chat_title(&ctitle, v);
    else if (!show_con) ptext(&ctitle.p, S_FAINT, "hidden");
    span_init(&ktitle, title_room(m.w, show_chat ? 0 : clock.p.used));
    ptext(&ktitle.p, S_FAINT, "console");
    // Its bottom edge is the input box's top, which draw_input() draws.
    if (show_con) edge(w, m.top, m.left, m.w, top_left(m), G_TR, bs, &ktitle, show_chat ? NULL : &clock);
    else edge(w, m.top, m.left, m.w, top_left(m), G_TR, bs, &ctitle, &clock);
    sides(w, m.top + 1, inner, m.left, m.w, bs);

    int row = m.top + 1;
    if (show_con) {
        grid_reset(&g_grid, show_chat ? con_h : inner, m.w - 4);
        draw_lines(&g_grid, 0, g_grid.rows, console, 0, 1);
        grid_emit(w, &g_grid, row, m.left + 1, 1);
        row += g_grid.rows;
        if (show_chat) edge(w, row++, m.left, m.w, G_LT, G_RT, bs, &ctitle, &clock);
    }
    if (show_chat || !show_con) {
        grid_reset(&g_grid, m.top + m.h - 1 - row, m.w - 4);
        if (show_chat) draw_chat_pane(&g_grid, 0, g_grid.rows, sb, v);
        else draw_center(&g_grid, 0, g_grid.rows, HIDDEN_HINT, NULL);
        grid_emit(w, &g_grid, row, m.left + 1, 1);
    }
}

// ---- the sidebar: sessions, the peers in the selected one, and how it reaches them ----

enum { L_BLANK, L_HEAD_SESSIONS, L_NO_SESSIONS, L_SESSION, L_HEAD_PEERS, L_PEER, L_HEAD_NET, L_NET };

static void heading(pen_t *p, const char *title, int count) {
    ptext(p, S_FAINT, title);
    if (count >= 0) {
        char n[16];
        snprintf(n, sizeof n, "%d", count);
        pspace(p, p->room - (int)strlen(n));
        ptext(p, S_FAINT, n);
    }
}

static void session_line(pen_t *p, const tui_session_row_t *s, int sel) {
    static const char *const GLYPH[] = { G_RING, G_DOTTED, G_DOT };
    static const style_t STYLE[] = { S_FAINT, S_YELLOW, S_GREEN };
    unsigned st = (unsigned)s->state < 3 ? (unsigned)s->state : 2;
    char count[16];
    snprintf(count, sizeof count, "%d", s->online);
    int unread = s->unread && !sel;
    int right = 2 + (int)strlen(count) + (unread ? 2 : 0);
    ptext(p, sel ? S_ACCENT_BOLD : S_PLAIN, sel ? G_PTR " " : "  ");
    pell(p, sel ? S_ACCENT_BOLD : unread ? S_BOLD : S_PLAIN, s->label, p->room - p->used - right - 1);
    pspace(p, p->room - right);
    if (unread) ptext(p, S_ACCENT_BOLD, G_BULLET " ");
    ptext(p, STYLE[st], GLYPH[st]);
    ptext(p, S_FAINT, " ");
    ptext(p, S_FAINT, count);
}

// The verify state and a modified client in words while they fit beside the nick, then the verify
// state alone in words, then both in glyphs; the nick is cut for them, never they for it.
static void peer_line(pen_t *p, const tui_peer_row_t *pr) {
    const char *word, *glyph;
    style_t st;
    if (pr->you) { word = glyph = "you"; st = S_FAINT; }
    else if (pr->verify == 1) { word = G_CHECK " verified"; glyph = G_CHECK; st = S_GREEN; }
    else if (pr->verify == 2) { word = G_CROSS " invalid"; glyph = G_CROSS; st = S_RED_BOLD; }
    else { word = "unverified"; glyph = "?"; st = S_FAINT; }
    const char *mod_word = pr->modified ? "modified " : "", *mod_glyph = pr->modified ? "! " : "";
    int tag_w = utf8_str_cols(pr->tag);
    int nick_w = utf8_str_cols(pr->nick);
    int room = p->room - 2 - tag_w - 1, want = nick_w < 6 ? nick_w : 6;
    const char *m = mod_word, *v = word;
    if (room - utf8_str_cols(m) - utf8_str_cols(v) < want) m = mod_glyph;
    if (room - utf8_str_cols(m) - utf8_str_cols(v) < want) v = glyph;
    int right = utf8_str_cols(m) + utf8_str_cols(v);
    sty_rgb(p->w, pr->color, 0, 0);
    p->used += wapp_trunc(p->w, G_DOT " ", p->room - p->used);
    int nick_room = p->room - p->used - tag_w - right - 1;
    prgb(p, pr->color, pr->you, pr->nick, nick_room < 1 ? 1 : nick_room);
    ptext(p, S_FAINT, pr->tag);
    pspace(p, p->room - right);
    ptext(p, S_RED_BOLD, m);
    ptext(p, st, v);
}

static void draw_sidebar(wbuf_t *w, rect_t r, const tui_session_row_t *sessions, int n_sessions, int selected,
                         const tui_peer_row_t *peers, int n_peers, const tui_kv_t *net, int n_net) {
    const char *bs = border_sgr(-1);
    span_t title, right;
    brand(&title, &right, r.w);
    box(w, r, bs, &title, &right, NULL);
    int h = r.h - 2;
    if (h > MAX_ROWS) h = MAX_ROWS;
    static int kind[MAX_ROWS], arg[MAX_ROWS];
    int n = 0;
#define ADD(k, a) do { if (n < h) { kind[n] = (k); arg[n] = (a); n++; } } while (0)
    ADD(L_HEAD_SESSIONS, 0);
    if (n_sessions == 0) ADD(L_NO_SESSIONS, 0);
    for (int i = 0; i < n_sessions; i++) ADD(L_SESSION, i);
    if (n_peers > 0) {
        ADD(L_BLANK, 0);
        ADD(L_HEAD_PEERS, 0);
        for (int i = 0; i < n_peers; i++) ADD(L_PEER, i);
    }
    if (n_net > 0) {
        // At the foot when there's room, else straight after the rest.
        int start = h - n_net - 1;
        if (start < n + 1) start = n + 1;
        while (n < start && n < h) ADD(L_BLANK, 0);
        ADD(L_HEAD_NET, 0);
        for (int i = 0; i < n_net; i++) ADD(L_NET, i);
    }
#undef ADD
    int lw = 0;
    for (int i = 0; i < n_net; i++) {
        int c = utf8_str_cols(net[i].label);
        if (c > lw) lw = c;
    }
    for (int i = 0; i < h; i++) {
        int k = i < n ? kind[i] : L_BLANK, a = i < n ? arg[i] : 0;
        int sel = k == L_SESSION && a == selected;
        row_select(sel);
        pen_t p;
        inner_begin(w, &p, r.top + 1 + i, r.left + 1, r.w - 2);
        switch (k) {
            case L_HEAD_SESSIONS: heading(&p, "SESSIONS", n_sessions > 0 ? n_sessions : -1); break;
            case L_NO_SESSIONS:   ptext(&p, S_FAINT, "none yet " G_MID " ctrl+n"); break;
            case L_SESSION:       session_line(&p, &sessions[a], sel); break;
            case L_HEAD_PEERS:   heading(&p, "PEERS", n_peers); break;
            case L_PEER:          peer_line(&p, &peers[a]); break;
            case L_HEAD_NET:      heading(&p, "NETWORK", -1); break;
            case L_NET:
                ptext(&p, S_FAINT, net[a].label);
                pspace(&p, lw + 2);
                pell(&p, S_PLAIN, net[a].value, p.room - p.used);
                break;
            default: break;
        }
        inner_end(&p);
        row_select(0);
    }
}

// ---- the input box, the menu over it, and the bottom row ----

// The input's line (or placeholder, faint, while it's empty) from the pen on, scrolled so the text
// before the cursor fits with a column for the cursor itself. Returns the cursor's column.
static int draw_field(pen_t *f, const tui_input_t *in, int mask, const char *placeholder) {
    int start = f->used, room = f->room - f->used;
    if (room < 1) return start;
    if (in->len == 0) {
        if (placeholder) pell(f, S_FAINT, placeholder, room);
        return start;
    }
    sty(f->w, S_PLAIN);
    if (mask) {
        // One dot per character, not per byte.
        int dots = 0, before = 0;
        for (size_t i = 0, adv; i < (size_t)in->len; i += adv) {
            utf8_decode(in->buf, (size_t)in->len, i, &adv);
            if (i < (size_t)in->cursor) before++;
            if (dots < room) { wapp(f->w, G_BULLET); dots++; }
        }
        f->used += dots;
        return start + (before < room ? before : room - 1);
    }
    size_t s0 = 0;
    int before;
    utf8_fit_cols(in->buf, (size_t)in->cursor, INT_MAX, &before);
    while (before > room - 1 && s0 < (size_t)in->cursor) {
        size_t adv;
        before -= utf8_char_cols(in->buf, (size_t)in->len, s0, &adv);
        s0 += adv;
    }
    f->used += wapp_trunc(f->w, in->buf + s0, room);
    const char *nick = in->mode == TUI_IMODE_INSERT ? mention_suggestion(in) : NULL;
    if (nick) ptext(f, S_FAINT, nick + (in->cursor - mention_start(in)));
    return start + before;
}

#define MENU_ROWS 8

// The suggestions for the COMMAND line, at the foot of the box over the input box: the three read
// as one column. 0 if there are none, or no room.
static int draw_menu(wbuf_t *w, rect_t in_r, rect_t over, const tui_input_t *in, const char *bs) {
    int count = suggestion_count(in);
    if (count == 0) return 0;
    int vis = count < MENU_ROWS ? count : MENU_ROWS;
    if (vis > over.h - 3) vis = over.h - 3;
    if (vis < 1) return 0;
    int sel = in->menu_sel < 0 ? 0 : in->menu_sel >= count ? count - 1 : in->menu_sel;
    int first = sel - vis + 1 > 0 ? sel - vis + 1 : 0;
    int top = in_r.top - vis - 1;

    tui_suggestion_t s;
    span_t title, right;
    span_init(&right, in_r.w);
    char pos[24];
    snprintf(pos, sizeof pos, "%d/%d", sel + 1, count);
    ptext(&right.p, S_FAINT, pos);
    span_init(&title, title_room(in_r.w, right.p.used));
    if (in->suggest(in->cmd, sel, &s)) ptext(&title.p, S_FAINT, s.group);
    edge(w, top, in_r.left, in_r.w, G_LT, G_RT, bs, &title, &right);
    sides(w, top + 1, vis, in_r.left, in_r.w, bs);

    int nw = 0;
    for (int i = first; i < first + vis; i++) {
        if (!in->suggest(in->cmd, i, &s)) break;
        int c = utf8_str_cols(s.name) + (s.args[0] ? 1 + utf8_str_cols(s.args) : 0);
        if (c > nw) nw = c;
    }
    if (nw > (in_r.w - 6) / 2) nw = (in_r.w - 6) / 2;
    for (int i = 0; i < vis; i++) {
        int on = first + i == sel;
        int ok = in->suggest(in->cmd, first + i, &s);
        row_select(on && ok);
        pen_t p;
        inner_begin(w, &p, top + 1 + i, in_r.left + 1, in_r.w - 2);
        if (ok) {
            ptext(&p, on ? S_ACCENT_BOLD : S_PLAIN, on ? G_PTR " " : "  ");
            ptext(&p, on ? S_ACCENT_BOLD : S_BOLD, s.name);
            if (s.args[0]) { ptext(&p, S_FAINT, " "); ptext(&p, S_FAINT, s.args); }
            if (p.used < 2 + nw + 3) pspace(&p, 2 + nw + 3);
            else ptext(&p, S_PLAIN, "  ");
            pell(&p, on ? S_PLAIN : S_FAINT, s.help, p.room - p.used);
        }
        inner_end(&p);
        row_select(0);
    }
    return 1;
}

// Draws the input box (or, unboxed, its one row) and leaves the cursor's place in *cr, *cc. Its top
// edge is the bottom of the chat's box, or of the menu over it; it says how many newer messages
// are hidden below the chat.
static void draw_input(wbuf_t *w, rect_t r, int boxed, const tui_bar_t *bar, const tui_view_t *v, rect_t over,
                       int *cr, int *cc) {
    const tui_input_t *in = bar->input;
    *cr = 0;
    if (!in || r.h < 1) return;
    const char *bs = border_sgr((int)bar->tone);
    int row = r.top, left = r.left, width = r.w;
    if (boxed) {
        if (in->mode == TUI_IMODE_COMMAND) draw_menu(w, r, over, in, bs);
        span_t title, more, count;
        span_init(&more, r.w);
        if (v->chat && v->title && v->scroll > 0) {
            char t[48];
            snprintf(t, sizeof t, G_DOWN " %d newer " G_MID " pgdn", v->scroll);
            ptext(&more.p, S_ACCENT_BOLD, t);
        }
        span_init(&title, title_room(r.w, more.p.used));
        if (bar->prompt) {
            sty_tone(title.p.w, bar->tone, 1);
            title.p.used += wapp_trunc(title.p.w, bar->prompt, title.p.room);
        }
        span_init(&count, r.w);
        if (bar->limit > 0 && in->len > 0 && in->mode != TUI_IMODE_COMMAND) {
            char t[32];
            snprintf(t, sizeof t, "%d/%d", in->len, bar->limit);
            ptext(&count.p, in->len > bar->limit ? S_RED_BOLD : S_FAINT, t);
        }
        edge(w, r.top, r.left, r.w, G_LT, G_RT, bs, &title, &more);
        sides(w, r.top + 1, 1, r.left, r.w, bs);
        edge(w, r.top + 2, r.left, r.w, bottom_left(r), G_BR, bs, NULL, &count);
        row = r.top + 1;
        left = r.left + 1;
        width = r.w - 2;
    }
    pen_t p;
    inner_begin(w, &p, row, left, width);
    sty_tone(w, bar->tone, 1);
    p.used += wapp_trunc(w, G_PTR " ", p.room);
    int cursor;
    if (in->mode == TUI_IMODE_COMMAND) {
        char pre[2] = { in->cmd_prefix ? in->cmd_prefix : ':', '\0' };
        ptext(&p, S_ACCENT_BOLD, pre);
        ptext(&p, S_PLAIN, in->cmd);
        cursor = p.used;
        tui_suggestion_t s;
        if (tui_input_suggestion(in, &s) && strncmp(s.line, in->cmd, (size_t)in->cmd_len) == 0)
            ptext(&p, S_FAINT, s.line + in->cmd_len);
    } else {
        cursor = draw_field(&p, in, bar->mask_input, bar->placeholder);
    }
    inner_end(&p);
    if (cursor > p.room - 1) cursor = p.room - 1;
    *cr = row;
    *cc = left + 1 + cursor;
}

static void draw_status(wbuf_t *w, int row, int cols, const tui_bar_t *bar) {
    at(w, row, 1);
    pen_t p = { w, 0, cols };
    char chip[40];
    snprintf(chip, sizeof chip, " %s ", bar->chip ? bar->chip : "");
    sty_pill(w, bar->tone);
    p.used += wapp_trunc(w, chip, cols);
    ptext(&p, S_PLAIN, " ");
    if (bar->badge == TUI_ID_NONE) {
        ptext(&p, S_YELLOW, G_RING " unsigned");
    } else {
        const char *kind = bar->badge == TUI_ID_AGE ? "age" : bar->badge == TUI_ID_PGP ? "pgp" : "native";
        ptext(&p, S_GREEN, G_CHECK " signed ");
        ptext(&p, S_FAINT, kind);
    }
    if (bar->nick && bar->nick[0]) {
        ptext(&p, S_FAINT, "  ");
        if (bar->nick_color) prgb(&p, bar->nick_color, 1, bar->nick, p.room - p.used);
        else ptext(&p, S_BOLD, bar->nick);
    }
    if (bar->message && bar->message[0]) {
        ptext(&p, S_FAINT, "  " G_RSAQ " ");
        ptext(&p, S_BOLD, bar->message);
    }
    // As many of the hints as fit, from the first: they come most useful first.
    if (bar->hint && bar->hint[0]) {
        static const char SEP[] = " " G_MID " ";
        char fit[256] = "";
        for (const char *s = bar->hint; ; ) {
            const char *end = strstr(s, SEP);
            size_t upto = end ? (size_t)(end - bar->hint) : strlen(bar->hint);
            char part[256];
            if (upto >= sizeof part) break;
            memcpy(part, bar->hint, upto);
            part[upto] = '\0';
            if (p.used + 3 + utf8_str_cols(part) > cols) break;
            copy_str(fit, part, sizeof fit);
            if (!end) break;
            s = end + sizeof SEP - 1;
        }
        if (fit[0]) {
            pspace(&p, cols - utf8_str_cols(fit) - 1);
            draw_hint(&p, fit);
        }
    }
    pspace(&p, cols);
    wapp(w, "\x1b[0m");
}

// One frame, split by lines: the sidebar's right side is the chat's left, and the chat's bottom
// edge is the input box's top.
static void chat_layout(int rows, int cols, const tui_view_t *v, rect_t *side, rect_t *main_r, rect_t *input, int *boxed) {
    *boxed = rows >= 10 && cols >= 40;
    int sbw = 0;
    if (*boxed && v->sidebar) {
        sbw = cols / 4;
        if (sbw < 24) sbw = 24;
        if (sbw > 32) sbw = 32;
        if (cols - sbw < 44) sbw = 0;
    }
    *side = (rect_t){ 1, 1, rows - 1, sbw };
    int x = sbw > 0 ? sbw : 1, ih = *boxed ? 3 : 1;
    *input = (rect_t){ rows - ih, x, ih, cols - x + 1 };
    *main_r = (rect_t){ 1, x, rows - ih - (*boxed ? 0 : 1), cols - x + 1 };
}

void tui_render(int rows, int cols,
                const tui_session_row_t *sessions, int n_sessions, int selected,
                const tui_peer_row_t *peers, int n_peers, const tui_kv_t *net, int n_net,
                const tui_scrollback_t *sb, const tui_scrollback_t *console,
                const tui_view_t *view, const tui_bar_t *bar, int color_enabled) {
    clamp_size(&rows, &cols);
    g_color = color_enabled;
    g_row_bg = "";
    wbuf_t w = { g_frame, FRAME_CAP, 0 };
    rect_t side, main_r, input;
    int boxed;
    chat_layout(rows, cols, view, &side, &main_r, &input, &boxed);

    begin_frame(&w);
    if (side.w > 0) draw_sidebar(&w, side, sessions, n_sessions, selected, peers, n_peers, net, n_net);
    draw_main(&w, main_r, boxed, sb, console, view);
    int cr, cc;
    draw_input(&w, input, boxed, bar, view, main_r, &cr, &cc);
    draw_status(&w, rows, cols, bar);
    place_cursor(&w, cr, cc, bar->input);
    end_frame(&w, 1);
}

void tui_render_bar(int rows, int cols, const tui_view_t *view, const tui_bar_t *bar, int color_enabled) {
    clamp_size(&rows, &cols);
    g_color = color_enabled;
    g_row_bg = "";
    wbuf_t w = { g_frame, FRAME_CAP, 0 };
    rect_t side, main_r, input;
    int boxed;
    chat_layout(rows, cols, view, &side, &main_r, &input, &boxed);

    begin_frame(&w);
    int cr, cc;
    draw_input(&w, input, boxed, bar, view, main_r, &cr, &cc);
    draw_status(&w, rows, cols, bar);
    place_cursor(&w, cr, cc, bar->input);
    end_frame(&w, 0);
}

// ---- list pages ----

static void draw_nav(wbuf_t *w, rect_t r, const char *const *nav, int n_nav, int nav_sel) {
    span_t title, right;
    brand(&title, &right, r.w);
    box(w, r, border_sgr(-1), &title, &right, NULL);
    for (int i = 0; i < r.h - 2; i++) {
        int k = i - 1;   // a blank row above the first
        int on = k >= 0 && k < n_nav && k == nav_sel;
        row_select(on);
        pen_t p;
        inner_begin(w, &p, r.top + 1 + i, r.left + 1, r.w - 2);
        if (k >= 0 && k < n_nav) {
            ptext(&p, on ? S_ACCENT_BOLD : S_PLAIN, on ? G_PTR " " : "  ");
            pell(&p, on ? S_ACCENT_BOLD : S_FAINT, nav[k], p.room - p.used);
        }
        inner_end(&p);
        row_select(0);
    }
}

// "a › b › c": the way to this page faint, the page itself bold.
static void crumb_title(span_t *t, const char *title) {
    static const char SEP[] = " " G_RSAQ " ";
    for (const char *s = title; ; ) {
        const char *next = strstr(s, SEP);
        char part[1024];
        size_t n = next ? (size_t)(next - s) : strlen(s);
        if (n >= sizeof part) n = sizeof part - 1;
        memcpy(part, s, n);
        part[n] = '\0';
        ptext(&t->p, next ? S_FAINT : S_BOLD, part);
        if (!next) break;
        ptext(&t->p, S_FAINT, SEP);
        s = next + sizeof SEP - 1;
    }
}

static void draw_value(pen_t *p, const tui_row_t *r, int on) {
    if (r->swatch && g_color) {
        sty_rgb(p->w, r->swatch, 0, 1);
        p->used += wapp_trunc(p->w, G_BLOCK G_BLOCK " ", p->room - p->used);
    }
    int room = p->room - p->used;
    switch (r->kind) {
        case TUI_V_ON:
            ptext(p, S_GREEN, G_DOT " ");
            pell(p, S_PLAIN, r->value, room - 2);
            break;
        case TUI_V_OFF:
            ptext(p, S_FAINT, G_RING " ");
            pell(p, S_FAINT, r->value, room - 2);
            break;
        case TUI_V_CHOICE:
            if (!on) { pell(p, S_PLAIN, r->value, room); break; }
            ptext(p, S_FAINT, G_LSAQ " ");
            pell(p, S_BOLD, r->value, room - 4);
            ptext(p, S_FAINT, " " G_RSAQ);
            break;
        case TUI_V_LINK:
            pell(p, S_PLAIN, r->value, room - 2);
            ptext(p, S_FAINT, " " G_RSAQ);
            break;
        case TUI_V_MUTED:
            pell(p, S_FAINT, r->value, room);
            break;
        default:
            pell(p, S_PLAIN, r->value, room);
            break;
    }
}

enum { PL_BLANK, PL_HEADING, PL_ROW };
#define PAGE_LINES 2048

// The rows, by section, in nrows rows from top: scrolled so the selected row shows with its
// heading and as much of the rest of its section as fits, or to the end with the button selected.
// Leaves the cursor's place in *cr, *cc when the selected row is being typed in.
static void draw_list(wbuf_t *w, int top, int left, int iw, int nrows, const tui_page_t *pg, const tui_bar_t *bar,
                      int *cr, int *cc) {
    static int kind[PAGE_LINES], arg[PAGE_LINES];
    int n = 0, sel_line = -1, head_line = -1, end_line = -1, head = -1;
    for (int i = 0; i < pg->n_rows && n < PAGE_LINES - 3; i++) {
        if (pg->rows[i].section) {
            if (sel_line >= 0 && end_line < 0) end_line = n - 1;
            if (i > 0) { kind[n] = PL_BLANK; n++; }
            head = n;
            kind[n] = PL_HEADING; arg[n] = i; n++;
        }
        if (i == pg->selected) { sel_line = n; head_line = head >= 0 ? head : n; }
        kind[n] = PL_ROW; arg[n] = i; n++;
    }
    if (end_line < 0) end_line = n - 1;
    int scroll = 0;
    if (pg->selected >= pg->n_rows) scroll = n - nrows;
    else if (sel_line >= 0) {
        scroll = end_line - nrows + 1;
        if (scroll < sel_line - nrows + 1) scroll = sel_line - nrows + 1;
        if (scroll > head_line) scroll = head_line > sel_line - nrows + 1 ? head_line : sel_line - nrows + 1;
    }
    if (scroll < 0) scroll = 0;

    int cw = iw - 2, lw = 0, any_value = 0;
    for (int i = 0; i < pg->n_rows; i++) {
        int c = utf8_str_cols(pg->rows[i].label);
        if (c > lw) lw = c;
        if (pg->rows[i].value) any_value = 1;
    }
    lw += 3;
    if (!any_value || lw > (cw - 2) / 2) lw = any_value ? (cw - 2) / 2 : cw - 2;
    for (int r = 0; r < nrows; r++) {
        int li = scroll + r, row = top + r;
        if (li >= n || kind[li] == PL_BLANK) { blank_row(w, row, left, iw); continue; }
        const tui_row_t *pr = &pg->rows[arg[li]];
        pen_t p;
        if (kind[li] == PL_HEADING) {
            inner_begin(w, &p, row, left, iw);
            ptext(&p, S_ACCENT_BOLD, pr->section);
            inner_end(&p);
            continue;
        }
        int on = arg[li] == pg->selected;
        int editing = on && pg->editing && bar->input;
        row_select(on);
        inner_begin(w, &p, row, left, iw);
        ptext(&p, on ? S_ACCENT_BOLD : S_PLAIN, on ? G_PTR " " : "  ");
        pell(&p, on ? S_ACCENT_BOLD : pg->keys ? S_ACCENT : S_PLAIN, pr->label, pr->value || editing ? lw - 2 : lw);
        if (pr->value || editing) pspace(&p, 2 + lw);
        if (editing) {
            ptext(&p, S_ACCENT_BOLD, G_RSAQ " ");
            int c = draw_field(&p, bar->input, bar->mask_input, bar->placeholder);
            *cr = row;
            *cc = left + 1 + (c < p.room ? c : p.room - 1);
        } else if (pr->value) {
            draw_value(&p, pr, on);
        }
        inner_end(&p);
        row_select(0);
    }
}

static void draw_button(wbuf_t *w, int row, int left, int iw, const tui_page_t *pg) {
    pen_t p;
    inner_begin(w, &p, row, left, iw);
    char label[80];
    snprintf(label, sizeof label, " %s ", pg->button);
    if (pg->selected >= pg->n_rows) {
        ptext(&p, S_ACCENT_BOLD, G_PTR " ");
        sty_pill(w, TUI_TONE_PAGE);
        p.used += wapp_trunc(w, label, p.room - p.used);
    } else {
        ptext(&p, S_PLAIN, "  ");
        ptext(&p, S_FAINT, "[");
        ptext(&p, S_BOLD, label);
        ptext(&p, S_FAINT, "]");
    }
    inner_end(&p);
}

void tui_render_page(int rows, int cols, const tui_page_t *page, const tui_bar_t *bar, int color_enabled) {
    clamp_size(&rows, &cols);
    g_color = color_enabled;
    g_row_bg = "";
    wbuf_t w = { g_frame, FRAME_CAP, 0 };

    // The sections on the left: as given, or the rows' own, with the selected row's lit.
    const char *nav[32];
    int n_nav = 0, nav_sel = -1;
    if (page->nav) {
        for (int i = 0; i < page->n_nav && i < 32; i++) nav[n_nav++] = page->nav[i];
        nav_sel = page->nav_sel;
    } else {
        for (int i = 0; i < page->n_rows && n_nav < 32; i++) {
            if (page->rows[i].section) nav[n_nav++] = page->rows[i].section;
            if (i == page->selected) nav_sel = n_nav - 1;
        }
    }
    int boxed = rows >= 10 && cols >= 40;
    int navw = cols / 5;
    if (navw < 20) navw = 20;
    if (navw > 26) navw = 26;
    if (!boxed || n_nav == 0 || cols - navw < 56) navw = 0;

    begin_frame(&w);
    if (navw) draw_nav(&w, (rect_t){ 1, 1, rows - 1, navw }, nav, n_nav, nav_sel);

    // Sharing the nav's right side, as the chat shares the sidebar's.
    int x = navw > 0 ? navw : 1;
    rect_t r = { 1, x, rows - 1, cols - x + 1 };
    int top = boxed ? r.top + 1 : r.top, ih = boxed ? r.h - 2 : r.h;
    int left = boxed ? r.left + 1 : r.left, iw = boxed ? r.w - 2 : r.w;
    int cw = iw - 2;

    // Under the rows, past an edge titled with the selected row: its help and usage. Over them,
    // the intro. Rows go first when there's no room for all of it.
    static size_t hoff[5], hlen[5], ioff[3], ilen[3];
    int hl = boxed && page->help && page->help[0] ? wrap_rows(page->help, cw, cw, hoff, hlen, 5) : 0;
    int ul = boxed && page->usage && page->usage[0] ? 1 : 0;
    int il = boxed && page->intro && page->intro[0] ? wrap_rows(page->intro, cw, cw, ioff, ilen, 3) : 0;
    int btn = page->button ? 2 : 0;
    int list;
    for (;;) {
        int help_block = hl + ul ? hl + ul + 1 : 0;
        list = ih - help_block - (il ? il + 1 : 0) - btn;
        if (list >= 4 || (!il && hl <= 2 && !(hl + ul))) break;
        if (il) il = 0;
        else if (hl > 2) hl = 2;
        else hl = ul = 0;
    }
    if (list < 1) list = 1;

    int cr = 0, cc = 0;
    if (boxed) {
        span_t title, right;
        span_init(&right, r.w);
        if (page->clock) ptext(&right.p, S_FAINT, page->clock);
        span_init(&title, title_room(r.w, right.p.used));
        crumb_title(&title, page->title ? page->title : "");
        box(&w, r, border_sgr(TUI_TONE_PAGE), &title, &right, NULL);
    }
    int row = top, end = top + ih;
    for (int i = 0; i < il && row < end; i++, row++) {
        char piece[TUI_LINE_MAX];
        size_t n = ilen[i] < sizeof piece - 1 ? ilen[i] : sizeof piece - 1;
        memcpy(piece, page->intro + ioff[i], n);
        piece[n] = '\0';
        pen_t p;
        inner_begin(&w, &p, row, left, iw);
        ptext(&p, S_FAINT, piece);
        inner_end(&p);
    }
    if (il && row < end) blank_row(&w, row++, left, iw);
    if (list > end - row) list = end - row;
    draw_list(&w, row, left, iw, list, page, bar, &cr, &cc);
    row += list;
    if (btn && row + 1 < end) {
        blank_row(&w, row++, left, iw);
        draw_button(&w, row++, left, iw, page);
    }
    if (hl + ul && row < end) {
        span_t about;
        span_init(&about, title_room(r.w, 0));
        const char *what = page->selected < page->n_rows ? page->rows[page->selected].label : page->button;
        if (what) ptext(&about.p, S_FAINT, what);
        edge(&w, row++, r.left, r.w, G_LT, G_RT, border_sgr(TUI_TONE_PAGE), &about, NULL);
        for (int i = 0; i < hl && row < end; i++, row++) {
            char piece[TUI_LINE_MAX];
            size_t n = hlen[i] < sizeof piece - 1 ? hlen[i] : sizeof piece - 1;
            memcpy(piece, page->help + hoff[i], n);
            piece[n] = '\0';
            pen_t p;
            inner_begin(&w, &p, row, left, iw);
            ptext(&p, S_PLAIN, piece);
            inner_end(&p);
        }
        if (ul && row < end) {
            pen_t p;
            inner_begin(&w, &p, row++, left, iw);
            ptext(&p, S_ACCENT, page->usage);
            inner_end(&p);
        }
    }
    while (row < end) blank_row(&w, row++, left, iw);

    draw_status(&w, rows, cols, bar);
    place_cursor(&w, cr, cc, bar->input);
    end_frame(&w, 1);
}
