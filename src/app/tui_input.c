// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Keys as the terminal sends them, and the input line they edit.
#include "app/tui_draw.h"

#define ESC 0x1b
#define BEL 0x07
#define DEL 0x7f
#define CTRL_KEY(c) ((c) & 0x1f)

// "11;rgb:RRRR/GGGG/BBBB" (1 to 4 hex digits each), the terminal's background colour, as 8-bit rgb.
#define BG_DIGITS_MAX 4

static int parse_bg_report(const uint8_t *s, size_t n, uint8_t rgb[3]) {
    static const char head[] = "11;rgb:";
    size_t i = sizeof head - 1;
    if (n < i || memcmp(s, head, i) != 0) return -1;
    for (int c = 0; c < 3; c++) {
        if (c > 0) {
            if (i >= n || s[i] != '/') return -1;
            i++;
        }
        unsigned v = 0;
        int digits = 0;
        for (int d; i < n && (d = hex_value((char)s[i])) >= 0; i++, digits++)
            if (digits < BG_DIGITS_MAX) v = v * 16 + (unsigned)d;
        if (digits == 0 || digits > BG_DIGITS_MAX) return -1;
        rgb[c] = (uint8_t)(v * UINT8_MAX / ((1u << (4 * digits)) - 1));
    }
    return 0;
}

// A mouse report's button (64 and 65 for the wheel, plus 4, 8 and 16 with Shift, Alt and Ctrl),
// column and row. Only the wheel does anything.
static void mouse_key(unsigned b, int col, int row, tui_key_t *out) {
    unsigned button = b & ~28u;
    out->type = TUI_KEY_MOUSE;
    if (button != 64 && button != 65) return;
    out->type = button == 64 ? TUI_KEY_UP : TUI_KEY_DOWN;
    out->wheel = 1;
    out->col = col;
    out->row = row;
}

// "b;col;row", a mouse report's numbers with mode 1006.
#define MOUSE_NUM_MAX 99999

static int mouse_numbers(const uint8_t *s, size_t n, unsigned v[3]) {
    int i = 0;
    v[0] = v[1] = v[2] = 0;
    for (size_t k = 0; k < n; k++) {
        if (s[k] == ';') {
            if (++i > 2) return -1;
            continue;
        }
        if (s[k] < '0' || s[k] > '9' || v[i] > MOUSE_NUM_MAX) return -1;
        v[i] = v[i] * 10 + (unsigned)(s[k] - '0');
    }
    return i == 2 ? 0 : -1;
}

size_t tui_key_cut(const uint8_t *buf, size_t len) {
    size_t low = len > TUI_KEY_CUT_MAX ? len - TUI_KEY_CUT_MAX : 0, p = len;
    do {
        if (p == low) return 0;
        p--;
    } while (buf[p] != ESC);
    size_t n = len - p;
    if (n == 1) return n;
    if (buf[p + 1] == 'O') return n == 2 ? n : 0;
    if (buf[p + 1] != '[') return 0;
    if (n >= 3 && buf[p + 2] == 'M') return n < 6 ? n : 0;
    size_t k = p + 2;
    while (k < len && buf[k] >= ' ' && buf[k] <= '?') k++;
    return k == len ? n : 0;
}

size_t tui_decode_key(const uint8_t *buf, size_t len, tui_key_t *out) {
    out->type = TUI_KEY_NONE;
    out->ch_len = 0;
    out->wheel = 0;
    out->pasted = 0;
    if (len == 0) return 0;
    uint8_t b0 = buf[0];

    if (b0 == ESC) {
        if (len == 1) { out->type = TUI_KEY_ESCAPE; return 1; }

        // An OSC is the terminal answering a query. It's consumed in full, up to BEL or ST, so none of
        // it ends up in the input.
        if (buf[1] == ']') {
            size_t k = 2;
            while (k < len && buf[k] != BEL && !(buf[k] == ESC && k + 1 < len && buf[k + 1] == '\\')) k++;
            uint8_t rgb[3];
            out->type = TUI_KEY_UNKNOWN;
            if (k < len && parse_bg_report(buf + 2, k - 2, rgb) == 0) {
                out->type = TUI_KEY_BG_REPORT;
                memcpy(out->ch, rgb, 3);
                out->ch_len = 3;
            }
            if (k >= len) return len;
            return buf[k] == BEL ? k + 1 : k + 2;
        }

        // Unknown CSI sequences (Ctrl+arrows, F-keys, focus reports) are consumed in full, so the end
        // of them doesn't end up in the input as text.
        if (len >= 3 && buf[1] == '[') {
            switch (buf[2]) {
                case 'A': out->type = TUI_KEY_UP;    return 3;
                case 'B': out->type = TUI_KEY_DOWN;  return 3;
                case 'C': out->type = TUI_KEY_RIGHT; return 3;
                case 'D': out->type = TUI_KEY_LEFT;  return 3;
                case 'H': out->type = TUI_KEY_HOME;  return 3;
                case 'F': out->type = TUI_KEY_END;   return 3;
                case 'Z': out->type = TUI_KEY_BACKTAB; return 3;
                case 'M':
                    // A mouse report from a terminal without mode 1006: its numbers as bytes, each 32 over.
                    if (len < 6) { out->type = TUI_KEY_MOUSE; return len; }
                    mouse_key((unsigned)buf[3] - 32, buf[4] - 32, buf[5] - 32, out);
                    return 6;
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
            if (len >= 6 && buf[2] == '2' && buf[3] == '0' && (buf[4] == '0' || buf[4] == '1') && buf[5] == '~') {
                out->type = buf[4] == '0' ? TUI_KEY_PASTE_START : TUI_KEY_PASTE_END;
                return 6;
            }
            if (len >= 5 && buf[2] == '1' && buf[3] == '1' && buf[4] == '~') { out->type = TUI_KEY_HELP; return 5; }
            if (len >= 5 && buf[2] == '2' && buf[3] == '0' && buf[4] == '~') { out->type = TUI_KEY_F9; return 5; }
            if (len >= 5 && buf[2] == '2' && buf[3] == '4' && buf[4] == '~') { out->type = TUI_KEY_F12; return 5; }
            // Parameter and intermediate bytes run up to a final byte from '@' to '~'.
            size_t k = 2;
            while (k < len && buf[k] >= ' ' && buf[k] <= '?') k++;
            out->type = TUI_KEY_UNKNOWN;
            if (k < len && buf[k] >= '@' && buf[k] <= '~') {
                // "?997;1n" or "?997;2n": the terminal switched to a dark or a light theme.
                static const char theme[] = "?997;";
                if (buf[k] == 'n' && k - 2 >= sizeof theme - 1 && memcmp(buf + 2, theme, sizeof theme - 1) == 0)
                    out->type = TUI_KEY_THEME_CHANGED;
                // "<b;col;row", then M for a press or m for a release: a mouse report.
                unsigned v[3];
                if ((buf[k] == 'M' || buf[k] == 'm') && buf[2] == '<' && mouse_numbers(buf + 3, k - 3, v) == 0) {
                    if (buf[k] == 'M') mouse_key(v[0], (int)v[1], (int)v[2], out);
                    else out->type = TUI_KEY_MOUSE;
                }
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

        // Esc and the next key arrived in one read (a fast ':' after Esc, for example). The Esc is
        // handled on its own, like vim does.
        out->type = (buf[1] == '[' || buf[1] == 'O') ? TUI_KEY_UNKNOWN : TUI_KEY_ESCAPE;
        return 1;
    }

    switch (b0) {
        case '\r':                    out->type = TUI_KEY_ENTER; return 1;
        case '\n':                    out->type = TUI_KEY_JOIN_SESSION; return 1;
        case DEL: case CTRL_KEY('H'): out->type = TUI_KEY_BACKSPACE; return 1;
        case '\t':                    out->type = TUI_KEY_TAB; return 1;
        case CTRL_KEY('N'):           out->type = TUI_KEY_NEW_SESSION; return 1;
        case CTRL_KEY('W'):           out->type = TUI_KEY_DELETE_WORD; return 1;
        case CTRL_KEY('U'):           out->type = TUI_KEY_CTRL_U; return 1;
        case CTRL_KEY('D'):           out->type = TUI_KEY_CTRL_D; return 1;
        case CTRL_KEY('B'):           out->type = TUI_KEY_TOGGLE_SIDEBAR; return 1;
        case CTRL_KEY('O'):           out->type = TUI_KEY_TOGGLE_CONSOLE; return 1;
        case CTRL_KEY('T'):           out->type = TUI_KEY_TOGGLE_CHAT; return 1;
        case CTRL_KEY('S'):           out->type = TUI_KEY_SETTINGS; return 1;
        case CTRL_KEY('F'):           out->type = TUI_KEY_FILES; return 1;
        case CTRL_KEY('C'):           out->type = TUI_KEY_CTRL_C; return 1;
        case CTRL_KEY('G'):           out->type = TUI_KEY_CTRL_G; return 1;
        case CTRL_KEY('K'):           out->type = TUI_KEY_CTRL_K; return 1;
        case CTRL_KEY('L'):           out->type = TUI_KEY_CTRL_L; return 1;
        case CTRL_KEY('Q'):           out->type = TUI_KEY_CTRL_Q; return 1;
        case CTRL_KEY('X'):           out->type = TUI_KEY_CTRL_X; return 1;
        case CTRL_KEY('\\'):          out->type = TUI_KEY_CTRL_BACKSLASH; return 1;
        default:
            if (b0 < ' ') { out->type = TUI_KEY_UNKNOWN; return 1; }
    }

    // Only complete, valid characters reach the input line. A stray byte (including a C1 control)
    // is dropped instead of being echoed to the terminal.
    size_t seqlen = utf8_lead_len(b0);
    if (seqlen == 0 || seqlen > len) { out->type = TUI_KEY_UNKNOWN; return 1; }
    size_t adv;
    utf8_decode((const char *)buf, seqlen, 0, &adv);
    if (adv != seqlen) { out->type = TUI_KEY_UNKNOWN; return 1; }
    memcpy(out->ch, buf, seqlen);
    out->ch[seqlen] = '\0';
    out->ch_len = (int)seqlen;
    out->type = TUI_KEY_CHAR;
    return seqlen;
}

int tui_key_paste(tui_key_t *key) {
    key->pasted = 1;
    switch (key->type) {
        case TUI_KEY_CHAR: return 1;
        case TUI_KEY_ENTER: case TUI_KEY_JOIN_SESSION: key->type = TUI_KEY_ENTER; return 1;
        case TUI_KEY_TAB:
            key->type = TUI_KEY_CHAR;
            key->ch[0] = ' ';
            key->ch[1] = '\0';
            key->ch_len = 1;
            return 1;
        default: return 0;
    }
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
    if (pos > 0) { pos--; while (pos > 0 && utf8_is_cont(in->buf[pos])) pos--; }
    return pos;
}
static int step_right(const tui_input_t *in, int pos) {
    if (pos < in->len) { pos++; while (pos < in->len && utf8_is_cont(in->buf[pos])) pos++; }
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

// A '/' line can only turn back into text if it started on an empty line, so a draft isn't changed.
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
int mention_start(const tui_input_t *in) {
    if (!in->mention || in->cursor != in->len) return -1;
    int i = in->cursor;
    while (i > 0 && in->buf[i - 1] != ' ' && in->buf[i - 1] != '@') i--;
    if (i == 0 || in->buf[i - 1] != '@' || i == in->cursor) return -1;
    if (i >= 2 && in->buf[i - 2] != ' ') return -1;
    return i;
}

const char *mention_suggestion(const tui_input_t *in) {
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
            // '/' on an empty line opens the COMMAND line, like other chat programs.
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
            // Back over spaces, then the word before them, like vim and readline.
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
            // Everything before the cursor, like readline.
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
            // Handled by the caller: switching sessions, jumping to the newest message, opening the help
            // or the files, and showing or hiding the console, the chat and the sidebar.
            case 'j': case 'k': case 'G': case '?': case 'f': case 'c': case 'C': case 's': return 0;
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

int suggestion_count(const tui_input_t *in) {
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

int tui_input_completion(const tui_input_t *in, tui_suggestion_t *out) {
    int n = in->cmd_len;
    if (!tui_input_suggestion(in, out) || (int)strlen(out->line) <= n || strncmp(out->line, in->cmd, (size_t)n) != 0)
        return 0;
    return !out->no_default || in->menu_sel > 0;
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

// COMMAND mode handles every key except Enter, which the caller handles to run the line.
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
            // If it was opened from typing, a line that can't be a command goes back to being text.
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
            while (in->cmd_len > 0 && utf8_is_cont(in->cmd[in->cmd_len])) in->cmd_len--;
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

// A paste's lines run together, one space between them, and never send or open the command line.
int tui_input_paste(tui_input_t *in, const tui_key_t *key) {
    if (in->mode == TUI_IMODE_NORMAL) in->mode = TUI_IMODE_INSERT;
    const char *s = key->ch;
    int n = key->ch_len;
    if (key->type == TUI_KEY_ENTER) {
        const char *at = in->mode == TUI_IMODE_COMMAND ? in->cmd : in->buf;
        int pos = in->mode == TUI_IMODE_COMMAND ? in->cmd_len : in->cursor;
        if (pos == 0 || at[pos - 1] == ' ') return 1;
        s = " ";
        n = 1;
    } else if (key->type != TUI_KEY_CHAR) {
        return 1;
    }
    if (in->mode == TUI_IMODE_COMMAND) {
        if (in->cmd_len + n >= (int)sizeof in->cmd) return 0;
        memcpy(in->cmd + in->cmd_len, s, (size_t)n);
        in->cmd_len += n;
        in->cmd[in->cmd_len] = '\0';
        in->menu_sel = 0;
        if (in->cmd_as_text && !could_be_command(in)) tui_input_command_to_text(in);
        return 1;
    }
    if (in->len + n >= (int)sizeof in->buf) return 0;
    insert_bytes(in, s, n);
    return 1;
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
