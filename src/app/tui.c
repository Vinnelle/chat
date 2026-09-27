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

#define CHROME_WASH_BG  "\x1b[48;2;236;234;240m"
#define CHROME_WASH_FG  "\x1b[38;2;95;93;108m"
#define CHROME_DIM_FG   "\x1b[38;2;150;148;162m"
#define CHROME_CHIP_BG  "\x1b[48;2;205;200;218m"
#define CHROME_CHIP_FG  "\x1b[38;2;60;58;72m"
#define STATUS_BAR_BG   "\x1b[48;2;218;213;230m"
#define STATUS_BAR_FG   "\x1b[38;2;72;70;84m"
#define STATUS_CHIP_BG  "\x1b[48;2;180;173;198m"
#define STATUS_CHIP_FG  "\x1b[38;2;42;40;52m"

#define BADGE_UNSIGNED_BG "\x1b[48;2;240;205;207m"
#define BADGE_UNSIGNED_FG "\x1b[38;2;140;58;62m"
#define BADGE_SIGNED_BG   "\x1b[48;2;205;230;212m"
#define BADGE_SIGNED_FG   "\x1b[38;2;48;108;68m"
#define BADGE_NATIVE_BG   "\x1b[48;2;200;228;226m"
#define BADGE_NATIVE_FG   "\x1b[38;2;38;100;96m"
#define BADGE_AGE_BG      "\x1b[48;2;206;218;241m"
#define BADGE_AGE_FG      "\x1b[38;2;48;80;142m"
#define BADGE_PGP_BG      "\x1b[48;2;224;210;238m"
#define BADGE_PGP_FG      "\x1b[38;2;90;58;140m"

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

size_t tui_decode_key(const uint8_t *buf, size_t len, tui_key_t *out) {
    out->type = TUI_KEY_NONE;
    out->ch_len = 0;
    if (len == 0) return 0;
    uint8_t b0 = buf[0];

    if (b0 == 0x1b) {
        if (len == 1) { out->type = TUI_KEY_ESCAPE; return 1; }

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
                    case '1': case '7': out->type = TUI_KEY_HOME;   return 4;
                    case '3':           out->type = TUI_KEY_DELETE; return 4;
                    case '4': case '8': out->type = TUI_KEY_END;    return 4;
                    default: break;
                }
            }
            // Parameter and intermediate bytes run up to a final byte in 0x40-0x7e.
            size_t k = 2;
            while (k < len && buf[k] >= 0x20 && buf[k] <= 0x3f) k++;
            out->type = TUI_KEY_UNKNOWN;
            return (k < len && buf[k] >= 0x40 && buf[k] <= 0x7e) ? k + 1 : 1;
        } else if (len >= 3 && buf[1] == 'O') {
            switch (buf[2]) {
                case 'H': out->type = TUI_KEY_HOME; return 3;
                case 'F': out->type = TUI_KEY_END;  return 3;
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
    if (b0 == 0x17) { out->type = TUI_KEY_CLOSE_SESSION; return 1; }
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
}

static const char *mode_name(tui_input_mode_t mode) {
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

static void enter_command(tui_input_t *in) {
    in->mode = TUI_IMODE_COMMAND;
    in->cmd_len = 0; in->cmd[0] = '\0';
}

static void delete_at_cursor(tui_input_t *in) {
    if (in->cursor >= in->len) return;
    int fwd = step_right(in, in->cursor) - in->cursor;
    memmove(in->buf + in->cursor, in->buf + in->cursor + fwd, (size_t)(in->len - in->cursor - fwd));
    in->len -= fwd;
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
        case TUI_KEY_CHAR: {
            if (in->len + key->ch_len >= (int)sizeof(in->buf)) return 1;
            memmove(in->buf + in->cursor + key->ch_len, in->buf + in->cursor, (size_t)(in->len - in->cursor));
            memcpy(in->buf + in->cursor, key->ch, (size_t)key->ch_len);
            in->len += key->ch_len;
            in->cursor += key->ch_len;
            in->buf[in->len] = '\0';
            return 1;
        }
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
            case 'j': case 'k': return 1;
            case 'i': in->mode = TUI_IMODE_INSERT; return 1;
            case 'a': in->cursor = step_right(in, in->cursor); in->mode = TUI_IMODE_INSERT; return 1;
            case 'I': in->cursor = 0; in->mode = TUI_IMODE_INSERT; return 1;
            case 'A': in->cursor = in->len; in->mode = TUI_IMODE_INSERT; return 1;
            case 'x': delete_at_cursor(in); normal_clamp(in); return 1;
            case '0': in->cursor = 0; return 1;
            case '$': in->cursor = in->len; normal_clamp(in); return 1;
            case ':': enter_command(in); return 1;
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

static const char *cmd_suggestion(const tui_input_t *in) {
    return in->complete ? in->complete(in->cmd) : NULL;
}

// COMMAND mode owns every key except Enter, which the caller handles to run the line.
static int command_feed(tui_input_t *in, const tui_key_t *key) {
    switch (key->type) {
        case TUI_KEY_CHAR:
            if (in->cmd_len + key->ch_len >= (int)sizeof(in->cmd)) return 1;
            memcpy(in->cmd + in->cmd_len, key->ch, (size_t)key->ch_len);
            in->cmd_len += key->ch_len;
            in->cmd[in->cmd_len] = '\0';
            return 1;
        case TUI_KEY_TAB: {
            const char *sug = cmd_suggestion(in);
            if (!sug) return 1;
            size_t slen = strlen(sug);
            if (slen >= sizeof in->cmd) return 1;
            memcpy(in->cmd, sug, slen + 1);
            in->cmd_len = (int)slen;
            return 1;
        }
        case TUI_KEY_BACKSPACE:
            if (in->cmd_len == 0) { enter_normal(in); return 1; }
            in->cmd_len--;
            while (in->cmd_len > 0 && (in->cmd[in->cmd_len] & 0xc0) == 0x80) in->cmd_len--;
            in->cmd[in->cmd_len] = '\0';
            return 1;
        case TUI_KEY_ESCAPE:
            enter_normal(in);
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

#define FRAME_CAP 131072

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

static void wapp_pad(wbuf_t *w, int written, int width) {
    for (int i = written; i < width; i++) wapp(w, " ");
}

static int sidebar_width(int cols) {
    int w = cols / 4;
    if (w < 16) w = 16;
    if (w > 28) w = 28;
    if (w > cols - 20) w = cols - 20;
    if (w < 8) w = 8;
    return w;
}

static int geometry(int rows, int cols, int show_sidebar, int *pane_x, int *pane_rows) {
    if (rows < 6) rows = 6;
    if (cols < 30) cols = 30;
    int sbw = show_sidebar ? sidebar_width(cols) : 0;
    *pane_x = show_sidebar ? sbw + 2 : 1;
    *pane_rows = rows - 2;
    return sbw;
}

int tui_pane_geometry(int rows, int cols, int *pane_x, int *pane_rows) {
    return geometry(rows, cols, 1, pane_x, pane_rows);
}

static void draw_chrome(wbuf_t *w, int rows, int cols, int sbw, int color_enabled, const tui_view_t *view,
                         const tui_session_row_t *sessions, int n_sessions, int selected_session,
                         const tui_peer_row_t *peers, int n_peers,
                         const char *const *net_lines, int n_net_lines) {
    // Cleared first, so a title the width table overestimates leaves nothing behind at the end.
    wapp(w, "\x1b[1;1H");
    wapp(w, color_enabled ? CHROME_WASH_BG CHROME_WASH_FG "\x1b[K" : "\x1b[7m\x1b[K");
    int used = 0;
    wapp(w, color_enabled ? CHROME_WASH_BG CHROME_WASH_FG "\x1b[1m" : "\x1b[7m\x1b[1m");
    wapp(w, " chat");
    used += 5;
    wapp(w, "\x1b[22m");
    char crumb[200];
    if (view->title && view->title[0]) snprintf(crumb, sizeof crumb, "  \xc2\xb7  %s", view->title);
    else crumb[0] = '\0';
    if (color_enabled) wapp(w, CHROME_DIM_FG);
    int room = cols - used; if (room < 0) room = 0;
    used += wapp_trunc(w, crumb, room);
    wapp_pad(w, used, cols);
    wapp(w, "\x1b[0m");

    int sidebar_rows = rows - 1;

    int peers_header_row = n_sessions;
    int peers_start_row = n_sessions + 1;
    int content_end_row = peers_start_row + n_peers;

    int net_block_start = n_net_lines > 0 ? sidebar_rows - n_net_lines - 2 : -1;
    int net_fits = n_net_lines > 0 && net_block_start > content_end_row;

    for (int row = 0; row < sidebar_rows; row++) {
        int screen_row = row + 2;
        if (!view->sidebar) continue;
        wapp(w, "\x1b[%d;1H", screen_row);
        wapp(w, color_enabled ? CHROME_WASH_BG CHROME_WASH_FG : "\x1b[7m");

        if (row < n_sessions) {
            const tui_session_row_t *s = &sessions[row];
            int is_sel = (row == selected_session);
            if (is_sel) wapp(w, "\x1b[7m");
            char cell[64];
            snprintf(cell, sizeof cell, "%s%s (%d)%s", is_sel ? "> " : "  ", s->label, s->online,
                      (!is_sel && s->unread) ? " *" : "");
            wapp_pad(w, wapp_trunc(w, cell, sbw), sbw);
        } else if (n_peers > 0 && row == peers_header_row) {
            wapp(w, "\x1b[2m");
            wapp_pad(w, wapp_trunc(w, "  -- online --", sbw), sbw);
        } else if (n_peers > 0 && row >= peers_start_row && row - peers_start_row < n_peers) {
            const tui_peer_row_t *p = &peers[row - peers_start_row];
            char cell[64]; snprintf(cell, sizeof cell, "  %s", p->label);
            wapp_pad(w, wapp_trunc(w, cell, sbw), sbw);
        } else if (net_fits && row == net_block_start) {
            wapp(w, "\x1b[2m");
            wapp_pad(w, wapp_trunc(w, "  -- network --", sbw), sbw);
        } else if (net_fits && row > net_block_start && row - net_block_start - 1 < n_net_lines) {
            char cell[64]; snprintf(cell, sizeof cell, "  %s", net_lines[row - net_block_start - 1]);
            wapp_pad(w, wapp_trunc(w, cell, sbw), sbw);
        } else {
            wapp_pad(w, 0, sbw);
        }
        wapp(w, "\x1b[0m");

        wapp(w, "\x1b[%d;%dH\xe2\x94\x82", screen_row, sbw + 1);
    }
}

// Autowrap is off while a frame draws: a character the width table guesses too narrow is clipped
// at the right edge instead of pushing the rest of the frame down a row.
static void begin_frame(wbuf_t *w) { wapp(w, "\x1b[?2026h\x1b[?25l\x1b[?7l"); }
static void end_frame(wbuf_t *w) {
    // Written on its own so a frame that filled its buffer still turns autowrap back on.
    static const char tail[] = "\x1b[?7h\x1b[?2026l";
    platform_write_stdout(w->buf, w->len);
    platform_write_stdout(tail, sizeof tail - 1);
}

static int draw_identity_gap(wbuf_t *w, tui_identity_badge_t badge, int color_enabled, int room) {
    if (room <= 0) return 0;
    const char *kind = badge == TUI_ID_NATIVE ? "native" : badge == TUI_ID_AGE ? "age"
                      : badge == TUI_ID_PGP ? "pgp" : NULL;
    if (!color_enabled) {
        char buf[24];
        if (kind) snprintf(buf, sizeof buf, "signed: %s", kind);
        else snprintf(buf, sizeof buf, "unsigned");
        wapp(w, "\x1b[2m");
        wapp_trunc(w, buf, room);
        wapp(w, STATUS_BAR_FG);
        size_t bl = strlen(buf);
        return (int)(bl < (size_t)room ? bl : (size_t)room);
    }
    const char *word = kind ? "signed" : "unsigned";
    int wlen = (int)strlen(word);
    if (wlen + 2 > room) return 0;
    int used = 0;
    wapp(w, kind ? BADGE_SIGNED_BG BADGE_SIGNED_FG : BADGE_UNSIGNED_BG BADGE_UNSIGNED_FG);
    wapp(w, " %s ", word);
    used += wlen + 2;
    wapp(w, STATUS_BAR_BG STATUS_BAR_FG);

    if (kind && used < room) {
        int klen = (int)strlen(kind);
        int kroom = room - used;
        if (klen + 2 <= kroom) {
            wapp(w, badge == TUI_ID_NATIVE ? BADGE_NATIVE_BG BADGE_NATIVE_FG
                   : badge == TUI_ID_AGE ? BADGE_AGE_BG BADGE_AGE_FG : BADGE_PGP_BG BADGE_PGP_FG);
            wapp(w, " %s ", kind);
            used += klen + 2;
            wapp(w, STATUS_BAR_BG STATUS_BAR_FG);
        }
    }
    return used;
}

static int draw_version_gap(wbuf_t *w, int room) {
    const char *v = "v" CHAT_VERSION;
    int vlen = (int)strlen(v);
    if (vlen + 1 > room) { v++; vlen--; }
    if (vlen + 1 > room) return 0;
    int trail = vlen + 2 <= room;
    wapp_pad(w, 0, room - vlen - trail);
    wapp(w, "\x1b[2m%s\x1b[22m", v);
    if (trail) wapp(w, " ");
    return room;
}

static void draw_input(wbuf_t *w, int rows, int cols, int pane_x,
                       const char *nick, const char *mode_prompt,
                       const tui_input_t *input, int color_enabled, int mask_input,
                       tui_identity_badge_t identity_badge, const char *status_right) {
    int input_row = rows;
    wapp(w, "\x1b[%d;1H", input_row);
    wapp(w, color_enabled ? STATUS_BAR_BG STATUS_BAR_FG "\x1b[K" : "\x1b[7m\x1b[K");
    int used = 0;

    wapp(w, color_enabled ? STATUS_CHIP_BG STATUS_CHIP_FG : "\x1b[7m");
    const char *name = mode_name(input->mode);
    wapp(w, " %s ", name);
    used += (int)strlen(name) + 2;
    wapp(w, color_enabled ? STATUS_BAR_BG STATUS_BAR_FG : "\x1b[7m");

    int align_to = pane_x - 1;
    used += draw_identity_gap(w, identity_badge, color_enabled, align_to - used);
    used += draw_version_gap(w, align_to - used);
    if (align_to > used) { wapp_pad(w, used, align_to); used = align_to; }

    int cursor_used;

    if (input->mode == TUI_IMODE_COMMAND) {
        wapp(w, ":"); used += 1;
        int room = cols - used; if (room < 0) room = 0;
        used += wapp_trunc(w, input->cmd, room);
        cursor_used = used;

        const char *sug = cmd_suggestion(input);
        if (sug) {
            const char *rest = sug + input->cmd_len;
            int room2 = cols - used;
            if (room2 > 0) {
                wapp(w, "\x1b[2m");
                used += wapp_trunc(w, rest, room2);
                wapp(w, color_enabled ? STATUS_BAR_FG : "\x1b[7m");
            }
        }
    } else {
        const char *label = mode_prompt ? mode_prompt : nick;
        char lbl[64]; snprintf(lbl, sizeof lbl, "%s> ", label);
        int room0 = cols - used; if (room0 < 0) room0 = 0;
        used += wapp_trunc(w, lbl, room0);
        int content_start = used;
        int room = cols - used; if (room < 1) room = 1;

        int show_hint = input->len == 0 && !mask_input;
        if (mask_input) {
            // One dot per character, not per byte.
            int dots = 0, before = 0;
            for (size_t i = 0, adv; i < (size_t)input->len; i += adv) {
                utf8_decode(input->buf, (size_t)input->len, i, &adv);
                if (i < (size_t)input->cursor) before++;
                if (dots < room) { wapp(w, "\xe2\x80\xa2"); dots++; }
            }
            used += dots;
            cursor_used = content_start + (before < room ? before : room - 1);
        } else if (show_hint) {
            const char *hint = input->hint ? input->hint : !input->modal ? "Enter confirm \xc2\xb7 Esc cancel"
                : input->mode == TUI_IMODE_NORMAL
                ? "i/a/I/A insert \xc2\xb7 h/l move \xc2\xb7 0/$ ends \xc2\xb7 x del \xc2\xb7 : command"
                : "type to chat \xc2\xb7 /help commands \xc2\xb7 Esc normal mode";
            wapp(w, "\x1b[2m");
            used += wapp_trunc(w, hint, room);
            wapp(w, color_enabled ? STATUS_BAR_FG : "\x1b[7m");
            cursor_used = content_start;
        } else {
            // A line wider than the field scrolls: it starts far enough in that the text before
            // the cursor fits, with a column left for the cursor itself.
            size_t start = 0;
            int before;
            utf8_fit_cols(input->buf, (size_t)input->cursor, INT_MAX, &before);
            while (before > room - 1 && start < (size_t)input->cursor) {
                size_t adv;
                before -= utf8_char_cols(input->buf, (size_t)input->len, start, &adv);
                start += adv;
            }
            used += wapp_trunc(w, input->buf + start, room);
            cursor_used = content_start + before;

            const char *nick = input->mode == TUI_IMODE_INSERT ? mention_suggestion(input) : NULL;
            if (nick) {
                const char *rest = nick + (input->cursor - mention_start(input));
                int room2 = cols - used;
                if (room2 > 0) {
                    wapp(w, "\x1b[2m");
                    used += wapp_trunc(w, rest, room2);
                    wapp(w, "\x1b[22m");
                }
            }
        }
    }

    if (status_right && status_right[0]) {
        int slen = utf8_str_cols(status_right);
        int remaining = cols - used;
        if (slen > 0 && slen + 1 <= remaining) {
            wapp_pad(w, 0, remaining - slen);
            wapp(w, "%s", status_right);
            used = cols;
        } else {
            wapp_pad(w, used, cols);
            used = cols;
        }
    } else {
        wapp_pad(w, used, cols);
        used = cols;
    }
    wapp(w, "\x1b[0m");

    int cursor_col = 1 + cursor_used;
    if (cursor_col > cols) cursor_col = cols;
    const char *shape = input->mode == TUI_IMODE_INSERT ? "\x1b[6 q" : "\x1b[2 q";
    wapp(w, "%s\x1b[%d;%dH\x1b[?25h", shape, input_row, cursor_col);
}

#define GRID_MAXROWS 200
#define GRID_ROWBYTES 1600

typedef struct {
    char buf[GRID_MAXROWS][GRID_ROWBYTES];
    int len[GRID_MAXROWS];
    int rows, pane_w;
} grid_t;

static grid_t g_grid;

static void grid_reset(grid_t *g, int rows, int pane_w) {
    if (rows > GRID_MAXROWS) rows = GRID_MAXROWS;
    g->rows = rows; g->pane_w = pane_w;
    for (int r = 0; r < rows; r++) g->len[r] = 0;
}

static wbuf_t grid_row(grid_t *g, int r) { wbuf_t w = { g->buf[r], GRID_ROWBYTES, (size_t)g->len[r] }; return w; }
static void grid_commit(grid_t *g, int r, const wbuf_t *w) { g->len[r] = (int)w->len; }

// The pane runs to the right edge, so each row is cleared to the end before it's drawn: nothing
// from the previous frame survives past the new text, whatever width the terminal gave it.
static void grid_emit(wbuf_t *w, const grid_t *g, int first_screen_row, int pane_x) {
    for (int r = 0; r < g->rows; r++) {
        wapp(w, "\x1b[%d;%dH\x1b[0m\x1b[K", first_screen_row + r, pane_x);
        if (g->len[r] > 0 && w->len + (size_t)g->len[r] < w->cap) {
            memcpy(w->buf + w->len, g->buf[r], (size_t)g->len[r]);
            w->len += (size_t)g->len[r];
        }
    }
}

static void grid_rule(grid_t *g, int r, const char *label) {
    if (r < 0 || r >= g->rows) return;
    wbuf_t w = grid_row(g, r);
    int used = 0;
    wapp(&w, "\x1b[2m\xe2\x94\x80 "); used += 2;
    used += wapp_trunc(&w, label, g->pane_w - 4);
    wapp(&w, " "); used += 1;
    for (; used < g->pane_w; used++) wapp(&w, "\xe2\x94\x80");
    wapp(&w, "\x1b[0m");
    grid_commit(g, r, &w);
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

static void grid_scroll(grid_t *g, const tui_scrollback_t *sb, int first_row, int nrows,
                        int color_enabled, int dim) {
    if (!sb) return;
    int pane_w = g->pane_w;
    int bottom = nrows - 1;
    for (int k = 0; k < sb->count && bottom >= 0; k++) {
        int idx = (sb->head - 1 - k + TUI_SCROLLBACK * 2) % TUI_SCROLLBACK;
        const tui_line_t *l = &sb->lines[idx];
        char pre[16]; snprintf(pre, sizeof pre, "[%s] ", l->hhmm);
        int prelen = (int)strlen(pre);
        int textw = pane_w - prelen;
        if (textw < 8) { prelen = 0; textw = pane_w; }

        size_t off[64], len[64];
        int nchunks = 0;
        const char *tx = l->text;
        size_t remain = strlen(tx);
        while (remain > 0 && nchunks < 64) {
            size_t take = wrap_chunk(tx, remain, textw);
            off[nchunks] = (size_t)(tx - l->text); len[nchunks] = take; nchunks++;
            tx += take; remain -= take;
            while (remain > 0 && *tx == ' ') { tx++; remain--; }
        }
        if (nchunks == 0) { off[0] = 0; len[0] = 0; nchunks = 1; }

        int hl = color_enabled && l->mention;

        int coloured = color_enabled && l->has_color && !hl;
        int subdued = dim && !coloured && color_enabled;
        for (int c = 0; c < nchunks; c++) {
            int row = bottom - (nchunks - 1 - c);
            if (row < 0) continue;
            int gr = first_row + row;
            if (gr < 0 || gr >= g->rows) continue;
            wbuf_t w = grid_row(g, gr);
            if (hl) wapp(&w, "\x1b[48;2;110;70;10m\x1b[1m\x1b[38;2;255;248;235m");
            if (subdued) wapp(&w, "\x1b[2m");
            int used = 0;
            if (c == 0 && prelen) { wapp_trunc(&w, pre, pane_w); used = prelen; }
            else if (prelen) { wapp_pad(&w, 0, prelen); used = prelen; }
            char piece[TUI_LINE_MAX + 1];
            memcpy(piece, l->text + off[c], len[c]); piece[len[c]] = '\0';

            size_t head = len[c];
            if (l->color_len > 0) head = (size_t)l->color_len > off[c] ? (size_t)l->color_len - off[c] : 0;
            if (head > len[c]) head = len[c];
            if (coloured && head > 0) {
                char hpart[TUI_LINE_MAX + 1];
                memcpy(hpart, piece, head); hpart[head] = '\0';
                wapp(&w, "\x1b[38;2;%d;%d;%dm", l->rgb[0], l->rgb[1], l->rgb[2]);
                used += wapp_trunc(&w, hpart, pane_w - used);
                wapp(&w, "\x1b[39m");
                if (head < len[c]) used += wapp_trunc(&w, piece + head, pane_w - used);
            } else {
                used += wapp_trunc(&w, piece, pane_w - used);
            }
            if (hl) { wapp_pad(&w, used, pane_w); used = pane_w; }
            if (hl || coloured || subdued) wapp(&w, "\x1b[0m");
            grid_commit(g, gr, &w);
        }
        bottom -= nchunks;
    }
}

void tui_render(int rows, int cols,
                 const tui_session_row_t *sessions, int n_sessions, int selected,
                 const tui_peer_row_t *peers, int n_peers,
                 const tui_scrollback_t *sb, const tui_scrollback_t *console,
                 const tui_view_t *view,
                 const char *nick, const char *mode_prompt,
                 const tui_input_t *input, int color_enabled, int mask_input,
                 tui_identity_badge_t identity_badge, const char *status_right,
                 const char *const *net_lines, int n_net_lines) {
    static char frame[FRAME_CAP];
    wbuf_t w = { frame, FRAME_CAP, 0 };

    if (rows < 6) rows = 6;
    if (cols < 30) cols = 30;
    int pane_x, pane_rows;
    int sbw = geometry(rows, cols, view->sidebar, &pane_x, &pane_rows);
    int pane_w = cols - pane_x + 1;

    begin_frame(&w);
    draw_chrome(&w, rows, cols, sbw, color_enabled, view, sessions, n_sessions, selected, peers, n_peers,
                net_lines, n_net_lines);

    grid_reset(&g_grid, pane_rows, pane_w);
    int show_console = console && view->console;
    int con_rows = 0;
    if (show_console && view->chat) {
        con_rows = pane_rows / 4;
        if (con_rows < 3) con_rows = 3;
        if (con_rows > 8) con_rows = 8;
        if (pane_rows - con_rows - 2 < 3) con_rows = pane_rows - 5;
        if (con_rows < 1) con_rows = 0;
    }
    if (con_rows > 0) {
        grid_rule(&g_grid, 0, "console");
        grid_scroll(&g_grid, console, 1, con_rows, color_enabled, 1);
        grid_rule(&g_grid, 1 + con_rows, "chat");
        grid_scroll(&g_grid, sb, 2 + con_rows, pane_rows - con_rows - 2, color_enabled, 0);
    } else if (show_console && !view->chat) {
        grid_rule(&g_grid, 0, "console");
        grid_scroll(&g_grid, console, 1, pane_rows - 1, color_enabled, 1);
    } else if (view->chat) {
        grid_scroll(&g_grid, sb, 0, pane_rows, color_enabled, 0);
    } else {
        wbuf_t hw = grid_row(&g_grid, 0);
        const char *hint = "  chat and console are hidden - ^T shows the chat, ^O shows the console";
        wapp(&hw, "\x1b[2m"); wapp_trunc(&hw, hint, pane_w); wapp(&hw, "\x1b[0m");
        grid_commit(&g_grid, 0, &hw);
    }
    grid_emit(&w, &g_grid, 2, pane_x);

    draw_input(&w, rows, cols, pane_x, nick, mode_prompt, input, color_enabled, mask_input, identity_badge, status_right);
    end_frame(&w);
}

void tui_render_input(int rows, int cols, const tui_view_t *view,
                      const char *nick, const char *mode_prompt,
                      const tui_input_t *input, int color_enabled, int mask_input,
                      tui_identity_badge_t identity_badge, const char *status_right) {
    static char frame[8192];
    wbuf_t w = { frame, sizeof frame, 0 };
    if (rows < 6) rows = 6;
    if (cols < 30) cols = 30;
    int pane_x, pane_rows;

    geometry(rows, cols, view->sidebar, &pane_x, &pane_rows);
    begin_frame(&w);
    draw_input(&w, rows, cols, pane_x, nick, mode_prompt, input, color_enabled, mask_input, identity_badge, status_right);
    end_frame(&w);
}

void tui_render_list(int rows, int cols,
                      const tui_session_row_t *sessions, int n_sessions, int selected_session,
                      const char *title, const tui_list_item_t *items, int n_items, int selected,
                      const char *hint, int color_enabled) {
    static char frame[FRAME_CAP];
    wbuf_t w = { frame, FRAME_CAP, 0 };

    if (rows < 6) rows = 6;
    if (cols < 30) cols = 30;
    int pane_x, pane_rows;
    int sbw = tui_pane_geometry(rows, cols, &pane_x, &pane_rows);
    int pane_w = cols - pane_x + 1;

    begin_frame(&w);
    static const tui_view_t full = { 1, 1, 1, NULL };
    draw_chrome(&w, rows, cols, sbw, color_enabled, &full, sessions, n_sessions, selected_session, NULL, 0, NULL, 0);

    wapp(&w, "\x1b[2;%dH\x1b[0K\x1b[2m", pane_x);
    wapp_trunc(&w, title, pane_w);
    wapp(&w, "\x1b[0m");

    int list_rows = pane_rows - 1;
    int scroll = 0;
    if (selected >= list_rows) scroll = selected - list_rows + 1;
    if (scroll > n_items - list_rows) scroll = n_items - list_rows;
    if (scroll < 0) scroll = 0;

    for (int row = 0; row < list_rows; row++) {
        int screen_row = row + 3;
        wapp(&w, "\x1b[%d;%dH\x1b[0K", screen_row, pane_x);
        int idx = row + scroll;
        if (idx < n_items) {
            int is_sel = (idx == selected);
            if (is_sel) wapp(&w, "\x1b[7m");
            char cell[TUI_LIST_LABEL_MAX + 4];
            snprintf(cell, sizeof cell, "%s%s%s", is_sel ? "> " : "  ",
                     items[idx].label, items[idx].is_dir ? "/" : "");
            int shown = wapp_trunc(&w, cell, pane_w);
            if (is_sel) wapp_pad(&w, shown, pane_w);
            if (is_sel) wapp(&w, "\x1b[0m");
        }
    }

    int input_row = rows;
    wapp(&w, "\x1b[%d;%dH\x1b[0K\x1b[2m", input_row, pane_x);
    wapp_trunc(&w, hint, pane_w);
    wapp(&w, "\x1b[0m\x1b[?25l");
    end_frame(&w);
}

void tui_render_settings(int rows, int cols,
                         const tui_session_row_t *sessions, int n_sessions, int selected_session,
                         const tui_setting_row_t *items, int n_items, int selected,
                         const char *help, const char *note, const char *hint, int color_enabled,
                         const tui_input_t *input, const char *prompt, int mask_input, const char *nick) {
    static char frame[FRAME_CAP];
    wbuf_t w = { frame, FRAME_CAP, 0 };

    if (rows < 6) rows = 6;
    if (cols < 30) cols = 30;
    int pane_x, pane_rows;
    int sbw = tui_pane_geometry(rows, cols, &pane_x, &pane_rows);
    int pane_w = cols - pane_x + 1;

    begin_frame(&w);
    static const tui_view_t full = { 1, 1, 1, "settings" };
    draw_chrome(&w, rows, cols, sbw, color_enabled, &full, sessions, n_sessions, selected_session, NULL, 0, NULL, 0);

    // The help text under the list: wrapped, up to six rows, then the note, then a blank row.
    int help_rows = 0;
    size_t off[6], len[6];
    {
        const char *tx = help ? help : "";
        size_t remain = strlen(tx);
        int width = pane_w - 2;
        while (remain > 0 && help_rows < 6) {
            size_t take = wrap_chunk(tx, remain, width);
            off[help_rows] = (size_t)(tx - help);
            len[help_rows] = take;
            help_rows++;
            tx += take; remain -= take;
            while (remain > 0 && *tx == ' ') { tx++; remain--; }
        }
    }
    int foot = help_rows + 2;
    int list_rows = pane_rows - foot - 1;
    if (list_rows < 3) list_rows = 3;

    // Rows on screen: section headings and settings, headings taking a row of their own.
    int line_of[64], total = 0;
    for (int i = 0; i < n_items && i < 64; i++) {
        if (items[i].section) total++;
        line_of[i] = total++;
    }
    int scroll = 0;
    if (selected >= 0 && selected < n_items) {
        int want = line_of[selected];
        if (selected > 0 && items[selected].section) want--;
        if (line_of[selected] >= list_rows) scroll = line_of[selected] - list_rows + 1;
        if (want < scroll) scroll = want;
    }
    int label_w = pane_w / 2 - 2;
    if (label_w > 30) label_w = 30;
    if (label_w < 12) label_w = 12;

    for (int r = 0; r < list_rows + 1; r++) wapp(&w, "\x1b[%d;%dH\x1b[0m\x1b[K", 2 + r, pane_x);
    int line = 0;
    for (int i = 0; i < n_items && i < 64; i++) {
        for (int pass = 0; pass < 2; pass++) {
            if (pass == 0 && !items[i].section) continue;
            int shown = line - scroll;
            line++;
            if (shown < 0 || shown >= list_rows) continue;
            wapp(&w, "\x1b[%d;%dH", 2 + shown, pane_x);
            if (pass == 0) {
                wapp(&w, "\x1b[2m\xe2\x94\x80 ");
                int used = 2 + wapp_trunc(&w, items[i].section, pane_w - 4);
                wapp(&w, " "); used++;
                for (; used < pane_w; used++) wapp(&w, "\xe2\x94\x80");
                wapp(&w, "\x1b[0m");
                continue;
            }
            int sel = i == selected;
            if (sel) wapp(&w, "\x1b[7m");
            else if (items[i].dim) wapp(&w, "\x1b[2m");
            int used = wapp_trunc(&w, sel ? "> " : "  ", pane_w);
            int lw = wapp_trunc(&w, items[i].label, label_w);
            wapp_pad(&w, lw, label_w);
            used += label_w;
            if (used < pane_w) { wapp(&w, " "); used++; }
            used += wapp_trunc(&w, items[i].value, pane_w - used);
            if (sel) wapp_pad(&w, used, pane_w);
            wapp(&w, "\x1b[0m");
        }
    }

    int help_top = 2 + list_rows + 1;
    for (int r = 0; r < help_rows; r++) {
        wapp(&w, "\x1b[%d;%dH\x1b[0m\x1b[K", help_top + r, pane_x);
        char piece[TUI_LINE_MAX + 1];
        size_t n = len[r] < TUI_LINE_MAX ? len[r] : TUI_LINE_MAX;
        memcpy(piece, help + off[r], n);
        piece[n] = '\0';
        wapp(&w, "  ");
        wapp_trunc(&w, piece, pane_w - 2);
    }
    for (int r = help_top + help_rows; r < rows; r++) wapp(&w, "\x1b[%d;%dH\x1b[0m\x1b[K", r, pane_x);
    if (note && note[0]) {
        wapp(&w, "\x1b[%d;%dH\x1b[1m  ", rows - 1, pane_x);
        wapp_trunc(&w, note, pane_w - 2);
        wapp(&w, "\x1b[0m");
    }

    if (input) {
        draw_input(&w, rows, cols, pane_x, nick, prompt, input, color_enabled, mask_input, TUI_ID_NONE, "");
    } else {
        wapp(&w, "\x1b[%d;%dH\x1b[0K\x1b[2m", rows, pane_x);
        wapp_trunc(&w, hint, pane_w);
        wapp(&w, "\x1b[0m\x1b[?25l");
    }
    end_frame(&w);
}
