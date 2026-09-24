// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "tui.h"
#include "crypto.h"
#include "platform.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

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
    if (n > TUI_LINE_MAX - 1) n = TUI_LINE_MAX - 1;
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
        } else if (len >= 3 && buf[1] == 'O') {
            switch (buf[2]) {
                case 'H': out->type = TUI_KEY_HOME; return 3;
                case 'F': out->type = TUI_KEY_END;  return 3;
                default: break;
            }
        }

        out->type = TUI_KEY_UNKNOWN;
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
    if (b0 < 0x20) { out->type = TUI_KEY_UNKNOWN; return 1; }

    size_t seqlen = 1;
    if ((b0 & 0xe0) == 0xc0) seqlen = 2;
    else if ((b0 & 0xf0) == 0xe0) seqlen = 3;
    else if ((b0 & 0xf8) == 0xf0) seqlen = 4;
    if (seqlen > len) seqlen = 1;
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

static void delete_at_cursor(tui_input_t *in) {
    if (in->cursor >= in->len) return;
    int fwd = step_right(in, in->cursor) - in->cursor;
    memmove(in->buf + in->cursor, in->buf + in->cursor + fwd, (size_t)(in->len - in->cursor - fwd));
    in->len -= fwd;
    in->buf[in->len] = '\0';
}

static int insert_feed(tui_input_t *in, const tui_key_t *key) {
    switch (key->type) {
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
            in->mode = TUI_IMODE_NORMAL;
            normal_clamp(in);
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
            case ':': in->mode = TUI_IMODE_COMMAND; in->cmd_len = 0; in->cmd[0] = '\0'; return 1;
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

static const char *CMD_WORDS[] = { "new", "join", "close", "nick", "sign", "copyid", "verify", "netverbose",
                                    "net", "peers", "colour", "color", "notify", "update", "help",
                                    "quit", "quitall", "q", "qa", "qall", "bd", "bw" };
#define N_CMD_WORDS (int)(sizeof(CMD_WORDS) / sizeof(CMD_WORDS[0]))

static const char *cmd_suggestion(const char *typed) {
    if (!typed[0] || strchr(typed, ' ')) return NULL;
    size_t tlen = strlen(typed);
    for (int i = 0; i < N_CMD_WORDS; i++)
        if (strlen(CMD_WORDS[i]) > tlen && strncmp(CMD_WORDS[i], typed, tlen) == 0) return CMD_WORDS[i];
    return NULL;
}

static int command_feed(tui_input_t *in, const tui_key_t *key) {
    switch (key->type) {
        case TUI_KEY_CHAR:
            if (in->cmd_len + key->ch_len >= (int)sizeof(in->cmd)) return 1;
            memcpy(in->cmd + in->cmd_len, key->ch, (size_t)key->ch_len);
            in->cmd_len += key->ch_len;
            in->cmd[in->cmd_len] = '\0';
            return 1;
        case TUI_KEY_TAB: {
            const char *sug = cmd_suggestion(in->cmd);
            if (!sug) return 0;
            size_t slen = strlen(sug);
            memcpy(in->cmd, sug, slen + 1);
            in->cmd_len = (int)slen;
            return 1;
        }
        case TUI_KEY_BACKSPACE:
            if (in->cmd_len == 0) { in->mode = TUI_IMODE_NORMAL; return 1; }
            in->cmd_len--;
            while (in->cmd_len > 0 && (in->cmd[in->cmd_len] & 0xc0) == 0x80) in->cmd_len--;
            in->cmd[in->cmd_len] = '\0';
            return 1;
        case TUI_KEY_ESCAPE:
            in->mode = TUI_IMODE_NORMAL;
            in->cmd_len = 0; in->cmd[0] = '\0';
            return 1;
        default: return 0;
    }
}

int tui_input_feed(tui_input_t *in, const tui_key_t *key) {
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

static int utf8_cols(const char *s) {
    int cols = 0;
    for (; *s; s++) if (((unsigned char)*s & 0xc0) != 0x80) cols++;
    return cols;
}

static void wapp_trunc(wbuf_t *w, const char *s, int width) {
    if (width <= 0) return;
    size_t n = strlen(s);
    if ((int)n > width) {
        n = (size_t)width;
        while (n > 0 && (((unsigned char)s[n]) & 0xc0) == 0x80) n--;
    }
    if (w->len >= w->cap) return;
    size_t room = w->cap - w->len;
    size_t take = n < room ? n : room;
    memcpy(w->buf + w->len, s, take);
    w->len += take;
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
    wapp(w, "\x1b[1;1H");
    wapp(w, color_enabled ? CHROME_WASH_BG CHROME_WASH_FG : "\x1b[7m");
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
    wapp_trunc(w, crumb, room);
    int shown = (int)strlen(crumb); if (shown > room) shown = room;
    used += shown;
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
            wapp_trunc(w, cell, sbw);
            wapp_pad(w, (int)strlen(cell), sbw);
        } else if (n_peers > 0 && row == peers_header_row) {
            wapp(w, "\x1b[2m");
            wapp_trunc(w, "  -- online --", sbw);
            wapp_pad(w, 14, sbw);
        } else if (n_peers > 0 && row >= peers_start_row && row - peers_start_row < n_peers) {
            const tui_peer_row_t *p = &peers[row - peers_start_row];
            char cell[64]; snprintf(cell, sizeof cell, "  %s", p->label);
            wapp_trunc(w, cell, sbw);
            wapp_pad(w, (int)strlen(cell), sbw);
        } else if (net_fits && row == net_block_start) {
            wapp(w, "\x1b[2m");
            wapp_trunc(w, "  -- network --", sbw);
            wapp_pad(w, 15, sbw);
        } else if (net_fits && row > net_block_start && row - net_block_start - 1 < n_net_lines) {
            char cell[64]; snprintf(cell, sizeof cell, "  %s", net_lines[row - net_block_start - 1]);
            wapp_trunc(w, cell, sbw);
            wapp_pad(w, (int)strlen(cell), sbw);
        } else {
            wapp_pad(w, 0, sbw);
        }
        wapp(w, "\x1b[0m");

        wapp(w, "\x1b[%d;%dH\xe2\x94\x82", screen_row, sbw + 1);
    }
}

static void begin_frame(wbuf_t *w) { wapp(w, "\x1b[?2026h\x1b[?25l"); }
static void end_frame(wbuf_t *w) {
    wapp(w, "\x1b[?2026l");
    platform_write_stdout(w->buf, w->len);
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

static void draw_input(wbuf_t *w, int rows, int cols, int pane_x,
                       const char *nick, const char *mode_prompt,
                       const tui_input_t *input, int color_enabled, int mask_input,
                       tui_identity_badge_t identity_badge, const char *status_right) {
    int input_row = rows;
    wapp(w, "\x1b[%d;1H", input_row);
    wapp(w, color_enabled ? STATUS_BAR_BG STATUS_BAR_FG : "\x1b[7m");
    int used = 0;

    wapp(w, color_enabled ? STATUS_CHIP_BG STATUS_CHIP_FG : "\x1b[7m");
    const char *name = input->mode == TUI_IMODE_NORMAL ? "NORMAL" : input->mode == TUI_IMODE_COMMAND ? "COMMAND" : "INSERT";
    wapp(w, " %s ", name);
    used += (int)strlen(name) + 2;
    wapp(w, color_enabled ? STATUS_BAR_BG STATUS_BAR_FG : "\x1b[7m");

    int align_to = pane_x - 1;
    used += draw_identity_gap(w, identity_badge, color_enabled, align_to - used);
    if (align_to > used) { wapp_pad(w, used, align_to); used = align_to; }

    int cursor_used;

    if (input->mode == TUI_IMODE_COMMAND) {
        wapp(w, ":"); used += 1;
        int room = cols - used; if (room < 0) room = 0;
        wapp_trunc(w, input->cmd, room);
        int cmd_shown = input->cmd_len < room ? input->cmd_len : room;
        used += cmd_shown;
        cursor_used = used;

        const char *sug = cmd_suggestion(input->cmd);
        if (sug) {
            const char *rest = sug + input->cmd_len;
            int room2 = cols - used;
            if (room2 > 0) {
                wapp(w, "\x1b[2m");
                wapp_trunc(w, rest, room2);
                wapp(w, color_enabled ? STATUS_BAR_FG : "\x1b[7m");
                size_t rl = strlen(rest);
                used += (int)(rl < (size_t)room2 ? rl : (size_t)room2);
            }
        }
    } else {
        const char *label = mode_prompt ? mode_prompt : nick;
        char lbl[64]; snprintf(lbl, sizeof lbl, "%s> ", label);
        int room0 = cols - used; if (room0 < 0) room0 = 0;
        wapp_trunc(w, lbl, room0);
        int lbl_shown = (int)strlen(lbl); if (lbl_shown > room0) lbl_shown = room0;
        used += lbl_shown;
        int content_start = used;

        int show_hint = input->len == 0 && !mask_input;
        if (mask_input) {

            int room = cols - used;
            for (int i = 0; i < input->len && i < room; i++) { wapp(w, "\xe2\x80\xa2"); used++; }
        } else if (show_hint) {
            const char *hint = input->mode == TUI_IMODE_NORMAL
                ? "i insert \xc2\xb7 a append \xc2\xb7 h/l move \xc2\xb7 0/$ ends \xc2\xb7 x del \xc2\xb7 : cmd"
                : "Esc: normal mode";
            int room = cols - used;
            if (room > 0) {
                wapp(w, "\x1b[2m");
                wapp_trunc(w, hint, room);
                wapp(w, color_enabled ? STATUS_BAR_FG : "\x1b[7m");
                int hl = utf8_cols(hint);
                used += hl < room ? hl : room;
            }
        } else {
            int room = cols - used; if (room < 0) room = 0;
            wapp_trunc(w, input->buf, room);
            int shown = input->len < room ? input->len : room;
            used += shown;
        }

        cursor_used = show_hint ? content_start : content_start + input->cursor;
    }

    if (status_right && status_right[0]) {
        int slen = utf8_cols(status_right);
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
    int used[GRID_MAXROWS];
    int rows, pane_w;
} grid_t;

static grid_t g_grid;

static void grid_reset(grid_t *g, int rows, int pane_w) {
    if (rows > GRID_MAXROWS) rows = GRID_MAXROWS;
    g->rows = rows; g->pane_w = pane_w;
    for (int r = 0; r < rows; r++) { g->len[r] = 0; g->used[r] = 0; }
}

static wbuf_t grid_row(grid_t *g, int r) { wbuf_t w = { g->buf[r], GRID_ROWBYTES, (size_t)g->len[r] }; return w; }
static void grid_commit(grid_t *g, int r, const wbuf_t *w, int used) { g->len[r] = (int)w->len; g->used[r] = used; }

static void grid_emit(wbuf_t *w, const grid_t *g, int first_screen_row, int pane_x) {
    for (int r = 0; r < g->rows; r++) {
        wapp(w, "\x1b[%d;%dH", first_screen_row + r, pane_x);
        if (g->len[r] > 0 && w->len + (size_t)g->len[r] < w->cap) {
            memcpy(w->buf + w->len, g->buf[r], (size_t)g->len[r]);
            w->len += (size_t)g->len[r];
        }
        wapp_pad(w, g->used[r], g->pane_w);
    }
}

static void grid_rule(grid_t *g, int r, const char *label) {
    if (r < 0 || r >= g->rows) return;
    wbuf_t w = grid_row(g, r);
    int used = 0;
    wapp(&w, "\x1b[2m\xe2\x94\x80 "); used += 2;
    int lab = (int)strlen(label); if (lab > g->pane_w - 4) lab = g->pane_w - 4;
    if (lab > 0) { wapp_trunc(&w, label, lab); used += lab; }
    wapp(&w, " "); used += 1;
    for (; used < g->pane_w; used++) wapp(&w, "\xe2\x94\x80");
    wapp(&w, "\x1b[0m");
    grid_commit(g, r, &w, g->pane_w);
}

static size_t wrap_chunk(const char *s, size_t len, int width) {
    if (width < 1) width = 1;
    if ((int)len <= width) return len;
    size_t n = (size_t)width;
    while (n > 0 && (((unsigned char)s[n]) & 0xc0) == 0x80) n--;
    size_t sp = n;
    while (sp > 0 && s[sp] != ' ') sp--;
    if (sp > n / 3) return sp;
    return n > 0 ? n : 1;
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
                wapp_trunc(&w, hpart, pane_w - used);
                wapp(&w, "\x1b[39m");
                if (head < len[c]) wapp_trunc(&w, piece + head, pane_w - used - (int)head);
            } else {
                wapp_trunc(&w, piece, pane_w - used);
            }
            used += (int)len[c];
            if (used > pane_w) used = pane_w;
            if (hl) { wapp_pad(&w, used, pane_w); used = pane_w; }
            if (hl || coloured || subdued) wapp(&w, "\x1b[0m");
            grid_commit(g, gr, &w, used);
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
        int hl = (int)strlen(hint); if (hl > pane_w) hl = pane_w;
        grid_commit(&g_grid, 0, &hw, hl);
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
            wapp_trunc(&w, cell, pane_w);
            if (is_sel) wapp_pad(&w, (int)strlen(cell), pane_w);
            if (is_sel) wapp(&w, "\x1b[0m");
        }
    }

    int input_row = rows;
    wapp(&w, "\x1b[%d;%dH\x1b[0K\x1b[2m", input_row, pane_x);
    wapp_trunc(&w, hint, pane_w);
    wapp(&w, "\x1b[0m\x1b[?25l");
    end_frame(&w);
}
