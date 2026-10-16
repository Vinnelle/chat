// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The bar (tui_bar_t): the input box, the command menu over it, the bottom row, and the dialog
// drawn over the screen.
#include "app/tui_draw.h"

// ---- the input box, the menu over it, and the bottom row ----

// The input line (or a faint placeholder while it's empty) from the pen onwards, scrolled so the
// text before the cursor fits with a column for the cursor itself. Returns the cursor's column.
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

// The suggestions for the COMMAND line, at the bottom of the box above the input box, with the
// three parts laid out as one column. 0 if there are none, or no room.
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
            pointer(&p, on);
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

#define WRAP_MAX ((int)sizeof(((tui_input_t *)0)->buf) + 2)

typedef struct { int n, start[WRAP_MAX], cur_row, cur_col; } wrap_t;

// The input text wrapped to rows width columns wide: where each row starts, and the cursor's row
// and column. A row ends after the last space that fits, with the space at the end of the row, or,
// in a word longer than a row, where the row is full. The cursor can sit in the column after a full
// row (the box's padding). Beyond that, after a trailing space at the end of the text, it starts a
// new row.
static void input_wrap(const tui_input_t *in, int width, wrap_t *wr) {
    const char *s = in->buf;
    int len = in->len, pos = 0;
    if (width < 1) width = 1;
    wr->n = 0;
    wr->start[wr->n++] = 0;
    while (pos < len && wr->n < WRAP_MAX - 1) {
        int take = (int)wrap_chunk(s + pos, (size_t)(len - pos), width);
        if (pos + take >= len) break;
        if (s[pos + take] == ' ') take++;
        pos += take;
        if (pos < len) wr->start[wr->n++] = pos;
    }
    int r = 0;
    while (r + 1 < wr->n && wr->start[r + 1] <= in->cursor) r++;
    int col;
    utf8_fit_cols(s + wr->start[r], (size_t)(in->cursor - wr->start[r]), INT_MAX, &col);
    if (col > width) {
        if (r + 1 < wr->n || wr->n >= WRAP_MAX) col = width;
        else { wr->start[wr->n++] = len; r++; col = 0; }
    }
    wr->cur_row = r;
    wr->cur_col = col;
}

// The rows of text the input box needs at box_w columns wide: the text, wrapped, up to most. The
// command line, a hidden field and an empty one (its placeholder) take one row.
int input_rows(const tui_bar_t *bar, int box_w, int most) {
    const tui_input_t *in = bar->input;
    if (most < 1) most = 1;
    if (!in || in->len == 0 || bar->mask_input || in->mode == TUI_IMODE_COMMAND) return 1;
    static wrap_t wr;
    input_wrap(in, box_w - 6, &wr);
    return wr.n < most ? wr.n : most;
}

// The text over nrows rows from row, wrapped and scrolled to the cursor's row, in a box's inner
// width columns. The first row starts with the prompt's mark, and the rest line up under it.
static void draw_wrapped(wbuf_t *w, int row, int left, int width, int nrows, const tui_input_t *in, tui_tone_t tone,
                         int *cr, int *cc) {
    static wrap_t wr;
    input_wrap(in, width - 4, &wr);
    int first = wr.cur_row - nrows + 1;
    if (first > wr.n - nrows) first = wr.n - nrows;
    if (first < 0) first = 0;
    const char *nick = in->mode == TUI_IMODE_INSERT ? mention_suggestion(in) : NULL;
    for (int i = 0; i < nrows; i++) {
        int k = first + i;
        pen_t p;
        inner_begin(w, &p, row + i, left, width);
        if (k == 0) {
            sty_tone(w, tone, 1);
            p.used += wapp_trunc(w, G_PTR " ", p.room);
        } else {
            pspace(&p, 2);
        }
        if (k < wr.n) {
            int end = k + 1 < wr.n ? wr.start[k + 1] : in->len;
            char piece[sizeof in->buf];
            copy_slice(piece, sizeof piece, in->buf + wr.start[k], (size_t)(end - wr.start[k]));
            ptext(&p, S_PLAIN, piece);
            if (nick && k == wr.cur_row) ptext(&p, S_FAINT, nick + (in->cursor - mention_start(in)));
        }
        inner_end(&p);
    }
    *cr = row + wr.cur_row - first;
    *cc = left + 3 + wr.cur_col;
}

// The input box's title without a prompt: "what · what to do", the first part yellow and the rest
// highlighted like keys, or just the first part when both don't fit.
static void draw_warn(pen_t *p, const char *warn) {
    const char *sep = strstr(warn, DOT_SEP);
    char what[256];
    copy_slice(what, sizeof what, warn, sep ? (size_t)(sep - warn) : strlen(warn));
    const char *todo = sep ? sep + sizeof DOT_SEP - 1 : NULL;
    int room = p->room - p->used;
    if (todo && utf8_str_cols(what) + utf8_str_cols(DOT_SEP) + utf8_str_cols(todo) > room) todo = NULL;
    pell(p, S_YELLOW_BOLD, what, room);
    if (todo) {
        ptext(p, S_FAINT, DOT_SEP);
        ptext(p, S_ACCENT, todo);
    }
}

// Draws the input box (or, without a box, its one row) and puts the cursor position in *cr, *cc.
// Its top edge is the bottom of the chat's box, or of the menu above it, and shows how many newer
// messages are hidden below the chat.
void draw_input(wbuf_t *w, rect_t r, int boxed, const tui_bar_t *bar, const tui_view_t *v, rect_t over,
                int *cr, int *cc) {
    const tui_input_t *in = bar->input;
    *cr = 0;
    if (!in || r.h < 1) return;
    const char *bs = border_sgr(bar->dialog ? -1 : (int)bar->tone);
    int row = r.top, left = r.left, width = r.w, nrows = 1;
    if (boxed) {
        if (in->mode == TUI_IMODE_COMMAND) draw_menu(w, r, over, in, bs);
        span_t title, more, count;
        span_init(&more, r.w);
        if (v->chat && v->title && v->scroll > 0) {
            char t[48];
            snprintf(t, sizeof t, G_DOWN " %d newer" DOT_SEP "pgdn", v->scroll);
            ptext(&more.p, S_ACCENT_BOLD, t);
        }
        span_init(&title, title_room(r.w, more.p.used));
        if (bar->warn && in->mode != TUI_IMODE_COMMAND) draw_warn(&title.p, bar->warn);
        span_init(&count, r.w);
        if (bar->limit > 0 && in->len > 0 && in->mode != TUI_IMODE_COMMAND) {
            char t[32];
            snprintf(t, sizeof t, "%d/%d", in->len, bar->limit);
            ptext(&count.p, in->len > bar->limit ? S_RED_BOLD : S_FAINT, t);
        }
        nrows = r.h - 2 > 1 ? r.h - 2 : 1;
        edge(w, r.top, r.left, r.w, G_LT, G_RT, bs, &title, &more);
        sides(w, r.top + 1, nrows, r.left, r.w, bs);
        edge(w, r.top + 1 + nrows, r.left, r.w, bottom_left(r), G_BR, bs, NULL, &count);
        row = r.top + 1;
        left = r.left + 1;
        width = r.w - 2;
        if (in->mode != TUI_IMODE_COMMAND && in->len > 0 && !bar->mask_input) {
            draw_wrapped(w, row, left, width, nrows, in, bar->tone, cr, cc);
            return;
        }
    }
    pen_t p;
    inner_begin(w, &p, row, left, width);
    sty_tone(w, bar->tone, 1);
    p.used += wapp_trunc(w, G_PTR " ", p.room);
    int cursor;
    if (in->mode == TUI_IMODE_COMMAND) {
        char pre[2] = { in->cmd_prefix ? in->cmd_prefix : ':', '\0' };
        ptext(&p, S_ACCENT_BOLD, pre);
        // A line wider than the box shows its end, where it's typed.
        const char *shown = in->cmd;
        int room = p.room - p.used - 1;
        if (utf8_str_cols(shown) > room) {
            while (*shown && utf8_str_cols(shown) > room - 1) {
                size_t adv = utf8_lead_len((unsigned char)*shown);
                shown += adv ? adv : 1;
            }
            ptext(&p, S_FAINT, G_ELLIPSIS);
        }
        ptext(&p, S_PLAIN, shown);
        cursor = p.used;
        tui_suggestion_t s;
        if (shown == in->cmd && tui_input_completion(in, &s)) ptext(&p, S_FAINT, s.line + in->cmd_len);
    } else {
        cursor = draw_field(&p, in, bar->mask_input, bar->placeholder);
    }
    inner_end(&p);
    if (cursor > p.room - 1) cursor = p.room - 1;
    *cr = row;
    *cc = left + 1 + cursor;
}

void draw_status(wbuf_t *w, int row, int cols, const tui_bar_t *bar) {
    at(w, row, 1);
    pen_t p = { w, 0, cols };
    char chip[40];
    snprintf(chip, sizeof chip, " %s ", bar->chip ? bar->chip : "");
    sty_pill(w, bar->tone);
    p.used += wapp_trunc(w, chip, cols);
    ptext(&p, S_PLAIN, " ");
    if (!bar->anonymous && bar->badge == TUI_ID_NONE) {
        ptext(&p, S_YELLOW, G_RING " unsigned");
    } else if (!bar->anonymous) {
        const char *kind = bar->badge == TUI_ID_AGE ? "age" : bar->badge == TUI_ID_PGP ? "pgp" : "native";
        ptext(&p, S_GREEN, G_CHECK " signed ");
        ptext(&p, S_FAINT, kind);
    }
    if (bar->nick && bar->nick[0] && !bar->anonymous) {
        ptext(&p, S_FAINT, "  ");
        if (bar->nick_color) prgb(&p, bar->nick_color, 1, bar->nick, p.room - p.used);
        else ptext(&p, S_BOLD, bar->nick);
    }
    if (bar->message && bar->message[0]) {
        ptext(&p, S_FAINT, "  " G_RSAQ " ");
        ptext(&p, S_BOLD, bar->message);
    }
    // As many of the hints as fit, starting from the first, since they're ordered most useful first.
    if (bar->hint && bar->hint[0]) {
        char fit[256] = "";
        for (const char *s = bar->hint; ; ) {
            const char *end = strstr(s, DOT_SEP);
            size_t upto = end ? (size_t)(end - bar->hint) : strlen(bar->hint);
            char part[256];
            if (upto >= sizeof part) break;
            memcpy(part, bar->hint, upto);
            part[upto] = '\0';
            if (p.used + 3 + utf8_str_cols(part) > cols) break;
            copy_str(fit, part, sizeof fit);
            if (!end) break;
            s = end + sizeof DOT_SEP - 1;
        }
        if (fit[0]) {
            pspace(&p, cols - utf8_str_cols(fit) - 1);
            draw_hint(&p, fit);
        }
    }
    pspace(&p, cols);
    wapp(w, SGR_RESET);
}

// ---- a dialog over the screen ----

#define DIALOG_NOTE_ROWS 6

static int dialog_rows(int text_n, int list_n, int field, int note_n) {
    return 1 + (text_n ? text_n + 1 : 0) + (list_n ? list_n + 1 : 0) + (field ? 2 : 0) + (note_n ? note_n + 1 : 0);
}

// The box's backdrop (a margin of mx by my around it), and its frame with the title on the top edge
// and the keys on the bottom, inner rows high and bw wide. Returns the rect inside its sides.
static rect_t dialog_frame(wbuf_t *w, int rows, int cols, int bw, int inner, int mx, int my, const tui_dialog_t *d) {
    int avail = rows - 1;
    int bh = inner + 2, outer_h = bh + 2 * my, outer_w = bw + 2 * mx;
    int top = 1 + (avail - outer_h) / 2, left = 1 + (cols - outer_w) / 2;
    if (top < 1) top = 1;
    for (int r = 0; r < outer_h; r++) {
        at(w, top + r, left);
        sty(w, S_PLAIN);
        for (int i = 0; i < outer_w; i++) wapp(w, " ");
    }
    rect_t bx = { top + my, left + mx, bh, bw };
    char bs[48];
    snprintf(bs, sizeof bs, "%s%s", border_sgr(TUI_TONE_PROMPT), g_row_bg);
    span_t title, keys;
    span_init(&keys, bw - 8);
    if (d->keys) draw_hint(&keys.p, d->keys);
    span_init(&title, title_room(bw, 0));
    if (d->title) ptext(&title.p, S_ACCENT_BOLD, d->title);
    edge(w, bx.top, bx.left, bw, G_TL, G_TR, bs, &title, NULL);
    sides(w, bx.top + 1, inner, bx.left, bw, bs);
    edge(w, bx.top + bh - 1, bx.left, bw, G_BL, G_BR, bs, NULL, &keys);
    return (rect_t){ bx.top + 1, bx.left + 1, inner, bw - 2 };
}

static style_t log_style(tui_log_kind_t k) {
    switch (k) {
        case TUI_LOG_INFO: return S_PLAIN;
        case TUI_LOG_GOOD: return S_GREEN;
        case TUI_LOG_BAD:  return S_RED;
        default:           return S_FAINT;
    }
}

#define CONSOLE_ROWS 12
#define CONSOLE_DIALOG_MAX_W 100
#define DIALOG_MAX_W 76

// Something in progress: its console in its own frame with the last lines that fit, then a progress
// bar as wide as the console with the percentage on its right, then the current step. The console
// loses rows on a short screen, but the rest is always shown.
static void draw_console_dialog(wbuf_t *w, int rows, int cols, const tui_dialog_t *d) {
    int avail = rows - 1;
    int bw = cols - 4 < CONSOLE_DIALOG_MAX_W ? cols - 4 : CONSOLE_DIALOG_MAX_W, my = 1;
    // A blank, the console's top edge, its rows, its bottom edge, a blank, the bar, a blank, the
    // step and a blank.
    const int fixed = 8;
    int con = CONSOLE_ROWS;
    if (con + fixed + 2 + 2 * my > avail) my = 0;
    if (con + fixed + 2 > avail) con = avail - fixed - 2;
    if (con < 1) con = 1;
    rect_t in = dialog_frame(w, rows, cols, bw, con + fixed, 2, my, d);
    int x = in.left, iw = in.w, row = in.top, end = in.top + in.h;
    int cx = x + 2, cw = iw - 4;

    blank_row(w, row++, x, iw);
    char cs[48];
    snprintf(cs, sizeof cs, "%s%s", border_sgr(-1), g_row_bg);
    for (int r = 0; r < con + 2; r++) blank_row(w, row + r, x, iw);
    edge(w, row, cx, cw, G_TL, G_TR, cs, NULL, NULL);
    sides(w, row + 1, con, cx, cw, cs);
    int first = d->n_log > con ? d->n_log - con : 0;
    for (int r = 0; r < con; r++) {
        pen_t p;
        inner_begin(w, &p, row + 1 + r, cx + 1, cw - 2);
        int i = first + r;
        if (i < d->n_log && d->log && d->log[i])
            pell(&p, log_style(d->log_kind ? (tui_log_kind_t)d->log_kind[i] : TUI_LOG_DETAIL), d->log[i], p.room);
        inner_end(&p);
    }
    edge(w, row + con + 1, cx, cw, G_BL, G_BR, cs, NULL, NULL);
    row += con + 2;
    blank_row(w, row++, x, iw);

    if (row < end) {
        pen_t p;
        inner_begin(w, &p, row++, x, iw);
        pspace(&p, 1);
        int pm = clamp_permille(d->progress ? d->progress->permille : 0);
        char right[TUI_LINE_MAX];
        if (d->progress && d->progress->text[0]) snprintf(right, sizeof right, "%3d%%  %s", pm / 10, d->progress->text);
        else snprintf(right, sizeof right, "%3d%%", pm / 10);
        int rw = (int)strlen(right);
        int barw = cw - rw - 1;
        if (barw < 8) { snprintf(right, sizeof right, "%3d%%", pm / 10); rw = (int)strlen(right); barw = cw - rw - 1; }
        if (barw < 0) barw = 0;
        draw_bar(&p, pm, barw);
        ptext(&p, S_PLAIN, " ");
        ptext(&p, S_BOLD, right);
        inner_end(&p);
    }
    if (row < end) blank_row(w, row++, x, iw);
    if (row < end) {
        pen_t p;
        inner_begin(w, &p, row++, x, iw);
        pspace(&p, 1);
        style_t st = d->step_kind == TUI_LOG_GOOD ? S_GREEN : d->step_kind == TUI_LOG_BAD ? S_RED_BOLD : S_ACCENT_BOLD;
        ptext(&p, st, G_RSAQ " ");
        if (d->step) pell(&p, st, d->step, p.room - p.used);
        inner_end(&p);
    }
    while (row < end) blank_row(w, row++, x, iw);
}

// What doesn't fit is cut from the end of the text, then from the note. The field is always shown.
static int dialog_width(int cols) {
    return cols - 4 < DIALOG_MAX_W ? cols - 4 : DIALOG_MAX_W;
}

int tui_dialog_rows(int cols, const tui_dialog_t *d) {
    int tw = dialog_width(cols) - 6;
    size_t off[DIALOG_NOTE_ROWS], len[DIALOG_NOTE_ROWS];
    int text_n = d->n_text > 0 ? layout_text(d->text, d->n_text, tw, NULL, NULL) : 0;
    int note_n = d->note && d->note[0] ? wrap_rows(d->note, tw, tw, off, len, DIALOG_NOTE_ROWS) : 0;
    return dialog_rows(text_n, d->n_items > 0 ? d->n_items : 0, d->input || d->status, note_n) + 3;
}

static void draw_dialog(wbuf_t *w, int rows, int cols, const tui_dialog_t *d, int *cr, int *cc) {
    *cr = 0;
    const char *was = g_row_bg;
    g_row_bg = g_color && g_have_bg ? g_sel_bg : "";
    if (d->console) {
        draw_console_dialog(w, rows, cols, d);
        g_row_bg = was;
        return;
    }
    int avail = rows - 1;
    int bw = dialog_width(cols), mx = 2, my = 1;
    int iw = bw - 2, tw = iw - 4;
    int text_n = d->n_text > 0 ? layout_text(d->text, d->n_text, tw, NULL, NULL) : 0;
    static size_t noff[DIALOG_NOTE_ROWS], nlen[DIALOG_NOTE_ROWS];
    int note_n = d->note && d->note[0] ? wrap_rows(d->note, tw, tw, noff, nlen, DIALOG_NOTE_ROWS) : 0;
    int field = d->input || d->status;
    int list_n = d->n_items > 0 ? d->n_items : 0;
    if (dialog_rows(text_n, list_n, field, note_n) + 2 + 2 * my > avail) my = 0;
    while (dialog_rows(text_n, list_n, field, note_n) + 2 > avail && (text_n > 0 || note_n > 0 || list_n > 1)) {
        if (text_n > 0) text_n--;
        else if (note_n > 0) note_n--;
        else list_n--;
    }
    int inner = dialog_rows(text_n, list_n, field, note_n);
    if (inner > avail - 2) inner = avail - 2 > 1 ? avail - 2 : 1;
    rect_t in = dialog_frame(w, rows, cols, bw, inner, mx, my, d);

    int row = in.top, end = row + inner, x = in.left;
    blank_row(w, row++, x, iw);
    if (text_n > 0) {
        text_draw_t td = { w, row, x, iw, tw, 0, text_n < end - row ? text_n : end - row };
        layout_text(d->text, d->n_text, tw, draw_text_row, &td);
        row += td.h;
        if (row < end) blank_row(w, row++, x, iw);
    }
    if (list_n > 0) {
        int first = d->sel >= list_n ? d->sel - list_n + 1 : 0;
        for (int r = 0; r < list_n && row < end; r++, row++) {
            int i = first + r, on = i == d->sel;
            pen_t p;
            inner_begin(w, &p, row, x, iw);
            pspace(&p, 1);
            pointer(&p, on);
            const char *detail = d->details && d->details[i] ? d->details[i] : "";
            int dw = utf8_str_cols(detail), nw = utf8_str_cols(d->items[i]);
            // The detail is left out unless the whole name fits beside it.
            if (nw + 3 + dw > p.room - p.used) dw = 0;
            pell(&p, on ? S_ACCENT_BOLD : S_BOLD, d->items[i], p.room - p.used - (dw ? dw + 3 : 1));
            if (dw) {
                pspace(&p, p.room - dw - 1);
                ptext(&p, S_FAINT, detail);
            }
            inner_end(&p);
        }
        if (row < end) blank_row(w, row++, x, iw);
    }
    if (field && row < end) {
        pen_t p;
        inner_begin(w, &p, row, x, iw);
        pspace(&p, 1);
        if (d->input) {
            ptext(&p, S_ACCENT_BOLD, G_RSAQ " ");
            p.room--;
            int c = draw_field(&p, d->input, d->mask, d->placeholder);
            p.room++;
            *cr = row;
            *cc = x + 1 + c;
        } else {
            pell(&p, S_FAINT, d->status, p.room - p.used - 1);
        }
        inner_end(&p);
        row++;
        if (row < end) blank_row(w, row++, x, iw);
    }
    for (int i = 0; i < note_n && row < end; i++, row++) {
        char piece[TUI_LINE_MAX];
        copy_slice(piece, sizeof piece, d->note + noff[i], nlen[i]);
        pen_t p;
        inner_begin(w, &p, row, x, iw);
        pspace(&p, 1);
        ptext(&p, S_FAINT, piece);
        inner_end(&p);
    }
    while (row < end) blank_row(w, row++, x, iw);
    g_row_bg = was;
}

// cr 0 hides the cursor, unless a dialog's field takes it.
void finish_frame(wbuf_t *w, int rows, int cols, const tui_bar_t *bar, int cr, int cc) {
    const tui_input_t *in = bar->input;
    if (bar->dialog) {
        draw_dialog(w, rows, cols, bar->dialog, &cr, &cc);
        in = bar->dialog->input;
    }
    draw_status(w, rows, cols, bar);
    place_cursor(w, cr, cc, in);
    end_frame(w, 1);
}
