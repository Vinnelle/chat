// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Scrollbacks, and what every screen is drawn with: styles, boxes, the grid and the frame.
#include "tui/tui_draw.h"

#ifndef CHAT_VERSION
#define CHAT_VERSION "0.0.0"
#endif

#define G_TT      "\xe2\x94\xac"   // ┬
#define G_BT      "\xe2\x94\xb4"   // ┴

static tui_line_t *oldest_line(tui_scrollback_t *sb) {
    return &sb->lines[(sb->head - sb->count + TUI_SCROLLBACK) % TUI_SCROLLBACK];
}

static void drop_oldest(tui_scrollback_t *sb) {
    tui_line_t *l = oldest_line(sb);
    crypto_wipe(sb->text + l->off, (size_t)l->len + 1);
    crypto_wipe(l, sizeof *l);
    sb->count--;
}

// Whether the oldest line's text is in [from, to) of the ring.
static int oldest_in(tui_scrollback_t *sb, uint32_t from, uint32_t to) {
    const tui_line_t *l = oldest_line(sb);
    return sb->count > 0 && l->off < to && from < l->off + l->len + 1u;
}

// Where n bytes of text go, after the newest line's, or from the start of the ring if they don't fit
// before its end. The lines that were there are the oldest, so they go.
static uint32_t text_room(tui_scrollback_t *sb, uint32_t n) {
    uint32_t at = sb->text_head;
    if (at + n > TUI_SCROLLBACK_TEXT) {
        while (oldest_in(sb, at, TUI_SCROLLBACK_TEXT)) drop_oldest(sb);
        crypto_wipe(sb->text + at, TUI_SCROLLBACK_TEXT - at);
        at = 0;
    }
    while (oldest_in(sb, at, at + n)) drop_oldest(sb);
    sb->text_head = at + n;
    return at;
}

void tui_scrollback_push(tui_scrollback_t *sb, const char *hhmm, const char *text, const uint8_t *rgb,
                         int mention, int color_len) {
    size_t n = strlen(text);
    if (n > TUI_LINE_MAX - 1) {
        // Cut before a character, never inside one.
        n = TUI_LINE_MAX - 1;
        while (n > 0 && utf8_is_cont(text[n])) n--;
    }
    if (sb->count == TUI_SCROLLBACK) drop_oldest(sb);
    uint32_t at = text_room(sb, (uint32_t)n + 1);
    tui_line_t *l = &sb->lines[sb->head];
    memcpy(l->hhmm, hhmm, HHMM_LEN);
    memcpy(sb->text + at, text, n);
    sb->text[at + n] = '\0';
    l->off = at;
    l->len = (uint16_t)n;
    if (rgb) { memcpy(l->rgb, rgb, sizeof l->rgb); l->has_color = 1; }
    else l->has_color = 0;
    l->mention = mention;
    l->color_len = color_len;
    l->file = 0;
    l->own = 0;
    l->delivery = TUI_SENDING;
    l->mark[0] = '\0';
    l->quote = 0;
    l->rule = 0;
    l->at = now_seconds();
    sb->head = (sb->head + 1) % TUI_SCROLLBACK;
    sb->count++;
    sb->total++;
}

void tui_scrollback_clear(tui_scrollback_t *sb) {
    crypto_wipe(sb, sizeof *sb);
}

void tui_scrollback_mark_file(tui_scrollback_t *sb, int file) {
    if (sb->count > 0) sb->lines[(sb->head - 1 + TUI_SCROLLBACK) % TUI_SCROLLBACK].file = file;
}

void tui_scrollback_mark_own(tui_scrollback_t *sb, unsigned own) {
    if (sb->count > 0) sb->lines[(sb->head - 1 + TUI_SCROLLBACK) % TUI_SCROLLBACK].own = own;
}

void tui_scrollback_mark_quote(tui_scrollback_t *sb, int quote) {
    if (sb->count > 0) sb->lines[(sb->head - 1 + TUI_SCROLLBACK) % TUI_SCROLLBACK].quote = quote;
}

void tui_scrollback_mark_rule(tui_scrollback_t *sb) {
    if (sb->count > 0) sb->lines[(sb->head - 1 + TUI_SCROLLBACK) % TUI_SCROLLBACK].rule = 1;
}

int tui_scrollback_expire(tui_scrollback_t *sb, double before, int *files, int *n_files, int max) {
    int gone = 0;
    while (sb->count > 0) {
        tui_line_t *l = oldest_line(sb);
        if (l->at >= before) break;
        if (l->file && *n_files < max) files[(*n_files)++] = l->file;
        drop_oldest(sb);
        gone++;
    }
    return gone;
}

int tui_scrollback_delivery(tui_scrollback_t *sb, unsigned own, const char *missed) {
    for (int k = 0; k < sb->count; k++) {
        tui_line_t *l = &sb->lines[(sb->head - 1 - k + TUI_SCROLLBACK * 2) % TUI_SCROLLBACK];
        if (!own || l->own != own) continue;
        if (!missed) {
            if (l->delivery == TUI_SENDING) l->delivery = TUI_REACHED;
            return 1;
        }
        size_t n = strlen(l->mark);
        if (l->delivery == TUI_MISSED && strstr(l->mark, missed)) return 1;
        if (l->delivery != TUI_MISSED) snprintf(l->mark, sizeof l->mark, "not reached: %s", missed);
        else if (n + 2 + strlen(missed) < sizeof l->mark) snprintf(l->mark + n, sizeof l->mark - n, ", %s", missed);
        l->delivery = TUI_MISSED;
        return 1;
    }
    return 0;
}

// ---- drawing ----
//
// Everything is drawn in the terminal's own colours: its default foreground and background, faint
// text for secondary things, and its 16 colour palette for accents. So the UI matches the
// terminal's theme, whatever it is, and changes with it. Peers' colours are the only exception
// (see readable()).

// A picture page can fill the screen with cells of two 24-bit colours each, up to 40 bytes a cell.
#define FRAME_CAP 1048576
static char g_frame[FRAME_CAP];

// While a frame is drawn: the terminal holds it back until it's whole (mode 2026), the cursor is
// hidden, and autowrap is off.
#define SYNC_BEGIN "\x1b[?2026h"
#define SYNC_END "\x1b[?2026l"
#define CURSOR_HIDE "\x1b[?25l"
#define CURSOR_SHOW "\x1b[?25h"
#define WRAP_OFF "\x1b[?7l"
#define WRAP_ON "\x1b[?7h"
// A steady block for NORMAL, a steady bar otherwise.
#define CURSOR_BLOCK "\x1b[2 q"
#define CURSOR_BAR "\x1b[6 q"

void wapp(wbuf_t *w, const char *fmt, ...) {
    if (w->len >= w->cap) return;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(w->buf + w->len, w->cap - w->len, fmt, ap);
    va_end(ap);
    if (n > 0) w->len += (size_t)n < w->cap - w->len ? (size_t)n : w->cap - w->len;
}

// Bytes already formatted (a span, a grid row), if they fit.
static void wapp_raw(wbuf_t *w, const char *s, size_t n) {
    if (w->len + n < w->cap) { memcpy(w->buf + w->len, s, n); w->len += n; }
}

// len bytes of s as a string, cut to fit cap.
void copy_slice(char *out, size_t cap, const char *s, size_t len) {
    if (len >= cap) len = cap - 1;
    memcpy(out, s, len);
    out[len] = '\0';
}

// Appends as much of s as fits in width columns and returns the columns it takes. A malformed
// byte or a control character is written as U+FFFD. All text reaches the terminal through here,
// and nothing in it can start an escape sequence, whatever the terminal's encoding.
int wapp_trunc(wbuf_t *w, const char *s, int width) {
    static const char REPLACEMENT[] = "\xef\xbf\xbd";
    int used = 0;
    size_t n = strlen(s);
    for (size_t i = 0, adv; i < n; i += adv) {
        int cw = utf8_char_cols(s, n, i, &adv);
        if (used + cw > width) break;
        uint32_t cp = utf8_decode(s, n, i, &adv);
        int bad = is_control_cp(cp) || (adv == 1 && cp >= 0x80);
        const char *src = bad ? REPLACEMENT : s + i;
        size_t len = bad ? sizeof REPLACEMENT - 1 : adv;
        if (len > w->cap - w->len) break;
        memcpy(w->buf + w->len, src, len);
        w->len += len;
        used += cw;
    }
    return used;
}

// Like wapp_trunc, but text that's cut off ends in an ellipsis.
static int wapp_ell(wbuf_t *w, const char *s, int width) {
    if (width <= 0) return 0;
    if (utf8_str_cols(s) <= width) return wapp_trunc(w, s, width);
    int used = wapp_trunc(w, s, width - 1);
    wapp(w, G_ELLIPSIS);
    return used + 1;
}

void at(wbuf_t *w, int row, int col) { wapp(w, "\x1b[%d;%dH", row, col); }

int g_color;                  // this frame's: colours, or attributes alone (NO_COLOR)
int g_have_bg;                // the terminal has reported its background colour
static uint8_t g_bg[3];
char g_sel_bg[32];            // a shade off that background, for the selected row
const char *g_row_bg = "";    // the background of the row being drawn, kept through styles

static const char *const STYLE_COLOR[] = {
    "", "\x1b[2m", "\x1b[1m", "\x1b[35m", "\x1b[1;35m", "\x1b[32m", "\x1b[33m", "\x1b[1;33m", "\x1b[31m", "\x1b[1;31m",
};
static const char *const STYLE_MONO[] = {
    "", "\x1b[2m", "\x1b[1m", "", "\x1b[1m", "", "", "\x1b[1m", "", "\x1b[1m",
};

// Every style starts from just the row's background, so nothing carries over into the next.
void sty(wbuf_t *w, style_t s) {
    wapp(w, SGR_RESET "%s%s", g_row_bg, (g_color ? STYLE_COLOR : STYLE_MONO)[s]);
}

// The palette colour of each tone: INSERT green, NORMAL blue, COMMAND yellow, prompts and pages magenta.
static const char *const TONE_SGR[] = { "\x1b[32m", "\x1b[34m", "\x1b[33m", "\x1b[35m", "\x1b[35m" };

static const char *tone_sgr(tui_tone_t t) { return TONE_SGR[(unsigned)t < COUNT_OF(TONE_SGR) ? (unsigned)t : 0]; }

void sty_tone(wbuf_t *w, tui_tone_t t, int bold) {
    wapp(w, SGR_RESET "%s%s", g_row_bg, bold ? "\x1b[1m" : "");
    if (g_color) wapp(w, "%s", tone_sgr(t));
}

// Reversed, so the chip takes the palette colour and its text the terminal's background.
void sty_pill(wbuf_t *w, tui_tone_t t) {
    wapp(w, SGR_RESET "\x1b[1;7m");
    if (g_color) wapp(w, "%s", tone_sgr(t));
}

// A box's border: faint, or in the tone of the keys it holds.
const char *border_sgr(int tone) {
    if (!g_color) return "";
    return tone >= 0 && (unsigned)tone < COUNT_OF(TONE_SGR) ? TONE_SGR[tone] : "\x1b[2m";
}

// Relative luminance, using a gamma of 2 to approximate sRGB's curve.
static double lum(const uint8_t c[3]) {
    double r = c[0] / 255.0, g = c[1] / 255.0, b = c[2] / 255.0;
    return 0.2126 * r * r + 0.7152 * g * g + 0.0722 * b * b;
}

static double contrast(const uint8_t a[3], const uint8_t b[3]) {
    double la = lum(a) + 0.05, lb = lum(b) + 0.05;
    return la > lb ? la / lb : lb / la;
}

#define DARK_LUM 0.25
static int is_dark(const uint8_t c[3]) { return lum(c) < DARK_LUM; }

// A person's colour, moved toward the terminal's foreground until it's readable on the background:
// yellow on a light theme gets darker, indigo on a dark one gets lighter. Unchanged until the
// terminal has reported its background. Readable is WCAG's contrast for large text, reached in at
// most READABLE_STEPS steps of a fifth of the way each.
#define READABLE_CONTRAST 3.0
#define READABLE_STEPS 12

static void readable(const uint8_t in[3], uint8_t out[3]) {
    memcpy(out, in, 3);
    if (!g_have_bg) return;
    int toward = is_dark(g_bg) ? UINT8_MAX : 0;
    for (int i = 0; i < READABLE_STEPS && contrast(out, g_bg) < READABLE_CONTRAST; i++)
        for (int k = 0; k < 3; k++) out[k] = (uint8_t)(out[k] + (toward - out[k]) / 5);
}

int tui_background_light(void) { return g_have_bg && !is_dark(g_bg); }

void tui_set_background(const uint8_t rgb[3]) {
    memcpy(g_bg, rgb, 3);
    g_have_bg = 1;
    int dark = is_dark(rgb);
    uint8_t s[3];
    for (int k = 0; k < 3; k++) s[k] = (uint8_t)(dark ? rgb[k] + (UINT8_MAX - rgb[k]) / 9 : rgb[k] - rgb[k] / 16);
    snprintf(g_sel_bg, sizeof g_sel_bg, "\x1b[48;2;%u;%u;%um", s[0], s[1], s[2]);
}

// exact: used as given (a colour sample), otherwise passed through readable().
void sty_rgb(wbuf_t *w, const uint8_t rgb[3], int bold, int exact) {
    wapp(w, SGR_RESET "%s%s", g_row_bg, bold ? "\x1b[1m" : "");
    if (!g_color) return;
    uint8_t c[3];
    if (exact) memcpy(c, rgb, 3);
    else readable(rgb, c);
    wapp(w, "\x1b[38;2;%u;%u;%um", c[0], c[1], c[2]);
}

// The selected row uses a slightly different shade of the background once it's known, or reverse
// video without colour.
void row_select(int on) {
    if (!on) g_row_bg = "";
    else if (!g_color) g_row_bg = "\x1b[7m";
    else g_row_bg = g_have_bg ? g_sel_bg : "";
}

void ptext(pen_t *p, style_t s, const char *t) {
    sty(p->w, s);
    p->used += wapp_trunc(p->w, t, p->room - p->used);
}

void pell(pen_t *p, style_t s, const char *t, int width) {
    int room = p->room - p->used;
    if (width > room) width = room;
    sty(p->w, s);
    p->used += wapp_ell(p->w, t, width);
}

void prgb(pen_t *p, const uint8_t rgb[3], int bold, const char *t, int width) {
    int room = p->room - p->used;
    if (width > room) width = room;
    sty_rgb(p->w, rgb, bold, 0);
    p->used += wapp_ell(p->w, t, width);
}

void pspace(pen_t *p, int to) {
    if (to > p->room) to = p->room;
    if (p->used >= to) return;
    sty(p->w, S_PLAIN);
    while (p->used < to) { wapp(p->w, " "); p->used++; }
}

// A row inside a box: a column of padding on each side of the pen, which fills the rest.
void inner_begin(wbuf_t *w, pen_t *p, int row, int left, int width) {
    at(w, row, left);
    sty(w, S_PLAIN);
    wapp(w, width > 0 ? " " : "");
    *p = (pen_t){ w, 0, width - 2 < 0 ? 0 : width - 2 };
}

void inner_end(pen_t *p) {
    pspace(p, p->room);
    sty(p->w, S_PLAIN);
    wapp(p->w, " " SGR_RESET);
}

void blank_row(wbuf_t *w, int row, int left, int width) {
    pen_t p;
    inner_begin(w, &p, row, left, width);
    inner_end(&p);
}

// "key action · key action": each key highlighted, what it does faint. It takes as many columns as
// it has characters.
void draw_hint(pen_t *p, const char *h) {
    for (const char *s = h; *s; ) {
        const char *end = strstr(s, DOT_SEP);
        char part[96];
        copy_slice(part, sizeof part, s, end ? (size_t)(end - s) : strlen(s));
        char *sp = strchr(part, ' ');
        if (sp) *sp = '\0';
        ptext(p, S_ACCENT, part);
        if (sp) { ptext(p, S_FAINT, " "); ptext(p, S_FAINT, sp + 1); }
        if (!end) break;
        ptext(p, S_FAINT, DOT_SEP);
        s = end + sizeof DOT_SEP - 1;
    }
}

void span_init(span_t *s, int room) {
    s->w = (wbuf_t){ s->buf, sizeof s->buf, 0 };
    s->p = (pen_t){ &s->w, 0, room < 0 ? 0 : room };
}

// An edge's corners and the rule beside each, which a title never covers, and the space either
// side of a title.
#define EDGE_ENDS 4

// The space for a title in an edge width columns wide, next to one right_cols wide on its right.
int title_room(int width, int right_cols) {
    int r = width - EDGE_ENDS - TITLE_PAD - (right_cols > 0 ? right_cols + TITLE_PAD : 0);
    return r < 0 ? 0 : r;
}

// A box's top or bottom edge, or a junction across it: lc, a rule with title near its left end and
// right near its right end, then rc. bs styles the rule.
void edge(wbuf_t *w, int row, int left, int width, const char *lc, const char *rc, const char *bs,
          const span_t *title, const span_t *right) {
    if (width < EDGE_ENDS) return;
    int tc = title && title->p.used > 0 ? title->p.used + TITLE_PAD : 0;
    int rc_w = right && right->p.used > 0 ? right->p.used + TITLE_PAD : 0;
    if (EDGE_ENDS + tc + rc_w > width) rc_w = 0;
    if (EDGE_ENDS + tc > width) tc = 0;
    at(w, row, left);
    wapp(w, SGR_RESET "%s%s" G_H, bs, lc);
    if (tc) {
        wapp(w, " ");
        wapp_raw(w, title->buf, title->w.len);
        wapp(w, SGR_RESET "%s ", bs);
    }
    for (int i = 0; i < width - EDGE_ENDS - tc - rc_w; i++) wapp(w, G_H);
    if (rc_w) {
        wapp(w, " ");
        wapp_raw(w, right->buf, right->w.len);
        wapp(w, SGR_RESET "%s ", bs);
    }
    wapp(w, G_H "%s" SGR_RESET, rc);
}

void sides(wbuf_t *w, int top, int h, int left, int width, const char *bs) {
    for (int r = top; r < top + h; r++) {
        at(w, r, left);
        wapp(w, SGR_RESET "%s" G_V, bs);
        at(w, r, left + width - 1);
        wapp(w, G_V SGR_RESET);
    }
}

// The screen is one frame. A box that isn't at the left edge shares its left side with the box
// before it, so its corners there join the frame's top and bottom edges.
const char *top_left(rect_t r) { return r.left > 1 ? G_TT : G_TL; }
const char *bottom_left(rect_t r) { return r.left > 1 ? G_BT : G_BL; }

void box(wbuf_t *w, rect_t r, const char *bs, const span_t *title, const span_t *right, const span_t *foot) {
    edge(w, r.top, r.left, r.w, top_left(r), G_TR, bs, title, right);
    sides(w, r.top + 1, r.h - 2, r.left, r.w, bs);
    edge(w, r.top + r.h - 1, r.left, r.w, bottom_left(r), G_BR, bs, NULL, foot);
}

// The "◆ chat" and version in the title of every screen's left hand box.
void brand(span_t *title, span_t *right, int width) {
    span_init(right, width);
    ptext(&right->p, S_FAINT, "v" CHAT_VERSION);
    span_init(title, title_room(width, right->p.used));
    ptext(&title->p, S_ACCENT_BOLD, BRAND);
}

// The left hand box is as wide on every screen, so its edge stays put going from the chat to a page:
// a quarter of the screen, within these, or none if what's right of it would get under right_min.
#define LEFT_MIN 24
#define LEFT_MAX 32

int left_width(int cols, int right_min) {
    int w = cols / 4;
    if (w < LEFT_MIN) w = LEFT_MIN;
    if (w > LEFT_MAX) w = LEFT_MAX;
    return cols - w < right_min ? 0 : w;
}

// The last whole frame sent, by its hash.
static uint8_t g_last_frame[SHA256_LEN];
static int g_last_frame_valid;

void tui_invalidate(void) { g_last_frame_valid = 0; }

static void lock_buffers(void);

// Autowrap is off while a frame is drawn, so a character the width table thinks is narrower than
// it is gets clipped at the right edge instead of pushing the rest of the frame down a row.
void begin_frame(wbuf_t *w) {
    lock_buffers();
    wapp(w, SYNC_BEGIN CURSOR_HIDE WRAP_OFF);
}

// whole: the frame covers the screen, and isn't sent if it's the same as what's already there (the
// clock redraws every second, but only shows minutes).
void end_frame(wbuf_t *w, int whole) {
    // Written separately so a frame that filled its buffer still turns autowrap back on.
    static const char tail[] = SGR_RESET WRAP_ON SYNC_END;
    if (whole) {
        uint8_t h[SHA256_LEN];
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

void place_cursor(wbuf_t *w, int row, int col, const tui_input_t *in) {
    if (row <= 0) { wapp(w, CURSOR_HIDE); return; }
    const char *shape = in && in->modal && in->mode == TUI_IMODE_NORMAL ? CURSOR_BLOCK : CURSOR_BAR;
    wapp(w, SGR_RESET "%s\x1b[%d;%dH" CURSOR_SHOW, shape, row, col);
}

#define MIN_ROWS 6
#define MIN_COLS 30

#define MAX_COLS 1000

void clamp_size(int *rows, int *cols) {
    if (*rows < MIN_ROWS) *rows = MIN_ROWS;
    if (*cols < MIN_COLS) *cols = MIN_COLS;
    if (*rows > MAX_ROWS) *rows = MAX_ROWS;
    if (*cols > MAX_COLS) *cols = MAX_COLS;
}

// Every frame starts from the screen's size, clamped, and an empty buffer.
wbuf_t frame_init(int *rows, int *cols, int color_enabled) {
    clamp_size(rows, cols);
    g_color = color_enabled;
    g_row_bg = "";
    return (wbuf_t){ g_frame, FRAME_CAP, 0 };
}

// ---- the grid: rows drawn out of order (the chat fills from the bottom), then put on screen ----

grid_t g_grid;

// The frame and the grid hold the conversation as drawn, so they're kept out of swap like the
// scrollbacks.
static void lock_buffers(void) {
    static int locked;
    if (locked) return;
    locked = 1;
    crypto_lock(g_frame, sizeof g_frame);
    crypto_lock(&g_grid, sizeof g_grid);
}

void grid_reset(grid_t *g, int rows, int w) {
    if (rows > MAX_ROWS) rows = MAX_ROWS;
    g->rows = rows < 0 ? 0 : rows;
    g->w = w < 0 ? 0 : w;
    for (int r = 0; r < g->rows; r++) g->len[r] = g->used[r] = 0;
}

void grid_open(grid_t *g, int r, gpen_t *gp) {
    gp->wb = (wbuf_t){ g->buf[r], GRID_ROWBYTES, (size_t)g->len[r] };
    gp->p = (pen_t){ &gp->wb, g->used[r], g->w };
}

void grid_close(grid_t *g, int r, const gpen_t *gp) {
    g->len[r] = (int)gp->wb.len;
    g->used[r] = gp->p.used;
}

// Puts the grid's rows on screen from (top, left), each padded to its full width, with pad
// columns more either side.
void grid_emit(wbuf_t *w, const grid_t *g, int top, int left, int pad) {
    for (int r = 0; r < g->rows; r++) {
        at(w, top + r, left);
        wapp(w, SGR_RESET);
        for (int i = 0; i < pad; i++) wapp(w, " ");
        wapp_raw(w, g->buf[r], (size_t)g->len[r]);
        wapp(w, SGR_RESET);
        for (int i = g->used[r]; i < g->w + pad; i++) wapp(w, " ");
    }
}
