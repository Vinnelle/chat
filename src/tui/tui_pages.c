// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The pages: lists (settings, help), a page of text, a picture, and the empty screen under a dialog.
#include "tui/tui_draw.h"

#define G_LSAQ    "\xe2\x80\xb9"   // ‹

#define G_BLOCK   "\xe2\x96\x88"   // █

#define G_WBULLET "\xe2\x97\xa6"   // ◦

// ---- list pages ----

// The first of n entries to show in shown rows: the one that puts sel in the middle, when they
// don't all fit.
static int centred_first(int n, int shown, int sel) {
    if (n <= shown || sel < 0) return 0;
    int first = sel - shown / 2;
    if (first > n - shown) first = n - shown;
    return first < 0 ? 0 : first;
}

static void draw_nav(wbuf_t *w, rect_t r, const char *const *nav, int n_nav, int nav_sel) {
    span_t title, right;
    brand(&title, &right, r.w);
    box(w, r, border_sgr(-1), &title, &right, NULL);
    int top = centred_first(n_nav, r.h - 3, nav_sel);
    for (int i = 0; i < r.h - 2; i++) {
        int k = i == 0 ? -1 : i - 1 + top;   // a blank row above the first
        int on = k >= 0 && k < n_nav && k == nav_sel;
        row_select(on);
        pen_t p;
        inner_begin(w, &p, r.top + 1 + i, r.left + 1, r.w - 2);
        if (k >= 0 && k < n_nav) {
            pointer(&p, on);
            pell(&p, on ? S_ACCENT_BOLD : S_FAINT, nav[k], p.room - p.used);
        }
        inner_end(&p);
        row_select(0);
    }
}

// "a › b › c": the path to this page faint, and the page itself bold.
static void crumb_title(span_t *t, const char *title) {
    static const char SEP[] = " " G_RSAQ " ";
    for (const char *s = title; ; ) {
        const char *next = strstr(s, SEP);
        char part[1024];
        copy_slice(part, sizeof part, s, next ? (size_t)(next - s) : strlen(s));
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
    if (r->disabled) { pell(p, S_FAINT, r->value, room); return; }
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
        case TUI_V_PROGRESS: {
            int bw = room >= 30 ? 10 : room >= 18 ? 6 : 0;
            if (bw) {
                draw_bar(p, r->permille, bw);
                ptext(p, S_PLAIN, " ");
            }
            pell(p, S_PLAIN, r->value, p->room - p->used);
            break;
        }
        case TUI_V_BAD:
            ptext(p, S_RED, G_CROSS " ");
            pell(p, S_PLAIN, r->value, room - 2);
            break;
        default:
            pell(p, S_PLAIN, r->value, room);
            break;
    }
}

enum { PL_BLANK, PL_HEADING, PL_ROW, PL_BUTTON };
#define PAGE_LINES 2048

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

// The rows, by section, then the button, in nrows rows from top, scrolled so the selected row is
// visible with its heading and as much of the rest of its section as fits. The help is drawn over
// the rest, so its length doesn't move anything.
static void draw_list(wbuf_t *w, int top, int left, int iw, int view, int nrows, const tui_page_t *pg) {
    static int kind[PAGE_LINES], arg[PAGE_LINES];
    int n = 0, sel_line = -1, head_line = -1, end_line = -1, head = -1;
    for (int i = 0; i < pg->n_rows && n < PAGE_LINES - 5; i++) {
        if (pg->rows[i].section) {
            if (sel_line >= 0 && end_line < 0) end_line = n - 1;
            if (i > 0) { kind[n] = PL_BLANK; n++; }
            head = n;
            kind[n] = PL_HEADING; arg[n] = i; n++;
        }
        // Rows before the first heading (or on a page without any) count as under one at the top.
        if (i == pg->selected) { sel_line = n; head_line = head >= 0 ? head : 0; }
        kind[n] = PL_ROW; arg[n] = i; n++;
    }
    if (end_line < 0) end_line = n - 1;
    if (pg->button) {
        kind[n] = PL_BLANK; n++;
        if (pg->selected >= pg->n_rows) sel_line = head_line = end_line = n;
        kind[n] = PL_BUTTON; n++;
    }
    int scroll = 0;
    if (sel_line >= 0) {
        scroll = end_line - view + 1;
        if (scroll < sel_line - view + 1) scroll = sel_line - view + 1;
        if (scroll > head_line) scroll = head_line > sel_line - view + 1 ? head_line : sel_line - view + 1;
    }
    if (scroll < 0) scroll = 0;

    int cw = iw - 2, lw = 0, any_value = 0;
    for (int i = 0; i < pg->n_rows; i++) {
        int c = utf8_str_cols(pg->rows[i].label) + (pg->rows[i].prefix ? utf8_str_cols(pg->rows[i].prefix) : 0);
        if (c > lw) lw = c;
        if (pg->rows[i].value) any_value = 1;
    }
    lw += 3;
    if (!any_value || lw > (cw - 2) / 2) lw = any_value ? (cw - 2) / 2 : cw - 2;
    for (int r = 0; r < nrows; r++) {
        int li = scroll + r, row = top + r;
        if (li >= n || kind[li] == PL_BLANK) { blank_row(w, row, left, iw); continue; }
        if (kind[li] == PL_BUTTON) { draw_button(w, row, left, iw, pg); continue; }
        const tui_row_t *pr = &pg->rows[arg[li]];
        pen_t p;
        if (kind[li] == PL_HEADING) {
            inner_begin(w, &p, row, left, iw);
            ptext(&p, S_ACCENT_BOLD, pr->section);
            inner_end(&p);
            continue;
        }
        int on = arg[li] == pg->selected;
        row_select(on);
        inner_begin(w, &p, row, left, iw);
        pointer(&p, on);
        int pc = 0;
        if (pr->prefix) {
            pc = utf8_str_cols(pr->prefix);
            ptext(&p, S_FAINT, pr->prefix);
        }
        pell(&p, pr->disabled ? S_FAINT : on ? S_ACCENT_BOLD : pg->keys ? S_ACCENT : S_PLAIN, pr->label,
             (pr->value ? lw - 2 : lw) - pc);
        if (pr->value) {
            pspace(&p, 2 + lw);
            draw_value(&p, pr, on);
        }
        inner_end(&p);
        row_select(0);
    }
}

// The side column takes a third of the rows' width, within these, if the rows keep ROWS_COLS_MIN.
#define SIDE_MIN 20
#define SIDE_MAX 36
#define ROWS_COLS_MIN 60
// The nav is the left hand box, as wide as the chat's sidebar, if the page keeps PAGE_COLS_MIN.
#define PAGE_COLS_MIN 56

// The side column's width for rows iw columns wide, its rule included, or 0 if it doesn't fit.
static int side_width(int iw) {
    int w = iw / 3;
    if (w < SIDE_MIN) w = SIDE_MIN;
    if (w > SIDE_MAX) w = SIDE_MAX;
    return iw - w >= ROWS_COLS_MIN ? w : 0;
}

static int nav_width(int cols) { return left_width(cols, PAGE_COLS_MIN); }

// The page's width inside its border, as tui_render_page works it out.
static int page_inner_width(int cols, int with_nav) {
    int navw = with_nav ? nav_width(cols) : 0;
    return cols - (navw > 0 ? navw : 1) - 1;
}

int tui_page_row_cols(int cols, int with_nav) { return page_inner_width(cols, with_nav) - 4; }

int tui_side_width(int cols, int with_nav) { return side_width(page_inner_width(cols, with_nav)); }

int tui_nav_text_cols(int cols) {
    int navw = cols - page_inner_width(cols, 1) - 1;
    return navw > 6 ? navw - 6 : 0;
}

// The side column: its title, a blank row, then its entries, scrolled so the selected one is in
// the middle when they don't all fit, with a rule on its right.
static void draw_side(wbuf_t *w, int top, int left, int width, int nrows, const tui_page_t *pg) {
    int first = centred_first(pg->n_side, nrows - 2, pg->side_sel);
    for (int i = 0; i < nrows; i++) {
        int k = i < 2 ? -1 : first + i - 2;
        int on = k >= 0 && k < pg->n_side && k == pg->side_sel;
        pen_t p;
        inner_begin(w, &p, top + i, left, width - 1);
        if (i == 0 && pg->side_title) {
            pell(&p, S_FAINT, pg->side_title, p.room);
        } else if (k >= 0 && k < pg->n_side) {
            pointer(&p, on);
            pell(&p, on ? S_ACCENT_BOLD : S_FAINT, pg->side[k], p.room - p.used);
        }
        pspace(&p, p.room);
        sty(w, S_PLAIN);
        wapp(w, " ");
        sty(w, S_FAINT);
        wapp(w, G_V SGR_RESET);
    }
}

// The most sections the nav takes from a page's rows, and the most rows of help and of intro.
#define ROW_SECTIONS_MAX 32
#define HELP_ROWS 5
#define INTRO_ROWS 3

void tui_render_page(int rows, int cols, const tui_page_t *page, const tui_bar_t *bar, int color_enabled) {
    wbuf_t w = frame_init(&rows, &cols, color_enabled);
    g_input_h = 0;

    // The sections on the left: as given, or taken from the rows, with the selected row's highlighted.
    static const char *nav[1024];
    int n_nav = 0, nav_sel = -1;
    if (page->nav) {
        for (int i = 0; i < page->n_nav && i < (int)COUNT_OF(nav); i++) nav[n_nav++] = page->nav[i];
        nav_sel = page->nav_sel;
    } else {
        for (int i = 0; i < page->n_rows && n_nav < ROW_SECTIONS_MAX; i++) {
            if (page->rows[i].section) nav[n_nav++] = page->rows[i].section;
            if (i == page->selected) nav_sel = n_nav - 1;
        }
    }
    int boxed = rows >= BOXED_ROWS && cols >= BOXED_COLS;
    int navw = boxed && n_nav > 0 ? nav_width(cols) : 0;

    begin_frame(&w);
    if (navw) draw_nav(&w, (rect_t){ 1, 1, rows - 1, navw }, nav, n_nav, nav_sel);

    // Shares the nav's right side, like the chat shares the sidebar's.
    int x = navw > 0 ? navw : 1;
    rect_t r = { 1, x, rows - 1, cols - x + 1 };
    int top = boxed ? r.top + 1 : r.top, ih = boxed ? r.h - 2 : r.h;
    int left = boxed ? r.left + 1 : r.left, iw = boxed ? r.w - 2 : r.w;
    int cw = iw - 2;

    // Over the bottom of the rows, below an edge titled with the selected row: its help and usage.
    // The rows scroll as if those were at their longest, so the rows don't move when they change.
    // Above the rows, the intro. Rows take priority when there's no room for all of it.
    static size_t hoff[HELP_ROWS], hlen[HELP_ROWS], ioff[INTRO_ROWS], ilen[INTRO_ROWS];
    int hl = boxed && page->help && page->help[0] ? wrap_rows(page->help, cw, cw, hoff, hlen, HELP_ROWS) : 0;
    int ul = boxed && page->usage && page->usage[0] ? 1 : 0;
    int il = boxed && page->intro && page->intro[0] ? wrap_rows(page->intro, cw, cw, ioff, ilen, INTRO_ROWS) : 0;
    int btn = page->button ? 2 : 0;
    int hmax = boxed ? HELP_ROWS : 0, umax = boxed;
    int list, view;
    for (;;) {
        list = ih - (il ? il + 1 : 0);
        view = list - (hmax + umax ? hmax + umax + 1 : 0);
        if (view >= 4 + btn || (!il && !(hmax + umax))) break;
        if (il) il = 0;
        else if (hmax > 2) hmax = 2;
        else hmax = umax = 0;
    }
    if (hl > hmax) hl = hmax;
    if (!umax) ul = 0;
    if (view < 1) view = 1;

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
        copy_slice(piece, sizeof piece, page->intro + ioff[i], ilen[i]);
        pen_t p;
        inner_begin(&w, &p, row, left, iw);
        ptext(&p, S_FAINT, piece);
        inner_end(&p);
    }
    if (il && row < end) blank_row(&w, row++, left, iw);
    if (list > end - row) list = end - row;
    int shown = list - (hl + ul ? hl + ul + 1 : 0);
    if (shown < 0) shown = 0;
    int sidew = page->side ? side_width(iw) : 0;
    if (sidew) draw_side(&w, row, left, sidew, shown, page);
    draw_list(&w, row, left + sidew, iw - sidew, view, shown, page);
    row += shown;
    if (hl + ul && row < end) {
        span_t about;
        span_init(&about, title_room(r.w, 0));
        const char *what = page->selected < page->n_rows ? page->rows[page->selected].label : page->button;
        if (what) ptext(&about.p, S_FAINT, what);
        edge(&w, row++, r.left, r.w, G_LT, G_RT, border_sgr(TUI_TONE_PAGE), &about, NULL);
        for (int i = 0; i < hl && row < end; i++, row++) {
            char piece[TUI_LINE_MAX];
            copy_slice(piece, sizeof piece, page->help + hoff[i], hlen[i]);
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

    finish_frame(&w, rows, cols, bar, 0, 0);
}

// ---- a page of text ----

// Inline Markdown, as plain text and a style for each byte of it.
enum { A_BOLD = 1, A_ITALIC = 2, A_CODE = 4, A_LINK = 8, A_FAINT = 16 };

static int md_flank_open(const char *s, size_t i, size_t n) { return i + 1 < n && s[i + 1] != ' '; }

// The closing mark for the one at s[i] (len bytes of ch), on the same paragraph, or 0.
static size_t md_close(const char *s, size_t i, size_t n, char ch, size_t len) {
    for (size_t k = i + len + 1; k + len <= n; k++) {
        if (s[k] == '\\') { k++; continue; }
        if (s[k] == '`') { while (++k < n && s[k] != '`') {} continue; }
        if (s[k] != ch || (len == 2 && s[k + 1] != ch)) continue;
        if (s[k - 1] == ' ') continue;
        // _ only closes at the end of a word: snake_case stays as it is.
        if (ch == '_' && k + len < n && (isalnum((unsigned char)s[k + len]))) continue;
        return k;
    }
    return 0;
}

static size_t md_inline(const char *s, char *out, uint8_t *attr, size_t cap) {
    size_t n = strlen(s), o = 0;
    uint8_t cur = 0;
#define PUT(c, a) do { if (o + 1 < cap) { out[o] = (c); attr[o] = (a); o++; } } while (0)
    for (size_t i = 0; i < n; i++) {
        char ch = s[i];
        if (ch == '\\' && i + 1 < n && strchr("\\`*_[]()#-.!>", s[i + 1])) { PUT(s[++i], cur); continue; }
        if (ch == '`') {
            size_t e = i + 1;
            while (e < n && s[e] != '`') e++;
            if (e < n) { for (size_t k = i + 1; k < e; k++) PUT(s[k], (uint8_t)(cur | A_CODE)); i = e; continue; }
        }
        if (ch == '*' && i + 1 < n && s[i + 1] == '*' && ((cur & A_BOLD)
                ? (i > 0 && s[i - 1] != ' ')
                : (md_flank_open(s, i + 1, n) && md_close(s, i, n, '*', 2)))) {
            cur ^= A_BOLD;
            i++;
            continue;
        }
        if ((ch == '*' || ch == '_') && ((cur & A_ITALIC)
                ? (i > 0 && s[i - 1] != ' ')
                : (md_flank_open(s, i, n) && (ch == '*' || i == 0 || !isalnum((unsigned char)s[i - 1])) && md_close(s, i, n, ch, 1)))) {
            cur ^= A_ITALIC;
            continue;
        }
        if (ch == '[') {
            const char *close = strchr(s + i + 1, ']');
            if (close && close[1] == '(' && strchr(close + 2, ')')) {
                const char *url = close + 2, *ue = strchr(url, ')');
                for (const char *k = s + i + 1; k < close; k++) PUT(*k, (uint8_t)(cur | A_LINK));
                // The address too, faint, since there's nothing to click.
                PUT(' ', cur); PUT('(', (uint8_t)(cur | A_FAINT));
                for (const char *k = url; k < ue; k++) PUT(*k, (uint8_t)(cur | A_FAINT));
                PUT(')', (uint8_t)(cur | A_FAINT));
                i = (size_t)(ue - s);
                continue;
            }
        }
        PUT(ch, cur);
    }
#undef PUT
    out[o] = '\0';
    return o;
}

// A list item's depth, as far as it's drawn.
#define LIST_DEPTH_MAX 6
static int para_level(const tui_para_t *pa) { return pa->level > LIST_DEPTH_MAX ? LIST_DEPTH_MAX : pa->level; }

// Columns before a paragraph's text: its list depth, and the bullet, number or bar.
static int para_hang(const tui_para_t *pa) {
    int lvl = para_level(pa);
    switch (pa->kind) {
        case TUI_P_BULLET:   return 2 + 2 * lvl;
        case TUI_P_NUMBERED: return (int)strlen(pa->marker) + 1 + 2 * lvl;
        case TUI_P_QUOTE:    return 2;
        case TUI_P_CODE:
        case TUI_P_ART:      return 2;
        default:             return 0;
    }
}

#define PARA_MAX 8192

int layout_text(const tui_para_t *paras, int n, int w, text_row_fn row, void *ctx) {
    static char plain[PARA_MAX];
    static uint8_t attr[PARA_MAX];
    int v = 0;
    for (int i = 0; i < n; i++) {
        const tui_para_t *pa = &paras[i];
        if (pa->kind == TUI_P_BLANK || pa->kind == TUI_P_RULE || !pa->text) {
            if (row) row(ctx, v, pa, "", attr, 0, 0, 1);
            v++;
            continue;
        }
        int hang = para_hang(pa);
        if (pa->kind == TUI_P_CODE || pa->kind == TUI_P_ART) {
            // Code keeps its spaces and lines: one row each, cut off at the edge.
            size_t len = strlen(pa->text);
            if (len > sizeof plain - 1) len = sizeof plain - 1;
            copy_slice(plain, sizeof plain, pa->text, len);
            memset(attr, pa->kind == TUI_P_CODE ? A_CODE : 0, len);
            if (row) row(ctx, v, pa, plain, attr, 0, len, 1);
            v++;
            continue;
        }
        md_inline(pa->text, plain, attr, sizeof plain);
        static size_t off[256], len[256];
        int k = wrap_rows(plain, w - hang, w - hang, off, len, (int)COUNT_OF(off));
        for (int j = 0; j < k; j++, v++)
            if (row) row(ctx, v, pa, plain, attr, off[j], len[j], j == 0);
    }
    return v;
}

// One run of text with the same marks, in the paragraph's own style underneath.
static void draw_run(pen_t *p, style_t base, uint8_t a, const char *t, size_t n) {
    char piece[TUI_LINE_MAX * 4];
    copy_slice(piece, sizeof piece, t, n);
    sty(p->w, (a & A_CODE) || (a & A_LINK) ? S_ACCENT : (a & A_FAINT) ? S_FAINT : base);
    if (a & A_BOLD) wapp(p->w, "\x1b[1m");
    if (a & A_ITALIC) wapp(p->w, "\x1b[3m");
    if (a & A_LINK) wapp(p->w, "\x1b[4m");
    p->used += wapp_trunc(p->w, piece, p->room - p->used);
}

void draw_text_row(void *ctx, int v, const tui_para_t *pa, const char *plain, const uint8_t *attr,
                   size_t off, size_t len, int first) {
    text_draw_t *d = ctx;
    if (v < d->first || v >= d->first + d->h) return;
    pen_t p;
    inner_begin(d->w, &p, d->top + (v - d->first), d->left, d->iw);
    pspace(&p, 1);
    if (pa->kind == TUI_P_RULE) {
        sty(p.w, S_FAINT);
        for (int x = 0; x < d->tw && p.used < p.room; x++) { wapp(p.w, G_H); p.used++; }
        inner_end(&p);
        return;
    }
    int lvl = para_level(pa);
    int hang = para_hang(pa);
    // A list item's first row starts with its bullet or number, and the rows after it are indented under its text.
    if (first && pa->kind == TUI_P_BULLET) {
        pspace(&p, 1 + 2 * lvl);
        ptext(&p, S_ACCENT, lvl % 2 ? G_WBULLET " " : G_BULLET " ");
    } else if (first && pa->kind == TUI_P_NUMBERED) {
        pspace(&p, 1 + 2 * lvl);
        ptext(&p, S_ACCENT, pa->marker);
        pspace(&p, 1 + hang);
    } else if (pa->kind == TUI_P_QUOTE) {
        ptext(&p, S_FAINT, G_V " ");
    } else {
        pspace(&p, 1 + hang);
    }
    style_t base = pa->kind == TUI_P_HEADING ? S_ACCENT_BOLD : pa->kind == TUI_P_SUBHEADING ? S_BOLD
                 : pa->kind == TUI_P_QUOTE ? S_FAINT : S_PLAIN;
    for (size_t i = off; i < off + len; ) {
        size_t e = i;
        while (e < off + len && attr[e] == attr[i]) e++;
        draw_run(&p, base, attr[i], plain + i, e - i);
        i = e;
    }
    inner_end(&p);
}

int tui_render_text(int rows, int cols, const char *title, const char *clock, const tui_para_t *paras, int n,
                    int *scroll, const tui_bar_t *bar, int color_enabled) {
    // Always in a box: the smallest screen it's drawn on has room for one.
    wbuf_t w = frame_init(&rows, &cols, color_enabled);
    g_input_h = 0;
    rect_t r = { 1, 1, rows - 1, cols };
    int top = r.top + 1, ih = r.h - 2, left = r.left + 1, iw = r.w - 2;
    int tw = iw - 3;   // minus the box's padding on each side and the margin before the text
    if (tw < 8) tw = 8;
    int total = layout_text(paras, n, tw, NULL, NULL);
    int most = total > ih ? total - ih : 0;
    if (*scroll > most) *scroll = most;
    if (*scroll < 0) *scroll = 0;

    begin_frame(&w);
    span_t t, right;
    span_init(&right, r.w);
    char where[48];
    snprintf(where, sizeof where, "%d%%", most ? *scroll * 100 / most : 100);
    ptext(&right.p, S_FAINT, where);
    if (clock) { ptext(&right.p, S_FAINT, "  "); ptext(&right.p, S_FAINT, clock); }
    span_init(&t, title_room(r.w, right.p.used));
    crumb_title(&t, title ? title : "");
    box(&w, r, border_sgr(TUI_TONE_PAGE), &t, &right, NULL);
    text_draw_t d = { &w, top, left, iw, tw, *scroll, ih };
    layout_text(paras, n, tw, draw_text_row, &d);
    for (int v = total - *scroll; v < ih; v++) blank_row(&w, top + v, left, iw);
    finish_frame(&w, rows, cols, bar, 0, 0);
    return most;
}

// ---- a picture ----

// Inside the border: a column of padding either side, and a blank row and the caption under the picture.
void tui_picture_room(int rows, int cols, int *w, int *h) {
    clamp_size(&rows, &cols);
    int pw = cols - 4, pr = rows - 5;
    *w = pw < 1 ? 1 : pw < TUI_PICTURE_MAX_W ? pw : TUI_PICTURE_MAX_W;
    *h = pr < 1 ? 2 : pr * 2 < TUI_PICTURE_MAX_H ? pr * 2 : TUI_PICTURE_MAX_H;
}

static void center_text(pen_t *p, style_t st, const char *mark, style_t mark_st, const char *t) {
    int c = utf8_str_cols(t) + (mark ? utf8_str_cols(mark) + 1 : 0);
    pspace(p, c < p->room ? (p->room - c) / 2 : 0);
    if (mark) { ptext(p, mark_st, mark); ptext(p, S_PLAIN, " "); }
    pell(p, st, t, p->room - p->used);
}

static void center_bar(pen_t *p, int permille) {
    int pm = clamp_permille(permille);
    char pct[8];
    snprintf(pct, sizeof pct, " %d%%", pm / 10);
    int bw = p->room - 8 < 40 ? p->room - 8 : 40;
    if (bw < 4) bw = 0;
    pspace(p, (p->room - bw - (int)strlen(pct)) / 2);
    draw_bar(p, pm, bw);
    ptext(p, S_BOLD, pct);
}

void tui_render_picture(int rows, int cols, const tui_picture_t *pic, const tui_bar_t *bar, int color_enabled) {
    wbuf_t w = frame_init(&rows, &cols, color_enabled);
    g_input_h = 0;
    begin_frame(&w);

    rect_t r = { 1, 1, rows - 1, cols };
    span_t title, right;
    span_init(&right, r.w);
    if (pic->clock) ptext(&right.p, S_FAINT, pic->clock);
    span_init(&title, title_room(r.w, right.p.used));
    crumb_title(&title, pic->title ? pic->title : "");
    box(&w, r, border_sgr(TUI_TONE_PAGE), &title, &right, NULL);

    int top = r.top + 1, ih = r.h - 2, left = r.left + 1, iw = r.w - 2;
    int caption = ih > 2, area = caption ? ih - 2 : ih;
    const tui_image_t *im = pic->image && pic->image->rgb && pic->image->w > 0 && pic->image->h > 0 ? pic->image : NULL;
    const char *lines[8];
    size_t lens[8];
    int nl = im ? 0 : split_lines(pic->note, lines, lens, (int)COUNT_OF(lines));
    const tui_progress_t *pg = im ? NULL : pic->progress;
    int pg_rows = pg ? (pg->kind == TUI_PROGRESS_BAR ? 2 : 1) : 0;
    int block = im ? (im->h + 1) / 2 : nl + (nl && pg ? 1 : 0) + pg_rows;
    if (block > area) block = area;
    int first = (area - block) / 2;

    for (int i = 0; i < ih; i++) {
        pen_t p;
        inner_begin(&w, &p, top + i, left, iw);
        int k = i - first;
        if (caption && i == ih - 1) {
            if (pic->caption) center_text(&p, S_FAINT, NULL, S_PLAIN, pic->caption);
        } else if (i < area && k >= 0 && k < block) {
            int under = k - nl - (nl && pg ? 1 : 0);
            if (im) {
                pspace(&p, im->w < p.room ? (p.room - im->w) / 2 : 0);
                draw_image_row(&p, im, im->w, k);
            } else if (k < nl) {
                char t[TUI_LINE_MAX];
                copy_slice(t, sizeof t, lines[k], lens[k]);
                center_text(&p, k == 0 ? S_BOLD : S_FAINT, NULL, S_PLAIN, t);
            } else if (pg && under == 0 && pg->kind == TUI_PROGRESS_BAR) {
                center_bar(&p, pg->permille);
            } else if (pg && under == pg_rows - 1) {
                const char *mark = pg->kind == TUI_PROGRESS_DONE ? G_CHECK : pg->kind == TUI_PROGRESS_FAILED ? G_CROSS : NULL;
                center_text(&p, S_FAINT, mark, pg->kind == TUI_PROGRESS_DONE ? S_GREEN : S_RED, pg->text);
            }
        }
        inner_end(&p);
    }
    finish_frame(&w, rows, cols, bar, 0, 0);
}

void tui_render_blank(int rows, int cols, const tui_bar_t *bar, int color_enabled) {
    wbuf_t w = frame_init(&rows, &cols, color_enabled);
    g_input_h = 0;
    begin_frame(&w);
    for (int r = 1; r < rows; r++) blank_row(&w, r, 1, cols);
    finish_frame(&w, rows, cols, bar, 0, 0);
}
