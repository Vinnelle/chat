// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What the TUI's files share: tui.c (styles, the grid, the frame), tui_input.c, tui_chat.c,
// tui_bar.c and tui_pages.c. The app uses tui.h.
#ifndef CHAT_TUI_DRAW_H
#define CHAT_TUI_DRAW_H

#include "tui/tui.h"
#include "crypto/crypto.h"
#include "platform/platform.h"
#include "common/util.h"
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>

#define G_H       "\xe2\x94\x80"   // ─

#define G_V       "\xe2\x94\x82"   // │
#define G_TL      "\xe2\x95\xad"   // ╭
#define G_TR      "\xe2\x95\xae"   // ╮
#define G_BL      "\xe2\x95\xb0"   // ╰
#define G_BR      "\xe2\x95\xaf"   // ╯
#define G_LT      "\xe2\x94\x9c"   // ├
#define G_RT      "\xe2\x94\xa4"   // ┤

#define G_DOT     "\xe2\x97\x8f"   // ●
#define G_RING    "\xe2\x97\x8b"   // ○

#define G_PTR     "\xe2\x9d\xaf"   // ❯
#define G_CHECK   "\xe2\x9c\x93"   // ✓
#define G_CROSS   "\xe2\x9c\x97"   // ✗
#define G_DIAMOND "\xe2\x97\x86"   // ◆
#define G_ELLIPSIS "\xe2\x80\xa6"  // …

#define G_RSAQ    "\xe2\x80\xba"   // ›

#define G_DOWN    "\xe2\x86\x93"   // ↓

#define G_BULLET  "\xe2\x80\xa2"   // •

#define SGR_RESET "\x1b[0m"

typedef struct { char *buf; size_t cap; size_t len; } wbuf_t;

typedef enum {
    S_PLAIN = 0, S_FAINT, S_BOLD, S_ACCENT, S_ACCENT_BOLD, S_GREEN, S_YELLOW, S_YELLOW_BOLD, S_RED, S_RED_BOLD
} style_t;

// Writes styled text into a row from the left, at most room columns.
typedef struct { wbuf_t *w; int used, room; } pen_t;

// Styled text built before its position is known: a box's titles.
typedef struct { char buf[1024]; wbuf_t w; pen_t p; } span_t;

#define TITLE_PAD 2

typedef struct { int top, left, h, w; } rect_t;

#define BRAND G_DIAMOND " chat"

#define MAX_ROWS 200

// A screen smaller than this is drawn without boxes.
#define BOXED_ROWS 10
#define BOXED_COLS 40

#define GRID_ROWBYTES 3072

typedef struct {
    char buf[MAX_ROWS][GRID_ROWBYTES];
    int len[MAX_ROWS], used[MAX_ROWS];
    int rows, w;
} grid_t;

typedef struct { wbuf_t wb; pen_t p; } gpen_t;

// Calls row(ctx, v, para, plain, attr, off, len, first) for each row the paragraphs wrap to at
// width w, with v counting from 0. Returns how many rows there are.
typedef void (*text_row_fn)(void *ctx, int v, const tui_para_t *pa, const char *plain, const uint8_t *attr,
                            size_t off, size_t len, int first);

typedef struct {
    wbuf_t *w;
    int top, left, iw, tw, first, h;
} text_draw_t;

static inline int clamp_permille(int pm) { return pm < 0 ? 0 : pm > 1000 ? 1000 : pm; }

extern int g_color;
extern int g_have_bg;
extern char g_sel_bg[32];
extern const char *g_row_bg;
extern grid_t g_grid;
extern int g_input_h;

// tui.c
void wapp(wbuf_t *w, const char *fmt, ...) PRINTF_LIKE(2, 3);
void copy_slice(char *out, size_t cap, const char *s, size_t len);
int wapp_trunc(wbuf_t *w, const char *s, int width);
void at(wbuf_t *w, int row, int col);
void sty(wbuf_t *w, style_t s);
void sty_tone(wbuf_t *w, tui_tone_t t, int bold);
void sty_pill(wbuf_t *w, tui_tone_t t);
const char *border_sgr(int tone);
void sty_rgb(wbuf_t *w, const uint8_t rgb[3], int bold, int exact);
void row_select(int on);
void ptext(pen_t *p, style_t s, const char *t);
void pell(pen_t *p, style_t s, const char *t, int width);
void prgb(pen_t *p, const uint8_t rgb[3], int bold, const char *t, int width);
void pspace(pen_t *p, int to);
void inner_begin(wbuf_t *w, pen_t *p, int row, int left, int width);
void inner_end(pen_t *p);
void blank_row(wbuf_t *w, int row, int left, int width);
void draw_hint(pen_t *p, const char *h);
void span_init(span_t *s, int room);
int title_room(int width, int right_cols);
void edge(wbuf_t *w, int row, int left, int width, const char *lc, const char *rc, const char *bs,
          const span_t *title, const span_t *right);
void sides(wbuf_t *w, int top, int h, int left, int width, const char *bs);
const char *top_left(rect_t r);
const char *bottom_left(rect_t r);
void box(wbuf_t *w, rect_t r, const char *bs, const span_t *title, const span_t *right, const span_t *foot);
void brand(span_t *title, span_t *right, int width);
void begin_frame(wbuf_t *w);
void end_frame(wbuf_t *w, int whole);
void place_cursor(wbuf_t *w, int row, int col, const tui_input_t *in);
void clamp_size(int *rows, int *cols);
wbuf_t frame_init(int *rows, int *cols, int color_enabled);
void grid_reset(grid_t *g, int rows, int w);
void grid_open(grid_t *g, int r, gpen_t *gp);
void grid_close(grid_t *g, int r, const gpen_t *gp);
void grid_emit(wbuf_t *w, const grid_t *g, int top, int left, int pad);

// tui_input.c
int mention_start(const tui_input_t *in);
const char *mention_suggestion(const tui_input_t *in);
int suggestion_count(const tui_input_t *in);

// tui_chat.c
size_t wrap_chunk(const char *s, size_t len, int width);
int wrap_rows(const char *text, int first_w, int rest_w, size_t *off, size_t *len, int max);
void draw_image_row(pen_t *p, const tui_image_t *im, int cols, int r);
void draw_bar(pen_t *p, int permille, int width);
int split_lines(const char *text, const char **lines, size_t *lens, int max);
void pointer(pen_t *p, int on);

// tui_bar.c
int input_rows(const tui_bar_t *bar, int box_w, int most);
void draw_input(wbuf_t *w, rect_t r, int boxed, const tui_bar_t *bar, const tui_view_t *v, rect_t over,
                int *cr, int *cc);
void draw_status(wbuf_t *w, int row, int cols, const tui_bar_t *bar);
void finish_frame(wbuf_t *w, int rows, int cols, const tui_bar_t *bar, int cr, int cc);

// tui_pages.c
int layout_text(const tui_para_t *paras, int n, int w, text_row_fn row, void *ctx);
void draw_text_row(void *ctx, int v, const tui_para_t *pa, const char *plain, const uint8_t *attr,
                   size_t off, size_t len, int first);

#endif
