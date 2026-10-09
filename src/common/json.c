// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "common/json.h"
#include "common/util.h"
#include <string.h>

// Digits an integer may have and still be read as one: any 18 fit in an int64_t.
#define JS_INT_DIGITS 18
#define JS_HEX_DIGITS 4   // in a \u escape

// UTF-16 surrogates: a \u escape of a high one must be followed by one of a low one.
enum { HIGH_SURROGATE = 0xd800, LOW_SURROGATE = 0xdc00, SURROGATE_END = 0xe000, SUPPLEMENTARY = 0x10000 };

// The escapes a string may hold, and the characters they stand for.
static const char ESCAPE_CODES[] = "\"\\/bfnrt", ESCAPED[] = "\"\\/\b\f\n\r\t";

typedef struct {
    const char *buf;
    size_t len, pos;
    js_arena *arena;
} js_ctx;

static js_value *alloc_node(js_ctx *c) {
    if (c->arena->used >= JS_MAX_NODES) return NULL;
    js_value *v = &c->arena->pool[c->arena->used++];
    memset(v, 0, sizeof *v);
    return v;
}

static void skip_ws(js_ctx *c) {
    while (c->pos < c->len) {
        char ch = c->buf[c->pos];
        if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r') break;
        c->pos++;
    }
}

static int literal(js_ctx *c, const char *word) {
    size_t n = strlen(word);
    if (c->len - c->pos < n || memcmp(c->buf + c->pos, word, n) != 0) return 0;
    c->pos += n;
    return 1;
}

static int hex4(js_ctx *c, uint32_t *out) {
    if (c->len - c->pos < JS_HEX_DIGITS) return -1;
    uint32_t v = 0;
    for (int i = 0; i < JS_HEX_DIGITS; i++) {
        int h = hex_value(c->buf[c->pos++]);
        if (h < 0) return -1;
        v = (v << 4) | (uint32_t)h;
    }
    *out = v;
    return 0;
}

// The character a \u escape stands for (and a second one, for a surrogate pair), as UTF-8.
static int unicode_escape(js_ctx *c, char enc[UTF8_CHAR_MAX], size_t *n) {
    uint32_t cp;
    if (hex4(c, &cp) != 0) return -1;
    if (cp >= HIGH_SURROGATE && cp < LOW_SURROGATE) {
        uint32_t lo;
        if (c->len - c->pos < 2 || c->buf[c->pos] != '\\' || c->buf[c->pos + 1] != 'u') return -1;
        c->pos += 2;
        if (hex4(c, &lo) != 0 || lo < LOW_SURROGATE || lo >= SURROGATE_END) return -1;
        cp = SUPPLEMENTARY + ((cp - HIGH_SURROGATE) << 10) + (lo - LOW_SURROGATE);
    } else if (cp >= LOW_SURROGATE && cp < SURROGATE_END) {
        return -1;
    }
    *n = utf8_put(cp, enc);
    return 0;
}

static js_value *parse_str(js_ctx *c) {
    if (c->pos >= c->len || c->buf[c->pos] != '"') return NULL;
    c->pos++;
    js_arena *a = c->arena;
    size_t start = a->text_used;
    for (;;) {
        if (c->pos >= c->len) return NULL;
        unsigned char ch = (unsigned char)c->buf[c->pos++];
        char enc[UTF8_CHAR_MAX];
        size_t n = 1;
        if (ch == '"') break;
        if (ch < 0x20) return NULL;
        if (ch != '\\') {
            enc[0] = (char)ch;
        } else {
            if (c->pos >= c->len) return NULL;
            char e = c->buf[c->pos++];
            const char *code = e ? strchr(ESCAPE_CODES, e) : NULL;
            if (code) enc[0] = ESCAPED[code - ESCAPE_CODES];
            else if (e != 'u' || unicode_escape(c, enc, &n) != 0) return NULL;
        }
        if (a->text_used + n + 1 > JS_MAX_TEXT) return NULL;
        memcpy(a->text + a->text_used, enc, n);
        a->text_used += n;
    }
    a->text[a->text_used] = '\0';
    js_value *v = alloc_node(c);
    if (!v) return NULL;
    v->type = JS_STR;
    v->s = a->text + start;
    v->slen = a->text_used - start;
    a->text_used++;
    return v;
}

static int at_digit(const js_ctx *c) { return c->pos < c->len && c->buf[c->pos] >= '0' && c->buf[c->pos] <= '9'; }

// Past one digit or more. -1 if there are none.
static int skip_digits(js_ctx *c) {
    size_t f = c->pos;
    while (at_digit(c)) c->pos++;
    return c->pos == f ? -1 : 0;
}

static js_value *parse_num(js_ctx *c) {
    int neg = 0;
    if (c->pos < c->len && c->buf[c->pos] == '-') { neg = 1; c->pos++; }
    size_t digits = c->pos;
    int64_t val = 0;
    int is_int = 1;
    while (at_digit(c)) {
        if (c->pos - digits >= JS_INT_DIGITS) is_int = 0;
        else val = val * 10 + (c->buf[c->pos] - '0');
        c->pos++;
    }
    if (c->pos == digits) return NULL;
    if (c->buf[digits] == '0' && c->pos - digits > 1) return NULL;
    if (c->pos < c->len && c->buf[c->pos] == '.') {
        is_int = 0;
        c->pos++;
        if (skip_digits(c) != 0) return NULL;
    }
    if (c->pos < c->len && (c->buf[c->pos] == 'e' || c->buf[c->pos] == 'E')) {
        is_int = 0;
        c->pos++;
        if (c->pos < c->len && (c->buf[c->pos] == '+' || c->buf[c->pos] == '-')) c->pos++;
        if (skip_digits(c) != 0) return NULL;
    }
    js_value *v = alloc_node(c);
    if (!v) return NULL;
    v->type = JS_NUM;
    v->is_int = is_int;
    v->i = neg ? -val : val;
    return v;
}

static js_value *parse_value(js_ctx *c, int depth);

// As in bencode.c: children end up wherever their own parse put them, so each container copies
// its direct children into one run afterwards.
#define JS_MAX_ITEMS 256

static size_t copy_run(js_ctx *c, const uint16_t *idx, size_t count) {
    size_t first = c->arena->used;
    for (size_t i = 0; i < count; i++) c->arena->pool[c->arena->used++] = c->arena->pool[idx[i]];
    return first;
}

static js_value *parse_arr(js_ctx *c, int depth) {
    c->pos++;
    uint16_t idx[JS_MAX_ITEMS];
    size_t count = 0;
    skip_ws(c);
    if (c->pos < c->len && c->buf[c->pos] == ']') c->pos++;
    else {
        for (;;) {
            if (count >= JS_MAX_ITEMS) return NULL;
            js_value *item = parse_value(c, depth + 1);
            if (!item) return NULL;
            idx[count++] = (uint16_t)(item - c->arena->pool);
            skip_ws(c);
            if (c->pos >= c->len) return NULL;
            char ch = c->buf[c->pos++];
            if (ch == ']') break;
            if (ch != ',') return NULL;
        }
    }
    if (c->arena->used + count + 1 > JS_MAX_NODES) return NULL;
    size_t first = copy_run(c, idx, count);
    js_value *v = alloc_node(c);
    if (!v) return NULL;
    v->type = JS_ARR;
    v->items = &c->arena->pool[first];
    v->n = count;
    return v;
}

static js_value *parse_obj(js_ctx *c, int depth) {
    c->pos++;
    uint16_t kidx[JS_MAX_ITEMS / 2], vidx[JS_MAX_ITEMS / 2];
    size_t count = 0;
    skip_ws(c);
    if (c->pos < c->len && c->buf[c->pos] == '}') c->pos++;
    else {
        for (;;) {
            if (count >= JS_MAX_ITEMS / 2) return NULL;
            skip_ws(c);
            js_value *k = parse_str(c);
            if (!k) return NULL;
            kidx[count] = (uint16_t)(k - c->arena->pool);
            skip_ws(c);
            if (c->pos >= c->len || c->buf[c->pos++] != ':') return NULL;
            js_value *val = parse_value(c, depth + 1);
            if (!val) return NULL;
            vidx[count++] = (uint16_t)(val - c->arena->pool);
            skip_ws(c);
            if (c->pos >= c->len) return NULL;
            char ch = c->buf[c->pos++];
            if (ch == '}') break;
            if (ch != ',') return NULL;
        }
    }
    if (c->arena->used + 2 * count + 1 > JS_MAX_NODES) return NULL;
    size_t kf = copy_run(c, kidx, count);
    size_t vf = copy_run(c, vidx, count);
    js_value *v = alloc_node(c);
    if (!v) return NULL;
    v->type = JS_OBJ;
    v->items = &c->arena->pool[kf];
    v->vals = &c->arena->pool[vf];
    v->n = count;
    return v;
}

static js_value *parse_value(js_ctx *c, int depth) {
    if (depth > JS_MAX_DEPTH) return NULL;
    skip_ws(c);
    if (c->pos >= c->len) return NULL;
    js_value *v;
    switch (c->buf[c->pos]) {
        case '{': return parse_obj(c, depth);
        case '[': return parse_arr(c, depth);
        case '"': return parse_str(c);
        case 't': if (!literal(c, "true")) return NULL; if ((v = alloc_node(c))) { v->type = JS_BOOL; v->b = 1; } return v;
        case 'f': if (!literal(c, "false")) return NULL; if ((v = alloc_node(c))) v->type = JS_BOOL; return v;
        case 'n': if (!literal(c, "null")) return NULL; if ((v = alloc_node(c))) v->type = JS_NULL; return v;
        default:  return parse_num(c);
    }
}

const js_value *js_parse(const char *data, size_t len, js_arena *arena) {
    arena->used = 0;
    arena->text_used = 0;
    js_ctx c = { data, len, 0, arena };
    js_value *v = parse_value(&c, 0);
    if (!v) return NULL;
    skip_ws(&c);
    return c.pos == len ? v : NULL;
}

const js_value *js_obj_get(const js_value *obj, const char *key) {
    if (!obj || obj->type != JS_OBJ) return NULL;
    size_t klen = strlen(key);
    for (size_t i = 0; i < obj->n; i++) {
        const js_value *k = &obj->items[i];
        if (k->slen == klen && memcmp(k->s, key, klen) == 0) return &obj->vals[i];
    }
    return NULL;
}

const char *js_str(const js_value *v) { return v && v->type == JS_STR ? v->s : NULL; }

size_t js_put_str(char *out, size_t pos, size_t cap, const char *s, size_t len) {
    if (pos >= cap) return cap;
    out[pos++] = '"';
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        // NIP-01 escapes these with a letter, and every other control character as \u00XX. '/' and
        // \0 (which strchr would find) are never escaped with a letter.
        const char *esc_at = ch && ch != '/' ? strchr(ESCAPED, ch) : NULL;
        char esc[7];
        size_t n;
        if (esc_at) {
            esc[0] = '\\'; esc[1] = ESCAPE_CODES[esc_at - ESCAPED]; n = 2;
        } else if (ch < 0x20) {
            esc[0] = '\\'; esc[1] = 'u'; esc[2] = '0'; esc[3] = '0';
            esc[4] = HEX_DIGITS[ch >> 4]; esc[5] = HEX_DIGITS[ch & 15]; n = 6;
        } else {
            esc[0] = (char)ch; n = 1;
        }
        if (pos + n >= cap) return cap;
        memcpy(out + pos, esc, n);
        pos += n;
    }
    if (pos + 1 >= cap) return cap;
    out[pos++] = '"';
    out[pos] = '\0';
    return pos;
}
