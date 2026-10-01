// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "common/toml.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *p;
    int line;
    char buf[TOML_STR_MAX * (TOML_ARRAY_MAX + 1)];
    size_t used;
} parser_t;

static void skip_ws(parser_t *ps) {
    while (*ps->p == ' ' || *ps->p == '\t') ps->p++;
}

static void skip_comment(parser_t *ps) {
    if (*ps->p == '#') while (*ps->p && *ps->p != '\n') ps->p++;
}

static int newline(parser_t *ps) {
    if (ps->p[0] == '\r' && ps->p[1] == '\n') ps->p++;
    if (*ps->p != '\n') return 0;
    ps->p++;
    ps->line++;
    return 1;
}

static void skip_space(parser_t *ps) {
    do {
        skip_ws(ps);
        skip_comment(ps);
    } while (newline(ps));
}

static int end_of_line(parser_t *ps) {
    skip_ws(ps);
    skip_comment(ps);
    return newline(ps) || !*ps->p ? 0 : -1;
}

static int bare_char(char c) {
    return isalnum((unsigned char)c) || c == '_' || c == '-';
}

static int put_utf8(char *out, size_t *n, size_t room, uint32_t cp) {
    uint8_t b[4];
    size_t k;
    if (cp < 0x80) { b[0] = (uint8_t)cp; k = 1; }
    else if (cp < 0x800) { b[0] = (uint8_t)(0xc0 | cp >> 6); b[1] = (uint8_t)(0x80 | (cp & 0x3f)); k = 2; }
    else if (cp < 0x10000) {
        b[0] = (uint8_t)(0xe0 | cp >> 12); b[1] = (uint8_t)(0x80 | (cp >> 6 & 0x3f)); b[2] = (uint8_t)(0x80 | (cp & 0x3f)); k = 3;
    } else {
        b[0] = (uint8_t)(0xf0 | cp >> 18); b[1] = (uint8_t)(0x80 | (cp >> 12 & 0x3f));
        b[2] = (uint8_t)(0x80 | (cp >> 6 & 0x3f)); b[3] = (uint8_t)(0x80 | (cp & 0x3f)); k = 4;
    }
    if (*n + k >= room) return -1;
    memcpy(out + *n, b, k);
    *n += k;
    return 0;
}

// Never steps past the end of the text: a failed parse goes on from where it stopped.
static int escape(parser_t *ps, char *out, size_t *n, size_t room) {
    static const char FROM[] = "btnfr\"\\", TO[] = "\b\t\n\f\r\"\\";
    char e = *ps->p;
    const char *at = e ? strchr(FROM, e) : NULL;
    if (!at && e != 'u' && e != 'U') return -1;
    ps->p++;
    if (at) return put_utf8(out, n, room, (uint8_t)TO[at - FROM]);
    uint32_t cp = 0;
    for (int k = 0; k < (e == 'u' ? 4 : 8); k++) {
        char h = *ps->p;
        if (!isxdigit((unsigned char)h)) return -1;
        ps->p++;
        cp = cp << 4 | (uint32_t)(isdigit((unsigned char)h) ? h - '0' : (tolower((unsigned char)h) - 'a' + 10));
    }
    // NUL would end the string early.
    if (cp == 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return -1;
    return put_utf8(out, n, room, cp);
}

static const char *string(parser_t *ps) {
    char q = *ps->p;
    if ((q != '"' && q != '\'') || (ps->p[1] == q && ps->p[2] == q)) return NULL;
    ps->p++;
    char *out = ps->buf + ps->used;
    size_t room = sizeof ps->buf - ps->used, n = 0;
    if (room > TOML_STR_MAX) room = TOML_STR_MAX;
    for (;;) {
        unsigned char c = (unsigned char)*ps->p;
        if (c == q) { ps->p++; break; }
        if (!c || (c < 0x20 && c != '\t') || c == 0x7f) return NULL;
        ps->p++;
        if (q == '"' && c == '\\') {
            if (escape(ps, out, &n, room) != 0) return NULL;
        } else {
            if (n + 1 >= room) return NULL;
            out[n++] = (char)c;
        }
    }
    out[n] = '\0';
    ps->used += n + 1;
    return out;
}

static int key(parser_t *ps, char out[TOML_KEY_MAX]) {
    if (*ps->p == '"' || *ps->p == '\'') {
        size_t mark = ps->used;
        const char *s = string(ps);
        ps->used = mark;
        if (!s || strlen(s) >= TOML_KEY_MAX) return -1;
        strcpy(out, s);
        return 0;
    }
    size_t n = 0;
    while (bare_char(*ps->p)) {
        if (n + 1 >= TOML_KEY_MAX) return -1;
        out[n++] = *ps->p++;
    }
    out[n] = '\0';
    return n ? 0 : -1;
}

static int integer(parser_t *ps, long long *out) {
    const char *p = ps->p;
    int neg = *p == '-';
    if (*p == '+' || *p == '-') p++;
    if (!isdigit((unsigned char)*p) || (*p == '0' && (isdigit((unsigned char)p[1]) || p[1] == '_'))) return -1;
    long long v = 0;
    for (; isdigit((unsigned char)*p) || *p == '_'; p++) {
        if (*p == '_') {
            if (!isdigit((unsigned char)p[1])) return -1;
            continue;
        }
        if (v > (999999999999999999LL - (*p - '0')) / 10) return -1;
        v = v * 10 + (*p - '0');
    }
    ps->p = p;
    *out = neg ? -v : v;
    return 0;
}

static int word(parser_t *ps, const char *w) {
    size_t n = strlen(w);
    if (strncmp(ps->p, w, n) != 0 || bare_char(ps->p[n])) return 0;
    ps->p += n;
    return 1;
}

static int value(parser_t *ps, toml_value *v) {
    memset(v, 0, sizeof *v);
    if (*ps->p == '"' || *ps->p == '\'') {
        v->type = TOML_STRING;
        v->s = string(ps);
        return v->s ? 0 : -1;
    }
    v->type = TOML_BOOL;
    if (word(ps, "true")) { v->b = 1; return 0; }
    if (word(ps, "false")) return 0;
    if (*ps->p != '[') {
        v->type = TOML_INT;
        return integer(ps, &v->i);
    }
    v->type = TOML_ARRAY;
    ps->p++;
    for (;;) {
        skip_space(ps);
        if (*ps->p == ']') { ps->p++; return 0; }
        if (v->n >= TOML_ARRAY_MAX || !(v->items[v->n++] = string(ps))) return -1;
        skip_space(ps);
        if (*ps->p == ',') ps->p++;
        else if (*ps->p != ']') return -1;
    }
}

int toml_parse(const char *text, toml_fn fn, void *ctx, int *bad_line) {
    parser_t ps;
    ps.p = text;
    ps.line = 1;
    if (strncmp(ps.p, "\xef\xbb\xbf", 3) == 0) ps.p += 3;
    char table[TOML_KEY_MAX] = "";
    int bad = 0, lost = 0;
    if (bad_line) *bad_line = 0;
    for (;;) {
        skip_space(&ps);
        if (!*ps.p) break;
        int line = ps.line, ok;
        ps.used = 0;
        if (*ps.p == '[') {
            char name[TOML_KEY_MAX];
            ps.p++;
            skip_ws(&ps);
            ok = key(&ps, name) == 0;
            if (ok) { skip_ws(&ps); ok = *ps.p == ']'; }
            if (ok) { ps.p++; ok = end_of_line(&ps) == 0; }
            lost = !ok;
            if (ok) strcpy(table, name);
        } else {
            char k[TOML_KEY_MAX];
            toml_value v;
            ok = key(&ps, k) == 0;
            if (ok) { skip_ws(&ps); ok = *ps.p == '='; }
            if (ok) { ps.p++; skip_ws(&ps); ok = value(&ps, &v) == 0 && end_of_line(&ps) == 0; }
            ok = ok && !lost;
            if (ok) fn(ctx, table, k, &v);
        }
        if (!ok) {
            if (!bad++ && bad_line) *bad_line = line;
            while (*ps.p && *ps.p != '\n') ps.p++;
        }
    }
    return bad;
}

size_t toml_put_str(char *out, size_t pos, size_t cap, const char *s) {
    size_t p = pos;
#define PUT(c) do { if (p + 1 >= cap) return cap; out[p++] = (c); } while (0)
    PUT('"');
    for (const unsigned char *c = (const unsigned char *)s; *c; c++) {
        if (*c == '"' || *c == '\\') { PUT('\\'); PUT((char)*c); }
        else if (*c < 0x20 || *c == 0x7f) {
            char esc[8];
            snprintf(esc, sizeof esc, "\\u%04x", *c);
            for (char *e = esc; *e; e++) PUT(*e);
        } else PUT((char)*c);
    }
    PUT('"');
#undef PUT
    out[p] = '\0';
    return p;
}
