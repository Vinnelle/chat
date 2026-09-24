// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "bencode.h"
#include <string.h>

typedef struct {
    const uint8_t *buf;
    size_t len, pos;
    be_arena *arena;
} be_ctx;

static be_value *alloc_node(be_ctx *c) {
    if (c->arena->used >= BE_MAX_NODES) return NULL;
    be_value *v = &c->arena->pool[c->arena->used++];
    memset(v, 0, sizeof *v);
    return v;
}

static be_value *parse_value(be_ctx *c, int depth);

static be_value *parse_int(be_ctx *c) {

    size_t start = ++c->pos;
    int neg = 0;
    if (c->pos < c->len && c->buf[c->pos] == '-') { neg = 1; c->pos++; }
    size_t digits_start = c->pos;
    int64_t val = 0;
    while (c->pos < c->len && c->buf[c->pos] >= '0' && c->buf[c->pos] <= '9') {

        if (c->pos - digits_start >= 18) return NULL;
        val = val * 10 + (c->buf[c->pos] - '0');
        c->pos++;
    }
    if (c->pos == digits_start || c->pos >= c->len || c->buf[c->pos] != 'e') return NULL;
    c->pos++;
    (void)start;
    be_value *v = alloc_node(c);
    if (!v) return NULL;
    v->type = BE_INT;
    v->i = neg ? -val : val;
    return v;
}

static be_value *parse_str(be_ctx *c) {

    size_t digits_start = c->pos;
    size_t n = 0;
    while (c->pos < c->len && c->buf[c->pos] >= '0' && c->buf[c->pos] <= '9') {
        n = n * 10 + (c->buf[c->pos] - '0');
        c->pos++;
        if (n > c->len) return NULL;
    }
    if (c->pos == digits_start || c->pos >= c->len || c->buf[c->pos] != ':') return NULL;
    c->pos++;
    if (c->pos + n > c->len) return NULL;
    be_value *v = alloc_node(c);
    if (!v) return NULL;
    v->type = BE_STR;
    v->s = c->buf + c->pos;
    v->slen = n;
    c->pos += n;
    return v;
}

static be_value *parse_list(be_ctx *c, int depth) {
    c->pos++;
    size_t first = c->arena->used;
    size_t count = 0;
    while (c->pos < c->len && c->buf[c->pos] != 'e') {
        if (!parse_value(c, depth + 1)) return NULL;
        count++;
    }
    if (c->pos >= c->len) return NULL;
    c->pos++;
    be_value *v = alloc_node(c);
    if (!v) return NULL;
    v->type = BE_LIST;
    v->items = &c->arena->pool[first];
    v->n = count;
    return v;
}

static be_value *parse_dict(be_ctx *c, int depth) {
    c->pos++;

    size_t key_idx[128], val_idx[128];
    size_t count = 0;
    while (c->pos < c->len && c->buf[c->pos] != 'e') {
        if (count >= 128) return NULL;
        be_value *k = parse_str(c);
        if (!k) return NULL;
        key_idx[count] = (size_t)(k - c->arena->pool);
        be_value *val = parse_value(c, depth + 1);
        if (!val) return NULL;
        val_idx[count] = (size_t)(val - c->arena->pool);
        count++;
    }
    if (c->pos >= c->len) return NULL;
    c->pos++;
    if (c->arena->used + 2 * count > BE_MAX_NODES) return NULL;
    size_t keys_first = c->arena->used;
    for (size_t i = 0; i < count; i++) c->arena->pool[c->arena->used++] = c->arena->pool[key_idx[i]];
    size_t vals_first = c->arena->used;
    for (size_t i = 0; i < count; i++) c->arena->pool[c->arena->used++] = c->arena->pool[val_idx[i]];
    be_value *v = alloc_node(c);
    if (!v) return NULL;
    v->type = BE_DICT;
    v->items = &c->arena->pool[keys_first];
    v->dict_vals = &c->arena->pool[vals_first];
    v->n = count;
    return v;
}

static be_value *parse_value(be_ctx *c, int depth) {
    if (depth > BE_MAX_DEPTH || c->pos >= c->len) return NULL;
    switch (c->buf[c->pos]) {
        case 'i': return parse_int(c);
        case 'l': return parse_list(c, depth);
        case 'd': return parse_dict(c, depth);
        default:
            if (c->buf[c->pos] >= '0' && c->buf[c->pos] <= '9') return parse_str(c);
            return NULL;
    }
}

const be_value *be_parse(const uint8_t *data, size_t len, be_arena *arena) {
    arena->used = 0;
    be_ctx c = { data, len, 0, arena };
    return parse_value(&c, 0);
}

const be_value *be_dict_get(const be_value *dict, const char *key) {
    if (!dict || dict->type != BE_DICT) return NULL;
    size_t klen = strlen(key);
    for (size_t i = 0; i < dict->n; i++) {
        const be_value *k = &dict->items[i];
        if (k->slen == klen && memcmp(k->s, key, klen) == 0) return &dict->dict_vals[i];
    }
    return NULL;
}
