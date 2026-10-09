// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "common/bencode.h"
#include <string.h>

// Digits an integer may have: any 18 fit in an int64_t.
#define BE_INT_DIGITS 18

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

static int at_digit(const be_ctx *c) { return c->pos < c->len && c->buf[c->pos] >= '0' && c->buf[c->pos] <= '9'; }

static be_value *parse_int(be_ctx *c) {
    c->pos++;
    int neg = 0;
    if (c->pos < c->len && c->buf[c->pos] == '-') { neg = 1; c->pos++; }
    size_t digits_start = c->pos;
    int64_t val = 0;
    while (at_digit(c)) {
        if (c->pos - digits_start >= BE_INT_DIGITS) return NULL;
        val = val * 10 + (c->buf[c->pos] - '0');
        c->pos++;
    }
    if (c->pos == digits_start || c->pos >= c->len || c->buf[c->pos] != 'e') return NULL;
    c->pos++;
    be_value *v = alloc_node(c);
    if (!v) return NULL;
    v->type = BE_INT;
    v->i = neg ? -val : val;
    return v;
}

static be_value *parse_str(be_ctx *c) {
    size_t digits_start = c->pos;
    size_t n = 0;
    while (at_digit(c)) {
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

// Children are parsed first, and a child that is itself a list or dict allocates its own children
// before its node, so a container's direct children aren't adjacent in the pool. Each container
// records where they ended up and copies them into one run for items[] to index.
#define BE_MAX_ITEMS 256

static size_t copy_run(be_ctx *c, const uint16_t *idx, size_t count) {
    size_t first = c->arena->used;
    for (size_t i = 0; i < count; i++) c->arena->pool[c->arena->used++] = c->arena->pool[idx[i]];
    return first;
}

static be_value *parse_list(be_ctx *c, int depth) {
    c->pos++;
    uint16_t item_idx[BE_MAX_ITEMS];
    size_t count = 0;
    while (c->pos < c->len && c->buf[c->pos] != 'e') {
        if (count >= BE_MAX_ITEMS) return NULL;
        be_value *item = parse_value(c, depth + 1);
        if (!item) return NULL;
        item_idx[count++] = (uint16_t)(item - c->arena->pool);
    }
    if (c->pos >= c->len) return NULL;
    c->pos++;
    if (c->arena->used + count + 1 > BE_MAX_NODES) return NULL;
    size_t first = copy_run(c, item_idx, count);
    be_value *v = alloc_node(c);
    if (!v) return NULL;
    v->type = BE_LIST;
    v->items = &c->arena->pool[first];
    v->n = count;
    return v;
}

static be_value *parse_dict(be_ctx *c, int depth) {
    c->pos++;
    uint16_t key_idx[BE_MAX_ITEMS / 2], val_idx[BE_MAX_ITEMS / 2];
    size_t count = 0;
    while (c->pos < c->len && c->buf[c->pos] != 'e') {
        if (count >= BE_MAX_ITEMS / 2) return NULL;
        be_value *k = parse_str(c);
        if (!k) return NULL;
        key_idx[count] = (uint16_t)(k - c->arena->pool);
        be_value *val = parse_value(c, depth + 1);
        if (!val) return NULL;
        val_idx[count] = (uint16_t)(val - c->arena->pool);
        count++;
    }
    if (c->pos >= c->len) return NULL;
    c->pos++;
    if (c->arena->used + 2 * count + 1 > BE_MAX_NODES) return NULL;
    size_t keys_first = copy_run(c, key_idx, count);
    size_t vals_first = copy_run(c, val_idx, count);
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
        default:  return at_digit(c) ? parse_str(c) : NULL;
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
